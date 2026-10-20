#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install only project-owned files; preserve the existing sshd jail policy."""
import argparse
from contextlib import closing
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import f2btelegram as f
import f2bmanage as m

APP = Path('/opt/fail2ban-telegram-control')
UNIT = Path('/etc/systemd/system/fail2ban-telegram-control.service')
ACTION = Path('/etc/fail2ban/action.d/telegram_control.py')
INCLUDE = Path('/etc/fail2ban/jail.d/zz-telegram-control-whitelist.local')
BACKUPS = Path('/var/backups/fail2ban-telegram-control')
SERVICE = 'fail2ban-telegram-control'
MANIFEST = f.STATE / 'install-manifest.json'
FILES = ('f2btelegram.py', 'f2bmanage.py', 'i18n.py', 'telegram_action.py',
         'setup_credentials.py', 'installer.py', 'install.sh', 'uninstall.sh',
         'fail2ban-telegram-control.service', 'locales/ru.json', 'LICENSE',
         'THIRD_PARTY_NOTICES.md', 'README.md', 'README.ru.md')


def call(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=60)
    if check and result.returncode:
        raise RuntimeError('Command failed: '+' '.join(args[:3])+'; '+result.stderr[-1000:])
    return result


def require_root():
    if os.name != 'posix' or os.geteuid() != 0:
        raise RuntimeError('Use sudo on the Ubuntu server (not on a Windows workstation).')


def verify_platform():
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04':
        raise RuntimeError('This release is tested only on Ubuntu 24.04 LTS.')
    version = call('fail2ban-client', 'version').stdout.strip().split()[-1]
    f.check_fail2ban_version(version)


def preflight():
    require_root()
    for name in ('nft', 'ip', 'sshd', 'fail2ban-client', 'systemctl', 'systemd-analyze'):
        if not shutil.which(name):
            raise RuntimeError('Missing command: '+name+'. See the prerequisites in README.md.')
    verify_platform()
    cfg = f.config()
    call('systemctl', 'is-active', '--quiet', 'fail2ban')
    actions = m.engine('get', 'sshd', 'actions')
    if not any('nftables' in name.lower() for name in actions):
        raise RuntimeError('The enabled sshd jail must already use an nftables action. Its firewall action will not be replaced.')
    m.verify_scope(cfg)
    ignored = m.engine('get', 'sshd', 'ignoreip')
    for entry in ignored:
        try:
            ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            raise RuntimeError('Hostname-based ignoreip entries are not supported by this release.') from None
    target = f.STATE / 'whitelist.local'
    if (INCLUDE.exists() or INCLUDE.is_symlink()) and (not INCLUDE.is_symlink() or INCLUDE.resolve() != target):
        raise RuntimeError('An unmanaged file already exists at '+str(INCLUDE))
    if (APP.exists() or ACTION.exists() or UNIT.exists()) and not MANIFEST.exists():
        raise RuntimeError('Project paths already exist without an ownership manifest; inspect them before installing.')
    if 'telegram_control' in actions and not MANIFEST.exists():
        raise RuntimeError('An action named telegram_control already exists and is not owned by this installation.')
    return cfg, list(ignored)


def normalize(entries):
    return {str(ipaddress.ip_network(str(n), strict=False)): str(n) for n in entries}


def restore_ignores(entries):
    current = normalize(m.engine('get', 'sshd', 'ignoreip'))
    desired = normalize(entries)
    for net in current.keys()-desired.keys():
        m.engine('set', 'sshd', 'delignoreip', current[net])
    for net in desired.keys()-current.keys():
        m.engine('set', 'sshd', 'addignoreip', desired[net])


def install(source):
    cfg, original_ignores = preflight()
    source = source.resolve()
    for name in FILES:
        if not (source/name).is_file():
            raise RuntimeError('Incomplete source distribution: '+name)
    os.umask(0o077)
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = BACKUPS / stamp
    backup.mkdir(parents=True, mode=0o700)
    had_app, had_include = APP.exists(), INCLUDE.is_symlink()
    old_running = call('systemctl', 'is-active', '--quiet', SERVICE, check=False).returncode == 0
    if had_app:
        shutil.copytree(APP, backup/'app')
    for item in (UNIT, ACTION):
        if item.exists():
            shutil.copy2(item, backup/item.name)
    if MANIFEST.exists():
        shutil.copy2(MANIFEST, backup/'install-manifest.json')
    if (f.STATE/'state.sqlite3').exists():
        with closing(sqlite3.connect(f.STATE/'state.sqlite3')) as src, closing(sqlite3.connect(backup/'state.sqlite3')) as dst:
            src.backup(dst)
    (backup/'original-ignores.json').write_text(json.dumps(original_ignores), encoding='utf-8')
    call('systemctl', 'stop', SERVICE, check=False)
    try:
        APP.mkdir(mode=0o755, parents=True, exist_ok=True)
        for name in FILES:
            target = APP/name
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if (source/name).resolve() != target.resolve():
                shutil.copy2(source/name, target)
            os.chmod(target, 0o644)
        shutil.copy2(source/'telegram_action.py', ACTION)
        os.chmod(ACTION, 0o644)
        f.initialize()
        actions = m.engine('get', 'sshd', 'actions')
        if 'telegram_control' in actions:
            m.engine('set', 'sshd', 'delaction', 'telegram_control')
        m.engine('set', 'sshd', 'addaction', 'telegram_control', str(ACTION), '{}')
        m.sync_whitelist(cfg)
        if not had_include:
            INCLUDE.symlink_to(f.STATE/'whitelist.local')
        call('fail2ban-client', '-t')
        shutil.copy2(source/'fail2ban-telegram-control.service', UNIT)
        call('systemd-analyze', 'verify', str(UNIT))
        MANIFEST.write_text(json.dumps({'version':'0.1.0','backup':str(backup),'app':str(APP)},indent=2)+'\n', encoding='utf-8')
        call('systemctl', 'daemon-reload')
        call('systemctl', 'enable', SERVICE)
        call('systemctl', 'restart', SERVICE)
        call('systemctl', 'is-active', '--quiet', SERVICE)
    except Exception:
        call('systemctl', 'stop', SERVICE, check=False)
        try:
            if 'telegram_control' in m.engine('get', 'sshd', 'actions'):
                m.engine('set', 'sshd', 'delaction', 'telegram_control')
            restore_ignores(original_ignores)
        except (OSError, RuntimeError):
            print('Runtime rollback could not reach Fail2ban; inspect its state and the backup.', file=sys.stderr)
        if not had_include and INCLUDE.is_symlink():
            INCLUDE.unlink()
        for item in (UNIT, ACTION):
            saved = backup/item.name
            if saved.exists():
                shutil.copy2(saved, item)
            elif item.exists():
                item.unlink()
        # Delete only our individually enumerated copied files; never recursively
        # delete an existing installation or another administrator's directory.
        for name in FILES:
            saved = backup/'app'/name
            target = APP/name
            if saved.exists():
                shutil.copy2(saved, target)
            elif target.exists():
                target.unlink()
        if (backup/'install-manifest.json').exists():
            shutil.copy2(backup/'install-manifest.json', MANIFEST)
        elif MANIFEST.exists():
            MANIFEST.unlink()
        if not had_app:
            call('nft', 'delete', 'table', 'inet', 'f2b_telegram_control', check=False)
        call('systemctl', 'daemon-reload')
        if old_running:
            call('systemctl', 'start', SERVICE)
        raise
    print('Installed Fail2ban Telegram Control 0.1.0. Existing jail actions and ban-time policy were preserved.')
    print('Backup:', backup)
    print('Check: sudo systemctl status '+SERVICE)


def uninstall():
    require_root()
    if not MANIFEST.exists():
        raise RuntimeError('No ownership manifest found; refusing to remove files.')
    cfg = f.config()
    call('systemctl', 'disable', '--now', SERVICE, check=False)
    try:
        # Baseline records belong to the administrator, not to the bot.
        restore_ignores(m.baseline(cfg))
        if 'telegram_control' in m.engine('get', 'sshd', 'actions'):
            m.engine('set', 'sshd', 'delaction', 'telegram_control')
    except (OSError, RuntimeError):
        print('Fail2ban is unavailable. Its original configuration will apply on its next start.')
    call('nft', 'delete', 'table', 'inet', 'f2b_telegram_control', check=False)
    if INCLUDE.is_symlink() and INCLUDE.resolve() == f.STATE/'whitelist.local':
        INCLUDE.unlink()
    for item in (UNIT, ACTION):
        if item.exists():
            item.unlink()
    call('systemctl', 'daemon-reload')
    print('Service and subnet rules removed. IP bans in the original jail were preserved.')
    print('Configuration, state, code and backups were retained for recovery.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('install', 'doctor', 'uninstall'))
    parser.add_argument('--source', type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    if args.operation == 'install':
        install(args.source)
    elif args.operation == 'uninstall':
        uninstall()
    else:
        cfg, ignored = preflight()
        print('Preflight passed. SSH ports:', cfg['ssh_ports'], '; existing ignored entries:',len(ignored))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError) as exc:
        raise SystemExit('Installation stopped: '+str(exc)) from None
