#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Interactive configuration. The bot token is never an argument or echoed."""
import getpass
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
from zoneinfo import ZoneInfo
import f2btelegram as f


def ask(en, ru, language):
    return input(ru if language == 'ru' else en).strip()


def detect_ports():
    output = f.run(['sshd', '-T'])
    ports = sorted({int(line.split()[1]) for line in output.splitlines() if line.startswith('port ')})
    if not ports:
        raise ValueError('Could not detect SSH ports from sshd -T')
    return ports


def save_config(cfg, path):
    cfg = f.validate_config(cfg)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix='config-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(cfg, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    if os.name != 'posix' or os.geteuid() != 0:
        raise SystemExit('Run on the Linux server as root: sudo python3 setup_credentials.py')
    os.umask(0o077)
    cfg = json.loads(f.CONFIG.read_text(encoding='utf-8')) if f.CONFIG.exists() else {}
    language = input('Language / Язык [en/ru, default en]: ').strip().lower() or cfg.get('language', 'en')
    if language not in ('en', 'ru'):
        raise SystemExit('Choose en or ru')
    cfg['language'] = language
    cfg['timezone'] = ask('Timezone [UTC]: ', 'Часовой пояс [UTC]: ', language) or cfg.get('timezone', 'UTC')
    ZoneInfo(cfg['timezone'])
    ports = detect_ports()
    prompt = ','.join(map(str, ports))
    value = ask(f'SSH TCP ports [{prompt}]: ', f'TCP-порты SSH [{prompt}]: ', language)
    cfg['ssh_ports'] = [int(p.strip()) for p in value.split(',')] if value else ports
    cfg['server_name'] = ask('Server label [ssh-server]: ', 'Название сервера [ssh-server]: ', language) or cfg.get('server_name', 'ssh-server')
    token = getpass.getpass('Bot token (hidden; Enter keeps the existing token): ').strip()
    if token:
        cfg['token'] = token
    try:
        f.validate_token(cfg.get('token'))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    cfg['chat_id'] = int(ask('Private Telegram chat ID: ', 'ID личного Telegram-чата: ', language))
    cfg['user_id'] = cfg['chat_id']
    geo = ask('Enable country/ISP lookup via ipwho.is? Banned IPs will be sent there [y/N]: ',
              'Включить страну/провайдера через ipwho.is? Заблокированные IP будут переданы сервису [y/N]: ', language)
    cfg['geoip'] = geo.lower() in ('y', 'yes', 'д', 'да')
    protected = set(cfg.get('protected', [])) | {'127.0.0.0/8', '::1/128'}
    for interface in json.loads(f.run(['ip', '-j', 'addr', 'show'])):
        for addr in interface.get('addr_info', []):
            local = ipaddress.ip_address(addr['local'])
            protected.add(f'{local}/{local.max_prefixlen}')
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if connection:
        client = ipaddress.ip_address(connection[0])
        protected.add(f'{client}/{client.max_prefixlen}')
    extra = ask('Additional protected IPs/CIDRs (space separated): ', 'Дополнительные защищённые IP/CIDR через пробел: ', language)
    protected.update(str(ipaddress.ip_network(n, strict=False)) for n in extra.replace(',', ' ').split())
    cfg['protected'] = sorted(protected)
    cfg = f.validate_config(cfg)
    bot = f.api(cfg, 'getMe')
    if f.api(cfg, 'getWebhookInfo').get('url'):
        raise SystemExit('The bot has a webhook. Use a dedicated bot; this tool will not delete its webhook.')
    f.api(cfg, 'sendMessage', chat_id=cfg['chat_id'], text=(
        'Подключение проверено. Установка ещё не завершена.' if language == 'ru'
        else 'Connection verified. Installation has not finished yet.'))
    save_config(cfg, f.CONFIG)
    print('Saved securely for @'+bot['username']+'. Continue with: sudo bash install.sh')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, f.APIError, OSError, subprocess.SubprocessError) as exc:
        # Network errors never include a URL containing the token.
        raise SystemExit('Setup failed: '+(str(exc) if isinstance(exc, (ValueError, f.APIError)) else type(exc).__name__)) from None
