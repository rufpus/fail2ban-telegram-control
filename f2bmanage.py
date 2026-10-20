# SPDX-License-Identifier: MIT
"""Validated Telegram commands for the sshd jail; no shell command execution."""
import html
import ipaddress as ips
import json
import os
from pathlib import Path
import re
import socket
import tempfile
import threading
import time
import f2btelegram as f
from i18n import tr
MAXTIME = f.MAX_BAN_SECONDS
ADMIN_LOCK = threading.RLock()
AUDIT_RESULT_PREVIEW_LIMIT = 120  # Keep audit report pages within Telegram limits.
HELP = '<b>SSH / Fail2ban control</b>\n/status — service and notification queue\n/bans [page] — active IP and /24 bans\n/ip IP — IP status, whitelist and history\n/ban IP [duration] — ban an IP (default: 24h)\n/unban IP — remove an individual IP ban\n/bansubnet NETWORK [duration] — ban a /24 after confirmation\n/unbansubnet NETWORK — unban a /24 after confirmation\n/extend ADDRESS 7d — set expiry to 7 days from now\n/extend ADDRESS +7d — add 7 days to the current expiry\n/whitelist [page] — persistent whitelist\n/whitelist add IP_OR_CIDR — whitelist and unban\n/whitelist del IP_OR_CIDR — remove an entry (does not ban)\n/audit [page] — administration audit log\n/help — this help\n\nDuration: an integer followed by s, m, h, d or w; 1 second to 5 weeks.\nExamples: <code>/ban 203.0.113.8 7d</code>, <code>/bansubnet 203.0.113.0/24 2d</code>.\nIP commands run immediately. Subnet changes require confirmation.\nWhitelist networks: /24–/32. Banned networks: /24 only, TCP/{ports} only.\nRepeating a ban does not change its expiry. /extend without + can shorten it.\nOnly the sshd jail is managed. /unban does not remove a subnet ban.\nTimes use the configured timezone. Access is limited to the configured owner.'

def engine(*args):
    from fail2ban.client.csocket import CSocket
    sock = CSocket(timeout=12)
    try:
        result = sock.send(list(args))
    finally:
        sock.close()
    if result[0] != 0:
        raise RuntimeError(tr('Fail2ban rejected the operation; check the server journal.'))
    return result[1]

def snapshot():
    try:
        return engine('set', 'sshd', 'action', 'telegram_control', 'snapshot')
    except RuntimeError:
        with ADMIN_LOCK:
            actions = engine('get', 'sshd', 'actions')
            if 'telegram_control' not in actions:
                engine('set', 'sshd', 'addaction', 'telegram_control', '/etc/fail2ban/action.d/telegram_control.py', '{}')
            return engine('set', 'sshd', 'action', 'telegram_control', 'snapshot')

def manage(operation, ip, deadline=None):
    payload = dict(operation=operation, ip=ip)
    if deadline is not None:
        payload['deadline'] = deadline
    return engine('set', 'sshd', 'action', 'telegram_control', 'manage', json.dumps(payload))


def action_ports(value):
    result = set()
    for part in str(value).replace(' ', '').split(','):
        try:
            port = int(part) if part.isdecimal() else socket.getservbyname(part, 'tcp')
        except (OSError, ValueError):
            raise ValueError(tr('Unsupported sshd action port list; use explicit SSH TCP ports')) from None
        if not 1 <= port <= 65535:
            raise ValueError(tr('Invalid sshd action port'))
        result.add(port)
    return result


def verify_scope(cfg):
    actions = engine('get', 'sshd', 'actions')
    nft_actions = [name for name in actions if 'nftables' in name.lower()]
    if not nft_actions:
        raise RuntimeError(tr('The sshd jail must use nftables; its existing actions are preserved.'))
    expected = set(cfg.get('ssh_ports', f.SETTINGS['ssh_ports']))
    for name in nft_actions:
        startup = engine('get', 'sshd', 'action', name, 'actionstart')
        protocol = engine('get', 'sshd', 'action', name, 'protocol')
        ports = engine('get', 'sshd', 'action', name, 'port')
        if not re.search(r'\bdport\b', startup) or protocol != 'tcp' or action_ports(ports) != expected:
            raise RuntimeError(tr('sshd nftables action ports must match ssh_ports and use type=multiport. Update the jail and configuration, then run doctor.'))

def whitelist_networks():
    with f.database() as db:
        return [r[0] for r in db.execute('SELECT network FROM whitelist ORDER BY network')]

def baseline(cfg):
    with f.database() as db:
        row = db.execute("SELECT value FROM meta WHERE key='baseline_ignores'").fetchone()
    return sorted({str(ips.ip_network(n, strict=False)) for n in list(cfg['protected']) + (json.loads(row[0]) if row else [])})

def protected_ip(cfg, ip):
    address = ips.IPv4Address(ip)
    networks = baseline(cfg) + whitelist_networks() + ['127.0.0.0/8'] + list(f.local_addresses())
    if any((address in ips.ip_network(n, strict=False) for n in networks)):
        raise ValueError(tr('This IP is protected or whitelisted. Banning it is not allowed.'))

def sync_whitelist(cfg):
    """Persist a jail include under StateDirectory and reconcile runtime ignores."""
    with ADMIN_LOCK:
        state = snapshot()
        refresh_active_events(state)
        with f.database() as db:
            row = db.execute("SELECT value FROM meta WHERE key='baseline_ignores'").fetchone()
            if not row:
                fixed = sorted({str(ips.ip_network(n, strict=False)) for n in cfg['protected'] + state['ignored']})
                db.execute("INSERT INTO meta VALUES ('baseline_ignores',?)", (json.dumps(fixed),))
        desired = sorted(set(baseline(cfg)) | set(whitelist_networks()))
        contents = '[sshd]\nignoreip = ' + ' '.join(desired) + '\n'
        path = f.STATE / 'whitelist.local'
        if not path.exists() or path.read_text() != contents:
            fd, temporary = tempfile.mkstemp(prefix='whitelist-', dir=f.STATE)
            try:
                with os.fdopen(fd, 'w') as handle:
                    handle.write(contents)
                os.chmod(temporary, 384)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        with f.database() as db:
            saved = db.execute("SELECT value FROM meta WHERE key='applied_whitelist'").fetchone()
        prior = {str(ips.ip_network(n, strict=False)) for n in (json.loads(saved[0]) if saved else [])}
        runtime_names = {str(ips.ip_network(n, strict=False)): n for n in state['ignored']}
        runtime = set(runtime_names)
        for net in set(desired) - runtime:
            engine('set', 'sshd', 'addignoreip', net)
        for net in (prior - set(desired)) & runtime:
            name = runtime_names.get(net)
            if name is not None:
                engine('set', 'sshd', 'delignoreip', name)
        for row in state['bans']:
            address = ips.ip_address(row['ip'])
            if any((address in ips.ip_network(n, strict=False) for n in desired)):
                manage('unban', row['ip'])
        with f.database() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES ('applied_whitelist',?)", (json.dumps(desired),))

def refresh_active_events(state):
    with f.database() as db:
        for row in state['bans']:
            seconds = row.get('duration')
            if seconds is None:
                seconds = row['expires'] - row['started'] if row['expires'] is not None else -1
            db.execute("UPDATE events SET ended=NULL,duration=?\n                WHERE jail='sshd' AND ip=? AND abs(started-?)<?", (int(seconds), row['ip'], row['started'], f.TIME_TOLERANCE_SECONDS))

def parse_seconds(text):
    found = re.fullmatch('([1-9][0-9]{0,8})([smhdw])', text.lower())
    if not found:
        raise ValueError(tr('Duration must be a positive integer followed by s/m/h/d/w, for example 24h or 7d.'))
    seconds = int(found[1]) * dict(s=1, m=60, h=3600, d=86400, w=604800)[found[2]]
    if seconds > MAXTIME:
        raise ValueError(tr('The maximum duration is 5 weeks.'))
    return seconds

def address(text, subnet=False, white=False):
    if subnet or white:
        net = ips.IPv4Network(text, strict=True)
        if subnet and net.prefixlen != 24:
            raise ValueError(tr('This command accepts only an IPv4 /24 subnet.'))
        if white and net.prefixlen < 24:
            raise ValueError(tr('The bot accepts whitelist networks from /24 to /32 only.'))
        return str(net)
    if '/' in text:
        raise ValueError(tr('Use a single IPv4 address without a prefix length here.'))
    return str(ips.IPv4Address(text))

def overlaps(target):
    net = ips.ip_network(target, strict=False)
    with f.database() as db:
        return [dict(r) for r in db.execute('SELECT * FROM subnets WHERE expires>?', (time.time(),)) if net.overlaps(ips.ip_network(r['network']))]

def reply(text, keys=None):
    with f.database() as db:
        f.queue(db, text, keys)

def audit(db, cfg, payload, result):
    db.execute('INSERT INTO audit(happened,user_id,operation,target,result) VALUES (?,?,?,?,?)', (time.time(), cfg['user_id'], payload['op'], payload.get('target', ''), result))

def new_deadline(now, spec, old=None):
    additive = spec.startswith('+')
    seconds = parse_seconds(spec[1:] if additive else spec)
    if additive and old is None:
        raise ValueError(tr('Cannot add a duration to a permanent ban.'))
    result = (old if additive else now) + seconds
    if result - now > MAXTIME + f.TIME_TOLERANCE_SECONDS:
        raise ValueError(tr('The remaining duration after this change cannot exceed 5 weeks.'))
    return result

def execute(cfg, opid, payload):
    """Absolute deadlines + durable intents make crash recovery idempotent."""
    with ADMIN_LOCK:
        with f.database() as db:
            previous = db.execute('SELECT * FROM admin_operations WHERE id=?', (opid,)).fetchone()
            if previous and previous['status'] in ('done', 'failed'):
                return previous['result']
            if previous:
                payload = json.loads(previous['payload'])
            else:
                db.execute('INSERT INTO admin_operations VALUES (?,?,?,?,?)', (opid, json.dumps(payload), 'pending', None, time.time()))
        try:
            result = apply(cfg, payload)
            status = 'done'
        except Exception as exc:
            result = tr('Error: ') + str(exc) if isinstance(exc, (ValueError, RuntimeError)) else tr('The operation did not complete. Check the service journal on the server.')
            f.LOG.exception('Admin operation failed: %s', payload['op'])
            status = 'failed'
        with f.database() as db:
            db.execute('UPDATE admin_operations SET status=?,result=? WHERE id=?', (status, result, opid))
            audit(db, cfg, payload, result)
            f.queue(db, html.escape(result))
        return result

def apply(cfg, payload):
    op, target = (payload['op'], payload['target'])
    if op in ('ban', 'deadline'):
        verify_scope(cfg)
        protected_ip(cfg, target)
        if payload['deadline'] <= time.time():
            raise ValueError(tr('The requested expiry is already in the past. Repeat the command.'))
        current = next((r for r in snapshot()['bans'] if r['ip'] == target), None)
        if op == 'ban' and current:
            return 'IP ' + target + tr(' is already banned. ') + end_text(current['expires']) + tr(' Use /extend to change its expiry.')
        if op == 'deadline' and (not current):
            raise ValueError(tr('This IP is not currently banned. Use /ban.'))
        result = manage(op, target, payload['deadline'])
        old = tr('\nPrevious expiry: ') + (f.stamp(current['expires']) if current['expires'] else tr('permanent')) if current and op == 'deadline' else ''
        return 'IP ' + target + (tr(' was banned.') if op == 'ban' else tr(': expiry updated.')) + old + tr('\nNew expiry: ') + f.stamp(result['expires']) + tr('. SSH TCP/{ports} only.')
    if op == 'unban':
        manage('unban', target)
        networks = overlaps(target)
        return tr('Individual ban for IP ') + target + tr(' was removed (or was already absent).') + (tr('\nAccess is still blocked by a subnet ban: ') + ', '.join((n['network'] for n in networks)) + tr('. Remove it separately: /unbansubnet NETWORK (with confirmation).') if networks else '')
    if op in ('subnet_ban', 'subnet_deadline', 'subnet_unban'):
        with f.LOCK, f.database() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM subnets WHERE network=? AND expires>?', (target, time.time())).fetchone()
            if op == 'subnet_unban':
                if row and payload.get('expected') and (abs(row['expires'] - payload['expected']) > f.TIME_TOLERANCE_SECONDS):
                    raise ValueError(tr('The subnet ban changed after this request. Repeat the command.'))
                db.execute('DELETE FROM subnets WHERE network=?', (target,))
            else:
                f.safe_network(cfg, target)
                if payload['deadline'] <= time.time():
                    raise ValueError(tr('The expiry is already in the past. Repeat the command.'))
                if op == 'subnet_ban' and row:
                    return tr('The subnet is already banned. ') + end_text(row['expires']) + tr(' Use /extend.')
                if op == 'subnet_deadline':
                    if not row:
                        raise ValueError(tr('This subnet is no longer banned.'))
                    expected = payload.get('expected')
                    if expected and abs(row['expires'] - expected) > f.TIME_TOLERANCE_SECONDS:
                        raise ValueError(tr('The expiry changed after this request. Repeat the command.'))
                    db.execute('UPDATE subnets SET expires=? WHERE network=?', (payload['deadline'], target))
                else:
                    db.execute('INSERT INTO subnets VALUES (?,?,?)', (target, time.time(), payload['deadline']))
            f.nft_sync(db, cfg)
            keys = [[f.button(db, 'request_unban', target, tr('Unban ') + target)]] if op != 'subnet_unban' else None
            if keys:
                f.queue(db, tr('Subnet controls for <code>') + html.escape(target) + '</code>:', keys)
        if op == 'subnet_unban':
            return tr('Ban on subnet ') + target + tr(' was removed. Individual IP bans remain.')
        old = tr('\nPrevious expiry: ') + f.stamp(row['expires']) if row and op == 'subnet_deadline' else ''
        return tr('Subnet ') + target + tr(': TCP/{ports} ban.') + old + tr('\nNew expiry: ') + f.stamp(payload['deadline'])
    if op in ('white_add', 'white_del'):
        target = address(target, white=True)
        if op == 'white_del':
            if target in {str(ips.ip_network(n, strict=False)) for n in baseline(cfg)}:
                raise ValueError(tr('This is a mandatory protected entry; it cannot be removed through the bot.'))
            with f.database() as db:
                db.execute('DELETE FROM whitelist WHERE network=?', (target,))
            sync_whitelist(cfg)
            return tr('Entry ') + target + tr(' was removed from the whitelist (or was absent). No ban was created.')
        conflicts = overlaps(target)
        approved = payload.get('conflicts', {})
        for row in conflicts:
            if row['network'] not in approved or abs(row['expires'] - approved[row['network']]) > f.TIME_TOLERANCE_SECONDS:
                raise ValueError(tr('A new or changed subnet ban overlaps this entry. Repeat the command to confirm it.'))
        with f.LOCK, f.database() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in conflicts:
                db.execute('DELETE FROM subnets WHERE network=?', (row['network'],))
            f.nft_sync(db, cfg)
            db.execute('INSERT OR IGNORE INTO whitelist VALUES (?,?,?)', (target, time.time(), cfg['user_id']))
        sync_whitelist(cfg)
        return tr('Entry ') + target + tr(' was added to the persistent sshd whitelist. Current IP bans in this entry were removed.') + (tr(' Subnet ban removed: ') + ', '.join((r['network'] for r in conflicts)) if conflicts else '')
    raise ValueError(tr('Unknown operation.'))

def end_text(expires):
    return tr('Permanent ban.') if expires is None else tr('Remaining: ') + f.duration(max(0, expires - time.time())) + tr('; until ') + f.stamp(expires) + '.'

def request_confirmation(cfg, opid, payload, text):
    with f.database() as db:
        if db.execute('SELECT 1 FROM admin_operations WHERE id=?', (opid,)).fetchone():
            return
        expires = time.time() + f.CONFIRMATION_TTL_SECONDS
        keys = [[f.button(db, 'admin', json.dumps(payload), tr('Confirm'), expires=expires), f.button(db, 'cancel', '', tr('Cancel'), expires=expires)]]
        f.queue(db, html.escape(text) + tr('\nThis confirmation expires in 2 minutes.'), keys)
        db.execute('INSERT INTO admin_operations VALUES (?,?,?,?,?)', (opid, json.dumps(payload), 'confirmation', tr('Confirmation requested.'), time.time()))

def confirm(cfg, cb):
    msg = cb.get('message', {})
    if cb.get('from', {}).get('id') != cfg['user_id'] or msg.get('chat', {}).get('id') != cfg['chat_id']:
        return tr('Access denied.')
    with ADMIN_LOCK:
        with f.database() as db:
            row = db.execute("SELECT * FROM buttons WHERE token=? AND kind='admin'", (cb.get('data'),)).fetchone()
            if not row or row['message_id'] != msg.get('message_id'):
                return tr('Invalid button.')
            if row['used'] or row['expires'] < time.time():
                return tr('This confirmation was used or expired.')
            payload = json.loads(row['target'])
        result = execute(cfg, 'callback:' + row['token'], payload)
        with f.database() as db:
            db.execute('UPDATE buttons SET used=1 WHERE message_id=?', (row['message_id'],))
        return result[:f.CALLBACK_TEXT_LIMIT]

def report(cfg, command, args):
    state = snapshot()
    if command == '/status':
        with f.database() as db:
            pending = db.execute("SELECT count(*) FROM outbox WHERE sent IS NULL AND status='pending'").fetchone()[0]
            networks = db.execute('SELECT count(*) FROM subnets WHERE expires>?', (time.time(),)).fetchone()[0]
        return tr('Bot is running. Jail: sshd. SSH: TCP/{ports}.\nBanned IPs: {v1}. Subnets: {v3}.\nQueued notifications: {v5}.\nHelp: /help', v1=len(state['bans']), v3=networks, v5=pending)
    if command == '/ip':
        if len(args) != 1:
            raise ValueError(tr('Usage: /ip IPv4'))
        ip = address(args[0])
        banned = next((r for r in state['bans'] if r['ip'] == ip), None)
        listed = [n for n in state['ignored'] if ips.ip_address(ip) in ips.ip_network(n, strict=False)]
        networks = overlaps(ip)
        with f.database() as db:
            history = db.execute('SELECT count(*), max(started) FROM events WHERE ip=?', (ip,)).fetchone()
        geo = f.geodata(ip)
        return html.escape(tr('IP: {v1}\nIndividual ban: ', v1=ip) + (end_text(banned['expires']) if banned else tr('none')) + tr('\nSubnet bans: ') + (', '.join((n['network'] for n in networks)) or tr('none')) + tr('\nWhitelist: ') + (', '.join(listed) or tr('none')) + tr('\nBans recorded since installation: {v1}', v1=history[0]) + (tr('; last: ') + f.stamp(history[1]) if history[1] else '') + tr('\nCountry: ') + geo.get('country', tr('no data')) + tr('\nISP: ') + str(geo.get('connection', {}).get('isp') or tr('no data')))
    if len(args) > 1:
        raise ValueError(tr('Provide only a page number.'))
    page = int(args[0]) if args else 1
    if page < 1:
        raise ValueError(tr('The page number must be positive.'))
    if command == '/bans':
        entries = [r['ip'] + ' — ' + end_text(r['expires']) for r in sorted(state['bans'], key=lambda r: r['ip'])]
        with f.database() as db:
            entries += [r['network'] + tr(' (subnet) — ') + end_text(r['expires']) for r in db.execute('SELECT * FROM subnets WHERE expires>? ORDER BY network', (time.time(),))]
        title = tr('Active sshd and subnet bans')
    elif command == '/whitelist':
        fixed = set(baseline(cfg))
        entries = [n + (tr(' — mandatory protection') if n in fixed else tr(' — added through the bot')) for n in sorted(fixed | set(whitelist_networks()))]
        title = tr('Persistent sshd whitelist')
    else:
        with f.database() as db:
            entries = [f.stamp(r['happened']) + f' | user {r['user_id']} | {r['operation']} {r['target']} | ' + r['result'][:AUDIT_RESULT_PREVIEW_LIMIT] for r in db.execute('SELECT * FROM audit ORDER BY id DESC')]
        title = tr('Administration audit log')
    pages = max(1, (len(entries) + 9) // 10)
    if page > pages:
        raise ValueError(tr('Total pages: ') + str(pages))
    return html.escape(title + tr(' — page {v1}/{v3}\n', v1=page, v3=pages) + ('\n'.join(entries[(page - 1) * 10:page * 10]) or tr('No entries.')) + (tr('\nNext: {v1} {v3}', v1=command, v3=page + 1) if page < pages else ''))

def handle_message(cfg, msg):
    if msg.get('chat', {}).get('id') != cfg['chat_id'] or msg.get('from', {}).get('id') != cfg['user_id']:
        return
    if time.time() - msg.get('date', time.time()) > f.COMMAND_MAX_AGE_SECONDS:
        if msg.get('text', '').startswith('/'):
            reply(tr('This command is older than 5 minutes and was not executed. Send it again.'))
        return
    text = msg.get('text', '').strip()
    if not text.startswith('/'):
        return
    parts = text.split()
    command, args = (parts[0].split('@')[0].lower(), parts[1:])
    opid = f'message:{cfg['chat_id']}:{msg['message_id']}'
    with ADMIN_LOCK:
        with f.database() as db:
            old = db.execute('SELECT * FROM admin_operations WHERE id=?', (opid,)).fetchone()
        if old:
            if old['status'] == 'pending':
                execute(cfg, opid, json.loads(old['payload']))
            return
        try:
            if command in ('/help', '/start'):
                reply(tr(HELP))
                return
            if command in ('/status', '/bans', '/ip', '/audit') or (command == '/whitelist' and (not args or args[0].isdigit())):
                reply(report(cfg, command, args))
                return
            now = time.time()
            if command in ('/ban', '/unban', '/bansubnet', '/unbansubnet', '/extend'):
                if not args or len(args) > 2:
                    raise ValueError(tr('Provide an address and a duration if required. See /help for examples.'))
                subnet = command in ('/bansubnet', '/unbansubnet') or (command == '/extend' and '/' in args[0])
                target = address(args[0], subnet=subnet)
                if command in ('/unban', '/unbansubnet'):
                    if len(args) != 1:
                        raise ValueError(tr('An unban command accepts only an address.'))
                    payload = {'op': 'subnet_unban' if subnet else 'unban', 'target': target}
                    if subnet:
                        active = overlaps(target)
                        if active:
                            payload['expected'] = active[0]['expires']
                else:
                    if command == '/extend' and len(args) != 2:
                        raise ValueError(tr('Usage: /extend ADDRESS 7d or /extend ADDRESS +7d'))
                    if subnet:
                        f.safe_network(cfg, target)
                    else:
                        protected_ip(cfg, target)
                    spec = args[1] if len(args) == 2 else '24h'
                    old_end = None
                    if command == '/extend':
                        active = overlaps(target) if subnet else [r for r in snapshot()['bans'] if r['ip'] == target]
                        if not active:
                            raise ValueError(tr('This address is not currently banned.'))
                        old_end = active[0]['expires']
                    deadline = new_deadline(now, spec, old_end)
                    payload = {'op': ('subnet_deadline' if subnet else 'deadline') if command == '/extend' else 'subnet_ban' if subnet else 'ban', 'target': target, 'deadline': deadline}
                    if subnet and old_end is not None:
                        payload['expected'] = old_end
                if subnet:
                    preview = tr('Confirm ') + command + ' ' + target + tr('. SSH TCP/{ports} only.')
                    if 'deadline' in payload:
                        preview += tr('\nNew expiry: ') + f.stamp(payload['deadline'])
                    request_confirmation(cfg, opid, payload, preview)
                else:
                    execute(cfg, opid, payload)
                return
            if command == '/whitelist':
                if len(args) != 2 or args[0] not in ('add', 'del'):
                    raise ValueError(tr('Usage: /whitelist [page], /whitelist add IP/CIDR or /whitelist del IP/CIDR'))
                target = address(args[1], white=True)
                net = ips.ip_network(target)
                payload = {'op': 'white_' + args[0], 'target': target}
                conflicts = overlaps(target) if args[0] == 'add' else []
                payload['conflicts'] = {r['network']: r['expires'] for r in conflicts}
                if net.prefixlen < 32 or conflicts:
                    count = sum((ips.ip_address(r['ip']) in net for r in snapshot()['bans']))
                    preview = tr('Confirm /whitelist {v1} {v3}. Addresses: {v5}.', v1=args[0], v3=target, v5=net.num_addresses)
                    if args[0] == 'add':
                        preview += tr('\nIndividual IP bans to remove: {v1}.', v1=count)
                    if conflicts:
                        preview += tr('\nThe entire subnet ban will also be removed: ') + ', '.join((r['network'] for r in conflicts))
                    request_confirmation(cfg, opid, payload, preview)
                else:
                    execute(cfg, opid, payload)
                return
            raise ValueError(tr('Unknown command. Help: /help'))
        except Exception as exc:
            reply(html.escape(str(exc)) if isinstance(exc, ValueError) else tr('The command failed. Check the service journal on the server.'))
            if not isinstance(exc, ValueError):
                f.LOG.exception('Command handling failed')

def recover_operations(cfg):
    sync_whitelist(cfg)
    with f.database() as db:
        rows = db.execute("SELECT * FROM admin_operations WHERE status='pending' ORDER BY created").fetchall()
    for row in rows:
        execute(cfg, row['id'], json.loads(row['payload']))

def register_commands(cfg):
    names = [('help', tr('Help and command examples')), ('status', tr('SSH protection status')), ('bans', tr('List bans: /bans 1')), ('ip', tr('Inspect an IP: /ip address')), ('ban', tr('Ban an IP: /ban address 24h')), ('unban', tr('Unban an IP: /unban address')), ('bansubnet', tr('Ban a /24: /bansubnet network 24h')), ('unbansubnet', tr('Unban a /24 after confirmation')), ('extend', tr('Set expiry: /extend address 7d or +7d')), ('whitelist', tr('Whitelist: add, del or list')), ('audit', tr('Audit log: /audit 1'))]
    f.api(cfg, 'setMyCommands', commands=[{'command': n, 'description': d} for n, d in names], scope={'type': 'chat', 'chat_id': cfg['chat_id']})
