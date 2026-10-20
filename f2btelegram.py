# SPDX-License-Identifier: MIT
"""Fail2ban Telegram worker. Python standard library only; secrets stay on server."""
import argparse
import contextlib
import datetime as dt
import html
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo
from i18n import tr, configure_language
sys.modules.setdefault('f2btelegram', sys.modules[__name__])
STATE = Path(os.environ.get('F2BT_STATE', '/var/lib/fail2ban-telegram-control'))
CONFIG = Path(os.environ.get('F2BT_CONFIG', '/etc/fail2ban-telegram-control/config.json'))
DEFAULT_SETTINGS = {'language': 'en', 'timezone': 'UTC', 'ssh_ports': [22], 'geoip': False}
SETTINGS = dict(DEFAULT_SETTINGS)
LOCK = threading.RLock()
LOG = logging.getLogger('fail2ban-telegram-control')
# Optional systemd Environment override; the JSON configuration stays unchanged.
DEFAULT_RETENTION_DAYS = 30
TELEGRAM_TEXT_LIMIT = 4096  # Conservative bound including HTML markup, in UTF-16 units.
OUTBOX_MAX_ATTEMPTS = 8  # Bound recovery traffic during a prolonged outage.
CAPTURE_SETTLE_SECONDS = 15  # Wait for asynchronous Fail2ban bantime increments.
COMMAND_TIMEOUT_SECONDS = 15  # Bound local command execution.
MAINTENANCE_INTERVAL_SECONDS = 15  # Reconcile state even without Telegram traffic.
CONFIRMATION_TTL_SECONDS = 120  # Short-lived destructive-action confirmation.
OUTBOX_BACKOFF_MAX_SECONDS = 300  # Upper retry delay during an outage.
COMMAND_MAX_AGE_SECONDS = 300  # Reject commands delayed by Telegram outages.
MAX_BAN_SECONDS = 35 * 86400  # Match the configured five-week safety cap.
DEADLINE_GRACE_SECONDS = 1  # Allow clock movement across the Fail2ban socket.
CALLBACK_TEXT_LIMIT = 190  # Leave room below Telegram's 200-character alert limit.
CAPTURE_LOG_LIMIT = 12000  # Bound log storage per Fail2ban event.
TIME_TOLERANCE_SECONDS = 0.01  # Ignore timestamp serialization round-off.
LOCAL_ADDRESS_CACHE_SECONDS = 15  # Refresh alongside firewall reconciliation.
_LOCAL_ADDRESS_LOCK = threading.Lock()
_LOCAL_ADDRESS_CACHE = None
_LOCAL_ADDRESS_EXPIRES = 0

@contextlib.contextmanager
def database():
    con = sqlite3.connect(STATE / 'state.sqlite3', timeout=3)
    con.row_factory = sqlite3.Row
    try:
        with con:
            yield con
    finally:
        con.close()

def initialize():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with database() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('\n        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);\n        CREATE TABLE IF NOT EXISTS events (\n          id INTEGER PRIMARY KEY, jail TEXT, ip TEXT, started REAL, duration INTEGER,\n          failures INTEGER, matches TEXT, ended REAL, previous_count INTEGER,\n          previous_time REAL, UNIQUE(jail,ip,started));\n        CREATE TABLE IF NOT EXISTS outbox (\n          id INTEGER PRIMARY KEY, event_id INTEGER UNIQUE, text TEXT, buttons TEXT,\n          ready REAL, sent REAL, message_id INTEGER, attempts INTEGER DEFAULT 0);\n        CREATE TABLE IF NOT EXISTS buttons (\n          token TEXT PRIMARY KEY, kind TEXT, target TEXT, event_id INTEGER,\n          message_id INTEGER, expires REAL, used INTEGER DEFAULT 0);\n        CREATE TABLE IF NOT EXISTS subnets (\n          network TEXT PRIMARY KEY, started REAL, expires REAL);\n        CREATE TABLE IF NOT EXISTS geo (\n          ip TEXT PRIMARY KEY, data TEXT, expires REAL);\n        CREATE TABLE IF NOT EXISTS whitelist (\n          network TEXT PRIMARY KEY, added REAL, user_id INTEGER);\n        CREATE TABLE IF NOT EXISTS admin_operations (\n          id TEXT PRIMARY KEY, payload TEXT, status TEXT, result TEXT, created REAL);\n        CREATE TABLE IF NOT EXISTS audit (\n          id INTEGER PRIMARY KEY, happened REAL, user_id INTEGER,\n          operation TEXT, target TEXT, result TEXT);\n        CREATE INDEX IF NOT EXISTS event_history ON events(ip,started);\n        CREATE INDEX IF NOT EXISTS pending_outbox ON outbox(ready,id) WHERE sent IS NULL;\n        ')
        db.execute("INSERT OR IGNORE INTO meta VALUES ('installed', ?)", (str(time.time()),))
        if 'created' not in {r['name'] for r in db.execute('PRAGMA table_info(outbox)')}:
            db.execute('ALTER TABLE outbox ADD COLUMN created REAL')
            db.execute('UPDATE outbox SET created=coalesce(sent,ready)')
        if 'status' not in {r['name'] for r in db.execute('PRAGMA table_info(outbox)')}:
            db.execute("ALTER TABLE outbox ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
            db.execute("UPDATE outbox SET status='sent' WHERE sent IS NOT NULL")

def number(value):
    return int(float(value))

def capture(jail, info, operation='ban'):
    """Called locally by Fail2ban: never perform network I/O or execute log text."""
    if operation != 'unban' and number(info.get('restored', 0)):
        return
    address = ipaddress.ip_address(str(info['ip']))
    if address.version != 4:
        return
    ip = str(address)
    started = float(info['time'])
    with database() as db:
        if operation == 'unban':
            db.execute('UPDATE events SET ended=? WHERE jail=? AND ip=? AND ended IS NULL', (time.time(), jail, ip))
            return
        old = db.execute('SELECT id FROM events WHERE jail=? AND ip=? AND started=?', (jail, ip, started)).fetchone()
        if old:
            db.execute('UPDATE events SET duration=? WHERE id=?', (number(info['bantime']), old['id']))
            return
        if operation == 'prolong':
            return
        history = db.execute('SELECT count(*), max(started) FROM events WHERE ip=?', (ip,)).fetchone()
        cur = db.execute('INSERT INTO events\n          (jail,ip,started,duration,failures,matches,previous_count,previous_time)\n          VALUES (?,?,?,?,?,?,?,?)', (jail, ip, started, number(info['bantime']), number(info.get('failures', 0)), str(info.get('matches', ''))[-CAPTURE_LOG_LIMIT:], *history))
        db.execute('INSERT INTO outbox(event_id,ready,created) VALUES (?,?,?)', (cur.lastrowid, time.time() + CAPTURE_SETTLE_SECONDS, time.time()))

def run(args, input_text=None):
    return subprocess.run(args, input=input_text, text=True, capture_output=True, check=True, timeout=COMMAND_TIMEOUT_SECONDS).stdout

def config():
    cfg = validate_config(json.loads(CONFIG.read_text(encoding='utf-8')))
    if os.name == 'posix' and CONFIG.stat().st_mode & 0o077:
        raise ValueError('Configuration must have mode 0600 (no group/other access)')
    if os.name == 'posix' and CONFIG.stat().st_uid != 0:
        raise ValueError('Configuration must be owned by root')
    SETTINGS.update({k: cfg[k] for k in SETTINGS})
    configure_language(cfg['language'], cfg['ssh_ports'], cfg['timezone'])
    return cfg


def validate_config(cfg):
    cfg = dict(cfg)
    validate_token(cfg.get('token'))
    for field in ('chat_id', 'user_id'):
        if isinstance(cfg.get(field), bool) or not isinstance(cfg.get(field), int) or cfg[field] <= 0:
            raise ValueError('chat_id and user_id must be positive integer Telegram IDs')
    if cfg['chat_id'] != cfg['user_id']:
        raise ValueError('This release supports a private chat with the owner only; IDs must match')
    for key, default in DEFAULT_SETTINGS.items():
        cfg.setdefault(key, default)
    if cfg['language'] not in ('en', 'ru'):
        raise ValueError('language must be en or ru')
    ZoneInfo(cfg['timezone'])
    if not isinstance(cfg['geoip'], bool):
        raise ValueError('geoip must be true or false')
    ports = cfg['ssh_ports']
    if not isinstance(ports, list) or not ports or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError('ssh_ports must be a nonempty list of TCP port numbers (1–65535)')
    cfg['ssh_ports'] = sorted(set(ports))
    cfg['protected'] = sorted({str(ipaddress.ip_network(n, strict=False)) for n in cfg.get('protected', [])})
    cfg.setdefault('server_name', socket.gethostname())
    if not isinstance(cfg['server_name'], str) or not 1 <= len(cfg['server_name']) <= 100:
        raise ValueError('server_name must be a string of 1–100 characters')
    return cfg

def validate_token(token):
    # BotFather tokens: positive ASCII bot ID and a 35-character URL-safe secret.
    # getMe during setup additionally verifies that Telegram actually issued it.
    if not isinstance(token, str) or not re.fullmatch(r'[1-9][0-9]*:[A-Za-z0-9_-]{35}', token):
        raise ValueError('Invalid Telegram token: paste the complete BotFather token (positive numeric ID, colon, 35 URL-safe characters).')

class APIError(Exception):

    def __init__(self, code, retry=0):
        super().__init__('Telegram API error %s' % code)
        self.code, self.retry = (code, retry)

def api(cfg, method, **data):
    req = urllib.request.Request('https://api.telegram.org/bot' + cfg['token'] + '/' + method, data=json.dumps(data).encode(), headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=40) as res:
            body = json.load(res)
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read())
        except (ValueError, OSError):
            body = {}
        raise APIError(exc.code, body.get('parameters', {}).get('retry_after', 0)) from None
    except (OSError, ValueError):
        raise APIError('network') from None
    if not body.get('ok'):
        raise APIError(body.get('error_code', 'unknown'))
    return body['result']

def stamp(value):
    return dt.datetime.fromtimestamp(value, ZoneInfo(SETTINGS['timezone'])).strftime('%Y-%m-%d %H:%M:%S %Z')

def duration(seconds):
    if seconds < 0:
        return tr('permanent')
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return ' '.join((f'{n} {unit}' for n, unit in [(days, tr('d')), (hours, tr('h')), (minutes, tr('min')), (seconds, tr('s'))] if n)) or tr('0 s')

def clean(text, limit=500):
    return ''.join((c for c in str(text) if c in '\n\t' or (ord(c) >= 32 and ord(c) != 127)))[:limit]

def reason(matches):
    lines = matches.lower()
    if 'manual ban requested through the telegram bot' in lines:
        return tr('manual ban requested by the owner through Telegram')
    result = []
    if 'invalid user' in lines or 'illegal user' in lines:
        result.append(tr('login attempts with a nonexistent username'))
    if 'failed password' in lines or 'authentication failure' in lines:
        result.append(tr('failed SSH password authentication (possible password guessing)'))
    if 'failed publickey' in lines:
        result.append(tr('failed SSH public-key authentication'))
    if 'maximum authentication attempts' in lines:
        result.append(tr('maximum authentication attempts exceeded'))
    if 'kex_exchange_identification' in lines or 'banner exchange' in lines:
        result.append(tr('SSH handshake errors (possible scanning)'))
    return '; '.join(result) or tr('the Fail2ban SSH filter matched; available records do not identify a more specific reason')

def geodata(ip):
    if not SETTINGS['geoip']:
        return {}
    with database() as db:
        row = db.execute('SELECT * FROM geo WHERE ip=? AND expires>?', (ip, time.time())).fetchone()
        if row:
            return json.loads(row['data'])
        limit = db.execute("SELECT value FROM meta WHERE key='geo_pause'").fetchone()
        if limit and float(limit[0]) > time.time():
            return {}
    if not ipaddress.ip_address(ip).is_global:
        return {}
    data, ttl = ({}, 3600)
    try:
        url = 'https://ipwho.is/' + str(ipaddress.IPv4Address(ip)) + '?fields=success,country,country_code,connection&lang=' + SETTINGS['language']
        with urllib.request.urlopen(url, timeout=4) as res:
            body = json.load(res)
        if body.get('success'):
            data = body
            ttl = 7 * 86400
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            with database() as db:
                db.execute("INSERT OR REPLACE INTO meta VALUES ('geo_pause',?)", (str(time.time() + 86400),))
    except (OSError, ValueError):
        pass
    with database() as db:
        db.execute('INSERT OR REPLACE INTO geo VALUES (?,?,?)', (ip, json.dumps(data), time.time() + ttl))
    return data

def button(db, kind, target, label, event_id=None, expires=None):
    token = secrets.token_urlsafe(18)
    db.execute('INSERT INTO buttons(token,kind,target,event_id,expires) VALUES (?,?,?,?,?)', (token, kind, target, event_id, expires))
    return {'text': label, 'callback_data': token}

def queue(db, text, buttons=None):
    validate_message(text)
    db.execute('INSERT INTO outbox(text,buttons,ready,created) VALUES (?,?,?,?)', (text, json.dumps(buttons or []), time.time(), time.time()))

def validate_message(text):
    if len(text.encode('utf-16-le')) // 2 > TELEGRAM_TEXT_LIMIT:
        raise ValueError('Message exceeds the Telegram 4096-character limit; request a smaller page or shorter text.')

def prune_data(db, now=None):
    """Keep live bans and undelivered notifications even beyond the retention TTL."""
    days = int(os.environ.get('F2BT_RETENTION_DAYS', DEFAULT_RETENTION_DAYS))
    if days <= 0:
        raise ValueError('F2BT_RETENTION_DAYS must be a positive integer')
    now = time.time() if now is None else now
    cutoff = now - days * 86400
    db.execute("DELETE FROM outbox WHERE (sent IS NOT NULL OR status='failed') AND coalesce(created,sent,ready)<?", (cutoff,))
    db.execute('DELETE FROM events WHERE started<? AND (ended IS NOT NULL OR (duration>=0 AND started+duration<=?)) AND NOT EXISTS (SELECT 1 FROM outbox WHERE event_id=events.id)', (cutoff, now))
    db.execute('DELETE FROM audit WHERE happened<?', (cutoff,))
    db.execute('DELETE FROM geo WHERE expires<?', (min(now, cutoff),))

def render_event(db, row, cfg, geo):
    end = row['started'] + row['duration'] if row['duration'] >= 0 else float('inf')
    live = row['ended'] is None and end > time.time()
    history = tr('yes, {v1}; previous ban: {v3}', v1=row['previous_count'], v3=stamp(row['previous_time'])) if row['previous_count'] else tr('no records since this integration was installed')
    installed = float(db.execute("SELECT value FROM meta WHERE key='installed'").fetchone()[0])
    e = lambda x: html.escape(clean(x, 800))
    lines = [tr('<b>SSH: IP banned</b>') if live else tr('<b>SSH: past IP ban</b>'), tr('Server: {v1}', v1=e(cfg.get('server_name', socket.gethostname()))), f'IP: <code>{e(row["ip"])}</code>', f'Jail: {e(row['jail'])}', tr('Started: {v1}', v1=stamp(row['started'])), tr('Duration: {v1}', v1=duration(row['duration'])), tr('Ends: ') + (stamp(end) if end != float('inf') else tr('permanent')), tr('Attempts in the Fail2ban event: {v1}', v1=e(row['failures'])), tr('Reason: {v1}', v1=e(reason(row['matches']))), tr('Previously: {v1}', v1=history), tr('History recorded since {v1}', v1=stamp(installed)), tr('Country: {v1}', v1=e(geo.get('country', tr('no data')))), tr('ISP: {v1}', v1=e(geo.get('connection', {}).get('isp') or tr('no data')))]
    if row['matches']:
        lines.append(tr('Log excerpts:\n<pre>') + html.escape('\n'.join((clean(x, 400) for x in row['matches'].splitlines()[-3:]))) + '</pre>')
    else:
        lines.append(tr('Log excerpts: unavailable (for example, a manual ban).'))
    if not live:
        lines.append(tr('This ban has ended or was removed; subnet controls are unavailable.'))
    keys = []
    if live:
        network = str(ipaddress.IPv4Network(row['ip'] + '/24', strict=False))
        keys = [[button(db, 'request_ban', network, tr('Ban ') + network, row['id'])]]
    return ('\n'.join(lines), keys)

def local_addresses():
    """Share one bounded cache; failed refreshes fail closed, never return stale data."""
    global _LOCAL_ADDRESS_CACHE, _LOCAL_ADDRESS_EXPIRES
    with _LOCAL_ADDRESS_LOCK:
        now = time.monotonic()
        if _LOCAL_ADDRESS_CACHE is None or now >= _LOCAL_ADDRESS_EXPIRES:
            interfaces = json.loads(run(['ip', '-j', '-4', 'addr', 'show']))
            addresses = tuple(str(ipaddress.IPv4Address(a['local'])) + '/32'
                              for interface in interfaces for a in interface.get('addr_info', []))
            _LOCAL_ADDRESS_CACHE = addresses
            _LOCAL_ADDRESS_EXPIRES = now + LOCAL_ADDRESS_CACHE_SECONDS
        return _LOCAL_ADDRESS_CACHE

def safe_network(cfg, network):
    from f2bmanage import whitelist_networks, baseline
    net = ipaddress.IPv4Network(network, strict=True)
    if net.prefixlen != 24:
        raise ValueError(tr('Only IPv4 /24 subnets are supported.'))
    protected = baseline(cfg) + whitelist_networks() + ['127.0.0.0/8'] + list(local_addresses())
    for item in protected:
        other = ipaddress.ip_network(item, strict=False)
        if other.version == 4 and net.overlaps(other):
            raise ValueError(tr('The subnet overlaps a protected address or network: ') + item)
    return str(net)

def nft_sync(db, cfg):
    """An independent table; never flush or replace Fail2ban's own rules."""
    ports = cfg.get('ssh_ports', SETTINGS['ssh_ports'])
    if not ports or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError('Invalid SSH port list')
    check = subprocess.run(['nft', 'list', 'table', 'inet', 'f2b_telegram_control'], capture_output=True, timeout=10)
    # nft applies the complete transaction atomically, including port changes.
    preamble = 'delete table inet f2b_telegram_control\n' if check.returncode == 0 else ''
    preamble += ('add table inet f2b_telegram_control\n'
        'add chain inet f2b_telegram_control input { type filter hook input priority -2; policy accept; }\n'
        'add set inet f2b_telegram_control subnets { type ipv4_addr; flags interval,timeout; }\n'
        'add rule inet f2b_telegram_control input tcp dport { '+', '.join(map(str, ports))+' } ip saddr @subnets counter drop\n')
    now = time.time()
    rows = db.execute('SELECT * FROM subnets WHERE expires>?', (now,)).fetchall()
    commands = preamble
    for row in rows:
        net = safe_network(cfg, row['network'])
        seconds = max(1, int(row['expires'] - now))
        commands += f'add element inet f2b_telegram_control subnets {{ {net} timeout {seconds}s }}\n'
    run(['nft', '-f', '-'], commands)

def live_event(db, event_id):
    row = db.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    if not row or row['ended'] is not None or (row['duration'] >= 0 and row['started'] + row['duration'] <= time.time()):
        raise ValueError(tr('The original ban has ended or was removed. This action is unavailable.'))
    return row

def callback(cfg, cb):
    msg = cb.get('message', {})
    if cb.get('from', {}).get('id') != cfg['user_id'] or msg.get('chat', {}).get('id') != cfg['chat_id']:
        return tr('Access denied.')
    token = cb.get('data', '')
    with database() as db:
        admin = db.execute('SELECT kind FROM buttons WHERE token=?', (token,)).fetchone()
    if admin and admin['kind'] == 'admin':
        from f2bmanage import confirm
        return confirm(cfg, cb)
    with LOCK, database() as db:
        db.execute('BEGIN IMMEDIATE')
        item = db.execute('SELECT * FROM buttons WHERE token=?', (token,)).fetchone()
        if not item or item['message_id'] != msg.get('message_id'):
            return tr('Invalid button.')
        if item['used'] or (item['expires'] and item['expires'] < time.time()):
            return tr('This confirmation was used or expired.')
        kind, net = (item['kind'], item['target'])
        if kind == 'cancel':
            db.execute('UPDATE buttons SET used=1 WHERE message_id=?', (item['message_id'],))
            return tr('Cancelled.')
        try:
            if kind in ('request_ban', 'confirm_ban'):
                live_event(db, item['event_id'])
                safe_network(cfg, net)
            active = db.execute('SELECT * FROM subnets WHERE network=? AND expires>?', (net, time.time())).fetchone()
            if kind in ('request_ban', 'confirm_ban') and active:
                return tr('The subnet is already banned. Remaining: ') + duration(active['expires'] - time.time()) + '.'
            if kind in ('request_unban', 'confirm_unban') and (not active):
                return tr('This subnet is already unbanned.')
            if kind.startswith('request_'):
                action = 'ban' if kind == 'request_ban' else 'unban'
                expires = time.time() + CONFIRMATION_TTL_SECONDS
                keys = [[button(db, 'confirm_' + action, net, tr('Confirm'), item['event_id'], expires), button(db, 'cancel', net, tr('Cancel'), expires=expires)]]
                text = tr('Confirm banning <code>{v1}</code> for 24 hours, TCP/{ports} only.', v1=html.escape(net)) if action == 'ban' else tr('Confirm unbanning <code>{v1}</code>. Individual IP bans will remain.', v1=html.escape(net))
                queue(db, text + tr('\nThis confirmation expires in 2 minutes.'), keys)
                return tr('A confirmation was queued as a separate message.')
            if kind == 'confirm_ban':
                now = time.time()
                db.execute('INSERT OR REPLACE INTO subnets VALUES (?,?,?)', (net, now, now + 86400))
                nft_sync(db, cfg)
                keys = [[button(db, 'request_unban', net, tr('Unban ') + net)]]
                queue(db, tr('Subnet <code>{v1}</code> is banned on TCP/{ports}.\nUntil {v3}.', v1=html.escape(net), v3=stamp(now + 86400)), keys)
            elif kind == 'confirm_unban':
                db.execute('DELETE FROM subnets WHERE network=?', (net,))
                nft_sync(db, cfg)
                queue(db, tr('Subnet <code>{v1}</code> was unbanned. Individual IP bans remain.', v1=html.escape(net)))
            else:
                return tr('Unknown action.')
            db.execute('UPDATE buttons SET used=1 WHERE message_id=?', (item['message_id'],))
            return tr('Done.')
        except ValueError as exc:
            return str(exc)[:CALLBACK_TEXT_LIMIT]

def deliver_one(cfg):
    with database() as db:
        row = db.execute("SELECT * FROM outbox WHERE sent IS NULL AND status='pending' AND ready<=? ORDER BY id LIMIT 1", (time.time(),)).fetchone()
    if not row:
        return False
    geo = {}
    if row['event_id']:
        with database() as db:
            event = db.execute('SELECT * FROM events WHERE id=?', (row['event_id'],)).fetchone()
        geo = geodata(event['ip'])
    with database() as db:
        if row['event_id']:
            event = db.execute('SELECT * FROM events WHERE id=?', (row['event_id'],)).fetchone()
            text, keys = render_event(db, event, cfg, geo)
        else:
            text, keys = (row['text'], json.loads(row['buttons'] or '[]'))
    try:
        # Structured events are rendered lazily to include the actual incremented bantime.
        validate_message(text)
        result = api(cfg, 'sendMessage', chat_id=cfg['chat_id'], text=text, parse_mode='HTML', reply_markup={'inline_keyboard': keys})
    except (APIError, ValueError) as exc:
        with database() as db:
            transient = isinstance(exc, APIError) and (exc.code == 'network' or isinstance(exc.code, int) and 500 <= exc.code < 600)
            retry = transient and row['attempts'] + 1 < OUTBOX_MAX_ATTEMPTS
            wait = max(getattr(exc, 'retry', 0), min(OUTBOX_BACKOFF_MAX_SECONDS, 2 ** min(row['attempts'] + 1, 8)))
            db.execute('UPDATE outbox SET attempts=attempts+1,ready=?,status=? WHERE id=?', (time.time() + wait, 'pending' if retry else 'failed', row['id']))
            if row['event_id']:
                for keyrow in keys:
                    for key in keyrow:
                        db.execute('DELETE FROM buttons WHERE token=?', (key['callback_data'],))
            LOG.warning('Notification %s: %s', 'delayed' if retry else 'dead-lettered', exc)
        return False
    with database() as db:
        for keyrow in keys:
            for key in keyrow:
                db.execute('UPDATE buttons SET message_id=? WHERE token=?', (result['message_id'], key['callback_data']))
        db.execute("UPDATE outbox SET sent=?,message_id=?,status='sent' WHERE id=?", (time.time(), result['message_id'], row['id']))
    return True

def maintenance(cfg):
    from f2bmanage import sync_whitelist
    last_error = None
    while True:
        try:
            sync_whitelist(cfg)
            with LOCK, database() as db:
                expired = db.execute('SELECT * FROM subnets WHERE expires<=?', (time.time(),)).fetchall()
                db.execute('DELETE FROM subnets WHERE expires<=?', (time.time(),))
                nft_sync(db, cfg)
                for row in expired:
                    queue(db, tr('The ban on subnet <code>{v1}</code> expired and was removed.', v1=html.escape(row['network'])))
                db.execute('DELETE FROM buttons WHERE (expires IS NOT NULL AND expires<?) OR used=1', (time.time() - 86400,))
                prune_data(db)
            last_error = None
        except Exception as exc:
            LOG.exception('Firewall maintenance failed')
            if last_error is None:
                with database() as db:
                    queue(db, tr('Subnet firewall maintenance failed. Check the fail2ban-telegram-control service on the server.'))
            last_error = time.time()
        time.sleep(MAINTENANCE_INTERVAL_SECONDS)

def sender(cfg):
    while True:
        try:
            delivered = deliver_one(cfg)
        except Exception as exc:
            LOG.exception('Outbox processing failed')
            delivered = False
        time.sleep(1.1 if delivered else 3)

def serve():
    from f2bmanage import handle_message, recover_operations, register_commands
    initialize()
    cfg = config()
    import fcntl
    instance_lock = (STATE / 'service.lock').open('a')
    try:
        fcntl.flock(instance_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('Another bot instance is already running') from None
    with LOCK, database() as db:
        nft_sync(db, cfg)
    recover_operations(cfg)
    try:
        webhook = api(cfg, 'getWebhookInfo')
    except APIError as exc:
        LOG.warning('Webhook check delayed: %s', exc)
        webhook = {}
    if webhook.get('url'):
        raise RuntimeError('Bot has an active webhook: use a dedicated bot')
    try:
        register_commands(cfg)
    except APIError as exc:
        LOG.warning('Command menu registration delayed: %s', exc)
    threading.Thread(target=maintenance, args=(cfg,), daemon=True).start()
    threading.Thread(target=sender, args=(cfg,), daemon=True).start()
    delay = 2
    while True:
        try:
            with database() as db:
                saved = db.execute("SELECT value FROM meta WHERE key='offset'").fetchone()
            updates = api(cfg, 'getUpdates', offset=int(saved[0]) if saved else 0, timeout=25, allowed_updates=['callback_query', 'message'])
            for update in updates:
                cb = update.get('callback_query')
                if cb:
                    try:
                        text = callback(cfg, cb)
                    except Exception as exc:
                        LOG.exception('Callback failed')
                        text = tr('Operation failed. Check the service on the server.')
                        with database() as db:
                            queue(db, tr('The subnet operation failed. Check the fail2ban-telegram-control journal on the server.'))
                    try:
                        api(cfg, 'answerCallbackQuery', callback_query_id=cb['id'], text=text, show_alert=True)
                    except APIError:
                        pass
                msg = update.get('message', {})
                if msg:
                    handle_message(cfg, msg)
                with database() as db:
                    db.execute("INSERT OR REPLACE INTO meta VALUES ('offset',?)", (str(update['update_id'] + 1),))
            delay = 2
        except APIError as exc:
            LOG.exception('Telegram polling delayed')
            time.sleep(max(delay, exc.retry))
            delay = min(60, delay * 2)
        except Exception:
            LOG.exception('Telegram polling failed')
            time.sleep(delay)
            delay = min(60, delay * 2)

def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['init', 'serve', 'check'])
    args = parser.parse_args()
    if args.command == 'init':
        initialize()
    elif args.command == 'check':
        cfg = config()
        print('Configuration valid; bot @' + api(cfg, 'getMe')['username'])
    else:
        serve()
if __name__ == '__main__':
    main()
