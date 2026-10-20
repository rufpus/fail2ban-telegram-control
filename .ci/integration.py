# SPDX-License-Identifier: MIT
"""Real Fail2ban/nftables tests, only in the disposable CI container."""
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, '/src')
import f2btelegram as f
import f2bmanage as m
import i18n

cfg = f.validate_config(dict(token='123456:'+('X'*35),user_id=123,chat_id=123,
    protected=['127.0.0.0/8','::1/128','192.0.2.10/32'],ssh_ports=[2222],geoip=False))
f.SETTINGS.update({k:cfg[k] for k in f.SETTINGS})
i18n.configure_language('en',[2222])
f.initialize()
m.sync_whitelist(cfg)
m.verify_scope(cfg)
sequence = 0


def message(text):
    global sequence
    sequence += 1
    msg = dict(message_id=sequence,date=time.time(),text=text,
               chat={'id':123},**{'from':{'id':123}})
    m.handle_message(cfg,msg)


def confirm():
    with f.database() as db:
        row = db.execute("SELECT * FROM buttons WHERE kind='admin' AND used=0 ORDER BY rowid DESC LIMIT 1").fetchone()
        assert row
        db.execute('UPDATE buttons SET message_id=10000 WHERE token=?',(row['token'],))
    result=m.confirm(cfg,dict(data=row['token'],message={'message_id':10000,'chat':{'id':123}},**{'from':{'id':123}}))
    assert not result.startswith('Error'),result


def ip_ban(ip):
    return next((r for r in m.snapshot()['bans'] if r['ip']==ip),None)


ip,net='198.18.0.42','198.18.0.0/24'
message('/ban '+ip+' 10m')
assert abs(ip_ban(ip)['expires']-time.time()-600)<2
message('/extend '+ip+' 1h')
assert abs(ip_ban(ip)['expires']-time.time()-3600)<2
old=ip_ban(ip)['expires']
message('/extend '+ip+' +1h')
assert abs(ip_ban(ip)['expires']-old-3600)<1
assert m.engine('get','sshd','bantime')==86400
print('Per-IP duration, shortening and extension preserve global bantime: OK')
message('/whitelist add '+ip)
assert ip_ban(ip) is None
assert ip+'/32' in m.whitelist_networks()
Path('/etc/fail2ban/jail.d/zz-telegram-control-whitelist.local').symlink_to(f.STATE/'whitelist.local')
subprocess.run(['fail2ban-client','-t'],check=True)
subprocess.run(['fail2ban-client','reload','sshd'],check=True)
m.sync_whitelist(cfg)
assert any(str(m.ips.ip_network(n,strict=False))==ip+'/32' for n in m.snapshot()['ignored'])
message('/whitelist del '+ip)
assert not any(str(m.ips.ip_network(n,strict=False))==ip+'/32' for n in m.snapshot()['ignored'])
print('Persistent whitelist and Python-action recovery after reload: OK')
message('/ban 198.18.1.42 1h')
before=f.run(['nft','-j','list','table','inet','f2b-table'])
message('/bansubnet '+net+' 1h')
assert not m.overlaps(ip)
confirm()
rules=f.run(['nft','list','table','inet','f2b_telegram_control'])
assert 'tcp dport 2222' in rules and net in rules and 'timeout' in rules
with f.database() as db:
    # An unchanged reconciliation must preserve table/set/rule handles and counters.
    from unittest.mock import patch
    with patch.object(f, 'run', wraps=f.run) as applied:
        f.nft_sync(db,cfg)
        assert not any(call.args[0] == ['nft','-f','-'] for call in applied.call_args_list), applied.call_args_list
    # Adjusting an active deadline must change the element, not rebuild the table.
    original=f.nft_state()
    original_rule=next(x['rule']['handle'] for x in original if 'rule' in x)
    db.execute('UPDATE subnets SET expires=expires+600 WHERE network=?',(net,))
    f.nft_sync(db,cfg)
    assert next(x['rule']['handle'] for x in f.nft_state() if 'rule' in x)==original_rule
message('/unban '+ip)
assert m.overlaps(ip)
message('/whitelist add '+ip)
assert ip+'/32' not in m.whitelist_networks()
confirm()
assert not m.overlaps(ip) and ip+'/32' in m.whitelist_networks()
assert ip_ban('198.18.1.42') is not None
assert before==f.run(['nft','-j','list','table','inet','f2b-table'])
print('Confirmed subnet operations, custom ports and separate firewall ownership: OK')
message('/whitelist del '+ip)
with f.database() as db:
    db.execute('INSERT OR REPLACE INTO subnets VALUES (?,?,?)',(net,time.time(),time.time()+4))
    f.nft_sync(db,cfg)
subprocess.run(['nft','delete','table','inet','f2b_telegram_control'],check=True)
with f.database() as db:
    f.nft_sync(db,cfg)
assert net in f.run(['nft','list','table','inet','f2b_telegram_control'])
time.sleep(5)
assert net not in f.run(['nft','list','table','inet','f2b_telegram_control'])
print('State recovery and kernel expiry without a running Telegram worker: OK')
for command in ('/help','/status','/bans','/ip '+ip,'/whitelist','/audit'):
    message(command)
print('All command handlers: OK; no Telegram account or token used')
