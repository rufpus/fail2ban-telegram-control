#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Render synthetic UI pages using the bot's own localized message functions."""
import datetime as dt
import html
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import f2btelegram as f
import f2bmanage as m
import i18n

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'.test-tmp'/'demo'
OUTPUT.mkdir(parents=True,exist_ok=True)
NOW=dt.datetime(2026,10,1,12,42,tzinfo=dt.timezone.utc).timestamp()

CSS='''
*{box-sizing:border-box}html{color-scheme:dark}body{margin:0;background:#0b1220;color:#dce6f3;font-family:Arial,"Segoe UI",sans-serif;font-size:15px;line-height:1.5}
.page{max-width:1320px;margin:auto;padding:42px 38px}.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}.brand{font-weight:700;letter-spacing:-.4px;font-size:20px}.pill{border:1px solid #5a492b;color:#f6ce80;padding:5px 12px;border-radius:30px;font-size:11px;font-weight:700;letter-spacing:1px}
h1{font-size:42px;line-height:1.12;letter-spacing:-1.8px;margin:0 0 12px;color:#f5f8fc}p.lead{color:#93a7c0;margin:0 0 32px;font-size:16px}.grid{display:grid;grid-template-columns:1.3fr 1fr 1fr;gap:18px;align-items:start}.panel{background:#111c2d;border:1px solid #233247;border-radius:18px;overflow:hidden;box-shadow:0 20px 60px #0003}
.panel-title{font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#82a2bf;padding:16px 18px 10px}.chat-head{display:flex;align-items:center;gap:12px;padding:15px 17px;border-bottom:1px solid #25354a;background:#172538}.avatar{background:#3bb99d;color:#042a24;width:37px;height:37px;border-radius:13px;display:grid;place-items:center;font-size:19px;font-weight:bold}.bot{font-weight:700;color:#f1f7fd;font-size:14px}.online{font-size:11px;color:#7d9fbc}.chat{padding:18px 13px;background:radial-gradient(ellipse at top right,#19374740,transparent 70%);min-height:480px}.bubble{border-radius:12px 12px 12px 3px;padding:13px 14px;background:#213247;font-size:12px;line-height:1.6;overflow-wrap:anywhere}.bubble b{color:#f3f8ff;font-weight:700}.bubble code{color:#75d9c2;font-family:Consolas,monospace}.bubble pre{background:#152335;border-radius:7px;padding:10px;font:10px/1.5 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;color:#b3c5d9;margin:12px 0 0}
.keys{display:flex;gap:6px;margin-top:7px}.key{flex:1;text-align:center;background:#28485a;color:#8fe1cf;border:1px solid #365c69;border-radius:8px;font-weight:bold;font-size:11px;line-height:1.35;padding:12px 7px}.time{text-align:right;color:#7f9cb5;font-size:10px;padding-top:7px}.user{background:#2d5b56;border-radius:12px 12px 3px 12px;margin:0 0 15px 35px;padding:12px 14px;color:#d6fff2;font:12px/1.5 Consolas,monospace}.hint{color:#9fb3ca;padding:17px 18px;font-size:12px;border-top:1px solid #223146}.commands{font:12px/1.9 Consolas,monospace;color:#a6cfc9;margin:15px 0 0}.caption{color:#738da8;font-size:11px;margin-top:25px;letter-spacing:.2px}.single.page{max-width:640px;padding:24px}.single h1{font-size:28px}.single .bubble{font-size:15px}.single .bubble pre{font-size:11px}.single .key{font-size:14px}.single .chat{min-height:0;padding:20px 16px}.single .user{font-size:14px}.single .commands{font-size:13px}.single .grid{display:block}.single .lead{font-size:13px;margin-bottom:22px}
'''


def bubble(text,keys=None,user=None):
    user_html='<div class="user">'+html.escape(user)+'</div>' if user else ''
    buttons=''.join('<div class="keys">'+''.join('<div class="key">'+html.escape(k['text'])+'</div>' for k in row)+'</div>' for row in (keys or []))
    return user_html+'<div class="bubble">'+text.replace('\n','<br>')+'<div class="time">12:42 · DEMO</div></div>'+buttons


def panel(title,content,hint,language):
    return '<section class="panel"><div class="panel-title">'+title+'</div><div class="chat-head"><div class="avatar">F</div><div><div class="bot">Fail2ban Control</div><div class="online">'+('бот · демонстрация' if language=='ru' else 'bot · demonstration')+'</div></div></div><div class="chat">'+content+'</div><div class="hint">'+hint+'</div></section>'


for language in ('en','ru'):
    i18n.configure_language(language,[2222])
    f.SETTINGS.update(language=language,timezone='UTC',ssh_ports=[2222],geoip=True)
    with tempfile.TemporaryDirectory(dir=ROOT/'.test-tmp') as directory, patch.object(f.time,'time',return_value=NOW), patch.object(f,'run',return_value='[]'):
        f.STATE=Path(directory)
        f.initialize()
        with f.database() as db:
            db.execute("UPDATE meta SET value=? WHERE key='installed'",(str(NOW-604800),))
        cfg=dict(user_id=123,chat_id=123,server_name='demo-ssh-01',protected=['192.0.2.10/32'],ssh_ports=[2222])
        logs='\n'.join(f'Oct 01 12:41:{n:02d} demo-ssh-01 sshd[1200]: Failed password for invalid user guest from 203.0.113.42 port 54321 ssh2' for n in (10,20,30))
        f.capture('sshd',dict(ip='203.0.113.42',time=NOW,bantime=86400,failures=3,matches=logs,restored=0))
        with f.database() as db:
            db.execute('UPDATE events SET previous_count=2,previous_time=?',(NOW-172800,))
            row=db.execute('SELECT * FROM events').fetchone()
            notification,keys=f.render_event(db,row,cfg,dict(country='Exampleland',connection={'isp':'Example Hosting · AS64500'}))
            db.execute('UPDATE buttons SET message_id=10')
        f.callback(cfg,dict(data=keys[0][0]['callback_data'],message={'message_id':10,'chat':{'id':123}},**{'from':{'id':123}}))
        with f.database() as db:
            confirmation=db.execute('SELECT text,buttons FROM outbox WHERE event_id IS NULL ORDER BY id DESC').fetchone()
            confirmation_text,confirmation_keys=confirmation[0],__import__('json').loads(confirmation[1])
        state={'bans':[dict(ip='203.0.113.42',started=NOW,expires=NOW+86400,duration=86400)],'ignored':['192.0.2.10']}
        with patch.object(m,'snapshot',return_value=state):
            status=m.report(cfg,'/status',[])
        if language=='en':
            titles=['01 / Ban notification','02 / Confirm a subnet ban','03 / Inspect and control']
            hints=['Actual message renderer · Synthetic log excerpts','A /24 change always asks for confirmation','Owner-only commands · Persistent local history']
            headline='Fail2ban. In your Telegram.'
            lead='Ban notifications, explicit subnet controls, and an audit trail. No inbound bot port.'
            footer='DEMO UI · Synthetic addresses, logs, IDs and provider data · Not a Telegram account or client'
        else:
            titles=['01 / Уведомление о бане','02 / Подтверждение /24','03 / Проверка и управление']
            hints=['Реальный рендер сообщений · Вымышленные журналы','Действия с /24 требуют подтверждения','Только владелец · Постоянная локальная история']
            headline='Fail2ban. В вашем Telegram.'
            lead='Уведомления, управление подсетями и журнал операций. Без входящего порта для бота.'
            footer='ДЕМО · Адреса, журналы, ID и провайдер вымышлены · Это не реальный Telegram-аккаунт или клиент'
        contents=[bubble(notification,keys),bubble(confirmation_text,confirmation_keys),
            bubble(status,user='/status')+'<div class="commands">/bans<br>/ip 203.0.113.42<br>/ban 203.0.113.77 7d<br>/unban 203.0.113.42<br>/extend 203.0.113.42 +7d<br>/whitelist<br>/audit</div>']
        panels=[panel(t,c,h,language) for t,c,h in zip(titles,contents,hints)]
        for name,indices in [('cover',range(3)),('notification',[0]),('confirmation',[1]),('commands',[2])]:
            single=name!='cover'
            document='<!doctype html><html lang="'+language+'"><meta charset="utf-8"><title>Demo — Fail2ban Telegram Control</title><style>'+CSS+'</style><main class="page '+('single' if single else '')+'"><div class="top"><div class="brand">Fail2ban Telegram Control</div><span class="pill">DEMO / 0.1.0</span></div><h1>'+headline+'</h1><p class="lead">'+lead+'</p><div class="grid">'+''.join(panels[i] for i in indices)+'</div><footer class="caption">'+footer+'</footer></main></html>'
            (OUTPUT/f'{name}-{language}.html').write_text(document,encoding='utf-8')
print('Generated 8 synthetic demo pages in',OUTPUT)
