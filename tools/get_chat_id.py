#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Find your own private chat using a one-time challenge; never print a token."""
import getpass
from pathlib import Path
import secrets
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from f2btelegram import api, APIError


def main():
    cfg={'token':getpass.getpass('Dedicated bot token (hidden): ').strip()}
    bot=api(cfg,'getMe')
    if api(cfg,'getWebhookInfo').get('url'):
        raise SystemExit('This bot has a webhook; use a new dedicated bot.')
    challenge='/identify '+secrets.token_hex(6)
    print('Send this exact message in a PRIVATE chat to @'+bot['username']+':\n'+challenge)
    input('Press Enter after sending it: ')
    updates=api(cfg,'getUpdates',timeout=0,limit=100,allowed_updates=['message'])
    found=set()
    for update in updates:
        msg=update.get('message',{})
        chat=msg.get('chat',{})
        sender=msg.get('from',{})
        if msg.get('text')==challenge and chat.get('type')=='private' and chat.get('id')==sender.get('id'):
            found.add(chat['id'])
    if len(found)!=1:
        raise SystemExit('No unique matching private message found. Check the bot and send the challenge again; do not run another poller.')
    print('Your private chat_id and user_id:',found.pop())


if __name__=='__main__':
    try:
        main()
    except APIError as exc:
        raise SystemExit(str(exc)) from None
