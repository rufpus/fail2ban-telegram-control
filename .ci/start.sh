#!/usr/bin/env bash
set -euo pipefail
mkdir -p /work
cp -a /src/. /work/
cd /work
mkdir -p /run/sshd /run/fail2ban /opt/fail2ban-telegram-control/locales
cp f2btelegram.py f2bmanage.py i18n.py /opt/fail2ban-telegram-control/
cp locales/ru.json /opt/fail2ban-telegram-control/locales/
cp telegram_action.py /etc/fail2ban/action.d/telegram_control.py
touch /tmp/sshd-fixture.log
cat > /etc/fail2ban/jail.local <<'JAIL'
[DEFAULT]
backend = polling
banaction = nftables
bantime = 24h
findtime = 1h
maxretry = 3
[sshd]
enabled = true
backend = polling
logpath = /tmp/sshd-fixture.log
port = 2222
JAIL
fail2ban-client -x start
trap 'fail2ban-client stop >/dev/null 2>&1 || true' EXIT
python3 .ci/integration.py
python3 -m unittest discover -q
