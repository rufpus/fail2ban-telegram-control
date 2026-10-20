#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# This fixture intentionally changes only a disposable hosted CI runner.
test "${GITHUB_ACTIONS:-}" = true
test "$(ps -p 1 -o comm= | tr -d ' ')" = systemd
app=/opt/fail2ban-telegram-control
unit=fail2ban-telegram-control.service
cleanup() {
    systemctl status "$unit" --no-pager || true
    journalctl -u "$unit" --no-pager -n 100 || true
    systemctl stop "$unit" fail2ban || true
}
trap cleanup EXIT
mkdir -p "$app/locales" /etc/fail2ban-telegram-control
cp f2b*.py i18n.py "$app/"
cp locales/ru.json "$app/locales/"
cp .ci/systemd_probe.py "$app/"
cp telegram_action.py /etc/fail2ban/action.d/telegram_control.py
cp fail2ban-telegram-control.service /etc/systemd/system/"$unit"
touch /var/log/f2b-control-ci.log
cat > /etc/fail2ban/jail.d/zz-ci.local <<'JAIL'
[sshd]
enabled = true
backend = polling
logpath = /var/log/f2b-control-ci.log
port = 2222
banaction = nftables
JAIL
python3 - <<'PY'
import json
import os
import f2btelegram as f
os.umask(0o077)
f.initialize()
cfg = f.validate_config(dict(token='123456:'+('X'*35),chat_id=123,user_id=123,
    server_name='ci-systemd',ssh_ports=[2222],protected=['127.0.0.0/8']))
f.CONFIG.write_text(json.dumps(cfg))
os.chmod(f.CONFIG, 0o600)
PY
mkdir -p /etc/systemd/system/"$unit".d
cat > /etc/systemd/system/"$unit".d/ci.conf <<'UNIT'
[Service]
ExecStartPre=/usr/bin/python3 /opt/fail2ban-telegram-control/systemd_probe.py
# The real worker runs with a deliberately invalid token. No Telegram traffic is needed.
IPAddressDeny=any
UNIT
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/"$unit"
systemctl restart fail2ban
systemctl start "$unit"
sleep 3
systemctl is-active --quiet "$unit"
test -s /var/lib/fail2ban-telegram-control/ci-socket-ok
systemctl show "$unit" -p MainPID -p ProtectSystem -p CapabilityBoundingSet -p RestrictAddressFamilies
nft list table inet f2b_telegram_control
echo 'Real systemd production unit, sandbox socket probe and worker startup: OK'
