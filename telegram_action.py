# SPDX-License-Identifier: MIT
"""Fail2ban Python action: direct local capture, no shell interpolation."""
import sys
import ipaddress
import threading
import time
sys.path.insert(0, '/opt/fail2ban-telegram-control')
from fail2ban.server.action import ActionBase
from f2btelegram import capture


class Action(ActionBase):
    def __init__(self, jail, name):
        super().__init__(jail, name)
        self._admin_lock = threading.RLock()

    def snapshot(self):
        """Structured, read-only jail state over the local Fail2ban socket."""
        actions = self._jail.actions
        now = time.time()
        bans = []
        for ticket in actions.banManager:
            if ipaddress.ip_address(str(ticket.getID())).version != 4:
                continue
            seconds = ticket.getBanTime(actions.getBanTime())
            end = ticket.getTime()+seconds if seconds >= 0 else None
            if end is None or end > now:
                bans.append(dict(ip=str(ticket.getID()), started=ticket.getTime(),
                                 duration=seconds, expires=end))
        return {'bans': bans, 'ignored': [str(i) for i in self._jail.filter.getIgnoreIP()]}

    def manage(self, operation, ip, deadline=None):
        """Only exact IPv4 bans; never change the jail's global bantime."""
        from fail2ban.server.ticket import BanTicket
        from fail2ban.server.ipdns import IPAddr
        from fail2ban.version import version
        if version != '1.0.2':
            raise ValueError('Per-IP mutations require the tested Fail2ban version 1.0.2')
        ip = str(ipaddress.IPv4Address(ip))
        if self._jail.name != 'sshd' or operation not in ('ban', 'unban', 'deadline'):
            raise ValueError('Unsupported operation')
        if operation != 'unban':
            for ignored in self.snapshot()['ignored']:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(ignored, strict=False):
                    raise ValueError('Address is whitelisted')
            if deadline is None or not 0 < float(deadline)-time.time() <= 3024001:
                raise ValueError('Invalid deadline')
        with self._admin_lock:
            actions = self._jail.actions
            if operation == 'unban':
                actions.removeBannedIP(ip, ifexists=True)
                return {'ip': ip, 'banned': False}
            if operation == 'ban':
                if any(r['ip'] == ip for r in self.snapshot()['bans']):
                    return {'ip': ip, 'existing': True}
                now = time.time()
                ticket = BanTicket(ip, now, matches=['Manual ban requested through the Telegram bot'])
                ticket.setBanTime(float(deadline)-now)
                # Same entry point used by Actions.addBannedIP in Fail2ban 1.0.2,
                # with an explicit ticket duration so the observer won't increment it.
                actions._Actions__checkBan([ticket])
            else:
                manager = actions.banManager
                # Fail2ban 1.0.2 has no public per-ticket deadline setter.
                # Modify in place under its own lock; never temporarily unban.
                with manager._BanManager__lock:
                    ticket = manager._BanManager__banList.get(IPAddr(ip))
                    if ticket is None:
                        raise ValueError('IP is not banned')
                    ticket.setBanTime(float(deadline)-ticket.getTime())
                    manager._nextUnbanTime = min(manager._nextUnbanTime, float(deadline))
                # Extending an existing ticket is not another ban-history event.
                actions._prolongBan(ticket)
            return next(r for r in self.snapshot()['bans'] if r['ip'] == ip)

    @property
    def _prolongable(self):
        return True

    def _capture(self, info, operation):
        try:
            data = {key: info[key] for key in
                    ('ip', 'time', 'bantime', 'failures', 'matches', 'restored')}
            capture(self._jail.name, data, operation)
        except Exception:
            self._logSys.exception('Failed to persist Telegram event')

    def ban(self, aInfo):
        self._capture(aInfo, 'ban')

    def prolong(self, aInfo):
        self._capture(aInfo, 'prolong')

    def unban(self, aInfo):
        self._capture(aInfo, 'unban')
