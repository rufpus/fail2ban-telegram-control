# SPDX-License-Identifier: MIT
"""Fail2ban Python action: direct local capture, no shell interpolation."""
import sys
import ipaddress
import threading
import time
sys.path.insert(0, '/opt/fail2ban-telegram-control')
from fail2ban.server.action import ActionBase
from f2btelegram import capture, MAX_BAN_SECONDS, DEADLINE_GRACE_SECONDS, check_fail2ban_version


class Action(ActionBase):
    def __init__(self, jail, name):
        super().__init__(jail, name)
        self._admin_lock = threading.RLock()

    def snapshot(self):
        try:
            return self._snapshot()
        except (AttributeError, TypeError) as exc:
            raise RuntimeError('Fail2ban private API unavailable while reading sshd state; inspect the installed Fail2ban version and service journal.') from exc

    def _snapshot(self):
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
        from fail2ban.version import version
        if getattr(self, '_checked_version', None) != version:
            check_fail2ban_version(version, self._logSys)
            self._checked_version = version
        try:
            actions = self._jail.actions
            if operation == 'ban':
                required = [actions._Actions__checkBan]
            elif operation == 'deadline':
                manager = actions.banManager
                required = [actions._prolongBan, manager._BanManager__banList.get]
                if not hasattr(manager._BanManager__lock, '__enter__') or not isinstance(manager._nextUnbanTime, (int, float)):
                    raise AttributeError('BanManager lock/deadline contract changed')
            else:
                required = [actions.removeBannedIP]
            if not all(callable(method) for method in required):
                raise AttributeError('required action method is not callable')
            return self._manage(operation, ip, deadline)
        except (AttributeError, TypeError) as exc:
            raise RuntimeError('Fail2ban %s private API unavailable for %s; no compatible per-IP operation is available. Check the service journal.' % (version, operation)) from exc

    def _manage(self, operation, ip, deadline=None):
        """Only exact IPv4 bans; never change the jail's global bantime."""
        from fail2ban.server.ticket import BanTicket
        from fail2ban.server.ipdns import IPAddr
        ip = str(ipaddress.IPv4Address(ip))
        if self._jail.name != 'sshd' or operation not in ('ban', 'unban', 'deadline'):
            raise ValueError('Unsupported operation')
        if operation != 'unban':
            for ignored in self.snapshot()['ignored']:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(ignored, strict=False):
                    raise ValueError('Address is whitelisted')
            if deadline is None or not 0 < float(deadline)-time.time() <= MAX_BAN_SECONDS + DEADLINE_GRACE_SECONDS:
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
