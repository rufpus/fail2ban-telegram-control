# SPDX-License-Identifier: MIT
"""Regression coverage for the technical audit; no real network or firewall."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch
import f2btelegram as f
import f2bmanage as m
import i18n


def load_action(version='1.0.2'):
    modules = {
        'fail2ban.server.action': types.SimpleNamespace(ActionBase=object),
        'fail2ban.server.ticket': types.SimpleNamespace(BanTicket=Mock()),
        'fail2ban.server.ipdns': types.SimpleNamespace(IPAddr=lambda ip: ip),
        'fail2ban.version': types.SimpleNamespace(version=version),
    }
    spec = importlib.util.spec_from_file_location('audit_action', Path(__file__).with_name('telegram_action.py'))
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    action = module.Action.__new__(module.Action)
    action._admin_lock = threading.RLock()
    action._logSys = Mock()
    ticket = Mock()
    ticket.getTime.return_value = time.time()-10
    manager = types.SimpleNamespace(_BanManager__lock=threading.RLock(),
                                   _BanManager__banList={'198.18.0.42': ticket}, _nextUnbanTime=time.time()+100)
    actions = Mock(banManager=manager)
    action._jail = types.SimpleNamespace(name='sshd', actions=actions, database=Mock())
    action.snapshot = Mock(return_value={'ignored': [], 'bans':[{'ip':'198.18.0.42'}]})
    return action, modules


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent/'.test-tmp')
        self.old_state = f.STATE
        f.STATE = Path(self.temp.name)
        f.initialize()
        i18n.configure_language('en')
        self.cfg = dict(chat_id=123, user_id=123, protected=[])

    def tearDown(self):
        f.STATE = self.old_state
        self.temp.cleanup()

    def test_retention_prunes_old_data_preserves_pending_and_live(self):
        now = time.time()
        old = now-40*86400
        for ip, seconds in [('198.18.0.1', 60), ('198.18.0.2', -1), ('198.18.0.3', 60)]:
            f.capture('sshd', dict(ip=ip,time=old,bantime=seconds))
        with f.database() as db:
            db.execute('UPDATE outbox SET sent=?,created=? WHERE event_id IN (1,2)', (old, old))
            db.execute('INSERT INTO audit(happened) VALUES (?)', (old,))
            db.execute('INSERT INTO geo VALUES (?,?,?)', ('198.18.0.1','{}',old))
            with patch.dict(os.environ, {'F2BT_RETENTION_DAYS':'30'}):
                f.prune_data(db, now)
            self.assertEqual([r['ip'] for r in db.execute('SELECT ip FROM events ORDER BY id')], ['198.18.0.2','198.18.0.3'])
            self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM geo').fetchone()[0], 0)
            with patch.dict(os.environ, {'F2BT_RETENTION_DAYS':'0'}), self.assertRaises(ValueError):
                f.prune_data(db, now)

    def test_extend_does_not_add_duplicate_ban_history(self):
        action, modules = load_action()
        with patch.dict(sys.modules, modules):
            action.manage('deadline', '198.18.0.42', time.time()+3600)
        action._jail.database.addBan.assert_not_called()
        action._jail.actions._prolongBan.assert_called_once()
