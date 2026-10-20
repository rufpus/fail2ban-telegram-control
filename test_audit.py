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
            db.execute('INSERT INTO geo VALUES (?,?,?,?)', ('198.18.0.1','{}',old,now))
            db.execute('INSERT INTO geo VALUES (?,?,?,?)', ('198.18.0.2','{}',now+86400,old))
            with patch.dict(os.environ, {'F2BT_RETENTION_DAYS':'30'}):
                f.prune_data(db, now)

            self.assertEqual([r['ip'] for r in db.execute('SELECT ip FROM events ORDER BY id')], ['198.18.0.2','198.18.0.3'])
            self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM geo').fetchone()[0], 0)
            with patch.dict(os.environ, {'F2BT_RETENTION_DAYS':'0'}), self.assertRaises(ValueError):
                f.prune_data(db, now)

    def test_maintenance_prunes_while_fail2ban_is_unavailable(self):
        with f.database() as db:
            db.execute('INSERT INTO audit(happened) VALUES (?)', (time.time()-40*86400,))
        with patch.object(m, 'sync_whitelist', side_effect=RuntimeError('offline')), patch.object(f.time, 'sleep', side_effect=InterruptedError), self.assertLogs(f.LOG, level='ERROR'), self.assertRaises(InterruptedError):
            f.maintenance(self.cfg)
        with f.database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0], 0)

    def test_extend_does_not_add_duplicate_ban_history(self):
        action, modules = load_action()
        with patch.dict(sys.modules, modules):
            action.manage('deadline', '198.18.0.42', time.time()+3600)
        action._jail.database.addBan.assert_not_called()
        action._jail.actions._prolongBan.assert_called_once()

    def test_version_range_warns_and_checks_private_api(self):
        for version in ('1.0.2', '1.0.3', '1.1.0', 'unknown'):
            action, modules = load_action(version)
            with patch.dict(sys.modules, modules):
                action.manage('deadline', '198.18.0.42', time.time()+3600)
            self.assertEqual(action._logSys.warning.called, version in ('1.1.0','unknown'))
        action, modules = load_action('1.1.0')
        del action._jail.actions.banManager._BanManager__banList
        with patch.dict(sys.modules, modules), self.assertRaisesRegex(RuntimeError, 'Fail2ban 1.1.0 private API unavailable'):
            action.manage('deadline', '198.18.0.42', time.time()+3600)
        action._jail.actions._prolongBan.assert_not_called()

    def test_local_address_cache_is_shared_expires_and_fails_closed(self):
        output = json.dumps([{'addr_info':[{'local':'192.0.2.10'}]}])
        with patch.object(f, '_LOCAL_ADDRESS_CACHE', None), patch.object(f, '_LOCAL_ADDRESS_EXPIRES', 0), patch.object(f.time, 'monotonic', return_value=100) as clock, patch.object(f, 'run', return_value=output) as run:
            with self.assertRaises(ValueError):
                m.protected_ip(self.cfg, '192.0.2.10')
            with self.assertRaises(ValueError):
                f.safe_network(self.cfg, '192.0.2.0/24')
            self.assertEqual(run.call_count, 1)
            clock.return_value = 100+f.LOCAL_ADDRESS_CACHE_SECONDS
            run.side_effect = RuntimeError('ip command failed')
            with self.assertRaisesRegex(RuntimeError, 'ip command failed'):
                f.local_addresses()
            self.assertEqual(run.call_count, 2)

    def test_nft_diff_preserves_unchanged_state_and_changes_only_elements(self):
        state = [
            {'chain':{'name':'input','type':'filter','hook':'input','prio':-2,'policy':'accept'}},
            {'set':{'name':'subnets','type':'ipv4_addr','flags':['interval','timeout'],
                    'elem':[{'elem':{'val':{'prefix':{'addr':'198.18.0.0','len':24}},'expires':3599}}]}},
            {'rule':{'chain':'input','handle':7,'expr':[
                {'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':22}},
                {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'@subnets'}},
                {'counter':{'packets':123,'bytes':456}}, {'drop':None}]}}]
        with patch.object(f, 'nft_state', return_value=state), patch.object(f, 'safe_network', side_effect=lambda cfg,net:net), patch.object(f, 'run') as run, patch.object(f.time, 'time', return_value=1000):
            with f.database() as db:
                db.execute('INSERT INTO subnets VALUES (?,?,?)', ('198.18.0.0/24',1000,4600))
                f.nft_sync(db, self.cfg)
                run.assert_not_called()
                db.execute('UPDATE subnets SET expires=8200')
                f.nft_sync(db, self.cfg)
                commands = run.call_args.args[1]
                self.assertIn('delete element', commands)
                self.assertIn('timeout 7200s', commands)
                self.assertNotIn('rule', commands)
                self.assertNotIn('delete table', commands)
                run.reset_mock()
                db.execute('DELETE FROM subnets')
                f.nft_sync(db, self.cfg)
                self.assertEqual(run.call_args.args[1], 'delete element inet f2b_telegram_control subnets { 198.18.0.0/24 }\n')

    def test_nft_read_failure_does_not_recreate_table(self):
        with patch.object(f.subprocess, 'run', return_value=types.SimpleNamespace(returncode=1,stderr='Operation not permitted')), patch.object(f, 'run') as run:
            with f.database() as db, self.assertRaisesRegex(RuntimeError, 'Cannot read'):
                f.nft_sync(db, self.cfg)
            run.assert_not_called()

    def test_outbox_rejects_oversize_before_insert(self):
        with f.database() as db:
            for text in ('x'*4097, '\U0001f600'*2049):
                with self.assertRaisesRegex(ValueError, '4096'):
                    f.queue(db, text)
            self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0], 0)
            f.queue(db, 'x'*4096)

    def test_token_validation_rejects_malformed_values(self):
        f.validate_token('123456:'+ 'X'*35)
        for token in (None, 123, '0:'+ 'X'*35, '\u0661:'+ 'X'*35,
                      '123:'+ 'X'*20, '123:'+ 'X'*36, '123:'+ 'X'*34+'!',
                      '123:'+ 'X'*35+'\n'):
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, 'BotFather'):
                f.validate_token(token)

    def test_event_dynamic_values_are_html_escaped(self):
        f.capture('<jail&>', dict(ip='198.18.0.42',time=time.time()-60,bantime=1,matches='<log&>'))
        with f.database() as db:
            db.execute("UPDATE events SET ip='<ip&>', failures='<count&>'")
            row = db.execute('SELECT * FROM events').fetchone()
            text, _ = f.render_event(db, row, {'server_name':'<server&>'}, {'country':'<country&>','connection':{'isp':'<isp&>'}})
            f.queue(db, text)
            for value in ('ip','jail','count','log','server','country','isp'):
                self.assertNotIn('<'+value+'&>', text)
                self.assertIn('&lt;'+value+'&amp;&gt;', text)
            self.assertIn('<code>&lt;ip&amp;&gt;</code>', text)

    def test_command_error_is_escaped_before_outbox(self):
        msg = dict(message_id=1,date=time.time(),text='/ban <b>&',chat={'id':123}, **{'from':{'id':123}})
        m.handle_message(self.cfg, msg)
        with f.database() as db:
            text = db.execute('SELECT text FROM outbox').fetchone()[0]
        self.assertNotIn('<b>', text)
        self.assertIn('&lt;b&gt;&amp;', text)

    def test_permanent_error_dead_letters_without_blocking_next_message(self):
        with f.database() as db:
            f.queue(db, 'bad')
            f.queue(db, 'good')
        with patch.object(f, 'api', side_effect=[f.APIError(400), {'message_id':1}]) as api:
            self.assertFalse(f.deliver_one(self.cfg))
            self.assertTrue(f.deliver_one(self.cfg))
            self.assertFalse(f.deliver_one(self.cfg))
        self.assertEqual(api.call_count, 2)
        with f.database() as db:
            self.assertEqual([r[0] for r in db.execute('SELECT status FROM outbox ORDER BY id')], ['failed','sent'])
        with patch.object(m, 'snapshot', return_value={'bans':[], 'ignored':[]}):
            self.assertIn('Queued notifications: 0.', m.report(self.cfg, '/status', []))

    def test_transient_errors_back_off_and_exhaust_attempts(self):
        for code in ('network', 503):
            with f.database() as db:
                db.execute('DELETE FROM outbox')
                f.queue(db, 'retry')
            with patch.object(f, 'api', side_effect=f.APIError(code)) as api:
                for attempt in range(f.OUTBOX_MAX_ATTEMPTS):
                    before = time.time()
                    self.assertFalse(f.deliver_one(self.cfg))
                    with f.database() as db:
                        row = db.execute('SELECT * FROM outbox').fetchone()
                        self.assertGreaterEqual(row['ready'], before+min(300, 2**min(attempt+1,8)))
                        db.execute('UPDATE outbox SET ready=0')
                self.assertFalse(f.deliver_one(self.cfg))
                self.assertEqual(api.call_count, f.OUTBOX_MAX_ATTEMPTS)
