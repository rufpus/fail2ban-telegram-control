# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import f2btelegram as f
import i18n
import f2bmanage as m


Path(__file__).parent.joinpath(".test-tmp").mkdir(exist_ok=True)

class ManagementTests(unittest.TestCase):
    def setUp(self):
        i18n.configure_language("ru")
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent / ".test-tmp")
        self.old = f.STATE
        f.STATE = Path(self.temp.name)
        f.initialize()
        self.cfg = dict(user_id=123, chat_id=123, protected=['192.0.2.10/32', '198.51.100.10/32'])
        self.bans = {}
        self.ignored = list(self.cfg['protected'])
        self.calls = []
        def snap():
            return {'bans': [dict(r) for r in self.bans.values()], 'ignored': list(self.ignored)}
        def control(op, ip, deadline=None):
            self.calls.append((op, ip, deadline))
            if op == 'unban':
                self.bans.pop(ip, None)
                return {}
            if op == 'ban' and ip not in self.bans:
                self.bans[ip] = dict(ip=ip, started=time.time(), expires=deadline)
            elif op == 'deadline':
                if ip not in self.bans:
                    raise ValueError('Not banned')
                self.bans[ip]['expires'] = deadline
            return self.bans[ip]
        def engine(*args):
            if args[2] == 'addignoreip':
                self.ignored.append(args[3])
            elif args[2] == 'delignoreip':
                self.ignored.remove(args[3])
        self.patches = [patch.object(m, 'snapshot', side_effect=snap), patch.object(m, 'manage', side_effect=control), patch.object(m, 'verify_scope'),
            patch.object(m, 'engine', side_effect=engine), patch.object(f, 'nft_sync'),
            patch.object(f, 'run', return_value='[]'), patch.object(f, 'geodata', return_value={})]
        for p in self.patches:
            p.start()
        m.sync_whitelist(self.cfg)
        self.sequence = 0

    def tearDown(self):
        i18n.configure_language("en")
        for p in reversed(self.patches):
            p.stop()
        f.STATE = self.old
        self.temp.cleanup()

    def message(self, text, **kwargs):
        self.sequence += 1
        msg = dict(message_id=self.sequence, date=time.time(), text=text,
                   chat={'id':123}, **{'from':{'id':123}})
        msg.update(kwargs)
        m.handle_message(self.cfg, msg)
        return msg

    def confirm(self):
        with f.database() as db:
            row = db.execute("SELECT * FROM buttons WHERE kind='admin' AND used=0 ORDER BY rowid DESC LIMIT 1").fetchone()
            db.execute('UPDATE buttons SET message_id=100 WHERE token=?', (row['token'],))
        cb = dict(data=row['token'], message={'message_id':100,'chat':{'id':123}}, **{'from':{'id':123}})
        return m.confirm(self.cfg, cb)

    def last_text(self):
        with f.database() as db:
            return db.execute('SELECT text FROM outbox ORDER BY id DESC LIMIT 1').fetchone()[0]

    def test_time_syntax_and_boundaries(self):
        self.assertEqual(m.parse_seconds('7d'), 604800)
        self.assertEqual(m.new_deadline(1000, '7d', 5000), 605800)
        self.assertEqual(m.new_deadline(1000, '+7d', 5000), 609800)
        for bad in ('0d', '-2h', '6w', '1.5h', '3d;id'):
            with self.assertRaises(ValueError):
                m.parse_seconds(bad)
        with self.assertRaises(ValueError):
            m.new_deadline(1000, '+1d', 1000+m.MAXTIME)

    def test_operation_failure_logs_traceback(self):
        with patch.object(m, 'apply', side_effect=RuntimeError('test failure')), self.assertLogs(f.LOG, level='ERROR') as logs:
            m.execute(self.cfg, 'test:failure', {'op':'unban', 'target':'198.18.0.42'})
        self.assertIsNotNone(logs.records[0].exc_info)
        self.assertIn('RuntimeError: test failure', logs.output[0])

    def test_baseline_normalizes_bare_ip_and_host_cidr(self):
        with f.database() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES ('baseline_ignores',?)",
                       (json.dumps(['192.0.2.10', '192.0.2.10/32']),))
        self.assertEqual(m.baseline(self.cfg).count('192.0.2.10/32'), 1)
        self.assertNotIn('192.0.2.10', m.baseline(self.cfg))

    def test_auth_and_stale_commands(self):
        self.message('/ban 198.18.0.42', **{'from':{'id':999}})
        self.message('/ban 198.18.0.42', date=time.time()-301)
        self.assertFalse(self.bans)
        self.assertFalse(self.calls)

    def test_ip_ban_repeat_duration_and_idempotency(self):
        msg = self.message('/ban 198.18.0.42 7d')
        self.assertAlmostEqual(self.bans['198.18.0.42']['expires']-time.time(), 604800, delta=2)
        m.handle_message(self.cfg, msg)
        self.message('/ban 198.18.0.42 1h')
        self.assertEqual(len(self.calls), 1)
        self.message('/extend 198.18.0.42 1h')
        self.assertAlmostEqual(self.bans['198.18.0.42']['expires']-time.time(), 3600, delta=2)
        end = self.bans['198.18.0.42']['expires']
        self.message('/extend 198.18.0.42 +1h')
        self.assertAlmostEqual(self.bans['198.18.0.42']['expires'], end+3600, delta=.1)
        self.message('/unban 198.18.0.42')
        self.assertFalse(self.bans)

    def test_whitelist_persists_unbans_and_protects(self):
        self.message('/ban 198.18.0.42')
        self.message('/whitelist add 198.18.0.42')
        self.assertFalse(self.bans)
        self.assertIn('198.18.0.42/32', m.whitelist_networks())
        self.assertIn('198.18.0.42/32', (f.STATE/'whitelist.local').read_text())
        self.message('/ban 198.18.0.42')
        self.assertFalse(self.bans)
        self.assertIn('запрещена', self.last_text())
        self.message('/whitelist del 198.18.0.42')
        self.assertNotIn('198.18.0.42/32', m.whitelist_networks())
        self.assertNotIn('198.18.0.42/32', self.ignored)
        self.message('/whitelist del 192.0.2.10')
        self.assertIn('нельзя', self.last_text())

    def test_subnet_confirmation_custom_duration(self):
        self.message('/bansubnet 198.18.0.0/24 7d')
        with f.database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM subnets').fetchone()[0], 0)
        self.assertNotIn('Ошибка', self.confirm())
        with f.database() as db:
            end = db.execute('SELECT expires FROM subnets').fetchone()[0]
            self.assertAlmostEqual(end-time.time(), 604800, delta=2)
        self.message('/extend 198.18.0.0/24 +1d')
        self.confirm()
        with f.database() as db:
            self.assertAlmostEqual(db.execute('SELECT expires FROM subnets').fetchone()[0], end+86400, delta=.1)
        self.message('/unbansubnet 198.18.0.0/24')
        self.confirm()
        with f.database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM subnets').fetchone()[0], 0)

    def test_white_ip_with_subnet_conflict_needs_confirmation(self):
        self.message('/bansubnet 198.18.0.0/24')
        self.confirm()
        self.message('/whitelist add 198.18.0.42')
        self.assertNotIn('198.18.0.42/32', m.whitelist_networks())
        self.confirm()
        self.assertIn('198.18.0.42/32', m.whitelist_networks())
        with f.database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM subnets').fetchone()[0], 0)
        with self.assertRaises(ValueError):
            f.safe_network(self.cfg, '198.18.0.0/24')

    def test_unban_ip_preserves_subnet(self):
        self.message('/bansubnet 198.18.0.0/24')
        self.confirm()
        self.message('/unban 198.18.0.42')
        self.assertIn('всё ещё блокируется', self.last_text())
        with f.database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM subnets').fetchone()[0], 1)

    def test_white_subnet_limits_and_unban_members(self):
        self.message('/ban 198.18.0.42')
        self.message('/ban 198.18.1.42')
        self.message('/whitelist add 198.18.0.0/24')
        self.assertEqual(len(self.bans), 2)
        self.confirm()
        self.assertNotIn('198.18.0.42', self.bans)
        self.assertIn('198.18.1.42', self.bans)
        self.message('/whitelist add 198.18.0.0/16')
        self.assertIn('/24', self.last_text())

    def test_white_ip_removal_uses_fail2ban_bare_ip_form(self):
        self.message('/whitelist add 198.18.0.42')
        self.ignored = [n[:-3] if n.endswith('/32') else n for n in self.ignored]
        self.message('/whitelist del 198.18.0.42')
        self.assertNotIn('198.18.0.42', self.ignored)
        self.assertNotIn('198.18.0.42/32', m.whitelist_networks())

    def test_whitelist_removal_after_reload_clears_runtime_ignoreip(self):
        self.message('/whitelist add 198.18.0.42')
        self.assertIn('198.18.0.42/32', self.ignored)
        self.ignored.clear()  # Fail2ban reload lost the runtime ignoreip list.
        self.message('/whitelist del 198.18.0.42')
        self.assertNotIn('198.18.0.42/32', m.whitelist_networks())
        self.assertNotIn('198.18.0.42/32', self.ignored)
        with f.database() as db:
            self.assertEqual(db.execute('SELECT status FROM admin_operations ORDER BY created DESC LIMIT 1').fetchone()[0], 'done')

    def test_live_tickets_correct_reload_unban_markers(self):
        started = time.time()
        f.capture('sshd',dict(ip='198.18.0.42',time=started,bantime=86400,restored=0))
        f.capture('sshd',dict(ip='198.18.0.42',time=started,bantime=86400,restored=0),'unban')
        state = {'bans':[dict(ip='198.18.0.42',started=started,expires=started+3600,duration=3600)]}
        m.refresh_active_events(state)
        with f.database() as db:
            row = db.execute('SELECT * FROM events').fetchone()
            self.assertIsNone(row['ended'])
            self.assertEqual(row['duration'],3600)

    def test_reports_and_no_mass_or_shell_commands(self):
        for command in ('/help','/status','/bans','/ip 198.18.0.42','/whitelist','/audit'):
            self.message(command)
            self.assertTrue(self.last_text())
        for command in ('/unbanall','/ban 198.18.0.42;id','/ban 192.0.2.10','/ban 198.51.100.10'):
            self.message(command)
        self.assertFalse(self.bans)
        self.assertFalse(self.calls)


class BridgeTests(unittest.TestCase):
    def test_missing_action_is_restored_after_jail_reload(self):
        result = {'bans': [], 'ignored': []}
        with patch.object(m, 'engine', side_effect=[RuntimeError('missing'), ['nftables'], 'telegram_control', result]) as engine:
            self.assertEqual(m.snapshot(), result)
            self.assertEqual(engine.call_args_list[2].args[:4], ('set','sshd','addaction','telegram_control'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
