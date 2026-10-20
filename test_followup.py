# SPDX-License-Identifier: MIT
"""Rootless regression tests for the follow-up audit."""
import tempfile
import copy
import json
import os
import types
from pathlib import Path
import unittest
from unittest.mock import patch
import f2btelegram as f
import f2bmanage as m
import i18n


class FollowupTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).parent / '.test-tmp'
        root.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.temp.cleanup)
        self.state = patch.object(f, 'STATE', Path(self.temp.name))
        self.state.start()
        self.addCleanup(self.state.stop)
        i18n.configure_language('en')
        f.initialize()
        self.cfg = dict(user_id=123, chat_id=123)

    def fail_message(self):
        with f.database() as db:
            f.queue(db, 'test notification')
        with patch.object(f, 'api', side_effect=f.APIError(400)):
            f.deliver_one(self.cfg)

    def test_dead_letter_notice_is_aggregated_persistent_and_nonrecursive(self):
        self.fail_message()
        self.fail_message()
        with f.database() as db:
            f.notify_dead_letters(db, 1000)
            f.notify_dead_letters(db, 1001)
            notices = db.execute("SELECT * FROM outbox WHERE kind='dead_letter_notice'").fetchall()
            self.assertEqual(len(notices), 1)
            self.assertIn('2 new notifications', notices[0]['text'])
        # A permanent failure of the warning itself must never create another warning.
        with patch.object(f, 'api', side_effect=f.APIError(400)):
            self.assertFalse(f.deliver_one(self.cfg))
        f.initialize()  # Simulate a restart: aggregation cursor must survive.
        with f.database() as db:
            f.notify_dead_letters(db, 5000)
            self.assertEqual(db.execute("SELECT count(*) FROM outbox WHERE kind='dead_letter_notice'").fetchone()[0], 1)
        with patch.object(m, 'snapshot', return_value={'bans':[], 'ignored':[]}):
            self.assertIn('Failed notifications: 3.', m.report(self.cfg, '/status', []))
        self.fail_message()
        with f.database() as db:
            f.notify_dead_letters(db, 1100)  # Throttle still applies after the restart.
            self.assertEqual(db.execute("SELECT count(*) FROM outbox WHERE kind='dead_letter_notice'").fetchone()[0], 1)
            f.notify_dead_letters(db, 1400)
            self.assertEqual(db.execute("SELECT count(*) FROM outbox WHERE kind='dead_letter_notice'").fetchone()[0], 2)

    def test_pending_notice_prevents_duplicates_even_after_throttle(self):
        self.fail_message()
        with f.database() as db:
            f.notify_dead_letters(db, 1000)
        # Insert another failure without delivering the pending aggregate notice.
        with f.database() as db:
            db.execute("UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='dead_letter_total'")
            f.notify_dead_letters(db, 5000)
            self.assertEqual(db.execute("SELECT count(*) FROM outbox WHERE kind='dead_letter_notice'").fetchone()[0], 1)

    def test_nft_element_forms_and_invalid_values(self):
        prefix = {'prefix':{'addr':'198.18.0.0','len':24}}
        for value, expected in [
            (prefix, ('198.18.0.0/24', None)),
            ('198.18.0.0/24', ('198.18.0.0/24', None)),
            ({'elem':{'val':prefix,'expires':15,'timeout':60}}, ('198.18.0.0/24',15)),
            ({'elem':{'val':prefix,'timeout':60}}, ('198.18.0.0/24',60)),
            ({'elem':{'val':prefix,'expires':0,'timeout':60}}, ('198.18.0.0/24',0)),
        ]:
            with self.subTest(value=value):
                self.assertEqual(f.nft_element(value), expected)
        for value in ('not-an-ip', '198.18.0.42/24', '2001:db8::/32'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                f.nft_element(value)

    def test_nft_rule_matches_does_not_mutate_input(self):
        for right, ports in [(22,[22]), ({'set':[2222,22]}, [22,2222])]:
            rule = {'expr':[
                {'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':right}},
                {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'@subnets'}},
                {'counter':{'packets':1}}, {'drop':None}]}
            before = copy.deepcopy(rule)
            self.assertTrue(f.nft_rule_matches(rule, ports))
            self.assertEqual(rule, before)
            self.assertFalse(f.nft_rule_matches(rule, [2200]))
            self.assertEqual(rule, before)
        self.assertFalse(f.nft_rule_matches({'expr':[]}, [22]))

    def test_nft_state_success_missing_denied_and_invalid_json(self):
        cases = [(0, '{"nftables":[]}', '', []), (1, '', 'No such file or directory', None)]
        for code, stdout, stderr, expected in cases:
            with patch.object(f.subprocess, 'run', return_value=types.SimpleNamespace(returncode=code,stdout=stdout,stderr=stderr)) as run:
                self.assertEqual(f.nft_state(), expected)
                self.assertEqual(run.call_args.kwargs['env']['LC_ALL'], 'C')
                self.assertNotIn('shell', run.call_args.kwargs)
        with patch.object(f.subprocess, 'run', return_value=types.SimpleNamespace(returncode=1,stdout='',stderr='Operation not permitted')), self.assertRaises(RuntimeError):
            f.nft_state()
        with patch.object(f.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0,stdout='invalid',stderr='')), self.assertRaises(ValueError):
            f.nft_state()

    def test_dead_letter_classification_and_attempt_boundary(self):
        for error in (f.APIError('network'), f.APIError(500), f.APIError(599)):
            self.assertTrue(f.should_retry_delivery(error, 0))
            self.assertTrue(f.should_retry_delivery(error, f.OUTBOX_MAX_ATTEMPTS-2))
            self.assertFalse(f.should_retry_delivery(error, f.OUTBOX_MAX_ATTEMPTS-1))
        for error in (f.APIError(400), f.APIError(403), f.APIError(429), f.APIError('unknown'), ValueError('too long')):
            self.assertFalse(f.should_retry_delivery(error, 0))

    def test_version_range_boundaries(self):
        for version in ('1.0.2','1.0.3','1.0.99'):
            with self.assertNoLogs(f.LOG, level='WARNING'):
                self.assertTrue(f.check_fail2ban_version(version))
        for version in ('1.0.1','1.1.0','2.0.0','1.0.2-dev','invalid'):
            with self.assertLogs(f.LOG, level='WARNING') as logs:
                self.assertFalse(f.check_fail2ban_version(version))
            self.assertIn(version, logs.output[0])

    def test_prune_uses_configurable_ttl_and_rejects_invalid_override(self):
        with f.database() as db:
            db.executemany('INSERT INTO audit(happened) VALUES (?)', [(100,), (200000,)])
            with patch.dict(os.environ, {'F2BT_RETENTION_DAYS':'1'}):
                f.prune_data(db, 200001)
            self.assertEqual([r[0] for r in db.execute('SELECT happened FROM audit')], [200000])
            for days in ('0','-1','not-a-number'):
                with patch.dict(os.environ, {'F2BT_RETENTION_DAYS':days}), self.assertRaises(ValueError):
                    f.prune_data(db, 200001)

    def test_legacy_alter_table_migrations_are_idempotent_and_preserve_rows(self):
        for had_status in (False, True):
            legacy = Path(self.temp.name) / str(had_status)
            legacy.mkdir()
            with patch.object(f, 'STATE', legacy):
                with f.database() as db:
                    db.execute('CREATE TABLE outbox(id INTEGER PRIMARY KEY,event_id INTEGER UNIQUE,text TEXT,buttons TEXT,ready REAL,sent REAL,message_id INTEGER,attempts INTEGER DEFAULT 0)')
                    if had_status:
                        db.execute("ALTER TABLE outbox ADD COLUMN status TEXT DEFAULT 'pending'")
                    db.execute("INSERT INTO outbox(text,ready,sent,attempts) VALUES ('preserve',100,200,3)")
                    if had_status:
                        db.execute("UPDATE outbox SET sent=NULL,status='failed'")
                    db.execute('CREATE TABLE geo(ip TEXT PRIMARY KEY,data TEXT,expires REAL)')
                    db.execute('INSERT INTO geo VALUES (?,?,?)', ('198.18.0.42',json.dumps({'country':'Demo'}),500))
                f.initialize()
                f.initialize()
                with f.database() as db:
                    row = db.execute('SELECT * FROM outbox').fetchone()
                    self.assertEqual((row['text'],row['attempts'],row['kind']), ('preserve',3,'message'))
                    self.assertEqual(row['status'], 'failed' if had_status else 'sent')
                    self.assertEqual(row['created'], 100 if had_status else 200)
                    self.assertIsNotNone(db.execute('SELECT created FROM geo').fetchone()[0])
                    self.assertEqual(int(db.execute("SELECT value FROM meta WHERE key='dead_letter_total'").fetchone()[0]), int(had_status))
