# SPDX-License-Identifier: MIT
"""Rootless regression tests for the follow-up audit."""
import tempfile
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
