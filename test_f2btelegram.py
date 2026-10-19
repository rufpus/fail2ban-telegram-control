# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import f2btelegram as f
import i18n


Path(__file__).parent.joinpath(".test-tmp").mkdir(exist_ok=True)

class Tests(unittest.TestCase):
    def setUp(self):
        i18n.configure_language("ru")
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent / ".test-tmp")
        self.old_state = f.STATE
        f.STATE = Path(self.temp.name)
        f.initialize()
        self.cfg = {'user_id': 123, 'chat_id': 123, 'protected': ['192.0.2.10/32', '198.51.100.10/32']}
        self.info = dict(ip='198.18.0.42', time=time.time(), bantime=86400,
                         failures=3, matches='Failed password for invalid user test', restored=0)
        self.local = patch.object(f, 'run', return_value='[]')
        self.local.start()

    def tearDown(self):
        i18n.configure_language("en")
        self.local.stop()
        f.STATE = self.old_state
        self.temp.cleanup()

    def get_button(self, kind, target='198.18.0.0/24', event_id=1, expires=None, mid=9):
        with f.database() as db:
            key = f.button(db, kind, target, 'test', event_id, expires)
            db.execute('UPDATE buttons SET message_id=? WHERE token=?', (mid, key['callback_data']))
        return {'id': 'callback', 'data': key['callback_data'], 'from': {'id': 123},
                'message': {'message_id': mid, 'chat': {'id': 123}}}

    def test_history_prolong_restore_and_unban(self):
        f.capture('sshd', self.info)
        f.capture('sshd', self.info)
        prolonged = dict(self.info, bantime=638418)
        f.capture('sshd', prolonged, 'prolong')
        with f.database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT duration FROM events').fetchone()[0], 638418)
            self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)
        f.capture('sshd', dict(self.info, restored=1, time=time.time()+1))
        f.capture('sshd', dict(self.info, restored=1), 'unban')
        f.capture('sshd', dict(self.info, time=time.time()+2))
        with f.database() as db:
            rows = db.execute('SELECT * FROM events ORDER BY id').fetchall()
            self.assertIsNotNone(rows[0]['ended'])
            self.assertEqual(rows[1]['previous_count'], 1)

    def test_protected_overlap(self):
        for net in ('192.0.2.0/24', '198.51.100.0/24', '127.1.2.0/24', '198.18.0.0/16'):
            with self.assertRaises(ValueError):
                f.safe_network(self.cfg, net)
        self.assertEqual(f.safe_network(self.cfg, '198.18.0.0/24'), '198.18.0.0/24')

    def test_authorization_binding_and_expiry(self):
        f.capture('sshd', self.info)
        cb = self.get_button('confirm_ban', expires=time.time()-1)
        with patch.object(f, 'nft_sync') as nft:
            self.assertIn('устарело', f.callback(self.cfg, cb))
            cb['from']['id'] = 999
            self.assertIn('запрещён', f.callback(self.cfg, cb))
            cb['from']['id'] = 123
            cb['message']['message_id'] = 1
            self.assertIn('недействительна', f.callback(self.cfg, cb))
            nft.assert_not_called()

    def test_confirm_repeat_unban_and_ip_preservation(self):
        f.capture('sshd', self.info)
        cb = self.get_button('confirm_ban', expires=time.time()+120)
        with patch.object(f, 'nft_sync') as nft:
            self.assertEqual(f.callback(self.cfg, cb), 'Выполнено.')
            self.assertIn('использовано', f.callback(self.cfg, cb))
            request = self.get_button('request_ban', mid=10)
            self.assertIn('уже заблокирована', f.callback(self.cfg, request))
            unban = self.get_button('confirm_unban', mid=11, expires=time.time()+120)
            self.assertEqual(f.callback(self.cfg, unban), 'Выполнено.')
            self.assertEqual(nft.call_count, 2)
        with f.database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM subnets').fetchone()[0], 0)
            self.assertIsNone(db.execute('SELECT ended FROM events').fetchone()[0])

    def test_ended_ban_and_firewall_failure(self):
        f.capture('sshd', self.info)
        cb = self.get_button('confirm_ban', expires=time.time()+120)
        with patch.object(f, 'nft_sync', side_effect=RuntimeError('nft failure')):
            with self.assertRaises(RuntimeError):
                f.callback(self.cfg, cb)
        with f.database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM subnets').fetchone()[0], 0)
        f.capture('sshd', self.info, 'unban')
        self.assertIn('снят или истёк', f.callback(self.cfg, cb))

    def test_render_logs_are_escaped(self):
        f.capture('sshd', dict(self.info, matches='Failed password <b>bad</b>\ninvalid user'))
        with f.database() as db:
            row = db.execute('SELECT * FROM events').fetchone()
            text, keys = f.render_event(db, row, self.cfg, {})
            self.assertIn('&lt;b&gt;bad&lt;/b&gt;', text)
            self.assertNotIn('<b>bad</b>', text)
            self.assertIn('несуществующим', text)
            self.assertTrue(keys)
            db.execute('UPDATE events SET ended=?', (time.time(),))
            row = db.execute('SELECT * FROM events').fetchone()
            text, keys = f.render_event(db, row, self.cfg, {})
            self.assertFalse(keys)

    def test_network_does_not_lock_fail2ban_database(self):
        f.capture('sshd', self.info)
        with f.database() as db:
            db.execute('UPDATE outbox SET ready=0')
        def network(*args, **kwargs):
            errors = []
            def capture_again():
                try:
                    f.capture('sshd', dict(self.info, time=time.time()+2))
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=capture_again)
            thread.start()
            thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors)
            return {'message_id': 100}
        with patch.object(f, 'geodata', return_value={}), patch.object(f, 'api', side_effect=network):
            self.assertTrue(f.deliver_one(self.cfg))

    def test_send_failure_preserves_outbox(self):
        f.capture('sshd', self.info)
        with f.database() as db:
            db.execute('UPDATE outbox SET ready=0')
        with patch.object(f, 'geodata', return_value={}), patch.object(f, 'api', side_effect=f.APIError(429, 30)):
            self.assertFalse(f.deliver_one(self.cfg))
        with f.database() as db:
            row = db.execute('SELECT * FROM outbox').fetchone()
            self.assertIsNone(row['sent'])
            self.assertGreaterEqual(row['ready'], time.time()+28)
            self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
