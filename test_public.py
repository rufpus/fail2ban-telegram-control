# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import re
import string
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import f2btelegram as f
import f2bmanage as m
import i18n
import installer
from setup_credentials import save_config

TMP = Path(__file__).parent / '.test-tmp'
TMP.mkdir(exist_ok=True)


def valid_cfg():
    return dict(token='123456:'+('X'*35),chat_id=123,user_id=123,protected=['192.0.2.10/32'])


class PublicTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TMP)
        self.root = Path(self.temp.name)
        self.old_state, self.old_settings = f.STATE, dict(f.SETTINGS)
        f.STATE = self.root/'state'
        f.initialize()
        i18n.configure_language('en')
        f.SETTINGS.update(f.DEFAULT_SETTINGS)

    def tearDown(self):
        f.STATE = self.old_state
        f.SETTINGS.clear()
        f.SETTINGS.update(self.old_settings)
        i18n.configure_language('en')
        self.temp.cleanup()

    def test_default_configuration_is_english_utc_no_geo(self):
        f.SETTINGS.update(language='ru',timezone='Europe/Paris',geoip=True)
        cfg = f.validate_config(valid_cfg())
        self.assertEqual((cfg['language'],cfg['timezone'],cfg['geoip']),('en','UTC',False))

    def test_invalid_configurations_fail_closed(self):
        cases = [('chat_id',-1),('user_id',True),('user_id',456),('ssh_ports',['22;id']),
                 ('ssh_ports',[0]),('ssh_ports',[]),('geoip','false'),('language','xx')]
        for key,value in cases:
            with self.subTest(key=key,value=value), self.assertRaises(ValueError):
                f.validate_config(valid_cfg()|{key:value})

    def test_ip_mutations_reject_mismatched_firewall_ports(self):
        def engine(*args):
            if args[-1]=='actions': return ['nftables','telegram_control']
            if args[-1]=='actionstart': return 'tcp dport <port>'
            if args[-1]=='protocol': return 'tcp'
            if args[-1]=='port': return 'ssh'
        with patch.object(m,'engine',side_effect=engine):
            m.verify_scope(valid_cfg()|{'ssh_ports':[22]})
            with self.assertRaises(RuntimeError):
                m.verify_scope(valid_cfg()|{'ssh_ports':[2222]})
        self.assertEqual(m.action_ports('22,2222'),{22,2222})

    def test_atomic_configuration_write(self):
        target=self.root/'etc'/'config.json'
        save_config(valid_cfg(),target)
        self.assertEqual(json.loads(target.read_text())['chat_id'],123)
        self.assertEqual([p.name for p in target.parent.iterdir()],['config.json'])

    def test_bilingual_messages_and_help(self):
        f.capture('sshd',dict(ip='203.0.113.42',time=time.time(),bantime=86400,restored=0,
                             failures=3,matches='Failed password for invalid user guest'))
        for language in ('en','ru'):
            i18n.configure_language(language,ports=[2222])
            with f.database() as db:
                row=db.execute('SELECT * FROM events').fetchone()
                text,keys=f.render_event(db,row,valid_cfg(),{})
            help_text=i18n.tr(m.HELP)
            if language=='en':
                self.assertIn('Reason:',text)
                self.assertFalse(re.search('[А-Яа-яЁё]',text+help_text))
                self.assertTrue(keys[0][0]['text'].startswith('Ban '))
            else:
                self.assertIn('Причина:',text)
                self.assertIn('несуществующим',text)
                self.assertTrue(keys[0][0]['text'].startswith('Забанить '))
            self.assertIn('2222',help_text)

    def test_catalogue_preserves_template_fields(self):
        formatter=string.Formatter()
        fields=lambda s:{field for _,field,_,_ in formatter.parse(s) if field is not None}
        for en,ru in i18n._RU.items():
            self.assertEqual(fields(en),fields(ru),en)

    def test_geolocation_is_disabled_without_any_network_io(self):
        with patch.object(f.urllib.request,'urlopen') as request:
            self.assertEqual(f.geodata('203.0.113.42'),{})
            request.assert_not_called()

    def test_ipv6_events_do_not_break_ipv4_action(self):
        f.capture('sshd',dict(ip='2001:db8::42',time=time.time(),bantime=86400,restored=0))
        with f.database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0],0)

    def test_nft_transaction_uses_configured_ports_and_owned_table(self):
        cfg=valid_cfg()|{'ssh_ports':[2222,2200]}
        commands=[]
        def run(args,input_text=None):
            if args[0]=='ip': return '[]'
            commands.append(input_text)
            return ''
        with patch.object(f,'run',side_effect=run), patch.object(f,'nft_state',return_value=None):
            with f.database() as db:
                db.execute('INSERT INTO subnets VALUES (?,?,?)',('198.18.0.0/24',time.time(),time.time()+7200))
                f.nft_sync(db,cfg)
        command=commands[0]
        self.assertIn('dport { 2222, 2200 }',command)
        self.assertIn('timeout ',command)
        self.assertIn('add table inet f2b_telegram_control',command)
        self.assertNotIn('delete table',command)
        self.assertNotIn('flush ruleset',command)
        self.assertNotIn('f2b-table',command)

    def test_ipv6_baseline_does_not_block_valid_ipv4_subnet_validation(self):
        cfg=valid_cfg()|{'protected':['::1/128','192.0.2.10/32']}
        with patch.object(f,'run',return_value='[]'):
            self.assertEqual(f.safe_network(cfg,'198.18.0.0/24'),'198.18.0.0/24')

    def test_restore_ignore_entries_uses_the_runtime_string_form(self):
        calls=[]
        def engine(*args):
            calls.append(args)
            return ['192.0.2.10','203.0.113.42'] if args[0]=='get' else []
        with patch.object(m,'engine',side_effect=engine):
            installer.restore_ignores(['192.0.2.10/32'])
        self.assertIn(('set','sshd','delignoreip','203.0.113.42'),calls)

    @unittest.skipUnless(os.name == 'posix', 'symlink rollback runs on Linux CI')
    def test_rejected_install_rolls_back_owned_files_only(self):
        source=self.root/'source'
        app=self.root/'app'
        source.mkdir()
        app.mkdir()
        (app/'keep.txt').write_text('operator file')
        (app/'f2btelegram.py').write_text('previous version')
        for name in installer.FILES:
            path=source/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('new version')
        etc=self.root/'etc'
        etc.mkdir()
        unit,action,include=etc/'unit.service',etc/'action.py',etc/'whitelist.local'
        manifest=f.STATE/'install-manifest.json'
        manifest.write_text('{"version":"old"}')
        def call(*args,**kwargs):
            if args[:2]==('fail2ban-client','-t'):
                raise RuntimeError('invalid configuration')
            return types.SimpleNamespace(returncode=1,stdout='',stderr='')
        with patch.multiple(installer,APP=app,UNIT=unit,ACTION=action,INCLUDE=include,
                            BACKUPS=self.root/'backups',MANIFEST=manifest), \
             patch.object(installer,'preflight',return_value=(valid_cfg(),['192.0.2.10'])), \
             patch.object(installer,'call',side_effect=call), \
             patch.object(m,'engine',return_value=[]), patch.object(m,'sync_whitelist'), \
             patch.object(installer,'restore_ignores') as restore:
            with self.assertRaisesRegex(RuntimeError,'invalid configuration'):
                installer.install(source)
        self.assertEqual((app/'keep.txt').read_text(),'operator file')
        self.assertEqual((app/'f2btelegram.py').read_text(),'previous version')
        self.assertFalse((app/'i18n.py').exists())
        self.assertEqual(json.loads(manifest.read_text())['version'],'old')
        self.assertFalse(include.is_symlink())
        restore.assert_called_once_with(['192.0.2.10'])


if __name__=='__main__':
    unittest.main()
