import csv
import hashlib
import json
import os
import shutil
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / 'lib'), str(REPO / 'examples')]
import report
import probe_check
from make_demo import make_fixture


class Frames(unittest.TestCase):
    def test_types_and_flags(self):
        self.assertEqual(report.decode_frame(b'\x80\x00', 105), ('Beacon', False, False))
        self.assertEqual(report.decode_frame(b'\x08\x48', 105), ('Data', True, True))
        self.assertEqual(report.decode_frame(b'\x00\x00\x08\x00' + b'\x00'*4 + b'\x50\x00', 127)[0], 'Probe response')

    def test_truncated_and_unknown(self):
        for frame in (b'', b'\x00', b'\x00\x00\xff\xff' + b'\x00'*4):
            self.assertIn(report.decode_frame(frame, 127)[0], ('Malformed radiotap', 'Truncated 802.11'))
        self.assertEqual(report.decode_frame(b'\x01\x00', 105)[0], 'Unknown 802.11 version')

    def test_channels_and_csv(self):
        for freq, expected in ((2412000,1),(2484000,14),(5180000,36),(5955000,1),(0,'')):
            self.assertEqual(report.channel(freq), expected)
        self.assertEqual(report.safe_cell(' =1+1'), "' =1+1")
        self.assertEqual(report.safe_cell(-42), -42)


class ProbeCheck(unittest.TestCase):
    def test_request_layout_and_validation(self):
        frame = probe_check.probe_frame('Lab', '02:00:00:00:00:02', '02:00:00:00:00:01', 4097)
        self.assertEqual(struct.unpack_from('<H', frame)[0], 0x40)
        self.assertEqual(frame[4:10], bytes.fromhex('020000000001'))
        self.assertEqual(frame[10:16], bytes.fromhex('020000000002'))
        self.assertEqual(struct.unpack_from('<H', frame, 22)[0], 16)
        self.assertEqual(frame[24:29], b'\x00\x03Lab')
        for ssid, bssid in (('', '02:00:00:00:00:01'), ('a'*33, '02:00:00:00:00:01'), ('Lab', 'ff:ff:ff:ff:ff:ff')):
            with self.assertRaises(ValueError):
                probe_check.probe_frame(ssid, '02:00:00:00:00:02', bssid, 0)

    def test_response_requires_target_and_unique_destination(self):
        fields = dict(type_id=0, subtype_id=5, bssid='02:00:00:00:00:01',
                      source='02:00:00:00:00:01', dest='02:00:00:00:00:02', ssid='Lab')
        matches = lambda f: probe_check.response_matches(SimpleNamespace(**f), 'Lab', fields['bssid'], fields['dest'])
        self.assertTrue(matches(fields))
        for key, value in (('subtype_id',8),('ssid','Other'),('dest','ff:ff:ff:ff:ff:ff'),('source','02:00:00:00:00:03')):
            self.assertFalse(matches(dict(fields, **{key:value})))

    def test_invalid_cli_never_imports_radio(self):
        result = subprocess.run([sys.executable, str(REPO/'lib/probe_check.py'), '--ssid','Lab',
                                 '--bssid','not-a-mac','--channel','1'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('BSSID must', result.stderr)


class Reports(unittest.TestCase):
    def test_complete_counts_escaping_and_immutable_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root/'synthetic.kismet'
            make_fixture(source, count=2007, ssid='</script><script>alert(1)</script>')
            before = hashlib.sha256(source.read_bytes()).digest()
            calls = []
            def fake_converter(command, **kwargs):
                calls.append(command)
                Path(command[command.index('--out')+1]).write_bytes(b'\x0a\x0d\x0d\x0a')
            with patch.dict(os.environ, ALFA_PCAP_CONVERTER='mock-converter'), patch.object(report.subprocess, 'run', side_effect=fake_converter):
                self.assertEqual(report.build_report(source, root/'report'), 2007)
            self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), before)
            self.assertIn('--skip-clean', calls[0])
            with (root/'report/packets.csv').open(encoding='utf-8-sig') as file:
                self.assertEqual(len(list(csv.DictReader(file))), 2007)
            html = (root/'report/index.html').read_text()
            self.assertNotIn('</script><script>alert(1)</script>', html)
            self.assertIn('\\u003c/script\\u003e', html)
            self.assertEqual(html.count('"preview_hex"'), 2000)
            with (root/'report/frames.csv').open(encoding='utf-8-sig') as file:
                self.assertEqual(sum(int(row['packets']) for row in csv.DictReader(file)), 2007)

    def test_converter_false_success_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root/'synthetic.kismet'
            make_fixture(source, count=1)
            with patch.dict(os.environ, ALFA_PCAP_CONVERTER='mock'), patch.object(report.subprocess, 'run'):
                with self.assertRaises(FileNotFoundError):
                    report.build_report(source, root/'report')


class Install(unittest.TestCase):
    def test_source_destination_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            alias = home/'alias'
            alias.symlink_to(REPO, target_is_directory=True)
            env = dict(os.environ, HOME=str(home), ALFA_HOME=str(alias),
                       ALFA_BIN_DIR=str(home/'bin'), ALFA_DATA_DIR=str(home/'data'))
            result = subprocess.run(['bash', str(REPO/'install.sh'), '--no-desktop'],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('must differ', result.stderr)

    @unittest.skipUnless(sys.platform == 'darwin', 'Full setup entry point is macOS only')
    def test_full_setup_orders_both_installers_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            checkout = home/'checkout'
            checkout.mkdir()
            for name in ('install.sh','LICENSE','THIRD_PARTY.md'):
                shutil.copy(REPO/name, checkout/name)
            for name in ('bin','lib','patches','tests'):
                (checkout/name).mkdir()
            log = home/'steps'
            for name in ('alfa-setup','alfa-injection-setup'):
                (checkout/'bin'/name).write_text('#!/bin/bash\nprintf "%s\\n" "'+name+'" >> "$TEST_LOG"\n')
            env = dict(os.environ, HOME=str(home), TEST_LOG=str(log), ALFA_HOME=str(home/'runtime'),
                       ALFA_BIN_DIR=str(home/'bin'), ALFA_DATA_DIR=str(home/'data'))
            command = ['bash',str(checkout/'install.sh'),'--no-desktop','--with-injection']
            subprocess.run(command,env=env,check=True,capture_output=True)
            self.assertEqual(log.read_text().splitlines(), ['alfa-setup','alfa-injection-setup'])
            log.write_text('')
            (checkout/'bin/alfa-setup').write_text('#!/bin/bash\nexit 42\n')
            result = subprocess.run(command,env=env,capture_output=True)
            self.assertEqual(result.returncode,42)
            self.assertEqual(log.read_text(),'')

    def test_install_help_backup_and_space_paths(self):
        with tempfile.TemporaryDirectory(prefix='alfa test ') as temporary:
            home = Path(temporary)
            target = home/'custom runtime'
            commands = home/'custom bin'
            data = home/'custom data'
            env = dict(os.environ, HOME=str(home), ALFA_HOME=str(target), ALFA_BIN_DIR=str(commands),
                       ALFA_DATA_DIR=str(data), ALFA_PYTHON=sys.executable)
            command = ['bash', str(REPO/'install.sh'), '--no-desktop']
            subprocess.run(command, env=env, check=True, capture_output=True)
            for name in ('alfa-report','alfa-sniff','alfa-setup','alfa-injection-check','alfa-injection-setup'):
                result = subprocess.run([str(commands/name),'--help'], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            (target/'lib/previous-marker').write_text('previous')
            subprocess.run(command, env=env, check=True, capture_output=True)
            self.assertTrue(list((home/'.local/share/alfa-macos-backups').glob('*/runtime/lib/previous-marker')))
            self.assertFalse((target/'lib/previous-marker').exists())


if __name__ == '__main__':
    unittest.main()
