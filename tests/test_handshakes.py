from contextlib import closing
import csv
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'lib'), str(ROOT/'examples')]
import handshakes
import report
from make_demo import key_frame, make_fixture, add_demo_handshakes


def observe(tracker, message, counter, stamp, **kwargs):
    event = handshakes.extract(key_frame(message, counter, **kwargs), 105)
    event.update(_stamp=stamp, time=str(stamp), packet_row=int(stamp*10), channel=1)
    tracker.add(event)
    return event


class Decoder(unittest.TestCase):
    def test_all_messages_and_large_replay_counter(self):
        for qos in (False, True):
            for message in range(1,5):
                event = handshakes.extract(key_frame(message, 2**64-1, qos=qos), 105)
                self.assertEqual(event['message'], f'M{message}')
                self.assertEqual(event['replay_counter'], str(2**64-1))
                self.assertEqual(event['bssid'], '02:00:00:00:00:01')
                self.assertEqual(event['client'], '02:00:00:00:00:02')

    def test_radiotap_padding_fcs_and_ht_control(self):
        packet = bytearray(key_frame(1, qos=True))
        struct.pack_into('<H',packet,0,struct.unpack_from('<H',packet)[0] | 0x8000)
        packet = packet[:26] + bytes(4) + bytes(2) + packet[26:]
        # Flags field: FCS included, data padding, bad FCS.
        radio = struct.pack('<BBHI',0,0,9,2) + b'\x70'
        event = handshakes.extract(radio+packet+bytes(4),127)
        self.assertEqual(event['message'],'M1')
        self.assertTrue(event['_bad_fcs'])
        # Extended presence bitmap and aligned TSFT before flags.
        radio = struct.pack('<BBHII',0,0,25,0x80000003,0) + bytes(4+8) + b'\0'
        self.assertEqual(handshakes.extract(radio+key_frame(2),127)['message'],'M2')

    def test_rejects_encrypted_fragmented_amsdu_and_wrong_direction(self):
        for bit in (0x4000,0x0400):
            frame = bytearray(key_frame(1))
            struct.pack_into('<H',frame,0,struct.unpack_from('<H',frame)[0] | bit)
            self.assertIsNone(handshakes.extract(frame,105))
        frame = bytearray(key_frame(1)); frame[22] |= 1
        self.assertIsNone(handshakes.extract(frame,105))
        frame = bytearray(key_frame(1,qos=True)); frame[24] |= 0x80
        self.assertIsNone(handshakes.extract(frame,105))
        frame = bytearray(key_frame(1)); frame[1] = 1
        self.assertEqual(handshakes.extract(frame,105)['message'],'Unclassified key')

    def test_group_key_unknown_version_and_empty_mic(self):
        frame = bytearray(key_frame(2))
        # Header 24 + LLC 8 + EAPOL 4 + descriptor 1, flags big-endian.
        frame[38] &= ~8
        self.assertEqual(handshakes.extract(frame,105)['message'],'Group key')
        frame = bytearray(key_frame(2)); frame[38] &= ~7
        self.assertEqual(handshakes.extract(frame,105)['message'],'Unclassified key')
        frame = bytearray(key_frame(2)); frame[113:129] = bytes(16)
        self.assertEqual(handshakes.extract(frame,105)['message'],'Unclassified key')

    def test_every_truncation_is_safe_and_never_completes(self):
        raw = key_frame(3)
        for end in range(len(raw)):
            event = handshakes.extract(raw[:end],105)
            self.assertTrue(event is None or event['message'] not in ('M1','M2','M3','M4'),end)
        frame = bytearray(raw); frame[33] = 0  # EAP packet, not key
        self.assertEqual(handshakes.extract(frame,105)['message'],'Other EAPOL')


class Correlation(unittest.TestCase):
    def test_full_exchange_and_repeated_step(self):
        tracker = handshakes.Tracker()
        for stamp,(msg,counter) in enumerate([(1,5),(2,5),(3,6),(3,6),(4,6)],1):
            observe(tracker,msg,counter,stamp)
        rows = tracker.summaries({})
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['status'],'All four observed')
        self.assertEqual(rows[0]['repeated'],1)

    def test_duplicate_m1_is_partial(self):
        tracker = handshakes.Tracker()
        for stamp in range(4): observe(tracker,1,5,stamp)
        row = tracker.summaries({})[0]
        self.assertEqual(row['status'],'Partial')
        self.assertEqual(row['missing'],'M2, M3, M4')

    def test_wrong_replay_nonce_time_or_client_cannot_complete(self):
        variations = [dict(counter=9), dict(nonce=b'B'*32), dict(stamp=60), dict(client='02:00:00:00:00:03')]
        for variation in variations:
            tracker = handshakes.Tracker()
            observe(tracker,1,5,1)
            # Wrong counter is applied to M2; other mismatches to M3.
            observe(tracker,2,variation.get('counter',5),2)
            observe(tracker,3,6,variation.get('stamp',3),**{k:v for k,v in variation.items() if k in ('nonce','client')})
            observe(tracker,4,6,variation.get('stamp',3)+1)
            self.assertFalse(any(r['status']=='All four observed' for r in tracker.summaries({})),variation)

    def test_changed_nonce_starts_separate_attempt(self):
        tracker = handshakes.Tracker()
        observe(tracker,1,5,1)
        observe(tracker,1,5,2,nonce=b'B'*32)
        observe(tracker,2,5,3)
        observe(tracker,3,6,4,nonce=b'B'*32)
        observe(tracker,4,6,5)
        rows = tracker.summaries({})
        self.assertEqual([r['status'] for r in rows],['Partial','All four observed'])


class Exports(unittest.TestCase):
    def test_empty_authentication_export_has_readable_interface(self):
        output = io.BytesIO()
        writer = handshakes.Pcapng(output)
        writer.finish()
        data = output.getvalue()
        self.assertEqual(len(data),48)  # SHB + IDB, no packet blocks
        self.assertEqual(struct.unpack_from('<I',data,28)[0],1)
        self.assertEqual(struct.unpack_from('<H',data,36)[0],105)
        self.assertGreater(struct.unpack_from('<I',data,40)[0],0)

    def test_pcapng_mixed_linktypes_timestamps_and_padding(self):
        output = io.BytesIO()
        writer = handshakes.Pcapng(output)
        writer.write(b'abc',105,1700000000,123456,8)
        writer.write(bytes(10),127,1700000001,654321,10)
        data, offset, blocks = output.getvalue(), 0, []
        while offset < len(data):
            kind,length = struct.unpack_from('<II',data,offset)
            self.assertGreaterEqual(length,12)
            self.assertEqual(length % 4,0)
            self.assertEqual(struct.unpack_from('<I',data,offset+length-4)[0],length)
            blocks.append((kind,data[offset+8:offset+length-4]))
            offset += length
        self.assertEqual([b[0] for b in blocks],[0x0a0d0d0a,1,6,1,6])
        interface,high,low,caplen,original = struct.unpack_from('<IIIII',blocks[2][1])
        self.assertEqual((interface,(high<<32)|low,caplen,original),(0,1700000000123456,3,8))
        self.assertEqual(blocks[2][1][20:23],b'abc')

    def test_report_scans_beyond_packet_preview_and_excludes_error_frames(self):
        for flagged in (False,True):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp); source = root/'synthetic.kismet'
                make_fixture(source,count=2100)
                add_demo_handshakes(source)
                if flagged:
                    with closing(sqlite3.connect(source)) as db, db:
                        db.execute('UPDATE packets SET error=1 WHERE rowid=2105')  # M4
                def converter(command,**kwargs):
                    Path(command[command.index('--out')+1]).write_bytes(b'\x0a\x0d\x0d\x0a')
                with patch.dict(os.environ,ALFA_PCAP_CONVERTER='mock'),patch.object(report.subprocess,'run',side_effect=converter):
                    report.build_report(source,root/'report')
                html = (root/'report/index.html').read_text()
                payload = json.loads(html.split('<script id="report-data" type="application/json">')[1].split('</script>',1)[0])
                self.assertEqual(payload['authentication']['total'],7)
                self.assertEqual(payload['authentication']['four_observed'],0 if flagged else 1)
                self.assertEqual(len(payload['tables']['packets']),2000)
                self.assertFalse(any(p['authentication'] for p in payload['tables']['packets']))
                with (root/'report/eapol.csv').open(encoding='utf-8-sig') as file:
                    self.assertEqual(len(list(csv.DictReader(file))),7)
                self.assertNotIn('<!--REPORT_SCRIPT-->',html)


if __name__ == '__main__':
    unittest.main()
