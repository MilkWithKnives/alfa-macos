#!/usr/bin/env python3
"""Generate an entirely synthetic Kismet fixture and offline report."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import struct
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'lib'))
import report


def make_fixture(path, count=24, ssid='Example Lab'):
    """Create only invented addresses and frames; never inspect a real capture."""
    ap = '02:00:00:00:00:01'
    client = '02:00:00:00:00:02'
    datasource = '00000000-0000-4000-8000-000000000001'
    start = 1700000000
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript('''
            CREATE TABLE KISMET (kismet_version TEXT, db_version INT, db_module TEXT);
            INSERT INTO KISMET VALUES ('synthetic',11,'kismetlog');
            CREATE TABLE datasources (uuid TEXT, typestring TEXT, definition TEXT, name TEXT, interface TEXT);
            CREATE TABLE snapshots (ts_sec INT, ts_usec INT, json TEXT, snaptype TEXT);
            CREATE TABLE devices (devmac TEXT, type TEXT, strongest_signal INT, first_time INT, last_time INT, device TEXT);
            CREATE TABLE packets (ts_sec INT, ts_usec INT, phyname TEXT, sourcemac TEXT,
                destmac TEXT, transmac TEXT, frequency REAL, signal INT, packet_len INT,
                error INT, datarate REAL, dlt INT, tags TEXT, packet BLOB, datasource TEXT,
                lat REAL, lon REAL, alt REAL);
        ''')
        db.execute('INSERT INTO datasources VALUES (?,?,?,?,?)',
                   (datasource, 'synthetic', 'synthetic', 'Synthetic demo', 'demo0'))
        device = {
            'kismet.device.base.commonname': ssid,
            'kismet.device.base.type': 'Wi-Fi AP',
            'kismet.device.base.channel': '1',
            'kismet.device.base.packets.total': count,
            'dot11.device': {'dot11.device.advertised_ssid_map': [{
                'dot11.advertisedssid.ssid': ssid,
                'dot11.advertisedssid.crypt_string': 'Open',
                'dot11.advertisedssid.channel': '1',
                'dot11.advertisedssid.last_time': start + count,
            }]},
        }
        db.execute('INSERT INTO devices VALUES (?,?,?,?,?,?)',
                   (ap, 'Wi-Fi AP', -38, start, start + count, json.dumps(device)))
        ap_bytes = bytes.fromhex(ap.replace(':', ''))
        client_bytes = bytes.fromhex(client.replace(':', ''))
        for i in range(count):
            beacon = i % 3 == 0
            dest = b'\xff' * 6 if beacon else client_bytes
            frame = struct.pack('<HH', 0x0080 if beacon else 0x0008, 0)
            frame += dest + ap_bytes + ap_bytes + struct.pack('<H', (i % 4096) << 4)
            if beacon:
                name = ssid.encode()[:32]
                frame += struct.pack('<QHH', i * 102400, 100, 1)
                frame += bytes([0, len(name)]) + name + b'\x01\x04\x82\x84\x8b\x96\x03\x01\x01'
            else:
                frame += b'Synthetic demonstration payload'
            db.execute('INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (start+i, 0, 'IEEE802.11', ap, 'ff:ff:ff:ff:ff:ff' if beacon else client,
                        ap, 2412000, -38-i % 12, len(frame), 0, 1, 105, 'synthetic',
                        frame, datasource, 0, 0, 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=REPO / 'build/demo')
    args = parser.parse_args()
    root = args.output.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    source = root / 'synthetic.kismet'
    if source.exists():
        parser.error(f'Refusing to overwrite {source}; choose a fresh --output directory')
    make_fixture(source)
    report.build_report(source, root / 'report')
    print(root / 'report/index.html')


if __name__ == '__main__':
    main()
