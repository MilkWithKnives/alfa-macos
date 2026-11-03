#!/usr/bin/env python3
"""Offline Kismet reports; stdlib only, read-only snapshot of the source DB."""
import argparse
import collections
from contextlib import closing
import csv
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile

ROOT = Path(os.environ.get('ALFA_DATA_DIR', str(Path.home() / 'Captures/ALFA'))).expanduser().resolve()
PACKET_LIMIT = 2000
MGMT = {0:'Association request',1:'Association response',2:'Reassociation request',
        3:'Reassociation response',4:'Probe request',5:'Probe response',8:'Beacon',
        9:'ATIM',10:'Disassociation',11:'Authentication',12:'Deauthentication',
        13:'Action',14:'Action (no ACK)'}
CTRL = {7:'Control wrapper',8:'Block ACK request',9:'Block ACK',10:'PS-Poll',
        11:'RTS',12:'CTS',13:'Acknowledgement',14:'CF-End',15:'CF-End + ACK'}
DATA = {0:'Data',1:'Data + CF-ACK',2:'Data + CF-Poll',3:'Data + CF-ACK/Poll',
        4:'Null data',5:'CF-ACK',6:'CF-Poll',7:'CF-ACK/Poll',8:'QoS data',
        9:'QoS data + CF-ACK',10:'QoS data + CF-Poll',11:'QoS data + CF-ACK/Poll',
        12:'QoS null',14:'QoS CF-Poll',15:'QoS CF-ACK/Poll'}
PACKET_COLS = ['packet_row','time','frame','source','destination','transmitter',
               'channel','frequency_mhz','signal_dbm','bytes','captured_bytes',
               'protected','retry','error','rate_mbps','phy','link_type','tags']

def local_time(value, micros=0):
    if not value:
        return ''
    stamp = dt.datetime.fromtimestamp(value, dt.timezone.utc).astimezone()
    if micros:
        stamp = stamp.replace(microsecond=int(micros))
    return stamp.isoformat(timespec='microseconds' if micros else 'seconds')

def channel(khz):
    mhz = float(khz or 0) / 1000
    if mhz == 2484: return 14
    if 2412 <= mhz <= 2472: return int((mhz-2407)/5)
    if mhz == 5935: return 2
    if 5955 <= mhz <= 7115: return int((mhz-5950)/5)
    if 5000 <= mhz < 5925: return int((mhz-5000)/5)
    if 4910 <= mhz <= 4980: return int((mhz-4000)/5)
    return ''

def decode_frame(packet, dlt):
    offset = 0
    if dlt == 127:
        if len(packet) < 8 or packet[0] != 0:
            return 'Malformed radiotap', '', ''
        offset = struct.unpack_from('<H', packet, 2)[0]
        if offset < 8:
            return 'Malformed radiotap', '', ''
    elif dlt != 105:
        return ('Ethernet' if dlt == 1 else f'Link type {dlt}'), '', ''
    if len(packet) < offset + 2:
        return 'Truncated 802.11', '', ''
    fc = struct.unpack_from('<H', packet, offset)[0]
    if fc & 3:
        return 'Unknown 802.11 version', '', ''
    kind, sub = (fc >> 2) & 3, (fc >> 4) & 15
    names = {0: MGMT, 1: CTRL, 2: DATA}
    label = names.get(kind, {}).get(sub, f'802.11 type {kind}, subtype {sub}')
    return label, bool(fc & 0x4000), bool(fc & 0x0800)

def safe_cell(value):
    # Quoting CSV alone does not prevent spreadsheet formula execution.
    if isinstance(value, str) and (value.lstrip().startswith(('=', '+', '-', '@'))
                                  or value.startswith(('\t', '\r', '\n'))):
        return "'" + value
    return value

def csv_file(path, columns, rows):
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([safe_cell(row.get(c, '')) for c in columns])

def entries(value):
    return value.values() if isinstance(value, dict) else value if isinstance(value, list) else []

def packet_record(row):
    blob = row['packet'] or b''
    frame, protected, retry = decode_frame(blob, row['dlt'])
    return dict(zip(PACKET_COLS, [
        row['report_row'], local_time(row['ts_sec'], row['ts_usec']), frame,
        row['sourcemac'], row['destmac'], row['transmac'], channel(row['frequency']),
        round((row['frequency'] or 0)/1000, 3), row['signal'] or None,
        row['packet_len'], len(blob), protected, retry, bool(row['error']),
        row['datarate'] or None, row['phyname'], row['dlt'], row['tags'] or ''
    ]))

def build_report(source, destination):
    destination.mkdir(parents=True, exist_ok=True)
    # Snapshot avoids mixing rows from different moments during a live capture.
    with tempfile.TemporaryDirectory(prefix='.alfa-report-', dir=source.parent) as temp:
        snapshot = Path(temp)/'snapshot.kismet'
        with closing(sqlite3.connect(source.as_uri()+'?mode=ro', uri=True, timeout=10)) as live:
            with closing(sqlite3.connect(snapshot)) as target:
                live.backup(target, pages=1024, sleep=0.05)
        db = sqlite3.connect(snapshot)
        db.row_factory = sqlite3.Row
        try:
            return export_report(db, source, snapshot, destination)
        finally:
            db.close()

def export_report(db, source, snapshot, destination):
    counts = dict(db.execute('SELECT count(*) total, min(ts_sec) first, max(ts_sec) last, '
                             'coalesce(sum(packet_len),0) bytes FROM packets').fetchone())
    devices, networks = [], []
    skipped = 0
    for row in db.execute('SELECT * FROM devices ORDER BY last_time DESC'):
        try:
            dev = json.loads(row['device'])
        except (ValueError, TypeError):
            skipped += 1
            continue
        wifi = dev.get('dot11.device', {})
        devices.append({
            'name':dev.get('kismet.device.base.commonname') or dev.get('kismet.device.base.name',''),
            'mac':row['devmac'], 'role':dev.get('kismet.device.base.type',row['type']),
            'manufacturer':dev.get('kismet.device.base.manuf',''),
            'channel':dev.get('kismet.device.base.channel',''),
            'packets':dev.get('kismet.device.base.packets.total',0),
            'data_packets':dev.get('kismet.device.base.packets.data',0),
            'peak_dbm':row['strongest_signal'] or None,
            'first_seen':local_time(row['first_time']), 'last_seen':local_time(row['last_time'])})
        for ssid in entries(wifi.get('dot11.device.advertised_ssid_map', [])):
            networks.append({
                'ssid':ssid.get('dot11.advertisedssid.ssid') or '(hidden / unnamed)',
                'bssid':row['devmac'], 'security':ssid.get('dot11.advertisedssid.crypt_string','Unknown'),
                'channel':ssid.get('dot11.advertisedssid.channel',''),
                'mode':ssid.get('dot11.advertisedssid.ht_mode',''),
                'peak_dbm':row['strongest_signal'] or None,
                'observed_clients':wifi.get('dot11.device.num_associated_clients',0),
                'last_seen':local_time(ssid.get('dot11.advertisedssid.last_time',row['last_time']))})
    device_cols = ['name','mac','role','manufacturer','channel','packets','data_packets','peak_dbm','first_seen','last_seen']
    network_cols = ['ssid','bssid','security','channel','mode','peak_dbm','observed_clients','last_seen']
    csv_file(destination/'devices.csv', device_cols, devices)
    csv_file(destination/'networks.csv', network_cols, networks)
    frames = collections.Counter()
    chan_stats = {}
    displayed = collections.deque(maxlen=PACKET_LIMIT)
    errors = retries = protected_count = 0
    with (destination/'packets.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer = csv.writer(f)
        writer.writerow(PACKET_COLS)
        for row in db.execute('SELECT rowid report_row, * FROM packets ORDER BY ts_sec, ts_usec, rowid'):
            record = packet_record(row)
            writer.writerow([safe_cell(record[c]) for c in PACKET_COLS])
            frames[record['frame']] += 1
            errors += bool(record['error'])
            retries += record['retry'] is True
            protected_count += record['protected'] is True
            key = record['frequency_mhz']
            stat = chan_stats.setdefault(key, {'channel':record['channel'], 'frequency_mhz':key,
                                               'packets':0,'bytes':0,'errors':0,'signal_sum':0,'signal_n':0})
            stat['packets'] += 1
            stat['bytes'] += record['bytes'] or 0
            stat['errors'] += bool(record['error'])
            if record['signal_dbm'] is not None:
                stat['signal_sum'] += record['signal_dbm']; stat['signal_n'] += 1
            record['preview_hex'] = (row['packet'] or b'')[:96].hex(' ')
            displayed.append(record)
    channels = []
    for stat in chan_stats.values():
        stat['mean_dbm'] = round(stat.pop('signal_sum')/stat['signal_n'],1) if stat['signal_n'] else None
        stat.pop('signal_n')
        stat.pop('signal_sum',None)
        channels.append(stat)
    frame_rows = [{'frame':name,'packets':num,'share_percent':round(num*100/max(counts['total'],1),1)}
                  for name,num in frames.most_common()]
    csv_file(destination/'frames.csv', ['frame','packets','share_percent'], frame_rows)
    csv_file(destination/'channels.csv', ['channel','frequency_mhz','packets','bytes','errors','mean_dbm'],channels)
    # Address pairs describe observed traffic, not inferred connections or identities.
    pairs = [dict(r) for r in db.execute('SELECT sourcemac source, destmac destination, count(*) packets, '
             'sum(packet_len) bytes FROM packets GROUP BY sourcemac,destmac ORDER BY packets DESC')]
    csv_file(destination/'address-pairs.csv',['source','destination','packets','bytes'],pairs)
    converter = os.environ.get('ALFA_PCAP_CONVERTER') or shutil.which('kismetdb_to_pcap')
    if not converter:
        raise ValueError('kismetdb_to_pcap is missing; install Kismet or set ALFA_PCAP_CONVERTER')
    subprocess.run([converter,'--in',str(snapshot),'--out',str(destination/'capture.pcapng'),
                    '--skip-clean'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Some converter failures return success; require the promised export as well.
    with (destination/'capture.pcapng').open('rb') as capture:
        if capture.read(4) != b'\x0a\x0d\x0d\x0a':
            raise ValueError('Kismet converter did not produce a PCAPNG capture')
    payload = {
        'session':source.parent.name, 'source_file':source.name,
        'generated':dt.datetime.now().astimezone().isoformat(timespec='seconds'),
        'first':local_time(counts['first']), 'last':local_time(counts['last']),
        'total':counts['total'], 'bytes':counts['bytes'], 'errors':errors,
        'retries':retries,'protected':protected_count,'skipped_devices':skipped,
        'packet_limit':PACKET_LIMIT,
        'tables':{'networks':networks,'devices':devices,'packets':list(reversed(displayed)),
                  'channels':channels,'frames':frame_rows,'pairs':pairs},
        'columns':{'networks':network_cols,'devices':device_cols,'packets':PACKET_COLS,
                   'channels':['channel','frequency_mhz','packets','bytes','errors','mean_dbm'],
                   'frames':['frame','packets','share_percent'],
                   'pairs':['source','destination','packets','bytes']}}
    template = Path(__file__).with_name('report.html').read_text()
    encoded = json.dumps(payload, ensure_ascii=True).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    (destination/'index.html').write_text(template.replace('<!--REPORT_DATA-->',encoded),encoding='utf-8')
    return counts['total']

def choose_source(path):
    if path:
        root = Path(path).expanduser().resolve()
        candidates = [root] if root.is_file() else list(root.glob('*.kismet'))
    else:
        candidates = list(ROOT.glob('*/*.kismet'))
    if not candidates:
        raise ValueError('No Kismet captures found. Run alfa-sniff first.')
    return max(candidates,key=lambda p:p.stat().st_mtime).resolve()

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',nargs='?',help='Kismet file or session directory; default: latest session')
    parser.add_argument('--open',action='store_true',help='Open the generated report in your browser')
    args = parser.parse_args()
    try:
        source = choose_source(args.capture)
        # Immutable report generations keep a browser-open report and downloads consistent.
        report_parent = source.parent/'reports'
        report_parent.mkdir(exist_ok=True)
        destination = Path(tempfile.mkdtemp(prefix=dt.datetime.now().strftime('%Y%m%d-%H%M%S-'),dir=report_parent))
        try:
            count = build_report(source,destination)
        except BaseException:
            shutil.rmtree(destination)
            raise
        ROOT.mkdir(parents=True,exist_ok=True)
        link = ROOT/'Latest Report'
        if link.exists() and not link.is_symlink():
            raise ValueError(f'Will not replace existing folder: {link}')
        pending = ROOT/f'.report-link-{os.getpid()}'
        pending.symlink_to(destination,target_is_directory=True)
        pending.replace(link)
        print(f'Report ready: {destination / "index.html"}\n{count:,} packets exported to CSV and PCAPNG.')
        if args.open:
            subprocess.run(['/usr/bin/open',str(destination/'index.html')],check=True)
    except (OSError, ValueError, sqlite3.Error, subprocess.CalledProcessError) as exc:
        print(f'Report failed: {exc}',file=sys.stderr)
        if isinstance(exc,subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr.strip(),file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
