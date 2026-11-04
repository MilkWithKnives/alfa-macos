# SPDX-License-Identifier: GPL-2.0-or-later
"""Passive EAPOL evidence extraction; no key recovery or MIC verification.

Layout/flags: hostap src/common/wpa_common.h. Correlation is deliberately
conservative: 30-second windows, direction, replay counters and AP nonce.
"""
import collections
import struct

WINDOW = 30
LLC = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e'
EVENT_COLS = ['packet_row', 'time', 'bssid', 'client', 'direction', 'message',
              'replay_counter', 'key_info', 'descriptor', 'channel', 'signal_dbm',
              'retry', 'assessment', 'attempt']
HANDSHAKE_COLS = ['attempt', 'ssid', 'bssid', 'client', 'status', 'messages',
                  'missing', 'first_seen', 'last_seen', 'frames', 'repeated',
                  'packet_rows', 'assessment']


def mac(value):
    return ':'.join(f'{byte:02x}' for byte in value)


def extract(packet, dlt):
    """Return EAPOL observations from unfragmented infrastructure data frames.

    Supports plain 802.11 and radiotap, QoS/HT-control, radiotap data padding.
    Four-address, A-MSDU, encrypted, fragmented, Ethernet and SAE auth frames
    are outside this decoder. Do not infer absence of authentication from None.
    """
    offset = flags = 0
    if dlt == 127:
        if len(packet) < 8 or packet[0] != 0:
            return None
        offset = struct.unpack_from('<H', packet, 2)[0]
        if not 8 <= offset <= len(packet):
            return None
        present = struct.unpack_from('<I', packet, 4)[0]
        pos, word = 8, present
        while word & 0x80000000:
            if pos + 4 > offset:
                return None
            word = struct.unpack_from('<I', packet, pos)[0]
            pos += 4
        if present & 1:  # TSFT precedes flags and has eight-byte alignment.
            pos = (pos + 7) & ~7
            pos += 8
        if present & 2:
            if pos >= offset:
                return None
            flags = packet[pos]
    elif dlt != 105:
        return None
    frame = packet[offset:]
    if flags & 0x10:  # FCS included; it is not part of the EAPOL payload.
        frame = frame[:-4] if len(frame) >= 4 else b''
    if len(frame) < 24:
        return None
    fc, = struct.unpack_from('<H', frame)
    if fc & 3 or (fc >> 2) & 3 != 2 or fc & (0x4000 | 0x0400):
        return None
    if struct.unpack_from('<H', frame, 22)[0] & 15:
        return None
    ds = (fc >> 8) & 3
    subtype = (fc >> 4) & 15
    if ds not in (1, 2) or subtype & 4:  # null-data variants
        return None
    size = 24
    if subtype & 8:
        if len(frame) < 26 or frame[24] & 0x80:  # no A-MSDU reassembly
            return None
        size += 2 + (4 if fc & 0x8000 else 0)
    if flags & 0x20:
        size = (size + 3) & ~3
    if frame[size:size+8] != LLC:
        return None
    ap, client = (frame[4:10], frame[10:16]) if ds == 1 else (frame[10:16], frame[4:10])
    event = dict(bssid=mac(ap), client=mac(client), direction='Client → AP' if ds == 1 else 'AP → client',
                 message='Other EAPOL', replay_counter='', key_info='', descriptor='',
                 assessment='', _nonce='', _counter=0, _version=0, _bad_fcs=bool(flags & 0x40))
    data = frame[size+8:]
    if len(data) < 4:
        event.update(message='Malformed EAPOL', assessment='Truncated EAPOL header')
        return event
    length = int.from_bytes(data[2:4], 'big')
    if len(data) < length + 4:
        event.update(message='Malformed EAPOL', assessment='Declared EAPOL length exceeds captured bytes')
        return event
    if data[0] not in (1, 2, 3):
        event.update(message='Malformed EAPOL', assessment='Unsupported EAPOL protocol version')
        return event
    if data[1] != 3:
        event['assessment'] = {0:'EAP authentication packet', 1:'EAPOL start', 2:'EAPOL logoff'}.get(data[1], 'Other EAPOL type')
        return event
    event['message'] = 'Unclassified key'
    body = data[4:4+length]
    if len(body) < 95 or body[0] not in (2, 254):
        event['assessment'] = 'Unsupported or truncated key descriptor'
        return event
    info = int.from_bytes(body[1:3], 'big')
    counter = int.from_bytes(body[5:13], 'big')
    nonce = body[13:45]
    event.update(key_info=f'0x{info:04x}', descriptor='RSN' if body[0] == 2 else 'WPA',
                 replay_counter=str(counter), _counter=counter, _nonce=nonce.hex(), _version=info & 7)
    key_length = int.from_bytes(body[93:95], 'big')
    if (info & 7) not in (1, 2, 3) or len(body) != 95 + key_length:
        event['assessment'] = 'Unsupported descriptor version, MIC layout, or key-data length'
        return event
    if not info & 8:
        event.update(message='Group key', assessment='Group-key exchange; not a pairwise four-way message')
        return event
    if info & (0x0400 | 0x0800 | 0x2000) or ap[0] & 1 or client[0] & 1:
        event['assessment'] = 'Request/error/SMK flags or multicast address; excluded from correlation'
        return event
    ack, mic, install, secure = (bool(info & bit) for bit in (128, 256, 64, 512))
    message = None
    if ds == 2 and ack and not mic and not install and not secure and any(nonce):
        message = 'M1'
    elif ds == 1 and mic and not ack and not install and not secure and key_length and any(nonce):
        message = 'M2'
    elif ds == 2 and ack and mic and install and any(nonce):
        message = 'M3'
    elif ds == 1 and mic and not ack and not install and key_length == 0 and (secure or not any(nonce)):
        message = 'M4'
    if mic and not any(body[77:93]):
        message = None
    event['message'] = message or 'Unclassified key'
    event['assessment'] = 'Message flags and direction observed; MIC not verified' if message else 'Unexpected flags, direction, nonce, or empty MIC'
    return event


class Tracker:
    """Group only compatible observations; repeated frames do not fill gaps."""
    def __init__(self):
        self.attempts = []
        self.recent = collections.defaultdict(lambda: collections.deque(maxlen=8))

    def accepts(self, attempt, event):
        if not 0 <= event['_stamp'] - attempt['start'] <= WINDOW:
            return False
        message, seen = event['message'], attempt['seen']
        counter, nonce = event['_counter'], event['_nonce']
        if message in seen:
            old = seen[message]
            return counter == old['_counter'] and nonce == old['_nonce']
        if message == 'M1':
            return False
        if message == 'M2':
            return 'M1' in seen and 'M3' not in seen and counter == seen['M1']['_counter']
        if message == 'M3':
            previous = seen.get('M1') or seen.get('M2')
            return bool(previous and counter > previous['_counter'] and
                        ('M1' not in seen or nonce == seen['M1']['_nonce']))
        if message == 'M4':
            return 'M3' in seen and counter == seen['M3']['_counter']
        return False

    def add(self, event):
        event['attempt'] = ''
        if event['message'] not in ('M1', 'M2', 'M3', 'M4'):
            return
        key = (event['bssid'], event['client'], event['descriptor'], event['_version'])
        attempt = next((a for a in reversed(self.recent[key]) if self.accepts(a, event)), None)
        if attempt is None:
            attempt = dict(id=len(self.attempts)+1, start=event['_stamp'], seen={}, events=[])
            self.attempts.append(attempt)
            self.recent[key].append(attempt)
        attempt['seen'].setdefault(event['message'], event)
        attempt['events'].append(event)
        event['attempt'] = attempt['id']

    def summaries(self, names):
        rows = []
        for attempt in self.attempts:
            events, seen = attempt['events'], attempt['seen']
            first, last = events[0], events[-1]
            messages = [m for m in ('M1','M2','M3','M4') if m in seen]
            missing = [m for m in ('M1','M2','M3','M4') if m not in seen]
            rows.append(dict(attempt=attempt['id'], ssid=names.get(first['bssid'], 'Unknown SSID'),
                             bssid=first['bssid'], client=first['client'],
                             status='All four observed' if not missing else 'Partial',
                             messages=' · '.join(messages), missing=', '.join(missing) or 'None',
                             first_seen=first['time'], last_seen=last['time'], frames=len(events),
                             repeated=len(events)-len(messages), packet_rows=', '.join(str(e['packet_row']) for e in events),
                             assessment='Time, replay counters and AP nonce agree; MICs not verified' if not missing else
                             'Incomplete observation; missing messages may have occurred outside capture coverage',
                             steps=messages))
        return rows


class Pcapng:
    """Streaming authentication subset with per-DLT interfaces and microsecond time."""
    def __init__(self, file):
        self.file, self.interfaces = file, {}
        self.block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))

    def block(self, kind, body):
        body += b'\0' * (-len(body) % 4)
        length = len(body) + 12
        self.file.write(struct.pack('<II', kind, length) + body + struct.pack('<I', length))

    def write(self, raw, dlt, seconds, micros, original_length):
        if dlt not in self.interfaces:
            self.interfaces[dlt] = len(self.interfaces)
            self.block(1, struct.pack('<HHI', dlt, 0, 262144))
        stamp = int(seconds)*1_000_000 + int(micros)
        self.block(6, struct.pack('<IIIII', self.interfaces[dlt], stamp >> 32, stamp & 0xffffffff,
                                  len(raw), max(len(raw), original_length or 0)) + raw)

    def finish(self):
        # libpcap readers require an interface even for an empty capture.
        if not self.interfaces:
            self.interfaces[105] = 0
            self.block(1, struct.pack('<HHI', 105, 0, 262144))
