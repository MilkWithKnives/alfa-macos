# SPDX-License-Identifier: GPL-2.0-or-later
"""Read HC22000 metadata without recovering keys or asserting packet completeness."""
import hashlib
import re
from pathlib import Path

MAX_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 20000
COLUMNS = ['record_type', 'ssid', 'bssid', 'client', 'message_pair', 'pair_flags',
           'eapol_bytes', 'source_file', 'source_line', 'assessment', 'record_id']
TYPES = {'01':'PMKID', '02':'EAPOL', '03':'FT PMKID', '04':'FT EAPOL'}
PAIRS = {0:'M1+M2', 1:'M1+M4', 2:'M2+M3', 3:'M2+M3', 4:'M3+M4', 5:'M3+M4'}


def hex_field(value, minimum, maximum):
    return minimum <= len(value) <= maximum and len(value) % 2 == 0 and re.fullmatch('[0-9a-fA-F]*', value) is not None


def parse_line(line, source_file, source_line):
    parts = line.strip().split('*')
    if len(parts) not in (9, 12) or parts[0] != 'WPA' or parts[1] not in TYPES:
        raise ValueError('Expected a WPA*01/02 record or a WPA*03/04 FT record')
    kind = parts[1]
    if len(parts) != (12 if kind in ('03','04') else 9):
        raise ValueError('Incorrect number of fields for this record type')
    if not (hex_field(parts[2],32,32) and hex_field(parts[3],12,12) and hex_field(parts[4],12,12)):
        raise ValueError('Invalid digest/MIC or AP/client address length or hex encoding')
    if not hex_field(parts[5],0,64):
        raise ValueError('SSID must be 0–32 bytes encoded as hex')
    if parts[8] and not hex_field(parts[8],2,2):
        raise ValueError('Message-pair flags must be one hex byte')
    if kind in ('03','04') and not (hex_field(parts[9],4,4) and hex_field(parts[10],2,96) and hex_field(parts[11],2,96)):
        raise ValueError('Invalid FT identifiers')
    eapol = b''
    pmkid = kind in ('01','03')
    if pmkid:
        if parts[6] or parts[7]:
            raise ValueError('PMKID records must not contain nonce/EAPOL fields')
    else:
        if not (hex_field(parts[6],64,64) and hex_field(parts[7],198,8192) and hex_field(parts[8],2,2)):
            raise ValueError('Invalid nonce, EAPOL length/hex encoding, or message-pair flags')
        eapol = bytes.fromhex(parts[7])
        if eapol[0] not in (1,2,3) or eapol[1] != 3 or int.from_bytes(eapol[2:4],'big') + 4 != len(eapol):
            raise ValueError('Embedded EAPOL-Key header or declared length is inconsistent')
    normalized = ['WPA'] + [part.lower() for part in parts[1:]]
    normalized[8] = normalized[8] or '00'
    flags = int(normalized[8],16)
    ssid = bytes.fromhex(parts[5]).decode('utf-8',errors='replace')
    mac = lambda value: ':'.join(value[i:i+2].lower() for i in range(0,12,2))
    return dict(record_type=TYPES[kind], ssid=ssid or '(empty SSID)', bssid=mac(parts[3]), client=mac(parts[4]),
                message_pair='Not applicable' if pmkid else PAIRS.get(flags & 7, 'Unknown pair') + ' (export label)',
                pair_flags='0x'+normalized[8], eapol_bytes=len(eapol), source_file=source_file, source_line=source_line,
                assessment='Imported metadata; no cryptographic verification or full four-way capture claim',
                record_id=hashlib.sha256('*'.join(normalized).encode('ascii')).hexdigest())


def parse_text(text, filename):
    records, issues, invalid = [], [], 0
    for number, line in enumerate(text.lstrip('\ufeff').splitlines(),1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        try:
            records.append(parse_line(line, filename, number))
        except ValueError as exc:
            invalid += 1
            if len(issues) < 100:
                issues.append(dict(source_file=filename, source_line=number, reason=str(exc)))
        if len(records) > MAX_RECORDS:
            raise ValueError(f'{filename}: exceeds the {MAX_RECORDS:,}-record import limit')
    return dict(records=records, issues=issues, invalid=invalid)


def load_files(paths):
    records, issues, files, invalid, duplicates = {}, [], [], 0, 0
    total_bytes = 0
    for path in dict.fromkeys(Path(p).expanduser().resolve() for p in paths):
        if path.suffix.lower() != '.hc22000':
            raise ValueError('Import files must have the .hc22000 extension')
        # Bound the actual read, not just stat(), in case a file changes during import.
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        total_bytes += len(raw)
        if len(raw) > MAX_BYTES or total_bytes > 2*MAX_BYTES:
            raise ValueError('Import limit: 10 MiB per file and 20 MiB total')
        parsed = parse_text(raw.decode('utf-8-sig',errors='replace'),path.name)
        files.append(path.name)
        invalid += parsed['invalid']
        issues.extend(parsed['issues'][:max(0,100-len(issues))])
        for record in parsed['records']:
            if record['record_id'] in records:
                duplicates += 1
            else:
                records[record['record_id']] = record
        if len(records) > MAX_RECORDS:
            raise ValueError(f'Combined import exceeds {MAX_RECORDS:,} unique records')
    return dict(records=list(records.values()), issues=issues, invalid=invalid, duplicates=duplicates, files=files)
