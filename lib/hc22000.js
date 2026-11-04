/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Metadata-only counterpart of hc22000.py; never sends or cracks imported data. */
(function(root) {
  'use strict';
  const types = {'01':'PMKID', '02':'EAPOL', '03':'FT PMKID', '04':'FT EAPOL'};
  const pairs = {0:'M1+M2', 1:'M1+M4', 2:'M2+M3', 3:'M2+M3', 4:'M3+M4', 5:'M3+M4'};
  const hex = (value,min,max) => value.length >= min && value.length <= max && value.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(value);
  const bytes = value => Uint8Array.from(value.match(/../g) || [], pair => parseInt(pair,16));
  const fail = message => { throw new Error(message); };
  async function parseLine(line, filename, number) {
    const parts = line.trim().split('*');
    if (![9,12].includes(parts.length) || parts[0] !== 'WPA' || !Object.hasOwn(types,parts[1])) fail('Expected a WPA*01/02 record or a WPA*03/04 FT record');
    const kind = parts[1], ft = ['03','04'].includes(kind), pmkid = ['01','03'].includes(kind);
    if (parts.length !== (ft ? 12 : 9)) fail('Incorrect number of fields for this record type');
    if (!hex(parts[2],32,32) || !hex(parts[3],12,12) || !hex(parts[4],12,12)) fail('Invalid digest/MIC or AP/client address length or hex encoding');
    if (!hex(parts[5],0,64)) fail('SSID must be 0–32 bytes encoded as hex');
    if (parts[8] && !hex(parts[8],2,2)) fail('Message-pair flags must be one hex byte');
    if (ft && (!hex(parts[9],4,4) || !hex(parts[10],2,96) || !hex(parts[11],2,96))) fail('Invalid FT identifiers');
    let eapol = new Uint8Array();
    if (pmkid) {
      if (parts[6] || parts[7]) fail('PMKID records must not contain nonce/EAPOL fields');
    } else {
      if (!hex(parts[6],64,64) || !hex(parts[7],198,8192) || !hex(parts[8],2,2)) fail('Invalid nonce, EAPOL length/hex encoding, or message-pair flags');
      eapol = bytes(parts[7]);
      if (![1,2,3].includes(eapol[0]) || eapol[1] !== 3 || (eapol[2]*256+eapol[3]+4) !== eapol.length) fail('Embedded EAPOL-Key header or declared length is inconsistent');
    }
    const normalized = ['WPA',...parts.slice(1).map(part => part.toLowerCase())]; normalized[8] ||= '00';
    if (!root.crypto?.subtle) fail('Local import requires a browser with Web Crypto support');
    const digest = await root.crypto.subtle.digest('SHA-256',new TextEncoder().encode(normalized.join('*')));
    const recordID = Array.from(new Uint8Array(digest),v => v.toString(16).padStart(2,'0')).join('');
    const flags = parseInt(normalized[8],16), mac = value => value.match(/../g).join(':').toLowerCase();
    const ssid = new TextDecoder('utf-8',{ignoreBOM:true}).decode(bytes(parts[5]));
    return {record_type:types[kind], ssid:ssid || '(empty SSID)', bssid:mac(parts[3]), client:mac(parts[4]),
      message_pair:pmkid ? 'Not applicable' : (pairs[flags & 7] || 'Unknown pair')+' (export label)',
      pair_flags:'0x'+normalized[8], eapol_bytes:eapol.length, source_file:filename, source_line:number,
      assessment:'Imported metadata; no cryptographic verification or full four-way capture claim', record_id:recordID};
  }
  async function parseText(text, filename) {
    const records = [], issues = []; let invalid = 0;
    const lines = text.replace(/^\uFEFF/,'').split(/\r\n|\n|\r/);
    for (let i=0; i<lines.length; i++) {
      if (!lines[i].trim() || lines[i].trimStart().startsWith('#')) continue;
      try { records.push(await parseLine(lines[i],filename,i+1)); }
      catch (error) { invalid++; if (issues.length < 100) issues.push({source_file:filename,source_line:i+1,reason:error.message}); }
      if (records.length > 20000) fail(filename+': exceeds the 20,000-record import limit');
    }
    return {records,issues,invalid};
  }
  root.HC22000 = {parseLine,parseText};
})(globalThis);
