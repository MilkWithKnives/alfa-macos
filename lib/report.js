/* SPDX-License-Identifier: GPL-2.0-or-later */
'use strict';
const DATA = JSON.parse(document.getElementById('report-data').textContent);
const $ = id => document.getElementById(id);
const num = n => Number(n || 0).toLocaleString();
const titles = DATA.has_capture ? {hc22000:'HC22000 imports', handshakes:'Handshakes', eapol:'EAPOL evidence', networks:'Networks', devices:'Devices', packets:'Packets', channels:'Channels', frames:'Frame types', pairs:'Address pairs'} : {hc22000:'HC22000 imports'};
const files = {hc22000:'hc22000.csv',handshakes:'handshakes.csv', eapol:'eapol.csv', networks:'networks.csv', devices:'devices.csv', packets:'packets.csv', channels:'channels.csv', frames:'frames.csv', pairs:'address-pairs.csv'};
const labels = {ssid:'Network / SSID', bssid:'BSSID', client:'Client MAC', security:'Security', channel:'Channel', mode:'Wi-Fi mode', peak_dbm:'Peak signal · dBm', observed_clients:'Observed clients', last_seen:'Last seen', first_seen:'First seen', name:'Name', mac:'MAC address', role:'Role', manufacturer:'Manufacturer', packets:'Packets', data_packets:'Data packets', packet_row:'DB row', time:'Time', frame:'Frame type', source:'Source', destination:'Destination', transmitter:'Transmitter', frequency_mhz:'Frequency · MHz', signal_dbm:'Signal · dBm', bytes:'Bytes', captured_bytes:'Captured bytes', protected:'Protected', retry:'Retry', error:'Error', rate_mbps:'Rate · Mbps', phy:'PHY', link_type:'Link type', tags:'Tags', errors:'Errors', mean_dbm:'Mean signal · dBm', share_percent:'Share · %', authentication:'Authentication', attempt:'Attempt', status:'Observation', messages:'Observed steps', missing:'Missing steps', frames:'Frames', repeated:'Repeated steps', packet_rows:'DB packet rows', assessment:'Interpretation', direction:'Direction', message:'Message', replay_counter:'Replay counter', key_info:'Key flags', descriptor:'Descriptor'};
const tips = {bssid:'Access point radio/interface address', client:'Observed station address; may be randomized', packet_row:'Original Kismet row, not a Wireshark frame number', packet_rows:'Original Kismet row references', status:'Observation coverage, not cryptographic validation', repeated:'Additional observations of an already seen step; not additional handshake steps', replay_counter:'64-bit replay value retained exactly as text', security:'Advertised security; not a security assessment', signal_dbm:'Received power at this adapter; closer to zero is stronger', peak_dbm:'Strongest saved signal observation', mean_dbm:'Arithmetic mean of recorded dBm observations', retry:'802.11 retry flag, not a packet-loss measurement', rate_mbps:'Recorded PHY rate, not application throughput', observed_clients:'Summary can lag packet data', protected:'Encrypted content; this report does not decrypt it'};
Object.assign(labels, {record_type:'Record type',message_pair:'Exported pair label',pair_flags:'Pair flags',eapol_bytes:'Embedded EAPOL bytes',source_file:'Source file',source_line:'Source line',record_id:'Record fingerprint'});
const state = {tab:!DATA.has_capture || DATA.tables.hc22000.length ? 'hc22000' : 'networks', page:0, sort:null, descending:false, attempt:null};
const PAGE = 75;
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function show(v) { return v === null || v === undefined || v === '' ? '—' : typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v); }
function setTab(tab, attempt = null) {
  Object.assign(state, {tab, page:0, sort:null, descending:false, attempt});
  $('search').value = ''; $('filter').value = 'all'; $('status-filter').value = 'all'; $('import-type-filter').value = 'all'; render();
}
function focusTable(tab, attempt = null) { setTab(tab, attempt); $('tabs').scrollIntoView({block:'start'}); $('search').focus({preventScroll:true}); }
function insight(title, body) { const card = el('article', undefined, 'insight'); card.append(el('h3', title), el('p', body)); $('insights').append(card); }
function steps(messages) {
  const row = el('div', undefined, 'steps');
  for (const m of ['M1','M2','M3','M4']) { const seen = messages.includes(m); const step = el('span', (seen ? '✓ ' : '○ ') + m, 'step' + (seen ? ' seen' : '')); step.title = seen ? 'Observed' : 'Not observed in this attempt'; row.append(step); }
  return row;
}
$('session').textContent = DATA.session + ' · ' + DATA.source_file;
$('period').textContent = DATA.first ? DATA.first + ' → ' + DATA.last : 'No packets in this capture';
if (!DATA.has_capture) {
  for (const id of ['cards','capture-overview','packet-handshakes','insights','capture-download','packets-download','packet-footer']) $(id).hidden = true;
  $('period').textContent = 'Standalone metadata report · no packet capture attached';
}
for (const [value,label] of [[DATA.total,'Captured packets'],[DATA.tables.networks.length,'Advertised networks'],[DATA.tables.devices.length,'Observed devices'],[DATA.tables.channels.length,'Captured frequencies'],[DATA.errors,'Packets flagged as errors']]) {
  const card = el('div', undefined, 'card'); card.append(el('b', num(value)), el('span', label)); $('cards').append(card);
}
for (const row of DATA.tables.frames.slice(0,5)) {
  const line = el('div', undefined, 'barrow'), track = el('div', undefined, 'track'), fill = el('div', undefined, 'fill');
  fill.style.width = Math.max(0, Math.min(100, row.share_percent)) + '%'; track.append(fill); line.append(el('span', row.frame), track, el('span', row.share_percent + '%')); $('bars').append(line);
}
$('summary').textContent = num(DATA.total) + ' frames · ' + (DATA.bytes/1048576).toFixed(2) + ' MiB recorded · ' + num(DATA.retries) + ' retries · ' + num(DATA.protected) + ' protected frames.';
$('generated').textContent = 'Generated ' + DATA.generated + (DATA.skipped_devices ? ' · ' + DATA.skipped_devices + ' malformed device records omitted.' : '');
const auth = DATA.authentication;
for (const [value,label] of [[auth.total,'Detected EAPOL frames'],[auth.four_observed,'Attempts with all four observed'],[auth.attempts-auth.four_observed,'Partial attempts']]) {
  const card = el('div'); card.append(el('b', num(value)), el('span', label)); $('auth-metrics').append(card);
}
$('auth-summary').textContent = auth.total ? 'Scanned every saved packet. Message evidence, repeated steps, and unclassified EAPOL remain available for inspection.' : 'No EAPOL frames were detected in supported packet layouts. Existing clients may already be connected; missing coverage or unsupported framing can also explain this.';
const pct = value => DATA.total ? (value*100/DATA.total).toFixed(1) + '%' : '0.0%';
insight('Reception evidence', pct(DATA.errors) + ' of saved packets are flagged as errors. ' + (DATA.errors ? 'Inspect their signal and frame details; errors alone do not establish a cause.' : 'No error flags were recorded. This does not measure packets that were never captured.'));
insight('Retransmissions', pct(DATA.retries) + ' of saved packets carry a retry flag. This is an observed share, not a packet-loss rate or proof of interference.');
insight('Capture coverage', num(DATA.tables.channels.length) + ' frequencies appear in saved packets. Counts depend on adapter dwell time and reception; they do not measure channel utilization.');
const unclassified = (auth.counts['Unclassified key'] || 0) + (auth.counts['Malformed EAPOL'] || 0) + (auth.counts['Flagged EAPOL'] || 0);
if (unclassified) insight('Authentication needs review', num(unclassified) + ' EAPOL observations were malformed, unsupported, or flagged. They are exported but cannot complete a grouped handshake.');
for (const [key,title] of Object.entries(titles)) { const button = el('button', title); button.dataset.tab = key; button.addEventListener('click', () => setTab(key)); $('tabs').append(button); }
$('show-handshakes').addEventListener('click', () => focusTable('handshakes'));
$('show-eapol').addEventListener('click', () => focusTable('eapol'));
function inspect(row, tab) {
  $('details-title').textContent = tab === 'hc22000' ? 'Imported ' + row.record_type + ' metadata' : tab === 'handshakes' ? 'Handshake attempt ' + row.attempt : tab === 'eapol' ? 'EAPOL evidence · row ' + row.packet_row : 'Packet · row ' + row.packet_row;
  $('details-extra').replaceChildren(); $('fields').replaceChildren();
  for (const key of DATA.columns[tab]) $('fields').append(el('dt', labels[key] || key), el('dd', show(row[key])));
  $('hex').hidden = $('hex-label').hidden = tab !== 'packets'; $('hex').textContent = row.preview_hex || 'No captured bytes.';
  $('details-download').href = tab === 'packets' ? 'capture.pcapng' : 'authentication.pcapng';
  $('details-download').hidden = tab === 'hc22000';
  if (tab === 'handshakes') {
    const filter = 'eapol && wlan.addr == ' + row.bssid + ' && wlan.addr == ' + row.client;
    const input = el('input', undefined, 'filter-code'); input.readOnly = true; input.value = filter; input.setAttribute('aria-label', 'Wireshark display filter');
    const copy = el('button', 'Copy Wireshark filter');
    copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(filter); copy.textContent = 'Copied'; } catch { input.focus(); input.select(); copy.textContent = 'Selected — press ⌘C / Ctrl-C'; } });
    const frames = el('button', 'View this attempt’s EAPOL frames'); frames.addEventListener('click', () => { $('details').close(); focusTable('eapol', row.attempt); });
    const actions = el('div', undefined, 'actions'); actions.append(copy, frames);
    $('details-extra').append(steps(row.steps), el('p', 'Observed structure only. Message integrity codes are not verified.', 'note'), input, actions);
  }
  $('details').showModal();
}
function matchingRows() {
  const columns = DATA.columns[state.tab], query = $('search').value.toLocaleLowerCase().trim();
  let rows = DATA.tables[state.tab];
  if (state.tab === 'eapol' && state.attempt !== null) rows = rows.filter(r => r.attempt === state.attempt);
  if (query) rows = rows.filter(r => columns.some(k => show(r[k]).toLocaleLowerCase().includes(query)));
  if (state.tab === 'packets' && $('filter').value !== 'all') { const key = $('filter').value === 'errors' ? 'error' : $('filter').value; rows = rows.filter(r => key === 'authentication' ? Boolean(r[key]) : r[key] === true); }
  if (state.tab === 'handshakes' && $('status-filter').value !== 'all') rows = rows.filter(r => r.status === $('status-filter').value);
  if (state.tab === 'hc22000' && $('import-type-filter').value !== 'all') rows = rows.filter(r => r.record_type.includes($('import-type-filter').value));
  if (state.sort) rows = [...rows].sort((a,b) => {
    const x = a[state.sort], y = b[state.sort];
    if (x === y) return 0; if (x == null || x === '') return 1; if (y == null || y === '') return -1;
    const result = typeof x === 'number' && typeof y === 'number' ? x-y : String(x).localeCompare(String(y), undefined, {numeric:true});
    return result*(state.descending ? -1 : 1);
  });
  return rows;
}
function render() {
  const columns = DATA.columns[state.tab], rows = matchingRows(), inspectable = ['packets','handshakes','eapol','hc22000'].includes(state.tab);
  for (const b of $('tabs').children) b.setAttribute('aria-pressed', String(b.dataset.tab === state.tab));
  $('filter-label').hidden = state.tab !== 'packets'; $('status-label').hidden = state.tab !== 'handshakes'; $('handshake-context').hidden = state.tab !== 'handshakes';
  $('import-type-label').hidden = state.tab !== 'hc22000';
  $('scope').hidden = state.tab !== 'eapol' || state.attempt === null; $('scope-text').textContent = 'Showing evidence for attempt ' + state.attempt;
  $('csv').href = files[state.tab]; $('filtered-csv').disabled = rows.length === 0;
  state.page = Math.min(state.page, Math.max(0, Math.ceil(rows.length/PAGE)-1)); const head = el('tr');
  if (inspectable) head.append(el('th', 'Inspect'));
  for (const key of columns) {
    const th = el('th'), button = el('button', (labels[key] || key) + (state.sort === key ? (state.descending ? ' ↓' : ' ↑') : ''));
    th.setAttribute('aria-sort', state.sort === key ? (state.descending ? 'descending' : 'ascending') : 'none'); button.title = tips[key] || 'Sort by ' + (labels[key] || key);
    button.addEventListener('click', () => { state.descending = state.sort === key ? !state.descending : false; state.sort = key; state.page = 0; render(); }); th.append(button); head.append(th);
  }
  $('table').querySelector('thead').replaceChildren(head); const body = $('table').querySelector('tbody'); body.replaceChildren();
  for (const row of rows.slice(state.page*PAGE, (state.page+1)*PAGE)) {
    const tr = el('tr');
    if (inspectable) { const td = el('td'), button = el('button', 'View'); button.setAttribute('aria-label', 'Inspect ' + (state.tab === 'hc22000' ? row.record_type+' from '+row.source_file+' line '+row.source_line : row.attempt && state.tab === 'handshakes' ? 'attempt ' + row.attempt : 'packet row ' + row.packet_row)); button.addEventListener('click', () => inspect(row, state.tab)); td.append(button); tr.append(td); }
    for (const key of columns) {
      const td = el('td', show(row[key]), ['mac','bssid','client','source','destination','transmitter'].includes(key) ? 'mono' : ''); td.title = show(row[key]);
      if (key === 'status') { td.replaceChildren(el('span', row[key], 'badge ' + (row[key] === 'All four observed' ? 'good' : 'partial'))); }
      if (key === 'messages') td.replaceChildren(steps(row.steps));
      if (key === 'error' && row[key]) td.classList.add('error'); tr.append(td);
    }
    body.append(tr);
  }
  if (!rows.length) {
    const noEvidence = !DATA.tables[state.tab].length && ['handshakes','eapol'].includes(state.tab);
    const td = el('td', noEvidence ? 'No supported evidence in this view. Existing clients may already be connected, or relevant frames may be outside capture/decoder coverage. See the interpretation guide below.' : state.attempt !== null ? 'No rows for this attempt in the loaded EAPOL preview. Clear the filter or use the full eapol.csv export.' : 'No matching rows. Try another search or filter.', 'empty-cell');
    td.colSpan = columns.length + (inspectable ? 1 : 0); const tr = el('tr'); tr.append(td); body.append(tr);
  }
  $('count').textContent = rows.length ? num(state.page*PAGE+1) + '–' + num(Math.min(rows.length,(state.page+1)*PAGE)) + ' of ' + num(rows.length) + ' matching rows' : '0 matching rows';
  $('previous').disabled = state.page === 0; $('next').disabled = (state.page+1)*PAGE >= rows.length;
  const notes = {packets:'Showing the newest ' + num(DATA.tables.packets.length) + ' of ' + num(DATA.total) + ' packet rows. Search covers the displayed subset; packets.csv contains every row.', handshakes:'Showing the newest ' + num(DATA.tables.handshakes.length) + ' of ' + num(auth.attempts) + ' grouped attempts. All saved packets were scanned. Repeated steps do not establish a complete exchange.', eapol:'Showing the newest ' + num(DATA.tables.eapol.length) + ' of ' + num(auth.total) + ' detected EAPOL frames. Replay counters are preserved as exact values; unclassified observations remain available.', networks:'One row per advertised SSID and BSSID. Security is advertised information, not a safety assessment.', pairs:'Observed source → destination traffic, including broadcast. These are not necessarily established connections.', channels:'Counts reflect capture dwell time and reception; this table does not measure utilization.'};
  notes.hc22000 = 'Imported metadata only. Exported pair labels are not proof of a full handshake or successful authentication. Exact duplicates are skipped; first-source attribution is retained. No raw hash material is included in CSV exports.';
  $('table-note').textContent = notes[state.tab] || 'Click a column heading to sort. Search filters the selected table. Hover a heading for field guidance.';
}
function csvCell(value) {
  let text = value == null ? '' : String(value);
  if (typeof value === 'string' && (/^[\s]*[=+@-]/.test(text) || /^[\t\r\n]/.test(text))) text = "'" + text;
  return '"' + text.replaceAll('"', '""') + '"';
}
function downloadCSV(columns, rows, filename) {
  const lines = [columns.map(csvCell).join(','), ...rows.map(row => columns.map(c => csvCell(row[c])).join(','))];
  const url = URL.createObjectURL(new Blob(['\ufeff' + lines.join('\r\n') + '\r\n'], {type:'text/csv;charset=utf-8'}));
  const link = el('a'); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('filtered-csv').addEventListener('click', () => downloadCSV(DATA.columns[state.tab],matchingRows(),state.tab+'-filtered.csv'));
$('csv').addEventListener('click', event => { if (state.tab === 'hc22000') { event.preventDefault(); downloadCSV(DATA.columns.hc22000,DATA.tables.hc22000,'hc22000.csv'); } });
$('clear-scope').addEventListener('click', () => setTab('eapol'));
for (const id of ['search','filter','status-filter','import-type-filter']) $(id).addEventListener(id === 'search' ? 'input' : 'change', () => { state.page = 0; render(); });
$('previous').addEventListener('click', () => { state.page--; render(); }); $('next').addEventListener('click', () => { state.page++; render(); });
$('close').addEventListener('click', () => $('details').close());
$('expand-guide').addEventListener('click', () => { const sections = [...document.querySelectorAll('#reading-guide details')], expand = sections.some(d => !d.open); for (const section of sections) section.open = expand; $('expand-guide').textContent = expand ? 'Collapse all explanations' : 'Expand all explanations'; });
const commandEntries = [];
for (const category of new Set(DATA.commands.map(command => command.category))) {
  const option = el('option', category); option.value = category; $('command-category').append(option);
}
for (const command of DATA.commands) {
  const entry = el('details', undefined, 'command-entry'), heading = el('summary');
  heading.append(el('span', command.title), el('span', command.category, 'badge'));
  entry.append(heading, el('p', command.description));
  if (command.kind === 'shortcut' || command.kind === 'action') {
    entry.append(el(command.kind === 'shortcut' ? 'kbd' : 'p', command.command, 'command-shortcut'));
  } else {
    const code = el('textarea', undefined, 'command-code'); code.readOnly = true; code.spellcheck = false;
    code.rows = Math.max(2, command.command.split('\n').length + 1); code.value = command.command;
    code.setAttribute('aria-label', command.title + ': shell command');
    const copy = el('button', 'Copy command'); copy.setAttribute('aria-label', 'Copy: ' + command.title);
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(command.command);
        $('command-copy-status').textContent = 'Copied: ' + command.title + '. Paste into Terminal when ready.';
      } catch {
        code.focus(); code.select(); code.setSelectionRange(0, code.value.length);
        $('command-copy-status').textContent = 'Command selected. Press ⌘C (Mac) or Ctrl-C to copy, then paste into Terminal.';
      }
    });
    const actions = el('div', undefined, 'actions'); actions.append(copy); entry.append(code, actions);
  }
  if (command.steps) {
    const stepsList = el('ol');
    for (const step of command.steps) stepsList.append(el('li', step));
    entry.append(stepsList);
  }
  $('command-list').append(entry);
  commandEntries.push({entry, command, search:[command.title, command.command, command.description, command.category, ...(command.steps || [])].join(' ').toLocaleLowerCase()});
  entry.addEventListener('toggle', updateCommandToggle);
}
function updateCommandToggle() {
  const visible = commandEntries.filter(item => !item.entry.hidden);
  $('expand-commands').disabled = visible.length === 0;
  $('expand-commands').textContent = visible.length && visible.every(item => item.entry.open) ? 'Collapse visible commands' : 'Expand visible commands';
}
function filterCommands() {
  const query = $('command-search').value.toLocaleLowerCase().trim(), category = $('command-category').value;
  let count = 0;
  for (const item of commandEntries) {
    const match = (category === 'all' || category === item.command.category) && query.split(/\s+/).every(word => item.search.includes(word));
    item.entry.hidden = !match;
    if (match) { count++; if (query) item.entry.open = true; }
  }
  $('command-count').textContent = count + ' of ' + commandEntries.length + ' command entries';
  $('command-empty').hidden = count !== 0; updateCommandToggle();
}
$('command-search').addEventListener('input', filterCommands);
$('command-category').addEventListener('change', filterCommands);
$('reset-commands').addEventListener('click', () => {
  $('command-search').value = ''; $('command-category').value = 'all'; $('command-copy-status').textContent = '';
  for (const item of commandEntries) item.entry.open = false;
  filterCommands(); $('command-search').focus();
});
$('expand-commands').addEventListener('click', () => {
  const visible = commandEntries.filter(item => !item.entry.hidden), expand = visible.some(item => !item.entry.open);
  for (const item of visible) item.entry.open = expand;
  updateCommandToggle();
});
filterCommands();
const originalImports = {records:[...DATA.tables.hc22000], info:JSON.parse(JSON.stringify(DATA.imports))};
let browserImports = false;
function updateImports() {
  const rows = DATA.tables.hc22000, pmkid = rows.filter(row => row.record_type.includes('PMKID')).length;
  $('hash-summary').textContent = rows.length+' unique records · '+pmkid+' PMKID · '+(rows.length-pmkid)+' EAPOL · '+DATA.imports.duplicates+' duplicates skipped · '+DATA.imports.invalid+' invalid lines.';
  $('hash-issue-list').replaceChildren();
  for (const issue of DATA.imports.issues) $('hash-issue-list').append(el('li',issue.source_file+':'+issue.source_line+' — '+issue.reason));
  $('hash-issues').hidden = DATA.imports.invalid === 0;
  if (DATA.imports.invalid > DATA.imports.issues.length) $('hash-issue-list').append(el('li','Showing the first '+DATA.imports.issues.length+' issues.'));
  $('clear-browser-imports').disabled = !browserImports;
}
$('show-imports').addEventListener('click', () => focusTable('hc22000'));
$('hash-files').addEventListener('change', async () => {
  const selected = [...$('hash-files').files];
  if (!selected.length) return;
  $('hash-files').disabled = true; $('clear-browser-imports').disabled = true;
  $('hash-import-status').textContent = 'Reading selected files locally…';
  try {
    if (selected.some(file => !file.name.toLowerCase().endsWith('.hc22000'))) throw new Error('Choose .hc22000 files.');
    if (selected.some(file => file.size > 10*1024*1024) || selected.reduce((total,file)=>total+file.size,0)>20*1024*1024) throw new Error('Import limit: 10 MiB per file and 20 MiB per selection.');
    if (!globalThis.crypto?.subtle) throw new Error('Local import requires a browser with Web Crypto support. Use alfa-report --hc22000 FILE instead.');
    const merged = new Map(DATA.tables.hc22000.map(row => [row.record_id,row]));
    const info = JSON.parse(JSON.stringify(DATA.imports));
    for (const file of selected) {
      const parsed = await HC22000.parseText(await file.text(),file.name);
      info.files.push(file.name); info.invalid += parsed.invalid;
      info.issues.push(...parsed.issues.slice(0,Math.max(0,100-info.issues.length)));
      for (const row of parsed.records) { if (merged.has(row.record_id)) info.duplicates++; else merged.set(row.record_id,row); }
      if (merged.size > 20000) throw new Error('Combined import exceeds 20,000 unique records.');
    }
    DATA.tables.hc22000 = [...merged.values()]; DATA.imports = info; browserImports = true;
    $('hash-import-status').textContent = 'Import complete. Browser additions last until reload; export CSV metadata or use the CLI to save a generated report.';
    focusTable('hc22000');
  } catch (error) {
    $('hash-import-status').textContent = 'Import failed: '+error.message+' Existing records were kept.';
  } finally {
    $('hash-files').disabled = false; $('hash-files').value = ''; updateImports();
  }
});
$('clear-browser-imports').addEventListener('click', () => {
  DATA.tables.hc22000 = [...originalImports.records]; DATA.imports = JSON.parse(JSON.stringify(originalImports.info)); browserImports = false;
  $('hash-import-status').textContent = 'Browser additions cleared. Records saved in this generated report are retained.';
  updateImports(); setTab('hc22000');
});
updateImports();
render();
