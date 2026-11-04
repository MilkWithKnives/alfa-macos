# alfa-macos

**Native ALFA Wi-Fi capture and packet injection on macOS, with deauthentication controls, handshake analysis, and offline packet reports.**

An ALFA AWUS036ACS can capture packets on Apple Silicon through Kismet's userspace USB driver. This project packages the byte-order fix that made our adapter work, installs the patched helper separately from Homebrew, and turns captures into searchable offline tables.

Packet injection and deauthentication use [wifit3](https://github.com/derv82/wifit3), installed with the optional injection setup. The separate `alfa-injection-check` command verifies transmission by sending five directed probe requests and checking for responses addressed to a fresh test MAC.

No kernel extension, Linux VM, or custom firmware. Kismet and wifit3 provide the drivers; this project supplies the fix, setup, reporting, and focused verification workflow.

| Capability | How it works |
| --- | --- |
| Native packet capture | `alfa-sniff` uses the patched Kismet USB helper. |
| Packet injection | wifit3 transmits through its userspace driver; `alfa-injection-check` verified matching over-air responses on the tested adapter. |
| Targeted deauthentication | wifit3's focused network view provides a **Deauthenticate Client** control. This is separate from the probe-check command. |
| Handshake analysis | Offline reports correlate captured EAPOL messages and show M1–M4 coverage. |
| PMKID / HC22000 inspection | Import `.hc22000` exports into searchable metadata tables. A PMKID record is distinct from a complete four-way handshake. |

**[Full command guide: activation, monitoring, injection, deauthentication, and reports](docs/commands.md)**

## Tested hardware

| Component | Verified configuration |
| --- | --- |
| Computer | MacBook Air, Apple M4 |
| OS | macOS 27.2, arm64 |
| Adapter | ALFA AWUS036ACS, RTL8811AU |
| USB ID | `0bda:0811` |
| Capture | Patched Kismet userspace `rtw8821a` driver |
| Injection check | wifit3 0.7.0 vendor-derived `rtl8821au_dkms` userspace driver, channel 1 |

The **ACS is not the ACM**. Other adapters, Intel Macs, other macOS versions, and 5 GHz injection have not been validated. The probe-check command currently accepts channels 1–11 only. Successful USB submission is not treated as proof of transmission.

## Install

Install [Homebrew](https://brew.sh) and Apple's command-line tools (`xcode-select --install`) first. Python 3.10 or newer is required.

```sh
git clone https://github.com/MilkWithKnives/alfa-macos.git
cd alfa-macos
./install.sh --with-capture
export PATH="$HOME/.local/bin:$PATH"
alfa-sniff --check
```

`install.sh --with-capture` handles the complete capture/report setup. To include injection tooling too, use `./install.sh --with-injection` instead. Neither starts a capture nor transmits packets.

The installer puts commands under `~/.local/bin`, backs up commands it replaces, and adds Desktop shortcuts when a Desktop directory exists. Use `--no-desktop` to skip the shortcuts. With no flags, it installs only the commands, so dependencies can be set up separately. Add the PATH line to your shell configuration to keep the commands available in new terminals.

`alfa-setup` installs Homebrew dependencies, fetches a pinned Kismet revision, applies the patch, builds the capture helper, and runs its C regression test. It leaves Homebrew's helper in place; capture sessions explicitly select the private helper. Build logs are under `~/.local/opt/kismet-alfa/logs`.

## Capture and read packets

```sh
alfa-sniff                 # channel hopping; Ctrl-C stops and generates a report
alfa-sniff --channel 1     # fixed channel
alfa-report --open        # regenerate/open the latest capture's report
alfa-report /path/to/session.kismet --open
```

Kismet's live UI is at `http://localhost:2501`. Configure its login on first use. Its HTTP listen address follows your Kismet configuration.

Captures live in `~/Captures/ALFA`. **Desktop → ALFA Captures → Latest Report → index.html** opens the newest report. Each report contains:

| View / file | Contents |
| --- | --- |
| `index.html` | Searchable, sortable tables, pagination, packet details, channel/frame summaries |
| `packets.csv` | Metadata for every packet |
| `networks.csv`, `devices.csv` | Observed networks and devices |
| `channels.csv`, `frames.csv` | Traffic counts and signal summaries |
| `address-pairs.csv` | Observed source/destination pairs |
| `handshakes.csv` | Per-AP/client attempts, M1–M4 coverage, repeated steps, packet references |
| `eapol.csv` | Every detected EAPOL observation, including unclassified and flagged frames |
| `authentication.pcapng` | Detected EAPOL packet subset with original bytes and timestamps |
| `capture.pcapng` | Full packet export for Wireshark |

The HTML displays the newest 2,000 packets with 96-byte previews; CSV and PCAPNG include the full capture. Reports work offline with no external scripts, fonts, analytics, or uploads. The original database is opened read-only and snapshotted before export. Encrypted packet payloads remain encrypted.

The **Captured handshakes** section scans all saved packets for supported EAPOL frames, then groups compatible messages by AP/client, time, replay counters, and AP nonce. It distinguishes **Partial** from **All four observed**, provides M1–M4 progress and packet evidence, and excludes flagged errors from correlation. This is structural evidence; MICs are not verified and no passwords are recovered. See [handshake analysis and limits](docs/handshakes.md).

An embedded interpretation guide explains signal, retries, security labels, capture coverage, and Wireshark filters. Table headings include field hints. **Filtered rows** exports the currently matching browser rows; **All rows · CSV** exports the full table. Authentication previews hold the newest 5,000 EAPOL observations and 1,000 attempts; totals and CSVs cover all detected observations.

The report's **Command glossary** includes searchable setup, capture, reporting, injection, help, and advanced examples with explanations and copy buttons. Use the link at the top of the report to jump to it. Commands are copied for you to run in Terminal; the report does not execute them.

### Import HC22000 files

Use the report's **HC22000 files** picker to inspect local exports, or save them into a generated report:

```sh
alfa-report --hc22000 "$HOME/Captures/example.hc22000" --open
alfa-report --hc22000 "/path/to/first.hc22000" --hc22000 "/path/to/second.hc22000" --open
alfa-report "/path/to/export.hc22000" --open  # standalone, no Kismet capture needed
```

`--hc22000` attaches metadata to the latest capture when available; a positional `.hc22000` file creates a standalone metadata report. Both update **Latest Report**. Repeat the import arguments when regenerating; files are not automatically scanned or remembered for subsequent capture sessions.

PMKID, EAPOL, FT PMKID, and FT EAPOL records have their own searchable table and `hc22000.csv` metadata export. Malformed lines are counted with filename/line explanations; exact normalized duplicates are skipped with first-source attribution retained. Imports do not increase packet counts or establish four-way handshake completeness. Raw hash material is not embedded in the metadata report. Browser additions last until reload and can be exported as CSV; CLI imports are saved in the generated HTML.

Limits are 10 MiB per input file, 20 MiB per CLI import or browser selection, and 20,000 unique records. The browser picker needs Web Crypto support; use the CLI if unavailable. See [HC22000 import details](docs/hc22000.md).

## Verify injection on your access point

Stop Kismet first; only one program should own the USB adapter.

```sh
alfa-injection-setup
alfa-injection-check --ssid "Your-Lab" --bssid "02:00:00:00:00:01" --channel 1
```

Skip `alfa-injection-setup` if you already installed with `--with-injection`.

Replace the example SSID/BSSID/channel with your access point's values. Use only networks you own or have permission to test.

The check listens for the specified network before transmitting. It sends five unicast probe requests, one per second, and confirms transmission only when it receives a matching probe response addressed to the unique test MAC. This command tests probe injection; deauthentication is available separately through the wifit3 controls below. A lack of responses is **inconclusive**, since access points can ignore directed probes.

Results go to `~/Captures/ALFA/Injection checks/<timestamp>/`:

- `result.json`: counts and outcome.
- `rx-target.pcap`: received target advertisements and responses.
- `tx-submitted.pcap`: submitted frames; this file alone does not prove over-air transmission.

Our hardware run submitted five requests and received 14 matching response frames. Retries can make the response count exceed the request count.

## Deauthentication controls

After installing with `--with-injection` (or running `alfa-injection-setup`), stop Kismet and launch wifit3:

```sh
WIFIT3_RTL8821=dkms "${ALFA_RADIO_DIR:-$HOME/.local/opt/wifit3}/venv/bin/python" -m wifit3
```

Select the adapter if prompted, open your authorized test network from the scanner, and use the target client's **✕ — Deauthenticate Client** control in the focused view. Press `q` to quit. The pinned version exposes this operation through its UI, not a standalone `--deauth` CLI flag. See the [command guide](docs/commands.md) and the HTML report's command glossary for the controls and their meanings.

The control sends deauthentication frames through wifit3's injection driver. Protected Management Frames can prevent a client from accepting them; transmit submission or an ACK alone does not prove disconnection. Deauthentication through the wifit3 UI is confirmed working by the project maintainer on the tested ALFA/macOS setup. This is a maintainer-reported hardware result; a separate deauthentication capture/log has not been reviewed or published here. The recorded five-request hardware check above independently verifies probe injection. The offline HTML report displays evidence and copies commands; radio operations run in Kismet or wifit3.

## Why the patch matters

On the tested Kismet revision, macOS lacked the Linux little-endian compatibility macros used by `struct rtw_phy_cond`. PHY table branch markers were interpreted as register writes, corrupting initialization and producing repeated `failed to send h2c command` errors. The patch defines the missing macros in the compatibility layer.

With the patch, the real AGC table regression changed from six invalid register writes to zero. A capture run recorded 4,376 packets. See [the driver investigation](docs/driver-fix.md) for details and pinned revisions.

## Development and configuration

```sh
python3 -m unittest discover -s tests -v
python3 examples/make_demo.py   # synthetic capture/report; requires kismetdb_to_pcap
open build/demo/report/index.html
```

The demo uses invented networks and locally administered MAC addresses. Real captures, logs, and injection results are ignored by Git.

| Environment variable | Default / purpose |
| --- | --- |
| `ALFA_HOME` | `~/.local/share/alfa-macos`, installed scripts |
| `ALFA_BIN_DIR` | `~/.local/bin`, installer command destination |
| `ALFA_DATA_DIR` | `~/Captures/ALFA`, captures and reports |
| `ALFA_DRIVER_DIR` | `~/.local/opt/kismet-alfa`, patched helper and source |
| `ALFA_RADIO_DIR` | `~/.local/opt/wifit3`, injection environment and source |
| `ALFA_PYTHON` | Python executable override |
| `ALFA_PCAP_CONVERTER` | `kismetdb_to_pcap` executable override |

For an existing local Kismet checkout, `alfa-setup --skip-deps --source /path/to/kismet` builds from the same pinned commit without fetching it. Dependency versions outside the pinned Kismet/wifit3 revisions can change; the injection installer records its resolved Python packages locally.

See [contributing](CONTRIBUTING.md) for tests and hardware reports. Licensed GPL-2.0-or-later; see [upstream credits and licenses](THIRD_PARTY.md).
