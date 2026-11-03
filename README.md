# alfa-macos

**Native ALFA Wi-Fi capture on macOS, readable packet reports, and a bounded injection check.**

An ALFA AWUS036ACS can capture packets on Apple Silicon through Kismet's userspace USB driver. This project packages the byte-order fix that made our adapter work, installs the patched helper separately from Homebrew, and turns captures into searchable offline tables.

Optional injection verification uses [wifit3](https://github.com/derv82/wifit3). It sends five directed probe requests to a specified access point and checks for responses addressed to a fresh test MAC.

No kernel extension, Linux VM, or custom firmware. Kismet and wifit3 provide the drivers; this project supplies the fix, setup, reporting, and focused verification workflow.

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
| `capture.pcapng` | Full packet export for Wireshark |

The HTML displays the newest 2,000 packets with 96-byte previews; CSV and PCAPNG include the full capture. Reports work offline with no external scripts, fonts, analytics, or uploads. The original database is opened read-only and snapshotted before export. Encrypted packet payloads remain encrypted.

## Verify injection on your access point

Stop Kismet first; only one program should own the USB adapter.

```sh
alfa-injection-setup
alfa-injection-check --ssid "Your-Lab" --bssid "02:00:00:00:00:01" --channel 1
```

Skip `alfa-injection-setup` if you already installed with `--with-injection`.

Replace the example SSID/BSSID/channel with your access point's values. Use only networks you own or have permission to test.

The check listens for the specified network before transmitting. It sends five unicast probe requests, one per second, and confirms transmission only when it receives a matching probe response addressed to the unique test MAC. It does not deauthenticate clients. A lack of responses is **inconclusive**, since access points can ignore directed probes.

Results go to `~/Captures/ALFA/Injection checks/<timestamp>/`:

- `result.json`: counts and outcome.
- `rx-target.pcap`: received target advertisements and responses.
- `tx-submitted.pcap`: submitted frames; this file alone does not prove over-air transmission.

Our hardware run submitted five requests and received 14 matching response frames. Retries can make the response count exceed the request count.

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
