# ALFA macOS command guide

This guide covers the ALFA AWUS036ACS (`0bda:0811`) workflow: start capture, watch packets, open saved reports, and verify packet injection using directed probe requests. Run commands in macOS Terminal. Only monitor and test networks you own or have permission to test.

## 1. Make the commands available

For an installed setup, run this in your current terminal:

```sh
export PATH="$HOME/.local/bin:$PATH"
command -v alfa-sniff alfa-report alfa-injection-check
```

The second command should print the paths of all three commands. There is no separate application activation or Python environment to activate; the wrappers select the needed tools automatically.

To keep this PATH setting across new zsh terminals, add this line once to `~/.zshrc`:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

If commands are missing, install from your checkout. The following assumes you cloned it to `~/Projects/alfa-macos`; adjust that path if necessary:

```sh
cd "$HOME/Projects/alfa-macos"
./install.sh --with-injection
```

`--with-injection` installs capture/report support and the optional injection tools. For capture and reporting only, use `./install.sh --with-capture`. Homebrew and Apple's command-line tools must already be installed. To refresh just the command scripts from your checkout while keeping installed driver builds, run `./install.sh` without flags.

## 2. Check the adapter

Connect the ALFA, then run:

```sh
alfa-sniff --check
```

This lists the device and checks for the expected USB ID. It does not start a capture. A successful result identifies `ALFA AWUS036ACS / RTL8811AU` and an interface such as `rtw8821a-0`.

If another program or a VM owns the adapter, release it first. Use one radio-owning program at a time.

## 3. Start monitoring packets

Choose one capture mode; do not run both commands at once.

**Discover networks across channels:**

```sh
alfa-sniff
```

Kismet hops channels. This is useful for discovery, but it can miss traffic on a channel while the adapter is tuned elsewhere.

**Stay on a particular channel:**

```sh
alfa-sniff --channel 1
```

Replace `1` with the channel shown for the access point you want to observe. Fixing the channel does not filter to a single SSID: the adapter can receive other networks on that channel too.

Leave the capture terminal running. In a second terminal, open Kismet's live interface:

```sh
open "http://localhost:2501"
```

Complete Kismet's login setup if this is your first visit. Its live interface shows discovered devices, networks, and packet counts. The capture terminal prints the session's save directory.

## 4. Stop capture and open packet tables

In the terminal running `alfa-sniff`, press **Control-C once**. Wait for Kismet to finish and for the `Report ready` message. The launcher automatically exports a report after capture stops.

Generate and open a report from the latest capture:

```sh
alfa-report --open
```

Or open the report that already exists without regenerating it:

```sh
open "$HOME/Captures/ALFA/Latest Report/index.html"
```

In the report:

1. Select **Networks** to find SSIDs, BSSIDs, channels, and advertised security.
2. Select **Packets** to inspect frame types, addresses, signal, size, retries, and protection flags.
3. Enter a name, MAC address, channel, or frame type in the search field to filter the selected table.
4. Click a column heading to sort.
5. Click **View** on a packet row to see its details and byte preview.
6. Select the other tables for devices, channels, frame summaries, and address pairs.

The report is a snapshot, not a continuously updating view. Run `alfa-report --open` again to refresh it. You can generate a snapshot in a second terminal while capture is running; device summaries may lag the current packet data.

For authentication evidence, select **Explore handshakes** near the top of the page. The report shows partial and all-four-observed M1–M4 attempts, including per-client progress, packet references, and a filtered EAPOL view. **Authentication packets** downloads the detected subset for Wireshark. The embedded interpretation guide explains these findings; see [handshake analysis and limits](handshakes.md) for full details. No separate injection command is needed to analyze saved handshakes.

The browser shows the newest **2,000 packets** and previews the first **96 bytes** of each. Its packet search covers those displayed rows. `packets.csv` and `capture.pcapng` contain the full capture. Encrypted payloads remain encrypted.

## 5. Find and export saved data

Open all sessions in Finder:

```sh
open "$HOME/Captures/ALFA"
```

Open the latest report folder:

```sh
open "$HOME/Captures/ALFA/Latest Report"
```

Open the full packet metadata CSV in your default CSV application:

```sh
open "$HOME/Captures/ALFA/Latest Report/packets.csv"
```

Open the full packet export in Wireshark, if Wireshark is installed:

```sh
open -a Wireshark "$HOME/Captures/ALFA/Latest Report/capture.pcapng"
```

Generate a report from a specific older capture or session directory:

```sh
alfa-report "/path/to/capture.kismet" --open
alfa-report "/path/to/session-directory" --open
```

Replace those example paths with actual files or folders. Each successful report generation also updates the `Latest Report` link, including when you explicitly select an older session.

| Saved item | Purpose |
| --- | --- |
| Session's `.kismet` file | Original Kismet database |
| `reports/<generation>/index.html` | Offline report for that generation |
| `packets.csv` | All packet metadata rows |
| `networks.csv` | SSID, BSSID, channel, advertised security |
| `devices.csv` | Observed device summaries |
| `channels.csv` | Per-frequency traffic and signal summaries |
| `frames.csv` | Counts by frame type |
| `address-pairs.csv` | Observed source/destination pairs |
| `capture.pcapng` | Complete captured packets for a protocol analyzer |
| `handshakes.csv` | Grouped handshake attempts and M1–M4 observation coverage |
| `eapol.csv` | All EAPOL observations detected by the report decoder |
| `authentication.pcapng` | Detected EAPOL subset with original bytes and timestamps |

## 6. Prepare an injection check

The provided injection command is a specific verification test: it transmits **five directed probe requests** to a chosen access point and checks for matching replies. It is not a general packet replay or arbitrary-frame command.

If you have not installed the optional tools yet:

```sh
alfa-injection-setup
```

This installs and smoke-tests the pinned wifit3 environment; it does not transmit.

From the report's **Networks** table, note your access point's exact:

- **SSID**: network name, including capitalization and spaces.
- **BSSID**: the access point radio's MAC address, not your computer's MAC.
- **Channel**: the currently observed channel.

One SSID can appear on several BSSIDs or bands. Choose the 2.4 GHz radio you intend to test. The command currently accepts channels **1–11**; 5 GHz injection is not covered by this workflow.

Stop `alfa-sniff` with **Control-C** and wait for it to finish before proceeding. The same ALFA cannot run Kismet capture and the injection check simultaneously; the injection check handles its own receive operation.

## 7. Run the injection check

Replace all three example values with your access point's details:

```sh
alfa-injection-check \
  --ssid "Your-Lab" \
  --bssid "02:00:00:00:00:01" \
  --channel 1
```

After initialization, the command listens up to eight seconds for the specified target. If it sees the target, it sends five directed requests, one per second, then waits briefly for additional replies. A random locally administered source MAC distinguishes replies to this test from other traffic.

| Output | Meaning |
| --- | --- |
| `CONFIRMED` | Received matching probe responses from the target, addressed to the test MAC; evidence of over-air transmission |
| `INCONCLUSIVE` | No matching response; the AP may ignore directed probes, so this does not by itself prove TX failed |
| `Target was not observed` | No requests transmitted; check SSID, BSSID, channel, range, and adapter access |
| `Injection check failed` | Initialization, USB, tuning, or another operation failed; read the error |

Driver acceptance alone is not treated as proof of over-air injection. Response counts can exceed five because retries are counted as frames. This test does not deauthenticate clients or recover Wi-Fi passwords.

## 8. Inspect injection results and resume capture

The command prints its exact results directory. Open the parent directory:

```sh
open "$HOME/Captures/ALFA/Injection checks"
```

Each run has its own timestamped folder:

| File | Meaning |
| --- | --- |
| `result.json` | Target, channel, test MAC, outcome, submission and response counts |
| `rx-target.pcap` | Received target advertisements and responses |
| `tx-submitted.pcap` | Frames submitted to the driver; not an independent over-air capture |

For a particular run, substitute its printed directory:

```sh
python3 -m json.tool "/path/to/injection-run/result.json"
open -a Wireshark "/path/to/injection-run/rx-target.pcap"
```

Injection results are separate from the Kismet HTML reports. `alfa-report` consumes `.kismet` databases, not these injection PCAPs.

After the check exits, resume monitoring:

```sh
alfa-sniff --channel 1
```

## 9. Import HC22000 files

Use **HC22000 files** in the report to choose local files. Imported records appear in their own table with PMKID/EAPOL types, addresses, source references, and CSV downloads. Browser additions last until reload.

To save the import into a generated report alongside your latest capture:

```sh
alfa-report --hc22000 "/path/to/export.hc22000" --open
```

For a standalone metadata report, even without a Kismet capture:

```sh
alfa-report "/path/to/export.hc22000" --open
```

Replace the example paths. Repeat `--hc22000 FILE` for multiple imports. Reuse those arguments when regenerating to keep including the files. Importing a PMKID or EAPOL pair does not establish complete M1–M4 packet evidence. See [import details](hc22000.md).

## 10. Send a targeted deauthentication burst with wifit3

`alfa-injection-check` sends probe requests. The installed wifit3 0.7.0 exposes deauthentication through its terminal UI; its CLI does **not** have a standalone `--deauth` flag.

Deauthentication can disconnect the selected client. Use this on your own access point and a test device you control. Stop `alfa-sniff` first so wifit3 can own the adapter.

Open the installed interface using the same ALFA driver as the successful probe test:

```sh
WIFIT3_RTL8821=dkms "${ALFA_RADIO_DIR:-$HOME/.local/opt/wifit3}/venv/bin/python" -m wifit3
```

1. Select the ALFA if the interface prompts for an adapter.
2. In the scanner, select your network row to open its focused view. Confirm the **BSSID**, not just its name. The focused view tunes to that AP's channel.
3. In the client list, locate your test device's MAC address. Click its **✕** button, whose tooltip is **Deauthenticate Client**. This is the action that transmits the targeted deauthentication burst.
4. The inspected version performs ten AP→client / client→AP rounds. Driver retries can add transmissions, so this is not a guarantee of exactly twenty over-air frames.
5. Read the focused view's send/ACK log and observe whether your test device reconnects. ACK reception is evidence of frame reception, not proof that the endpoint accepted the deauthentication or that a new handshake completed.
6. Press **q** to quit wifit3 before returning to `alfa-sniff`.

The per-client button is a finite action. The separate **Deauth all / d** control is broadcast, and **AutoDeauth** is a looping campaign with broader behavior; they are not the per-client control described above. This build disables ordinary deauth controls when Protected Management Frames are required or their advertised posture is invalid. Do not interpret a disabled control as failed USB injection.

The successful probe-injection test does not independently verify this deauth path on your adapter. These steps were checked against the installed CLI and source, without transmitting deauthentication frames.

wifit3's captures/results are separate from Kismet's `.kismet` databases. The HTML report does not automatically import a wifit3 capture. For a passive Kismet handshake observation, stay on your AP's channel while your own client connects normally, then regenerate the report. Disassociation is another management-frame type; this package does not expose a dedicated standalone disassociation CLI command.

## 11. Troubleshooting and help

| Situation | Command / action |
| --- | --- |
| Command not found | `export PATH="$HOME/.local/bin:$PATH"`; install the scripts if still missing |
| Check adapter visibility | `alfa-sniff --check` |
| Capture startup diagnostics | `alfa-sniff --diagnose --channel 1` |
| View saved device-list diagnostics | `cat "$HOME/Library/Logs/alfa-macos/devices.log"` |
| Patched helper missing | `alfa-setup` |
| Injection dependency missing | `alfa-injection-setup` |
| Adapter busy | Stop Kismet/other capture tools and release VM USB passthrough |
| No saved report | Stop capture cleanly, then run `alfa-report --open` |
| Browser cannot connect to port 2501 | Check that `alfa-sniff` is still running and inspect its terminal errors |

List the supported flags:

```sh
alfa-sniff --help
alfa-report --help
alfa-injection-check --help
alfa-setup --help
alfa-injection-setup --help
```

The paths above assume the defaults. For a different save location, set it before starting capture or running reports:

```sh
export ALFA_DATA_DIR="$HOME/Captures/ALFA-Lab"
alfa-sniff --channel 1
```

Use the same `ALFA_DATA_DIR` in other terminals when working with those sessions. For example, `open "$ALFA_DATA_DIR/Latest Report/index.html"` opens the report in that location. Run `unset ALFA_DATA_DIR` to return to the default for subsequent commands.
