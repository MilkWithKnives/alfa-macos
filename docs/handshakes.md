# Reading handshake evidence

Run `alfa-report --open` after capture to generate the enhanced report. No separate handshake collection command is needed: the analyzer inspects packet bytes already saved in the Kismet database. It does not transmit or initiate a connection.

## Using the report

1. Look at **Captured handshakes** for detected EAPOL frames, attempts with all four messages observed, and partial attempts.
2. Select **Explore handshakes**. Each attempt lists its AP/client, known SSID, M1–M4 progress, missing steps, timestamps, and database packet references.
3. Filter to **Partial** or **All four observed**, or search a BSSID, client, or SSID.
4. Select **View** for the attempt's details and a copyable Wireshark display filter. **View this attempt's EAPOL frames** opens its evidence table. Clear that filter to return to all loaded observations.
5. Download **Authentication packets** to inspect the detected subset in Wireshark. The complete `capture.pcapng` remains available for broader analysis.
6. Open the **How to interpret your capture** explanations for signal, retries, network identity, frame types, coverage, and export limits.

## What the labels mean

| Label | Interpretation |
| --- | --- |
| M1 | Observed AP challenge message |
| M2 | Observed client response |
| M3 | Observed AP key-install message |
| M4 | Observed client acknowledgment |
| All four observed | All four message types correlated by timing, addresses, descriptor, replay counters, and AP nonce |
| Partial | Only some message types were observed in this grouped attempt |
| Group key | Group-key exchange; does not fill pairwise handshake steps |
| Unclassified key | Unsupported layout or message fields that do not meet the classifier's rules |
| Malformed EAPOL | Incomplete header, inconsistent length, or unsupported EAPOL version |
| Flagged EAPOL | Kismet error or radiotap bad-FCS flag; retained as evidence but excluded from correlation |

These labels describe saved observations. No MIC verification, credential recovery, decryption, or authentication-success determination is performed. Four matching frames are not proof that the AP accepted the client. An SSID is joined from the captured device summaries; it can be unknown or list several advertised names for the same BSSID.

## Correlation and decoder scope

The decoder supports plain 802.11 (DLT 105) and radiotap (DLT 127), infrastructure To-DS/From-DS data frames, QoS/HT-control headers, and radiotap padding/FCS handling. WPA/RSN EAPOL-Key layouts with 16-byte MIC fields and key descriptor versions 1–3 are classified. Request/error/SMK flags, unexpected directions, and missing required nonce/MIC bytes cannot complete a handshake.

Attempts are correlated within a 30-second window from the first grouped observation. M2 must match M1's replay counter. M3 must advance the replay counter and, when M1 is present, match the AP nonce. M4 must match M3's counter. Repeated messages are retained without filling missing steps. Recent candidate attempts are bounded to eight per AP/client/descriptor combination. Delayed, reordered, overlapping, or unusual exchanges may remain separate partial attempts rather than being overclaimed as complete.

The decoder does not reassemble fragmented or A-MSDU traffic, four-address traffic, encrypted payloads, Ethernet, SAE authentication, FT roaming, or variable-MIC/AKM-defined layouts. Its absence of findings is not proof of absent authentication. Wireshark can decode more formats.

Reference layouts and field meanings: [hostap's WPA common definitions](https://w1.fi/wpa_supplicant/devel/wpa__common_8h_source.html), [Wireshark EAPOL fields](https://www.wireshark.org/docs/dfref/e/eapol.html), and [Wireshark RSN key fields](https://www.wireshark.org/docs/dfref/w/wlan_rsna_eapol.html).

## Exports and limits

- `handshakes.csv`: all grouped attempts, including packet row references.
- `eapol.csv`: all detected EAPOL observations, including excluded/unclassified frames.
- `authentication.pcapng`: detected EAPOL packet bytes and original timestamps; mixed supported link types are preserved as separate interfaces.
- `capture.pcapng`: complete capture export, including traffic outside this decoder's scope.

The page loads the newest 1,000 attempts, 5,000 EAPOL observations, and 2,000 general packet records. Full CSV files and aggregate counts are not limited by those previews. The attempt evidence button can therefore show no browser rows for an older attempt; use the full CSV/PCAPNG in that case. Database row numbers do not equal Wireshark frame numbers.

The bundled demo has one four-message observation with a repeated M3 and one partial M1/M2 attempt. Its addresses, frames, nonces, and MIC bytes are invented; its MIC placeholders are deliberately not valid signatures. Real captured data is never bundled with the repository.
