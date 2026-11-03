# Contributing

Include your Mac model/architecture, macOS version, exact adapter model, USB VID:PID, and the pinned dependency revision when reporting a hardware result. Distinguish successful initialization, received packets, accepted transmit submissions, and matching over-air responses.

Before sharing logs or captures, remove private SSIDs, MAC addresses, GPS coordinates, credentials, and packet payloads. Synthetic fixtures are preferred for report bugs.

Run `python3 -m unittest discover -s tests -v`. The tests cover frame classification, report escaping and counts, probe-response matching, and installation into paths containing spaces. They do not open the radio. `alfa-setup` separately builds and runs the PHY table C regression on macOS.

Generate a shareable synthetic report with `python3 examples/make_demo.py` after installing Kismet. Never commit personal capture files. Keep changes to upstream driver code as small, explained patches against a documented revision.
