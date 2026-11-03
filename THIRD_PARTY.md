# Upstream projects

This repository's original scripts, report UI, and tests are offered under GPL-2.0-or-later. See LICENSE. No firmware or compiled upstream driver is bundled.

- [Kismet](https://www.kismetwireless.net/): GPL-2.0-or-later, with component-specific notices in its source tree. The small patch here modifies its userspace compatibility header. Kismet supplies capture, database logging, and PCAPNG conversion.
- Kismet's userspace capture includes code derived from Linux wireless drivers and compatibility headers. Preserve upstream SPDX identifiers and notices when redistributing those components. The setup script builds them from the upstream source; this repository does not relicense them.
- [wifit3](https://github.com/derv82/wifit3): GPL-2.0, installed separately in an isolated environment. It supplies the native userspace transmit/receive implementation used by the probe check.
- Firmware is supplied by the Kismet installation and remains subject to its own upstream redistribution terms. It is not modified by this project.

Pinned revisions and the technical scope of the fix are documented in [docs/driver-fix.md](docs/driver-fix.md). The project is independent of ALFA, Apple, Kismet, and wifit3.
