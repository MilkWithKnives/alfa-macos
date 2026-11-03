# SPDX-License-Identifier: GPL-2.0-or-later
# Sourced by installed commands. ALFA_HOME can point to a development checkout.
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
ALFA_HOME="${ALFA_HOME:-$HOME/.local/share/alfa-macos}"
ALFA_DATA_DIR="${ALFA_DATA_DIR:-$HOME/Captures/ALFA}"
ALFA_DRIVER_DIR="${ALFA_DRIVER_DIR:-$HOME/.local/opt/kismet-alfa}"
ALFA_RADIO_DIR="${ALFA_RADIO_DIR:-$HOME/.local/opt/wifit3}"
export ALFA_HOME ALFA_DATA_DIR ALFA_DRIVER_DIR ALFA_RADIO_DIR
umask 077

alfa_python() {
  if [ -n "${ALFA_PYTHON:-}" ]; then printf '%s\n' "$ALFA_PYTHON"; return; fi
  command -v python3 || { printf 'Python 3.10+ is required.\n' >&2; return 1; }
}

alfa_no_capture() {
  if pgrep -x kismet >/dev/null || pgrep -x uwifi_test >/dev/null; then
    printf 'Stop Kismet and alfa-driver-check before opening the ALFA with another tool.\n' >&2
    return 1
  fi
}
