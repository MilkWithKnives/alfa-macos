#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail
umask 077
repo="$(cd "$(dirname "$0")" && pwd -P)"
desktop=true
capture=false
injection=false
while [ $# -gt 0 ]; do
  case "$1" in
    --no-desktop) desktop=false ;;
    --with-capture) capture=true ;;
    --with-injection) capture=true; injection=true ;;
    --help|-h)
      cat <<'HELP'
Usage: ./install.sh [--with-capture] [--with-injection] [--no-desktop]
  Default          Install commands and Desktop shortcuts only.
  --with-capture   Also install dependencies and build/test the capture driver.
  --with-injection Also install capture support and pinned injection tooling.
  --no-desktop     Skip Desktop shortcuts.
Existing commands are backed up. Does not start capture or transmit packets.
Requires Homebrew and Apple command-line tools for driver setup.
HELP
      exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done
if "$capture"; then
  [ "$(uname -s)" = Darwin ] || { printf 'Full driver setup supports macOS only.\n' >&2; exit 1; }
  export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
  command -v brew >/dev/null || { printf 'Install Homebrew first: https://brew.sh\n' >&2; exit 1; }
  xcrun --find clang >/dev/null || { printf 'Run xcode-select --install first.\n' >&2; exit 1; }
fi
target="${ALFA_HOME:-$HOME/.local/share/alfa-macos}"
bin_dir="${ALFA_BIN_DIR:-$HOME/.local/bin}"
data_dir="${ALFA_DATA_DIR:-$HOME/Captures/ALFA}"
backup="$HOME/.local/share/alfa-macos-backups/$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$target" "$bin_dir" "$data_dir"
target="$(cd "$target" && pwd -P)"
bin_dir="$(cd "$bin_dir" && pwd -P)"
data_dir="$(cd "$data_dir" && pwd -P)"
if [ "$repo" = "$target" ]; then printf 'Install destination must differ from the source checkout.\n' >&2; exit 1; fi
for directory in bin lib patches tests; do
  if [ -e "$target/$directory" ]; then
    mkdir -p "$backup/runtime"
    mv "$target/$directory" "$backup/runtime/$directory"
  fi
  cp -R "$repo/$directory" "$target/$directory"
done
cp "$repo/LICENSE" "$repo/THIRD_PARTY.md" "$target/"
for command_path in "$target"/bin/alfa-*; do
  chmod +x "$command_path"
  name="$(basename "$command_path")"
  if [ -e "$bin_dir/$name" ] || [ -L "$bin_dir/$name" ]; then
    mkdir -p "$backup/bin"
    mv "$bin_dir/$name" "$backup/bin/$name"
  fi
  # A wrapper supports custom install roots without editing the user's shell files.
  printf '#!/bin/bash\nexport ALFA_HOME=%q\nif [ -z "${ALFA_DATA_DIR:-}" ]; then export ALFA_DATA_DIR=%q; fi\nexec %q "$@"\n' \
    "$target" "$data_dir" "$command_path" > "$bin_dir/$name"
  chmod +x "$bin_dir/$name"
done
if "$desktop" && [ -d "$HOME/Desktop" ]; then
  if [ ! -e "$HOME/Desktop/ALFA Captures" ] && [ ! -L "$HOME/Desktop/ALFA Captures" ]; then
    ln -s "$data_dir" "$HOME/Desktop/ALFA Captures"
  fi
  opener="$HOME/Desktop/ALFA Report.command"
  if [ -e "$opener" ]; then mkdir -p "$backup/Desktop"; mv "$opener" "$backup/Desktop/"; fi
  printf '#!/bin/bash\nexec %q --open\n' "$bin_dir/alfa-report" > "$opener"
  chmod +x "$opener"
fi
printf 'Installed commands in %s\n' "$bin_dir"
if "$capture"; then
  "$bin_dir/alfa-setup"
fi
if "$injection"; then
  "$bin_dir/alfa-injection-setup"
fi
if "$capture"; then
  printf '\nSetup complete. Connect your ALFA, then run:\n  alfa-sniff --check\n  alfa-sniff\nStop with Ctrl-C, then open the report with alfa-report --open.\n'
else
  printf 'Next: alfa-setup\nOptional injection tooling: alfa-injection-setup\n'
fi
case ":$PATH:" in *":$bin_dir:"*) ;; *) printf 'Add this directory to PATH, or run %s/alfa-setup directly.\n' "$bin_dir" ;; esac
if [ -d "$backup" ]; then printf 'Previous installation saved in %s\n' "$backup"; fi
