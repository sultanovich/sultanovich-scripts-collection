#!/bin/bash
# File name: security-collect-endpoint-triage.sh
# Version: 1.0.1
# Last updated: 2026-11-16
# Copyright (C) 2026 sultanovich
#
# Changelog:
#   1.0.1 - 2026-11-16 - Fix empty log on macOS (portable redaction), hang on
#                        options without value, noise in credential metadata on
#                        GNU/Linux, process list not sorted by memory; create
#                        the log with restrictive permissions from the start.
#   1.0.0 - 2026-11-14 - Initial release.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

###############################################################################
# security-collect-endpoint-triage.sh
#
# Description:
#   Collects read-only endpoint metadata for incident triage after a suspected
#   credential theft or endpoint compromise: installed editor extensions,
#   credential file metadata, running processes, network connections,
#   persistence mechanisms, browser extensions, recently modified files and
#   shell history references to credentials.
#
#   The script never reads the contents of credential files, private keys or
#   secrets. It records only metadata: paths, timestamps, sizes and versions.
#   Output is additionally passed through a redaction filter that masks
#   anything resembling an access key or a private key block, so the resulting
#   log can be shared with a responder.
#
# Usage:
#   bash security-collect-endpoint-triage.sh [options]
#
# Options:
#   -o, --output DIR    Directory for the log file (default: Desktop, else $HOME)
#   -i, --ioc PATTERN   Extra case-insensitive pattern to search for in editor
#                       extensions and process names (repeatable)
#   -q, --quiet         Suppress progress output on stderr
#   -h, --help          Show this help message and exit
#   -V, --version       Show version and exit
#
# Examples:
#   bash security-collect-endpoint-triage.sh
#   bash security-collect-endpoint-triage.sh -o /tmp -i 'some.extension-1.2.3'
#
# Supported systems:
#   - GNU/Linux (Debian, Ubuntu, RHEL, Fedora, Arch, Amazon Linux)
#   - macOS
#
# The script does NOT require root. Run it as the user being investigated so
# that their home directory and session are in scope.
#
# Exit codes:
#   0 - collection completed
#   1 - invalid usage
#   2 - output directory not writable
###############################################################################

# -e is deliberately NOT enabled: this is a collector and a single missing
# binary or unreadable path must not abort the whole run.
set -uo pipefail

# The log holds sensitive metadata: create it readable by the owner only.
umask 077

readonly SCRIPT_NAME="security-collect-endpoint-triage.sh"
readonly SCRIPT_VERSION="1.0.1"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'
readonly RED GREEN YELLOW CYAN RESET

QUIET=0
OUTDIR=""
IOC_PATTERNS=()

show_help() {
  cat <<EOF
Usage: bash ${SCRIPT_NAME} [options]

Collects read-only endpoint metadata for incident triage. Never reads the
contents of credentials or private keys; records metadata only.

Options:
  -o, --output DIR    Directory for the log file (default: Desktop, else \$HOME)
  -i, --ioc PATTERN   Extra pattern to search for (repeatable)
  -q, --quiet         Suppress progress output
  -h, --help          Show this help message and exit
  -V, --version       Show version and exit

Exit codes:
  0 collection completed   1 invalid usage   2 output not writable
EOF
}

msg()  { [ "${QUIET}" -eq 1 ] || printf '%b\n' "${CYAN}[*]${RESET} $*" >&2; }
ok()   { [ "${QUIET}" -eq 1 ] || printf '%b\n' "${GREEN}[OK]${RESET} $*" >&2; }
warn() { printf '%b\n' "${YELLOW}[WARN]${RESET} $*" >&2; }
err()  { printf '%b\n' "${RED}[ERROR]${RESET} $*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output|-i|--ioc)
      if [ $# -lt 2 ] || [ -z "$2" ]; then
        err "Option $1 requires a value"; echo; show_help; exit 1
      fi
      case "$1" in
        -o|--output) OUTDIR="$2" ;;
        *)           IOC_PATTERNS+=("$2") ;;
      esac
      shift 2 ;;
    -q|--quiet)   QUIET=1; shift ;;
    -h|--help)    show_help; exit 0 ;;
    -V|--version) printf '%s %s\n' "${SCRIPT_NAME}" "${SCRIPT_VERSION}"; exit 0 ;;
    *)            err "Unknown argument: $1"; echo; show_help; exit 1 ;;
  esac
done

# Resolve output directory: explicit, else Desktop in either language, else HOME.
if [ -z "${OUTDIR}" ]; then
  for candidate in "${HOME}/Desktop" "${HOME}/Escritorio" "${HOME}"; do
    [ -d "${candidate}" ] && { OUTDIR="${candidate}"; break; }
  done
fi
[ -d "${OUTDIR}" ] && [ -w "${OUTDIR}" ] || { err "Output directory not writable: ${OUTDIR}"; exit 2; }

readonly HOSTNAME_SAFE="$(hostname 2>/dev/null | tr -cd '[:alnum:]._-' | cut -c1-40)"
readonly STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly LOGFILE="${OUTDIR}/endpoint-triage_${HOSTNAME_SAFE:-unknown}_${STAMP}.log"

# Defensive redaction: even though nothing here reads secret values, any output
# that looks like an access key, a bearer token or a private key block is masked
# before it reaches the log.
# ci WORD: case-insensitive bracket expression for WORD (e.g. key -> [kK][eE][yY]).
# BSD/macOS sed has no case-insensitive flag, so this keeps redaction portable.
ci() {
  printf '%s' "$1" | awk '{
    out = ""
    for (i = 1; i <= length($0); i++) {
      c = substr($0, i, 1)
      if (c ~ /[A-Za-z]/) out = out "[" tolower(c) toupper(c) "]"; else out = out c
    }
    printf "%s", out
  }'
}

readonly RE_AWS_SECRET="$(ci aws_secret_access_key)"
readonly RE_SECRET_WORDS="($(ci password)|$(ci passwd)|$(ci secret)|$(ci token)|$(ci api)[_-]?$(ci key))"

redact() {
  LC_ALL=C sed -E \
    -e 's/(AKIA|ASIA|AIDA|AROA)[A-Z0-9]{12,}/\1<REDACTED>/g' \
    -e "s/(${RE_AWS_SECRET}[[:space:]]*=[[:space:]]*).*/\\1<REDACTED>/" \
    -e "s/${RE_SECRET_WORDS}([[:space:]]*[:=][[:space:]]*).*/\\1\\2<REDACTED>/" \
    -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----/<REDACTED PRIVATE KEY BLOCK>/g' \
    -e 's/gh[pousr]_[A-Za-z0-9]{20,}/<REDACTED GITHUB TOKEN>/g'
}

section() {
  printf '\n%s\n== %s\n%s\n' \
    '==============================================================================' \
    "$1" \
    '=============================================================================='
}

# run <label> <command...> : execute, never abort, note when unavailable
run() {
  local label="$1"; shift
  printf -- '-- %s\n' "${label}"
  if ! "$@" 2>/dev/null; then
    printf '   (not available on this system or no data)\n'
  fi
}

collect() {
  printf '%s %s\n' "${SCRIPT_NAME}" "${SCRIPT_VERSION}"
  printf 'Collected: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s   User: %s\n' "${HOSTNAME_SAFE}" "$(id -un 2>/dev/null)"
  printf '\nThis report contains METADATA ONLY. No credential, key or secret\n'
  printf 'values are read or stored. Secret-like strings are redacted.\n'

  section '1. SYSTEM'
  run 'kernel' uname -a
  if command -v sw_vers >/dev/null 2>&1; then
    run 'macOS version' sw_vers
  elif [ -r /etc/os-release ]; then
    printf -- '-- distribution\n'; grep -E '^(NAME|VERSION)=' /etc/os-release
  fi
  run 'uptime' uptime

  section '2. EDITOR EXTENSIONS'
  printf 'Known supply-chain attacks ship through editor marketplaces. Review the\n'
  printf 'list below for anything the user did not install deliberately.\n\n'
  local d
  for d in "${HOME}/.vscode/extensions" "${HOME}/.vscode-insiders/extensions" \
           "${HOME}/.vscode-server/extensions" "${HOME}/.cursor/extensions" \
           "${HOME}/.windsurf/extensions"; do
    [ -d "${d}" ] || continue
    printf -- '-- %s\n' "${d}"
    ls -1 "${d}" 2>/dev/null | sed 's/^/   /'
  done
  local b
  for b in code code-insiders cursor windsurf; do
    command -v "${b}" >/dev/null 2>&1 || continue
    printf -- '-- %s --list-extensions --show-versions\n' "${b}"
    "${b}" --list-extensions --show-versions 2>/dev/null | sed 's/^/   /'
  done
  if [ "${#IOC_PATTERNS[@]}" -gt 0 ]; then
    local p
    for p in "${IOC_PATTERNS[@]}"; do
      printf -- '-- IOC search: %s\n' "${p}"
      find "${HOME}" -maxdepth 5 -iname "*${p}*" 2>/dev/null | head -20 | sed 's/^/   /'
      pgrep -ail "${p}" 2>/dev/null | sed 's/^/   process: /'
    done
  fi

  section '3. CREDENTIAL FILES PRESENT (metadata only, contents never read)'
  local f
  for f in "${HOME}"/.aws/credentials "${HOME}"/.aws/config "${HOME}"/.ssh/id_* \
           "${HOME}"/.npmrc "${HOME}"/.docker/config.json "${HOME}"/.pgpass \
           "${HOME}"/.kube/config "${HOME}"/.gitconfig "${HOME}"/.netrc; do
    [ -e "${f}" ] || continue
    if stat --version >/dev/null 2>&1; then
      stat -c '   %n | modified %y | accessed %x | %A | %s bytes' "${f}" 2>/dev/null
    else
      stat -f '   %N | modified %Sm | accessed %Sa | %Sp | %z bytes' -t '%Y-%m-%d %H:%M:%S' "${f}" 2>/dev/null
    fi
  done
  printf -- '-- additional kubeconfig files in HOME\n'
  ls -la "${HOME}"/*.kube 2>/dev/null | sed 's/^/   /'

  section '4. RUNNING PROCESSES (top 60 by memory)'
  if [ "$(uname -s)" = "Darwin" ]; then
    ps aux -m 2>/dev/null | head -61
  else
    ps aux --sort=-%mem 2>/dev/null | head -61
  fi

  section '5. ESTABLISHED NETWORK CONNECTIONS'
  if command -v ss >/dev/null 2>&1; then
    ss -tunap 2>/dev/null | head -60
  else
    netstat -anv 2>/dev/null | head -60
  fi

  section '6. PERSISTENCE'
  run 'user crontab' crontab -l
  printf -- '-- launch agents and daemons (macOS)\n'
  ls -la "${HOME}/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null | sed 's/^/   /'
  printf -- '-- systemd user units\n'
  ls -la "${HOME}/.config/systemd/user" 2>/dev/null | sed 's/^/   /'
  printf -- '-- shell profiles (modification times)\n'
  ls -la "${HOME}"/.bashrc "${HOME}"/.bash_profile "${HOME}"/.zshrc "${HOME}"/.profile 2>/dev/null | sed 's/^/   /'

  section '7. BROWSER EXTENSIONS'
  for d in "${HOME}/Library/Application Support/Google/Chrome" \
           "${HOME}/.config/google-chrome" "${HOME}/.config/chromium" \
           "${HOME}/Library/Application Support/BraveSoftware"; do
    [ -d "${d}" ] || continue
    printf -- '-- %s\n' "${d}"
    ls -1 "${d}"/*/Extensions 2>/dev/null | head -40 | sed 's/^/   /'
  done
  ls -1 "${HOME}/.mozilla/firefox"/*/extensions 2>/dev/null | head -20 | sed 's/^/   /'

  section '8. GLOBAL PACKAGES'
  command -v npm  >/dev/null 2>&1 && { printf -- '-- npm -g\n'; npm ls -g --depth=0 2>/dev/null | sed 's/^/   /'; }
  command -v pip3 >/dev/null 2>&1 && { printf -- '-- pip3\n'; pip3 list 2>/dev/null | tail -30 | sed 's/^/   /'; }

  section '9. FILES MODIFIED IN SENSITIVE PATHS (last 30 days)'
  find "${HOME}/.aws" "${HOME}/.ssh" "${HOME}/.config" -type f -mtime -30 2>/dev/null | head -40 | sed 's/^/   /'

  section '10. SHELL HISTORY REFERENCING CREDENTIALS (commands only, redacted)'
  grep -nIE 'AKIA|aws_secret|AWS_SECRET|export AWS|credentials' \
    "${HOME}/.bash_history" "${HOME}/.zsh_history" 2>/dev/null | tail -30 | cut -c1-200

  section '11. RECENT LOGINS'
  run 'last' last

  section 'END OF COLLECTION'
  printf 'Send this file to your security team.\n'
  printf 'Do not uninstall, clean or reboot until instructed.\n'
}

msg "Collecting endpoint triage data..."
collect 2>&1 | redact > "${LOGFILE}"
chmod 600 "${LOGFILE}" 2>/dev/null

ok "Report written to:"
printf '  %s\n' "${LOGFILE}"
printf '\n%b\n' "${YELLOW}Send this file to your security team. Do not uninstall, clean or reboot yet.${RESET}"
exit 0
