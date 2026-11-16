#!/bin/bash
# File name: security-collect-endpoint-triage.sh
# Version: 1.0.2
# Last updated: 2026-11-16
# Copyright (C) 2026 sultanovich
#
# Changelog:
#   1.0.2 - 2026-11-16 - Make every section state its result instead of
#                        printing an empty heading, and stop the collection
#                        noise from hiding the findings:
#                        * section 2 says so when no editor is installed, and
#                          also looks for VSCodium and vscode-server.
#                        * section 3 warns when a credential file is readable
#                          by other local users.
#                        * section 4 drops kernel threads and the collector's
#                          own processes.
#                        * section 5 reports listening sockets as well as
#                          established connections.
#                        * section 6 states explicitly that LaunchAgents do
#                          not apply off macOS, and when there are no systemd
#                          user units.
#                        * section 7 lists the extensions themselves - profile,
#                          id, name and version - instead of directory names,
#                          resolves localised names (__MSG_..__) from the
#                          extension locale files, matching keys without regard
#                          to case as Chrome does, collects Safari extensions
#                          through pluginkit, and says when a browser has none.
#                        * section 8 reports the package list in full, with a
#                          count.
#                        * section 9 excludes browser caches, Electron app-*
#                          trees and node_modules.
#                        * section 11 caps the login history.
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
readonly SCRIPT_VERSION="1.0.2"

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

# Chromium stores localised extension names as "__MSG_<key>__" and resolves
# them at run time from _locales/<locale>/messages.json. Without this the
# report shows the placeholder, which identifies nothing.
resolve_ext_name() {
  local raw="$1" verdir="$2" deflocale="$3"
  case "${raw}" in
    __MSG_*__) : ;;
    *) printf '%s' "${raw}"; return 0 ;;
  esac
  local key="${raw#__MSG_}"; key="${key%__}"
  local loc mfile flat realkey name
  for loc in "${deflocale}" en en_US en_GB es es_419; do
    [ -n "${loc}" ] || continue
    mfile="${verdir}_locales/${loc}/messages.json"
    [ -r "${mfile}" ] || continue
    flat="$(tr -d '\n\r' < "${mfile}" 2>/dev/null)"
    # Chrome looks message keys up without regard to case, so a manifest can
    # say __MSG_APP_NAME__ while messages.json defines "app_name". Find the
    # spelling the file actually uses before extracting the message.
    realkey="$(printf '%s' "${flat}" \
      | grep -oi "\"${key}\"[[:space:]]*:" | head -1 | cut -d'"' -f2)"
    [ -n "${realkey}" ] || continue
    name="$(printf '%s' "${flat}" \
      | sed -n "s/.*\"${realkey}\"[[:space:]]*:[[:space:]]*{//p" \
      | grep -o '"message"[[:space:]]*:[[:space:]]*"[^"]*"' \
      | head -1 | cut -d'"' -f4)"
    if [ -n "${name}" ]; then printf '%s' "${name}"; return 0; fi
  done
  printf '%s' "${raw}"
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
  # An empty section must never be ambiguous: a responder has to be able to
  # tell "no editor installed" apart from "the detection did not run".
  local d editor_found=0
  for d in "${HOME}/.vscode/extensions" "${HOME}/.vscode-insiders/extensions" \
           "${HOME}/.vscode-server/extensions" "${HOME}/.cursor/extensions" \
           "${HOME}/.windsurf/extensions" "${HOME}/.vscodium/extensions"; do
    [ -d "${d}" ] || continue
    editor_found=1
    printf -- '-- %s\n' "${d}"
    ls -1 "${d}" 2>/dev/null | sed 's/^/   /'
  done
  local b
  for b in code code-insiders codium cursor windsurf; do
    command -v "${b}" >/dev/null 2>&1 || continue
    editor_found=1
    printf -- '-- %s --list-extensions --show-versions\n' "${b}"
    "${b}" --list-extensions --show-versions 2>/dev/null | sed 's/^/   /'
  done
  if [ "${editor_found}" -eq 0 ]; then
    printf -- '-- RESULT: no editor installation found\n'
    printf '   No VS Code, VSCodium, Cursor or Windsurf directory or binary was\n'
    printf '   detected for this user. This section is empty BY RESULT, not\n'
    printf '   because the check failed to run.\n'
  fi
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
    case "${f}" in
      *.pub) : ;;
      *"/.aws/credentials"|*"/.ssh/id_"*|*"/.pgpass"|*"/.netrc"|*"/.npmrc"|\
      *"/.docker/config.json"|*"/.kube/config")
        local mode
        mode="$(stat -c '%a' "${f}" 2>/dev/null)" || mode=""
        [ -n "${mode}" ] || mode="$(stat -f '%OLp' "${f}" 2>/dev/null)" || mode=""
        case "${mode}" in
          600|400|"") : ;;
          *) printf '   ^^ WARNING: mode %s - readable by other local users, expected 600\n' "${mode}" ;;
        esac ;;
    esac
  done
  printf -- '-- additional kubeconfig files in HOME\n'
  ls -la "${HOME}"/*.kube 2>/dev/null | sed 's/^/   /'

  section '4. RUNNING PROCESSES (top 40 by memory, kernel threads excluded)'
  if [ "$(uname -s)" = "Darwin" ]; then
    ps aux -m 2>/dev/null | head -41
  else
    # Kernel threads appear as [name] and always report 0 memory: they would
    # otherwise fill most of the list with noise.
    ps aux --sort=-%mem 2>/dev/null \
      | grep -vE '[[:space:]]\[.+\][[:space:]]*$' \
      | grep -vF "${SCRIPT_NAME}" \
      | head -41
  fi

  section '5. NETWORK CONNECTIONS'
  if command -v ss >/dev/null 2>&1; then
    printf -- '-- established connections\n'
    ss -tnap state established 2>/dev/null | head -40 | sed 's/^/   /'
    printf -- '-- listening sockets\n'
    ss -tulnp 2>/dev/null | head -30 | sed 's/^/   /'
  else
    printf -- '-- established connections\n'
    netstat -anv 2>/dev/null | grep -i 'estab' | head -40 | sed 's/^/   /'
    printf -- '-- listening sockets\n'
    netstat -anv 2>/dev/null | grep -i 'listen' | head -30 | sed 's/^/   /'
  fi

  section '6. PERSISTENCE'
  run 'user crontab' crontab -l
  printf -- '-- launch agents and daemons (macOS)\n'
  local lad launch_found=0
  for lad in "${HOME}/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    [ -d "${lad}" ] || continue
    launch_found=1
    printf '   %s:\n' "${lad}"
    ls -la "${lad}" 2>/dev/null | sed 's/^/     /'
  done
  if [ "${launch_found}" -eq 0 ]; then
    if [ "$(uname -s)" = "Darwin" ]; then
      printf '   RESULT: no LaunchAgents or LaunchDaemons directory exists.\n'
      printf '   On macOS these are the main persistence mechanism, so this is a\n'
      printf '   meaningful negative: none are installed. The check did run.\n'
    else
      printf '   (not applicable: this host is not macOS)\n'
    fi
  fi
  printf -- '-- systemd user units\n'
  if [ -d "${HOME}/.config/systemd/user" ]; then
    ls -la "${HOME}/.config/systemd/user" 2>/dev/null | sed 's/^/   /'
  else
    printf '   (no user unit directory present)\n'
  fi
  printf -- '-- shell profiles (modification times)\n'
  ls -la "${HOME}"/.bashrc "${HOME}"/.bash_profile "${HOME}"/.zshrc "${HOME}"/.profile 2>/dev/null | sed 's/^/   /'

  section '7. BROWSER EXTENSIONS'
  printf 'Format: <profile> | <extension id> | <name from manifest> | <version>\n'
  printf 'A name shown as __MSG_...__ could not be resolved: look it up by id.\n\n'
  local extdir verdir mfile ename ever pname deflocale nexts listing browser_found=0
  for d in "${HOME}/Library/Application Support/Google/Chrome" \
           "${HOME}/.config/google-chrome" "${HOME}/.config/chromium" \
           "${HOME}/.config/microsoft-edge" \
           "${HOME}/.config/BraveSoftware/Brave-Browser" \
           "${HOME}/Library/Application Support/BraveSoftware"; do
    [ -d "${d}" ] || continue
    browser_found=1
    printf -- '-- %s\n' "${d}"
    nexts=0
    for extdir in "${d}"/*/Extensions/*/; do
      [ -d "${extdir}" ] || continue
      nexts=$((nexts + 1))
      verdir="$(ls -1d "${extdir}"*/ 2>/dev/null | tail -1)"
      mfile="${verdir}manifest.json"
      ename=""; ever=""; deflocale=""
      if [ -r "${mfile}" ]; then
        ename="$(grep -m1 -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "${mfile}" 2>/dev/null | cut -d'"' -f4)"
        ever="$(grep -m1 -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "${mfile}" 2>/dev/null | cut -d'"' -f4)"
        deflocale="$(grep -m1 -o '"default_locale"[[:space:]]*:[[:space:]]*"[^"]*"' "${mfile}" 2>/dev/null | cut -d'"' -f4)"
        [ -n "${ename}" ] && ename="$(resolve_ext_name "${ename}" "${verdir}" "${deflocale}")"
      fi
      # The profile matters: an extension in "Profile 1" is not under "Default",
      # and a report without it sends the reader to a path that does not exist.
      pname="$(basename "${extdir%/Extensions/*}")"
      printf '   %s | %s | %s | %s\n' \
        "${pname}" "$(basename "${extdir}")" "${ename:-<manifest unreadable>}" "${ever:-?}"
    done
    # A bare heading cannot be told apart from a check that failed to run.
    if [ "${nexts}" -eq 0 ]; then
      printf '   RESULT: no extension installed in any profile of this browser.\n'
    fi
  done
  for d in "${HOME}/Library/Safari/Extensions" \
           "${HOME}/Library/Containers/com.apple.Safari/Data/Library/Safari/Extensions"; do
    [ -d "${d}" ] || continue
    browser_found=1
    printf -- '-- %s\n' "${d}"
    listing="$(ls -1 "${d}" 2>/dev/null | head -30)"
    if [ -n "${listing}" ]; then
      printf '%s\n' "${listing}" | sed 's/^/   /'
    else
      printf '   RESULT: directory present but empty, no legacy extension.\n'
    fi
  done
  # Modern Safari App Extensions ship inside application bundles and are not
  # visible as files: ask the plug-in registry instead.
  if command -v pluginkit >/dev/null 2>&1; then
    printf -- '-- Safari app extensions (pluginkit)\n'
    pluginkit -mAvvv -p com.apple.Safari.extension 2>/dev/null | head -40 | sed 's/^/   /'
  fi
  for d in "${HOME}/.mozilla/firefox" "${HOME}/Library/Application Support/Firefox/Profiles"; do
    [ -d "${d}" ] || continue
    browser_found=1
    printf -- '-- %s\n' "${d}"
    listing="$(ls -1 "${d}"/*/extensions 2>/dev/null | head -30)"
    if [ -n "${listing}" ]; then
      printf '%s\n' "${listing}" | sed 's/^/   /'
    else
      printf '   RESULT: no extension installed in any profile of this browser.\n'
    fi
  done
  if [ "${browser_found}" -eq 0 ]; then
    printf -- '-- RESULT: no browser profile directory found\n'
  fi

  section '8. GLOBAL PACKAGES'
  command -v npm  >/dev/null 2>&1 && { printf -- '-- npm -g\n'; npm ls -g --depth=0 2>/dev/null | sed 's/^/   /'; }
  if command -v pip3 >/dev/null 2>&1; then
    # A truncated list is worse than none: it looks complete while hiding
    # everything before the cut.
    printf -- '-- pip3 (%s packages)\n' \
      "$(pip3 list 2>/dev/null | tail -n +3 | wc -l | tr -d ' ')"
    pip3 list 2>/dev/null | sed 's/^/   /'
  fi

  section '9. FILES MODIFIED IN SENSITIVE PATHS (last 30 days)'
  printf 'Browser caches and bundled application code (Electron app-* trees,\n'
  printf 'node_modules) are excluded: they are rewritten on every update and\n'
  printf 'would otherwise crowd out the real findings. Capped at 40 entries.\n\n'
  find "${HOME}/.aws" "${HOME}/.ssh" "${HOME}/.config" \
       "${HOME}/Library/Application Support" \
       -type f -mtime -30 2>/dev/null \
    | grep -vaE '/node_modules/|/app-[0-9][^/]*/(modules|resources)/|/(Cache|Cache_Data|GPUCache|Code Cache|Dawn[A-Za-z]*Cache|ShaderCache|GrShaderCache|Service Worker|Local Storage|Session Storage|IndexedDB|Crashpad|Crash Reports|BrowserMetrics|Dictionaries|blob_storage|component_crx_cache|extensions_crx_cache|No_Vary_Search)/|/(Trust Tokens|Network Persistent State|Variations|DIPS)$|-journal$|/LOG(\.old)?$|/LOCK$|/CURRENT$|/MANIFEST-|\.(ldb|sst|pma)$' \
    | head -40 | sed 's/^/   /'

  section '10. SHELL HISTORY REFERENCING CREDENTIALS (commands only, redacted)'
  grep -nIE 'AKIA|aws_secret|AWS_SECRET|export AWS|credentials' \
    "${HOME}/.bash_history" "${HOME}/.zsh_history" 2>/dev/null | tail -30 | cut -c1-200

  section '11. RECENT LOGINS'
  # Unbounded, last dumps the whole wtmp file and can be most of the report.
  run 'last (60 most recent entries)' last -n 60

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
