#!/bin/bash
# File name: delete-linux-local-user.sh
# Version: 1.0.0
# Last updated: 2025-06-23
# Copyright (C) 2025 sultanovich
#
# Changelog:
#   1.0.0 - 2025-06-23 - Initial release.
#
# WARNING: This script is intended for controlled environments only on Linux systems.
# All actions are logged to a local file for auditing purposes.
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
# delete-linux-local-user.sh
#
# Description:
#   Deletes a Linux local user and optionally removes their home directory.
#   All actions are logged to a local file.
#   Includes dry-run mode and prevents deletion of privileged or system users.
#   Only works on Linux systems.
#
# Usage:
#   sudo bash delete-linux-local-user.sh -u <username> [--remove-home] [--dry-run]
#
# Arguments:
#   -u <username>     Username to delete (required)
#   --remove-home     Remove user's home directory and mail spool (optional)
#   --dry-run         Show what would be done, but do not make changes
#   -h, --help        Show this help message and exit
#
# Output:
#   - [INFO] and [WARN] messages are only visible in the log file.
#   - [OK] and main [INFO] messages are shown on screen as per compliance best practices.
#
# Security & Compliance:
#   - Logs all actions for audit.
#   - Refuses to delete privileged or system accounts.
#   - Dry-run mode for change review.
###############################################################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Check for Linux OS
if [[ "$(uname -s)" != "Linux" ]]; then
  echo -e "${RED}[FAIL]${RESET} This script can only be executed on Linux systems."
  echo -e "${CYAN}NOTE:${RESET} Detected system: $(uname -s)"
  exit 1
fi

# Log file setup
LOGFILE="/var/log/$(basename "$0" .sh)_$(date "+%Y%m%d_%H%M%S").log"
touch "$LOGFILE" 2>/dev/null || LOGFILE="./$(basename "$0" .sh)_$(date "+%Y%m%d_%H%M%S").log"
chmod 600 "$LOGFILE"

log_local() {
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts] $*" >> "$LOGFILE"
}

info()    { echo -e "${CYAN}[INFO]${RESET} $*"; log_local "[INFO] $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET} $*"; log_local "[OK] $*"; }
warn()    { log_local "[WARN] $*"; }
fail()    { echo -e "${RED}[FAIL]${RESET} $*"; log_local "[FAIL] $*"; }

show_help() {
  echo "Usage: sudo bash $0 -u <username> [--remove-home] [--dry-run]"
  echo
  echo "Deletes a Linux user and optionally removes their home directory."
  echo
  echo "Arguments:"
  echo "  -u <username>     Username to delete (required)"
  echo "  --remove-home     Remove user's home directory and mail spool (optional)"
  echo "  --dry-run         Show what would be done, but do not make changes"
  echo "  -h, --help        Show this help message and exit"
  echo
  echo "Examples:"
  echo "  sudo bash $0 -u alice"
  echo "  sudo bash $0 -u bob --remove-home"
  echo "  sudo bash $0 -u test --dry-run"
  exit 0
}

USERNAME=""
REMOVE_HOME=0
DRY_RUN=0

if [ $# -eq 0 ]; then
  show_help
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -u)
      USERNAME="$2"
      shift 2
      ;;
    --remove-home)
      REMOVE_HOME=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      show_help
      ;;
    *)
      fail "Unknown argument: $1"
      show_help
      ;;
  esac
done

if [ "$EUID" -ne 0 ]; then
  fail "This script must be run as root. Try: sudo $0 ..."
  exit 1
fi

if [[ -z "$USERNAME" ]]; then
  fail "Username is required."
  show_help
fi

# Username validation
if [[ ! "$USERNAME" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
  fail "Invalid username: $USERNAME. Must start with a letter or underscore, only lowercase letters, numbers, underscores or dashes."
  exit 1
fi

# Do not allow privileged/system names
if [[ "$USERNAME" == "root" || "$USERNAME" == "admin" || "$USERNAME" == "sysadmin" ]]; then
  fail "Refusing to delete privileged/reserved account: $USERNAME"
  exit 1
fi

# Prevent deletion of system users (UID < 1000, except on some distros)
USER_ID=$(id -u "$USERNAME" 2>/dev/null)
if [[ -z "$USER_ID" ]]; then
  fail "User '$USERNAME' does not exist."
  exit 1
fi
if [[ "$USER_ID" -lt 1000 ]]; then
  fail "Refusing to delete system user '$USERNAME' (UID: $USER_ID < 1000)"
  exit 1
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo
  info "----------------------------------------------"
  info "User deletion process for $USERNAME (dry-run)"
  info "==="
  ok "User $USERNAME would be deleted (dry-run)"
  if [ "$REMOVE_HOME" -eq 1 ]; then
    ok "Home directory and mail spool for $USERNAME would be removed (dry-run)"
  fi
  info "----------------------------------------------"
  log_local "Dry-run mode: user $USERNAME would be deleted. Remove home: $REMOVE_HOME"
  echo -e "${CYAN}NOTE:${RESET} Execution log is available at: $LOGFILE"
  exit 0
fi

echo
info "----------------------------------------------"
info "User deletion process for $USERNAME"
info "==="

log_local "Starting deletion for $USERNAME (remove home: $REMOVE_HOME)"

DEL_OPTS="-f"
if [ "$REMOVE_HOME" -eq 1 ]; then
  DEL_OPTS="$DEL_OPTS -r"
fi

if userdel $DEL_OPTS "$USERNAME" 2>>"$LOGFILE"; then
  ok "User $USERNAME deleted"
  if [ "$REMOVE_HOME" -eq 1 ]; then
    ok "Home directory and mail spool for $USERNAME removed"
    log_local "User $USERNAME and home directory/mail spool deleted"
  else
    log_local "User $USERNAME deleted (home directory retained)"
  fi
else
  fail "Failed to delete user $USERNAME"
  exit 1
fi

echo
echo -e "${CYAN}NOTE:${RESET} Execution log is available at: $LOGFILE"
echo

exit 0