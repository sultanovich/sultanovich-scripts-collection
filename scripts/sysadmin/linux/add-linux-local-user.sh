#!/bin/bash
# File name: add-linux-local-user.sh
# Version: 1.0.0
# Last updated: 2025-06-21
# Copyright (C) 2025 sultanovich
#
# Changelog:
#   1.0.0 - 2025-06-21 - Initial release.
#
# WARNING: This script is intended for controlled environments only on Linux systems.
# Passing the password as a command-line argument may violate security best practices (SOC 2, PCI DSS).
# Prefer using the script interactively or ensure secure handling of credentials.
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
# add-linux-local-user.sh
#
# Description:
#   Creates a new Linux user with a specified password and optionally assigns
#   the user to an additional group. All actions are logged to a local file.
#   Includes dry-run mode and disables the account if login fails.
#   Sets password expiration policy for regulated environments.
#   Only works on Linux systems.
#
# Usage:
#   sudo bash add-linux-local-user.sh -u <username> -p <password> [-g <group>] [--dry-run]
#
# Arguments:
#   -u <username>    Username to create (required)
#   -p <password>    Password for the new user (required)
#   -g <group>       Additional group to assign (optional)
#   --dry-run        Show what would be done, but do not make changes
#   -h, --help       Show this help message and exit
#
# Output:
#   - [INFO] and [WARN] messages are only visible in the log file.
#   - [OK] and main [INFO] messages are shown on screen as per compliance best practices.
#
# Security & Compliance:
#   - Logs all actions for audit (SOC 2, PCI DSS).
#   - Sets password expiration policy (chage).
#   - Warns against insecure password handling (in log).
#   - Disables created user if login fails.
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
  echo "Usage: sudo bash $0 -u <username> -p <password> [-g <group>] [--dry-run]"
  echo
  echo "Creates a new Linux user with a specified password and optional group."
  echo
  echo "Arguments:"
  echo "  -u <username>    Username to create (required)"
  echo "  -p <password>    Password for the new user (required)"
  echo "                   WARNING: Passing password on command line may be insecure!"
  echo "  -g <group>       Additional group to assign (optional)"
  echo "  --dry-run        Show what would be done, but do not make changes"
  echo "  -h, --help       Show this help message and exit"
  echo
  echo "Examples:"
  echo "  sudo bash $0 -u alice -p S3guro2025!"
  echo "  sudo bash $0 -u bob -p MyPassw0rd -g developers"
  echo "  sudo bash $0 -u test -p Test1234 --dry-run"
  exit 0
}

USERNAME=""
PASSWORD=""
GROUP=""
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
    -p)
      PASSWORD="$2"
      shift 2
      ;;
    -g)
      GROUP="$2"
      shift 2
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

if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
  fail "Username and password are required."
  show_help
fi

# Security warning: password on CLI (only log)
if [[ "$(ps -o args= -p $$)" == *"$PASSWORD"* ]]; then
  warn "WARNING: Your password may be visible to other users via process list!"
  warn "Consider using a more secure method for password entry."
fi

# Username validation
if [[ ! "$USERNAME" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
  fail "Invalid username: $USERNAME. Must start with a letter or underscore, only lowercase letters, numbers, underscores or dashes."
  exit 1
fi

# Do not allow privileged names/groups
if [[ "$USERNAME" == "root" || "$USERNAME" == "admin" || "$USERNAME" == "sysadmin" ]]; then
  fail "Refusing to create user with privileged/reserved name: $USERNAME"
  exit 1
fi

if [[ -n "$GROUP" ]]; then
  if [[ "$GROUP" == "root" || "$GROUP" == "wheel" || "$GROUP" == "sudo" ]]; then
    fail "Refusing to add user to privileged group: $GROUP"
    exit 1
  fi
fi

# Password complexity (min 8, upper, lower, digit, symbol)
if ! [[ "$PASSWORD" =~ [A-Z] && "$PASSWORD" =~ [a-z] && "$PASSWORD" =~ [0-9] && "$PASSWORD" =~ [^A-Za-z0-9] && ${#PASSWORD} -ge 8 ]]; then
  fail "Password does not meet complexity requirements (min 8 chars, upper, lower, digit, symbol)."
  exit 1
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo
  info "----------------------------------------------"
  info "User creation process for $USERNAME (dry-run)"
  info "==="
  if [ -n "$GROUP" ]; then
    ok "User $USERNAME would be assigned to group $GROUP"
  fi
  ok "User $USERNAME would be created (dry-run)"
  info "Login test would be performed for user $USERNAME (dry-run)"
  info "Password expiration policy: max age 90 days, min age 7 days, warning 14 days before expiration"
  info "----------------------------------------------"
  echo
  log_local "Dry-run mode: user $USERNAME (group: $GROUP) would be created, password set, login tested."
  log_local "Dry-run: chage policy would be set: -M 90 -m 7 -W 14"
  echo -e "${CYAN}NOTE:${RESET} Execution log is available at: $LOGFILE"
  exit 0
fi

if id "$USERNAME" &>/dev/null; then
  fail "User '$USERNAME' already exists."
  exit 1
fi

echo
info "----------------------------------------------"
info "User creation process for $USERNAME"
info "==="
log_local "Starting user creation for $USERNAME"

if [[ -n "$GROUP" ]]; then
  if ! getent group "$GROUP" > /dev/null 2>&1; then
    log_local "Group '$GROUP' does not exist, creating it."
    if ! groupadd "$GROUP" 2>>"$LOGFILE"; then
      fail "Failed to create group $GROUP"
      exit 1
    fi
    log_local "Group $GROUP created for user $USERNAME"
  fi
fi

USER_CREATED=0
if [[ -n "$GROUP" ]]; then
  if useradd -m -G "$GROUP" "$USERNAME" 2>>"$LOGFILE"; then
    USER_ID=$(id -u "$USERNAME")
    ok "User $USERNAME created (UID: $USER_ID)"
    ok "User $USERNAME assigned to group $GROUP"
    log_local "User $USERNAME created and assigned to group $GROUP (UID: $USER_ID)"
    USER_CREATED=1
  fi
else
  if useradd -m "$USERNAME" 2>>"$LOGFILE"; then
    USER_ID=$(id -u "$USERNAME")
    ok "User $USERNAME created (UID: $USER_ID)"
    log_local "User $USERNAME created (UID: $USER_ID)"
    USER_CREATED=1
  fi
fi

if [ "$USER_CREATED" -ne 1 ]; then
  fail "Failed to create user $USERNAME"
  exit 1
fi

if ! echo "$USERNAME:$PASSWORD" | chpasswd 2>>"$LOGFILE"; then
  fail "Failed to set password for $USERNAME"
  exit 1
fi

# Set password expiration policy (SOC/PCI compliance)
if ! chage -M 90 -m 7 -W 14 "$USERNAME" 2>>"$LOGFILE"; then
  fail "Failed to set password expiration policy for $USERNAME"
  exit 1
fi
CHAGE_INFO=$(chage -l "$USERNAME" 2>>"$LOGFILE")

info "Password expiration policy configured:"
# Print only relevant chage lines
echo "$CHAGE_INFO" | grep -E 'Maximum|Minimum|warning|expires|last' | while read -r line; do
  echo -e "    ${CYAN}$line${RESET}"
done
log_local "Password expiration policy set for $USERNAME: chage -M 90 -m 7 -W 14"
log_local "chage -l output for $USERNAME:\n$CHAGE_INFO"

USER_HOME=$(eval echo "~$USERNAME")
log_local "UID: $USER_ID"
log_local "Home directory: $USER_HOME"
log_local "Home directory details:"
ls -ld "$USER_HOME" >> "$LOGFILE" 2>&1
ls -la "$USER_HOME" >> "$LOGFILE" 2>&1

echo
info "----------------------------------------------"
info "Login test for user $USERNAME"
info "==="
log_local "Testing login for user $USERNAME"

if command -v expect >/dev/null 2>&1; then
  TMP_EXPECT=$(mktemp)
  cat > "$TMP_EXPECT" <<EOF
set timeout 5
spawn su - $USERNAME -c "id"
expect {
  "Password:" {
    send "$PASSWORD\r"
    exp_continue
  }
  -re "uid=$USER_ID" {
    exit 0
  }
  "su: Authentication failure" {
    exit 2
  }
  eof {
    exit 3
  }
  timeout {
    exit 4
  }
}
EOF

  expect "$TMP_EXPECT" >> "$LOGFILE" 2>&1
  STATUS=$?
  rm -f "$TMP_EXPECT"
  if [ "$STATUS" -eq 0 ]; then
    ok "User $USERNAME can login successfully"
    log_local "[OK] User $USERNAME can login successfully"
  else
    fail "Login test failed for user $USERNAME. Account has been locked."
    log_local "[FAIL] Login test failed for $USERNAME. Account locked."
    usermod -L "$USERNAME" 2>>"$LOGFILE"
    log_local "Account for '$USERNAME' has been locked due to failed login test."
    exit 1
  fi
else
  warn "'expect' is not installed, skipping automated login test."
  log_local "To manually test, run: su - $USERNAME"
fi

unset PASSWORD

echo
echo -e "${CYAN}NOTE:${RESET} Execution log is available at: $LOGFILE"
echo

exit 0