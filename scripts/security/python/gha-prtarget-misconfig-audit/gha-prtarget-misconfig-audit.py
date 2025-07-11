#!/usr/bin/env python3
# File name: gha-prtarget-misconfig-audit.py
# Version: 1.0.2
# Last updated: 2025-07-11
# Copyright (C) 2025 sultanovich
#
# Changelog:
#   1.0.2 - 2025-07-11 - Replaced print-based logging with sanitized logging to file using Python's logging module
#   1.0.1 - 2025-07-06 - Added inline license header
#   1.0.0 - 2025-07-03 - Initial release
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
# gha-prtarget-misconfig-audit.py
#
# Description:
#   This Python script audits GitHub repositories to detect insecure use of
#   the `pull_request_target` event in GitHub Actions workflows. It flags
#   possible privilege escalation risks like untrusted code execution, secret
#   exposure, or unsafe usage of GITHUB_TOKEN on forks.
#
# Usage:
#   python gha-prtarget-misconfig-audit.py --org <organization>
#   python gha-prtarget-misconfig-audit.py --repo <owner/repo>
#
# Options:
#   --poc     Create a benign PoC file in affected repositories (locally only)
#   --debug   Enable verbose step-by-step analysis for debugging
#
# Requirements:
#   - Python 3.9 or higher
#   - GitHub CLI authenticated via `gh auth login`
#   - `git` installed
#   - Python package: PyYAML
#
# Notes:
#   - This tool performs only local, read-only analysis unless --poc is used.
#   - It is intended for authorized auditing purposes only.
###############################################################################



import os
import sys
import argparse
import subprocess
import tempfile
import shutil
import yaml
import logging
import re
from datetime import datetime
from pathlib import Path

CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
RESET = "\033[0m"

# Configure logging - only to file, not console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[])
logger = logging.getLogger(__name__)

# Patterns for sanitizing sensitive information
SENSITIVE_PATTERNS = [
    (r'/tmp/tmp[a-zA-Z0-9_]+', '/tmp/[REDACTED]'),
    (r'gh[pousr]_[A-Za-z0-9_]{36}', '[REDACTED_TOKEN]'),
    (r'/home/[^/\s]+', '/home/[USER]'),
    (r'C:\\\\Users\\\\[^\\\\]+', r'C:\\Users\\[USER]'),
]

def sanitize_message(msg):
    """Sanitize potentially sensitive information from log messages"""
    for pattern, replacement in SENSITIVE_PATTERNS:
        msg = re.sub(pattern, replacement, msg)
    return msg

def setup_file_logging(log_file):
    """Setup file logging with sanitization"""
    file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

def log(msg):
    """Log message to file with sanitization - replacement for original log() function"""
    sanitized_msg = sanitize_message(msg)
    logger.info(sanitized_msg)

def info(msg):
    print(f"{CYAN}[INFO]{RESET} {msg}")
    log(f"[INFO] {msg}")

def ok(msg):
    print(f"{GREEN}[OK]{RESET} {msg}")
    log(f"[OK] {msg}")

def warn(msg):
    print(f"{YELLOW}[WARN]{RESET} {msg}")
    log(f"[WARN] {msg}")

def fail(msg):
    print(f"{RED}[FAIL]{RESET} {msg}")
    log(f"[FAIL] {msg}")

def debug(msg, enabled):
    if enabled:
        print(f"{YELLOW}[DEBUG]{RESET} {msg}")
        log(f"[DEBUG] {msg}")

def parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--org', help='GitHub organization to scan')
    group.add_argument('--repo', help='Single repository to scan (owner/repo)')
    parser.add_argument('--poc', action='store_true', help='Create PoC file in affected repos')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    return parser.parse_args()

def check_gh_auth():
    try:
        subprocess.run(['gh', 'auth', 'status'], check=True, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        fail("GitHub CLI is not authenticated. Run 'gh auth login' first.")
        sys.exit(1)

def clone_repo(repo, workdir, debug_enabled):
    debug(f"Cloning {repo} into {workdir}", debug_enabled)
    try:
        subprocess.run(['gh', 'repo', 'clone', repo, workdir], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        # Don't expose detailed error information
        sanitized_repo = repo.replace('/', '_')
        fail(f"Failed to clone repository {sanitized_repo}")
        raise

def analyze_workflows(repo_path, debug_enabled):
    gha_dir = Path(repo_path) / '.github' / 'workflows'
    results = {'vuln': [], 'risk': [], 'safe': True}

    if not gha_dir.exists():
        debug("No .github/workflows directory found.", debug_enabled)
        return results

    for file in gha_dir.glob('*.yml'):
        debug(f"Parsing file: {file.name}", debug_enabled)
        with open(file, 'r', encoding='utf-8-sig') as f:
            try:
                doc = yaml.safe_load(f)
            except yaml.YAMLError:
                debug(f"Failed to parse {file.name}", debug_enabled)
                continue

        if not isinstance(doc, dict):
            debug(f"Skipping {file.name} because it's not a dictionary", debug_enabled)
            continue

        # PyYAML puede interpretar "on" como booleano True (YAML 1.1 quirk),
        # por eso lo buscamos explícitamente también como True.
        real_on_key = None
        for k in doc.keys():
            if str(k).strip('"').strip("'").lower() == 'on' or k is True:
                real_on_key = k
                break

        if real_on_key is None:
            debug(f"Skipping {file.name} due to missing 'on' key", debug_enabled)
            continue

        triggers = doc[real_on_key]
        has_pr_target = isinstance(triggers, dict) and 'pull_request_target' in triggers
        debug(f"pull_request_target present: {has_pr_target}", debug_enabled)

        if has_pr_target:
            real_jobs_key = None
            for k in doc.keys():
                if str(k).strip('"').strip("'").lower() == 'jobs':
                    real_jobs_key = k
                    break
            if real_jobs_key is None:
                debug(f"No 'jobs' key found in {file.name}", debug_enabled)
                continue

            jobs = doc[real_jobs_key]
            for job_name, job in jobs.items():
                steps = job.get('steps', [])
                debug(f"Analyzing job: {job_name} with {len(steps)} steps", debug_enabled)

                has_checkout = any('uses' in step and 'actions/checkout' in step['uses'] for step in steps)
                debug(f"  - uses checkout: {has_checkout}", debug_enabled)

                uses_secrets = any('run' in step and ('secrets.' in step['run'] or 'GITHUB_TOKEN' in step['run']) for step in steps)
                debug(f"  - uses secrets or token: {uses_secrets}", debug_enabled)

                has_if_fork = any('if' in step and 'fork' in step['if'] for step in steps)
                debug(f"  - has if condition for fork: {has_if_fork}", debug_enabled)

                has_permissions = 'permissions' in job
                debug(f"  - has permissions defined: {has_permissions}", debug_enabled)

                findings = []
                if has_checkout or uses_secrets or not has_if_fork or not has_permissions:
                    if has_checkout: findings.append("checkout usage found")
                    if uses_secrets: findings.append("secrets or GITHUB_TOKEN usage found")
                    if not has_if_fork: findings.append("no fork condition (if: ...fork == false)")
                    if not has_permissions: findings.append("permissions not set")
                    results['vuln'].append((file.name, job_name, findings))
                    results['safe'] = False
                else:
                    results['risk'].append(file.name)
                    results['safe'] = False

    return results

def scan_repo(repo, poc, debug_enabled):
    info(f"Scanning {repo} ...")
    workdir = tempfile.mkdtemp()
    try:
        clone_repo(repo, workdir, debug_enabled)
        results = analyze_workflows(workdir, debug_enabled)

        if results['vuln']:
            warn(f"VULNERABLE: {repo}")
            for wf, job, issues in results['vuln']:
                for issue in issues:
                    msg = f"  - {wf}:{job}: {issue}"
                    print(msg)
                    log(msg)
            if poc:
                poc_file = Path(workdir) / 'POC_PR_TARGET_MISCONFIG.txt'
                poc_file.write_text("This is a benign PoC file for pull_request_target misconfig.")
                ok(f"PoC file created in {repo}")
        elif results['risk']:
            warn(f"RISK (manual review): {repo}")
            for wf in results['risk']:
                msg = f"  - {wf}"
                print(msg)
                log(msg)
        else:
            ok(f"No risky pull_request_target usage detected in {repo}")

    except Exception as e:
        # Sanitize error messages - only log exception type, not details
        sanitized_repo = repo.replace('/', '_')
        fail(f"Error scanning {sanitized_repo}: {type(e).__name__}")
        if debug_enabled:
            debug(f"Exception details: {sanitize_message(str(e))}", debug_enabled)
    finally:
        shutil.rmtree(workdir)

def main():
    args = parse_args()
    check_gh_auth()

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = args.repo.replace('/', '_') if args.repo else args.org
    log_file = f"output/scan-{name}-{timestamp}.log"
    Path("output").mkdir(exist_ok=True)
    
    # Setup file logging
    setup_file_logging(log_file)
    log(f"Scan started at {timestamp}")

    if args.repo:
        scan_repo(args.repo, args.poc, args.debug)
    else:
        result = subprocess.run([
            'gh', 'repo', 'list', args.org, '--limit', '1000', '--json', 'nameWithOwner', '-q', '.[].nameWithOwner'
        ], stdout=subprocess.PIPE, check=True, text=True)
        repos = result.stdout.strip().splitlines()
        info(f"Total repositories to scan: {len(repos)}")
        for repo in repos:
            scan_repo(repo, args.poc, args.debug)

    log("Scan completed.")
    ok(f"Log saved to: {log_file}")

if __name__ == "__main__":
    main()