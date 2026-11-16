# Endpoint Triage Collector – Linux/macOS

This Bash script collects read-only metadata from an endpoint during incident triage, after a suspected credential theft or endpoint compromise.

It **never reads the contents** of credential files, private keys or secrets: it records only paths, timestamps, sizes and versions. Anything that looks like an access key, token or private key block is redacted, so the report can be shared with a responder.


## 🛡️ What It Collects

- Installed editor extensions (VS Code, Cursor, Windsurf) and browser extensions
- Credential file metadata (`~/.aws`, `~/.ssh`, `~/.kube`, `.npmrc`, `.netrc`, etc.)
- Running processes (top 60 by memory) and network connections
- Persistence: crontab, systemd user units, LaunchAgents/LaunchDaemons, shell profiles
- Global npm/pip packages and files recently modified in sensitive paths
- Shell history lines referencing credentials (redacted) and recent logins

---

## 🔧 Requirements

- Bash, on GNU/Linux or macOS
- No root required: run it **as the user being investigated**, so their home directory is in scope

## 🚀 Usage

```bash
# Default: report written to the Desktop (or $HOME)
bash security-collect-endpoint-triage.sh

# Custom output directory and an extra IOC pattern (repeatable)
bash security-collect-endpoint-triage.sh -o /tmp -i 'some.extension-1.2.3'

# Optional flags:
-q, --quiet     Suppress progress output
-h, --help      Show help
-V, --version   Show version
```

## 📂 Output

A single log file, readable by its owner only (`600`):

```bash
endpoint-triage_<hostname>_20261116T112025Z.log
```

Exit codes: `0` completed, `1` invalid usage, `2` output directory not writable.

## ⚠️ Disclaimer

This tool is provided for incident response and auditing purposes only.

Run it **only on systems you own or are explicitly authorized** to investigate. It is a quick triage aid, **not a replacement for forensic acquisition**: if a compromise is suspected, do not clean, uninstall or reboot the system until your security team says so.

The author assumes **no responsibility for misuse** of this tool.
