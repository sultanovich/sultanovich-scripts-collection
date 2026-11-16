# Endpoint Triage Collector – Windows

This PowerShell script collects read-only metadata from a Windows endpoint during incident triage, after a suspected credential theft or endpoint compromise.

It **never reads the contents** of credential files, private keys or secrets: it records only paths, timestamps, sizes and versions. Anything that looks like an access key, token or private key block is redacted, so the report can be shared with a responder.


## 🛡️ What It Collects

- Installed editor extensions (VS Code, Cursor, Windsurf) and browser extensions (Chrome, Edge, Brave)
- Credential file metadata (`.aws`, `.ssh`, `.kube`, `.npmrc`, `.docker`, etc.)
- Running processes (top 50 by memory) and established TCP connections
- Persistence: non-Microsoft scheduled tasks and `Run` registry keys
- Global npm/pip packages, software installed in the last 30 days and recently modified files in sensitive paths
- PowerShell history lines referencing credentials (redacted) and, if elevated, recent logons

---

## 🔧 Requirements

- Windows 10 / 11 / Server 2016+ with PowerShell 5.1 or later
- No administrator rights required. Without elevation, the recent logons section is skipped

## 🚀 Usage

```powershell
# Default: report written to the Desktop (or the user profile)
powershell -ExecutionPolicy Bypass -File .\security-collect-endpoint-triage.ps1

# Custom output directory and extra IOC patterns
powershell -ExecutionPolicy Bypass -File .\security-collect-endpoint-triage.ps1 -OutputDir C:\Temp -Ioc 'some.extension'

# Optional flags:
-Quiet     Suppress progress output
-Version   Show version
```

Run it from a file, not by pasting it into a console: the script ends with `exit`, which closes the window.

## 🔐 Execution Policy

By default, Windows may block the script with an error such as:

```text
... cannot be loaded because running scripts is disabled on this system.
... is not digitally signed. You cannot run this script on the current system.
```

Recommended ways to run it, without lowering security permanently:

- **Bypass only for this run** (as in the examples above):
  `powershell -ExecutionPolicy Bypass -File .\security-collect-endpoint-triage.ps1`
- **If the file was downloaded**, review it first and then remove the "downloaded from the Internet" mark:
  `Unblock-File .\security-collect-endpoint-triage.ps1`

Avoid `Set-ExecutionPolicy Unrestricted`: it changes the policy for every script on the system.

## 📂 Output

A single log file:

```text
endpoint-triage_<COMPUTERNAME>_20261116T112025Z.log
```

Exit codes: `0` completed, `2` output directory not writable.

## ⚠️ Disclaimer

This tool is provided for incident response and auditing purposes only.

Run it **only on systems you own or are explicitly authorized** to investigate. It is a quick triage aid, **not a replacement for forensic acquisition**: if a compromise is suspected, do not clean, uninstall or reboot the system until your security team says so.

The author assumes **no responsibility for misuse** of this tool.
