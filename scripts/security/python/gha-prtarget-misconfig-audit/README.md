# GitHub Actions – `pull_request_target` Misconfiguration Audit

This Python script scans GitHub repositories to detect insecure usage of the `pull_request_target` event in GitHub Actions workflows.  

It identifies patterns that may allow pull requests from untrusted forks to execute code with elevated privileges, leak secrets, or modify the repository.


## 🛡️ What It Checks

- Presence of the `pull_request_target` trigger
- Use of `actions/checkout` inside affected jobs
- Usage of secrets or `$GITHUB_TOKEN`
- Missing condition to block forks (`if: github.event.pull_request.head.repo.fork == false`)
- Absence of an explicit `permissions:` block (defaults to `write` access)

These conditions are commonly exploited if misconfigured, as described in:  

- [Sysdig Blog: Insecure GitHub Actions found in open source repositories](https://sysdig.com/blog/insecure-github-actions-found-in-mitre-splunk-and-other-open-source-repositories/)

---

## 🔧 Requirements

- Python 3.9 or higher
- [GitHub CLI (`gh`)](https://cli.github.com/) authenticated via `gh auth login`
- `git` installed
- Python dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

## 🚀 Usage

```bash
# Scan all repositories in an organization
python gha-prtarget-misconfig-audit.py --org my-org

# Scan a single repository
python gha-prtarget-misconfig-audit.py --repo user/repo

# Optional flags:
--poc     Create a benign local file in affected repos to demonstrate exploitability
--debug   Enable detailed debug output for step-by-step analysis
```

## 📂 Output

A log file will be created in the `output/` directory, e.g.:


```bash
output/scan-my-org-20250706-142301.log
```

Logs include detailed findings per repo, job, and workflow.

## ⚠️ Disclaimer

This tool is provided for educational and auditing purposes only.

Use it **responsibly** and only on repositories you **own or are explicitly authorized** to analyze.  
**Unauthorized scanning of third-party repositories is strictly discouraged** and may violate terms of service or applicable laws.

The author assumes **no responsibility for misuse** of this tool.