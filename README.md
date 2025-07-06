> **🌍 This project is available in English and Spanish.**  
> [🇬🇧 English](./README.md) | [🇪🇸 Español](./README.es.md)
>
> ---

# Sultanovich Scripts Collection

A curated collection of scripts for system administration, security, and monitoring across multiple operating systems. This repository is structured to be clear and scalable.

## Structure

- `scripts/`
  - `security/`: Security-related scripts, such as vulnerability checks and hardening tasks.
    - `python/`: Utilities developed in Python for cross-platform scripting (as long as Python and its dependencies are installed).
    - `linux/`: Scripts specific to GNU/Linux operating systems (although most will also work on other Unix-like systems).
    - `windows/`: Scripts specific to the Windows operating system.
  - `sysadmin/`: Scripts for system administration tasks, such as user management and automation of administrative processes.
    - `python/`: Utilities developed in Python for cross-platform scripting. These tools are designed to work on multiple operating systems, provided Python and its dependencies are available.
    - `linux/`: Scripts specific to GNU/Linux operating systems (although most will also work on other Unix-like systems).
    - `windows/`: Scripts specific to the Windows operating system.


## Scripts Summary

| Script                                                                                       | Description                          | Category/SO        |
|----------------------------------------------------------------------------------------------|--------------------------------------|--------------------|
| [security-check-cve-2025-6018-6019.sh](scripts/security/linux/security-check-cve-2025-6018-6019.sh)                                                         | Check for CVE-2025-6018 and CVE-2025-6019 vulnerabilities (PAM, udisks2/libblockdev) | Security / Linux   |
| [add-linux-local-user.sh](scripts/sysadmin/linux/add-linux-local-user.sh)                                                      | Bash script to create a local Linux user with password expiration policy (SOC/PCI compliant), secure logging, and login test. | Sysadmin / Linux   |
| [delete-linux-local-user.sh](scripts/sysadmin/linux/delete-linux-local-user.sh) | Bash script to securely delete a local Linux user (with optional home dir removal), secure logging, dry-run mode, and compliance protections. | Sysadmin / Linux   |
| [security-check-cve-2025-4322.sh](scripts/security/linux/security-check-cve-2025-4322.sh) | Checks for CVE-2025-4322 vulnerability (Motors WordPress Theme) and optionally attempts a safe PoC (admin password change) | Security / Linux    |


## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/sysops-automation-scripts.git
   ```
2. Browse the `scripts/` directory for available scripts.
3. Each script contains usage instructions in its header.

## Example

```bash
bash scripts/security/linux/check_cve.sh
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the [GNU GPL v2](LICENSE).

## Security

If you discover a security vulnerability, please follow the instructions in our [Security Policy](SECURITY.md) before disclosing any details publicly.

You can also use GitHub Issues to report security concerns, following the process described in the policy.