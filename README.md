> **🌍 This project is available in English and Spanish.**  
> [🇬🇧 English](./README.md) | [🇪🇸 Español](./README.es.md)
>
> ---

# Sultanovich Scripts Collection

A curated collection of scripts for system administration, security, and monitoring across multiple operating systems. This repository is structured to be clear and scalable.

## Structure

- `scripts/`
  - `security/`: Security-related scripts (e.g., vulnerability checks, hardening)
  - `sysadmin/`: System administration tasks (e.g., user management)


> [!TIP]
> Each category contains OS-specific folders (`linux/`, `windows/`, etc.) and subfolders for specific applications (if needed).

## Scripts Summary

| Script                                                                                       | Description                          | Category/SO        |
|----------------------------------------------------------------------------------------------|--------------------------------------|--------------------|
| security-check-cve-2025-6018-6019.sh                                                        | Check for CVE-2025-6018 and CVE-2025-6019 vulnerabilities (PAM, udisks2/libblockdev) | Security / Linux   |
| add-linux-local-user.sh                                                       | Bash script to create a local Linux user with password expiration policy (SOC/PCI compliant), secure logging, and login test. | Sysadmin / Linux   |
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