# vnetguard

`vnetguard` is a command-line network security scanning tool designed for Kali Linux. It inspects all 65535 ports on a targeted IP address, fingerprints running services, and evaluates whether the asset resides in a **Good** or **Critical** security stage based on exposed attack surfaces.

## Installation & Prerequisites

This tool relies on `nmap` and `python-nmap`. Ensure Nmap is updated on your Kali instance before running.

```bash
# Clone the repository
git clone [https://github.com/vyshakhak/vnetguard.git](https://github.com/vyshakhak/vnetguard.git)
cd vnetguard

# Install dependencies
pip3 install -r requirements.txt

# Make the script executable
chmod +x vnetguard.py
