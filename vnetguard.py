#!/usr/bin/env python3
import sys
import os
import argparse
import nmap

# Ensure the script is run with root privileges (required for SYN scan -sS)
if os.geteuid() != 0:
    sys.exit("[!] vnetguard requires root privileges. Please run with 'sudo'.")

def display_banner():
    # Added 'r' before the triple quotes to make it a raw string and fix the syntax warning
    banner = r"""
 __     __ _   _        _     ____                           _ 
 \ \   / /| \ | |  ___ | |_  / ___|  _   _   __ _  _ __   __| |
  \ \ / / |  \| | / _ \| __|| |  _  | | | | / _` || '__| / _` |
   \ V /  | |\  ||  __/| |_ | |_| | | |_| || (_| || |   | (_| |
    \_/   |_| \_| \___| \__| \____|  \__,_| \__,_||_|    \__,_|

   ❖ Advanced Network Scanner & Threat Intelligence Evaluator ❖
    """
    print(banner)

def evaluate_network(target_ip, aggressive=False):
    nm = nmap.PortScanner()
    
    # -sV determines service/version info
    # -sS performs a stealthy TCP SYN scan
    # -T4 sets timing template for faster execution
    scan_args = '-sS -sV -T4'
    if aggressive:
        scan_args += ' -A'  # Adds OS detection, traceroute, and script scanning

    print(f"\n[*] VNetGuard is analyzing all Critical ports on: \033[92m{target_ip}\033[0m")
    print("[*] This process may take a few minutes. Please wait...")
    
    try:
        nm.scan(target_ip, arguments=scan_args)
    except nmap.PortScannerError as e:
        sys.exit(f"[!] Nmap scan failed: {e}")
    except Exception as e:
        sys.exit(f"[!] An unexpected error occurred: {e}")

    # High-risk ports often targeted for initial access or lateral movement
    CRITICAL_PORTS = {
        21: "FTP (File Transfer Protocol) — Used for transferring files. [Vulnerable to sniffing/brute-force]",
        23: "Telnet - Cleartext authentication risk",
        135: "RPC - Potential remote code execution vector",
        139: "NetBIOS - Information disclosure risk",
        445: "SMB (Server Message Block) — Used for sharing files/printers. [High-risk vector for worms like EternalBlue]",
        1433: "MSSQL - Targeted for database exploitation",
        3306: "MySQL - Exposed database interface risk",
        3389: "RDP (Remote Desktop Protocol) — Used for remote control. [High target for brute-force]",
        5900: "VNC - Unencrypted or weakly secured remote access",
    }

    # Standard ports based on user definitions for context
    STANDARD_PORTS = {
        22: "SSH (Secure Shell) — Used for secure remote command-line login and SFTP.",
        25: "SMTP — Used for routing and sending emails between mail servers.",
        53: "DNS (Domain Name System) — Translates domain names into IP addresses.",
        67: "DHCP — Automatically assigns IP addresses on a network.",
        68: "DHCP — Automatically assigns IP addresses on a network.",
        80: "HTTP — Used for regular, unencrypted web browsing.",
        110: "POP3 — Used for downloading emails from a server to a client.",
        123: "NTP (Network Time Protocol) — Synchronizes network clocks.",
        143: "IMAP — Used for accessing and keeping emails on the mail server.",
        443: "HTTPS — Used for secure, encrypted web traffic (essential for privacy).",
        993: "IMAPS — The secure (encrypted) version of IMAP.",
        995: "POP3S — The secure (encrypted) version of POP3."
    }

    network_stage = "GOOD"
    findings = []

    if not nm.all_hosts():
        print("\033[91m[!] No active hosts detected. Verify the IP address or network connectivity.\033[0m")
        return

    for host in nm.all_hosts():
        print("\n" + "="*50)
        print(f"[-] Scan Report for Host: {host}")
        print(f"[-] State: {nm[host].state().upper()}")
        print("="*50)

        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())
            for port in ports:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port]['version']
                product = nm[host][proto][port]['product']

                if state == 'open':
                    # Check if port is explicitly in the critical registry
                    if port in CRITICAL_PORTS:
                        network_stage = "CRITICAL"
                        findings.append(f"\033[91m[CRITICAL]\033[0m Port {port}/{proto} ({service}) is OPEN.\n    ↳ Context: {CRITICAL_PORTS[port]}\n    ↳ Fingerprint: {product} {version}")
                    
                    # Check if port is in our standard known list
                    elif port in STANDARD_PORTS:
                        findings.append(f"\033[94m[INFO]\033[0m Port {port}/{proto} ({service}) is OPEN.\n    ↳ Context: {STANDARD_PORTS[port]}\n    ↳ Fingerprint: {product} {version}")
                    
                    # Fallback for unknown open ports
                    else:
                        findings.append(f"\033[94m[INFO]\033[0m Port {port}/{proto} ({service}) is OPEN.\n    ↳ Fingerprint: {product} {version}")

    # Display Final Assessment
    print("\n" + "#"*50)
    if network_stage == "CRITICAL":
        print(f" FINAL SECURITY ASSESSMENT: \033[91m{network_stage}\033[0m")
    else:
        print(f" FINAL SECURITY ASSESSMENT: \033[92m{network_stage}\033[0m")
    print("#"*50)
    
    print("\nDetailed breakdown:")
    for finding in findings:
        print(finding + "\n")

if __name__ == "__main__":
    # Print the custom banner as soon as the script runs
    display_banner()
    
    parser = argparse.ArgumentParser(description="vnetguard: Full-Port Network Scanner & Risk Evaluator")
    parser.add_argument("target", help="Target IP address or subnet to scan")
    parser.add_argument("-A", "--aggressive", action="store_true", help="Enable OS detection, traceroute, and advanced script scanning")
    
    args = parser.parse_args()
    evaluate_network(args.target, args.aggressive)
