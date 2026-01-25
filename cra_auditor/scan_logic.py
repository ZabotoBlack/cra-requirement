import sys
import json
import nmap
import requests
import argparse
import socket
from datetime import datetime

# --- CONFIGURATION ---
COMMON_CREDS = [('admin', 'admin'), ('root', 'root'), ('root', '1234')]

def check_secure_by_default(ip):
    """Attempt non-destructive login to verify default creds."""
    # Note: Simplified for PoC. Real implementation needs async/ssh libs.
    # Returns (Passed: bool, Details: str)
    try:
        # Mocking a socket check for telnet as a proxy for 'weak auth accessible'
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, 23))
        sock.close()
        if result == 0:
            return False, "Telnet port open - Potentially insecure default"
    except Exception as e:
        pass
    return True, "No obvious default access vectors found"

def check_confidentiality(nm, ip):
    """Check for unencrypted services."""
    unencrypted_ports = [21, 23, 80]
    open_unencrypted = []
    
    if ip not in nm.all_hosts():
        return True, "Host not responsive to detailed scan"

    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            if port in unencrypted_ports:
                state = nm[ip][proto][port]['state']
                if state == 'open':
                    open_unencrypted.append(str(port))
    
    if open_unencrypted:
        return False, f"Unencrypted ports open: {', '.join(open_unencrypted)}"
    return True, "No unencrypted management ports found"

def check_vulnerabilities(vendor):
    """Query vulnerability database by vendor."""
    if not vendor:
        return True, "Unknown Vendor"
    
    # Placeholder for actual NVD/CVE-Search API call
    # url = f"https://cve.circl.lu/api/search/{vendor}"
    # In a real thesis, implement the API request here.
    return True, "No CRITICAL CVEs found in last 12 months (Simulated)"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--subnet', required=True, help='Target IP range')
    args = parser.parse_args()

    nm = nmap.PortScanner()
    print(f"Scanning {args.subnet}...")
    nm.scan(hosts=args.subnet, arguments='-sV -O --top-ports 100')

    report = []

    for host in nm.all_hosts():
        if 'mac' not in nm[host]['addresses']:
            continue
            
        mac = nm[host]['addresses']['mac']
        vendor = nm[host]['vendor'].get(mac, "Unknown")
        
        # 1. Secure By Default
        sbd_pass, sbd_msg = check_secure_by_default(host)
        
        # 2. Confidentiality
        conf_pass, conf_msg = check_confidentiality(nm, host)
        
        # 3. Vulnerabilities
        vuln_pass, vuln_msg = check_vulnerabilities(vendor)

        status = "Compliant"
        if not sbd_pass or not vuln_pass:
            status = "Non-Compliant"
        elif not conf_pass:
            status = "Warning"

        device_report = {
            "ip": host,
            "mac": mac,
            "vendor": vendor,
            "status": status,
            "checks": {
                "secure_by_default": sbd_msg,
                "confidentiality": conf_msg,
                "vulnerabilities": vuln_msg
            }
        }
        report.append(device_report)

    # Output JSON for the frontend to consume
    with open('/share/report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("Scan complete. Report generated.")

if __name__ == "__main__":
    main()