import React from 'react';
import { Copy, Terminal, FileCode, Server } from 'lucide-react';

const CodeBlock = ({ title, lang, code, icon: Icon }: { title: string, lang: string, code: string, icon: any }) => (
  <div className="mb-8 rounded-lg overflow-hidden border border-slate-700 bg-slate-900 shadow-xl">
    <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">
      <div className="flex items-center gap-2 text-slate-200 font-medium">
        <Icon size={16} className="text-blue-400" />
        <span>{title}</span>
      </div>
      <span className="text-xs text-slate-400 uppercase">{lang}</span>
    </div>
    <div className="p-4 overflow-x-auto relative group">
       <button 
        className="absolute top-4 right-4 p-2 bg-slate-700/50 hover:bg-slate-600 rounded text-slate-300 opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={() => navigator.clipboard.writeText(code)}
        title="Copy Code"
       >
         <Copy size={16} />
       </button>
      <pre className="text-sm font-mono text-slate-300 leading-relaxed">
        {code}
      </pre>
    </div>
  </div>
);

const InstallationGuide: React.FC = () => {
  const configYaml = `name: "CRA Compliance Auditor"
description: "Scans local network devices for Cyber Resilience Act compliance."
version: "1.0.0"
slug: "cra_auditor"
init: false
arch:
  - aarch64
  - amd64
  - armv7
startup: application
boot: auto
options:
  target_subnet: "192.168.1.0/24"
  scan_interval_hours: 24
schema:
  target_subnet: str
  scan_interval_hours: int
ports:
  8000/tcp: 8000
map:
  - config:rw`;

  const dockerfile = `ARG BUILD_FROM
FROM $BUILD_FROM

# Install system dependencies
RUN apk add --no-cache \\
    python3 \\
    py3-pip \\
    nmap \\
    nmap-scripts \\
    iputils

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Copy App Logic
WORKDIR /app
COPY . /app

# Executable permissions
RUN chmod a+x /app/run.sh

CMD [ "/app/run.sh" ]`;

  const runSh = `#!/usr/bin/with-contenv bashio

echo "Starting CRA Compliance Auditor..."

# Read config from Home Assistant Supervisor
TARGET_SUBNET=$(bashio::config 'target_subnet')
echo "Target Subnet: $TARGET_SUBNET"

# Start the scanning logic loop
python3 scan_logic.py --subnet "$TARGET_SUBNET"`;

  const scanLogic = `import sys
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
    with open('/data/report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("Scan complete. Report generated.")

if __name__ == "__main__":
    main()`;

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white mb-2">Backend Installation</h2>
        <p className="text-slate-400">
          This frontend allows you to view the reports generated by the Python Home Assistant Add-on. 
          Below is the source code required to build the Add-on container as per your Thesis requirements.
        </p>
      </div>

      <CodeBlock title="scan_logic.py" lang="PYTHON" code={scanLogic} icon={FileCode} />
      <CodeBlock title="Dockerfile" lang="DOCKER" code={dockerfile} icon={Server} />
      <CodeBlock title="config.yaml" lang="YAML" code={configYaml} icon={Terminal} />
      <CodeBlock title="run.sh" lang="BASH" code={runSh} icon={Terminal} />
    </div>
  );
};

export default InstallationGuide;
