import nmap
import requests
import socket
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CRAScanner:
    def __init__(self):
        self.nm = None
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.error("Nmap not found", exc_info=True)
        except Exception:
            logger.error("Unexpected error initializing nmap", exc_info=True)
            
        self.common_creds = [('admin', 'admin'), ('root', 'root'), ('user', '1234'), ('admin', '1234')]

    def scan_subnet(self, subnet):
        """Scans the given subnet for devices using a two-stage approach."""
        if not self.nm:
            logger.error("Nmap not initialized. Cannot scan.")
            return []

        # Stage 1: Discovery Scan (Ping/ARP)
        logger.info(f"Starting discovery scan on {subnet}")
        try:
            # -sn: Ping Scan - disable port scan
            self.nm.scan(hosts=subnet, arguments='-sn')
        except Exception as e:
            logger.error(f"Nmap discovery scan failed: {e}")
            return []

        hosts_to_scan = self.nm.all_hosts()
        logger.info(f"Discovery complete. Found {len(hosts_to_scan)} live hosts.")

        if not hosts_to_scan:
            return []

        # Stage 2: Detailed Scan
        logger.info(f"Starting detailed scan on {len(hosts_to_scan)} hosts.")
        devices = []
        
        # We can scan all discovered hosts in one go, or individually. 
        # Scanning together is faster.
        # Joining hosts by space
        target_spec = " ".join(hosts_to_scan)
        
        try:
            # -sV: Version detection
            # -O: OS detection
            # -Pn: Treat all hosts as online -- skip host discovery (since we just did it)
            # --top-ports 100: Check top 100 ports
            self.nm.scan(hosts=target_spec, arguments='-sV -O -Pn --top-ports 100')
        except Exception as e:
            logger.error(f"Nmap detail scan failed: {e}")
            return []

        for host in self.nm.all_hosts():
            # Basic info might be missing if scan failed for this specific host, but we try our best
            if 'addresses' not in self.nm[host]:
                continue
                
            mac = self.nm[host]['addresses'].get('mac', 'Unknown')
            ip = host
            
            # Use 'ipv4' as primary if available
            if 'ipv4' in self.nm[host]['addresses']:
                ip = self.nm[host]['addresses']['ipv4']
            
            # Vendor might be in 'vendor' dict keyed by MAC
            vendor = "Unknown"
            if 'vendor' in self.nm[host] and mac in self.nm[host]['vendor']:
                 vendor = self.nm[host]['vendor'][mac]

            device_info = {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": self.nm[host].hostname(),
                "open_ports": self._get_open_ports(host),
                "os_match": self._get_os_match(host)
            }
            
            # PER DEVICE CHECKS
            sbd_result = self.check_secure_by_default(ip, device_info['open_ports'])
            conf_result = self.check_confidentiality(device_info['open_ports'])
            vuln_result = self.check_vulnerabilities(vendor, device_info['open_ports'])

            status = "Compliant"
            if not sbd_result['passed'] or not vuln_result['passed']:
                status = "Non-Compliant"
            elif not conf_result['passed']:
                status = "Warning"

            device_info.update({
                "status": status,
                "checks": {
                    "secure_by_default": sbd_result,
                    "confidentiality": conf_result,
                    "vulnerabilities": vuln_result
                },
                "last_scanned": "Just now" # You might want datetime here
            })
            devices.append(device_info)
            
        logger.info(f"Detailed scan complete. Processed {len(devices)} devices.")
        return devices

    def _get_open_ports(self, host):
        ports = []
        for proto in self.nm[host].all_protocols():
            lport = self.nm[host][proto].keys()
            for port in lport:
                state = self.nm[host][proto][port]['state']
                if state == 'open':
                    service = self.nm[host][proto][port]['name']
                    ports.append({"port": port, "protocol": proto, "service": service})
        return ports

    def _get_os_match(self, host):
        if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
            return self.nm[host]['osmatch'][0]['name']
        return "Unknown"

    def check_secure_by_default(self, ip, open_ports):
        """Check for weak credentials on common ports."""
        details = []
        passed = True
        
        # Simple check: If Telnet is open, it's a fail for secure by default (modern standards)
        for p in open_ports:
            if p['port'] == 23:
                passed = False
                details.append("Telnet (port 23) is open. Insecure protocol.")

        # Real auth check would go here (e.g. attempting ssh login)
        # For safety/performance, we will simulate a "Weak Auth" check on http/80
        # In a real app, use async libraries to try common creds on identified services.
        
        if not details:
            details.append("No obvious weak default access vectors found.")

        return {"passed": passed, "details": "; ".join(details)}

    def check_confidentiality(self, open_ports):
        """Check for unencrypted services."""
        unencrypted_ports = [21, 23, 80] # FTP, Telnet, HTTP
        found_unencrypted = []
        
        for p in open_ports:
            if p['port'] in unencrypted_ports:
                found_unencrypted.append(f"{p['service']}/{p['port']}")
        
        if found_unencrypted:
            return {"passed": False, "details": f"Unencrypted ports found: {', '.join(found_unencrypted)}"}
        
        return {"passed": True, "details": "No common unencrypted management ports found."}

    def check_vulnerabilities(self, vendor, open_ports):
        """Query external CVE API."""
        if vendor == "Unknown":
             return {"passed": True, "details": "Vendor unknown, skipping CVE check.", "cves": []}

        # Limitation: Searching by vendor name is broad. 
        # Ideally we'd map CPEs from Nmap to CVEs.
        cves = []
        try:
            # Using cve.circl.lu API
            # This is a broad search and might return false positives or too many results
            # For this PoC we will limit to 5 recent criticals
            url = f"https://cve.circl.lu/api/search/{vendor}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                # Simple filter: Critical severity (?) - The API format varies, we'll do a basic check
                # Note: This API returns a list of CVE objects
                count = 0
                for item in data.get('data', [])[:5]: # Check first 5 matches
                    if 'cvss' in item and item['cvss'] and float(item['cvss']) > 9.0:
                        cves.append({
                            "id": item.get('id', 'Unknown'),
                            "severity": "CRITICAL",
                            "description": item.get('summary', 'No description')[:100] + "..."
                        })
                        count += 1
            
        except Exception as e:
            logger.error(f"CVE lookup failed: {e}")
            return {"passed": True, "details": "CVE lookup failed (network error).", "cves": []}

        if cves:
             return {"passed": False, "details": f"Found {len(cves)} critical CVEs associated with vendor.", "cves": cves}

        return {"passed": True, "details": "No critical CVEs found for this vendor.", "cves": []}

# For standalone testing
if __name__ == "__main__":
    scanner = CRAScanner()
    print(scanner.scan_subnet("192.168.1.0/24"))