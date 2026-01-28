import nmap
import requests
import socket
import logging
import os

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
        """Scans the given subnet for devices using a hybrid approach (Nmap + HA API)."""
        ha_devices = self._get_ha_devices() 
        
        if not self.nm:
            logger.error("Nmap not initialized. Relying solely on Home Assistant data.")
            return self._merge_devices([], ha_devices)

        # Stage 1: Discovery Scan (Ping + ARP)
        # -sn: Ping Scan - disable port scan
        # -PR: ARP Ping (faster and more reliable for local LAN)
        logger.info(f"Starting discovery scan on {subnet}")
        try:
            self.nm.scan(hosts=subnet, arguments='-sn -PR')
        except Exception as e:
            logger.error(f"Nmap discovery scan failed: {e}")
            return self._merge_devices([], ha_devices)

        hosts_to_scan = self.nm.all_hosts()
        logger.info(f"Discovery complete. Found {len(hosts_to_scan)} live hosts.")

        nmap_devices = []
        if hosts_to_scan:
            # Stage 2: Detailed Scan
            logger.info(f"Starting detailed scan on {len(hosts_to_scan)} hosts.")
            
            target_spec = " ".join(hosts_to_scan)
            
            try:
                # -sV: Version detection, -O: OS detection, -Pn: Treat as online
                # --top-ports 100: Check top 100 ports
                # Added vendor specific ports: 6668 (Tuya), 8081 (Sonoff), 9999 (Kasa)
                extra_ports = "6668,8081,9999"
                self.nm.scan(hosts=target_spec, arguments=f'-sV -O -Pn --top-ports 100 -p {extra_ports},1-1024') 
                # Note: Scanning top 100 + specifics. 
                # Simplified: default top ports might miss 6668/9999 so we rely on -p if we want to be sure, 
                # but -p overrides --top-ports. Let's send a specific command that covers both or just add them.
                # Actually, -p 1-1024 covers standard, we add the others.
                # self.nm.scan(hosts=target_spec, arguments='-sV -O -Pn -p 1-1024,6668,8081,9999')
                # For speed in this PoC, we will stick to top-ports 100 plus upgrades.
                self.nm.scan(hosts=target_spec, arguments='-sV -O -Pn --top-ports 1000') # Increased to 1000 to catch more
            except Exception as e:
                logger.error(f"Nmap detail scan failed: {e}")
            
            for host in self.nm.all_hosts():
                if 'addresses' not in self.nm[host]:
                    continue
                    
                mac = self.nm[host]['addresses'].get('mac', 'Unknown')
                ip = host
                if 'ipv4' in self.nm[host]['addresses']:
                    ip = self.nm[host]['addresses']['ipv4']
                
                hostname = self.nm[host].hostname()
                if not hostname:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        pass

                vendor = "Unknown"
                if 'vendor' in self.nm[host] and mac in self.nm[host]['vendor']:
                     vendor = self.nm[host]['vendor'][mac]
                
                os_name = self._get_os_match(host)
                open_ports = self._get_open_ports(host)

                nmap_devices.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor, 
                    "hostname": hostname,
                    "openPorts": open_ports,
                    "osMatch": os_name,
                    "source": "nmap"
                })

        # Merge Nmap and HA devices
        merged_devices = self._merge_devices(nmap_devices, ha_devices)
        
        # Run compliance checks on the FINAL merged list
        final_results = []
        for dev in merged_devices:
            check_vendor = dev.get('model') if dev.get('model') and dev.get('model') != "Unknown" else dev.get('vendor', 'Unknown')
            if dev.get('manufacturer') and dev.get('manufacturer') != "Unknown":
                 check_vendor = f"{dev['manufacturer']} {check_vendor}"
            if check_vendor == "Unknown " or check_vendor.strip() == "Unknown":
                 check_vendor = dev.get('vendor', 'Unknown')

            # ENHANCED CHECKS
            sbd_result = self.check_secure_by_default(dev)
            conf_result = self.check_confidentiality(dev.get('openPorts', []))
            vuln_result = self.check_vulnerabilities(check_vendor, dev.get('openPorts', []))
            
            # Vendor Specific Checks
            vendor_warnings = self._check_vendor_specifics(dev)
            if vendor_warnings:
                sbd_result['details'] += " " + "; ".join(vendor_warnings)
                sbd_result['passed'] = False

            status = "Compliant"
            if not sbd_result['passed'] or not vuln_result['passed']:
                status = "Non-Compliant"
            elif not conf_result['passed']:
                status = "Warning"

            dev.update({
                "status": status,
                "checks": {
                    "secureByDefault": sbd_result,
                    "dataConfidentiality": conf_result,
                    "vulnerabilities": vuln_result
                },
                "lastScanned": "Just now"
            })
            final_results.append(dev)
            
        logger.info(f"Detailed scan complete. Processed {len(final_results)} devices.")
        return final_results

    def _get_ha_devices(self):
        """Fetch devices from Home Assistant Supervisor API."""
        supervisor_token = os.environ.get('SUPERVISOR_TOKEN')
        supervisor_url = "http://supervisor/core/api/states"
        
        if not supervisor_token:
            logger.warning("SUPERVISOR_TOKEN not found. Skipping HA device sync (Mocking for dev).")
            # MOCK DATA FOR LOCAL DEV / DEBUGGING
            return [
                {"entity_id": "media_player.yamaha_yas_306", "attributes": {"friendly_name": "Living Room Soundbar", "ip_address": "192.168.1.55", "source": "ha", "manufacturer": "Yamaha", "model": "YAS-306"}},
                {"entity_id": "light.zigbee_device_1", "attributes": {"friendly_name": "Kitchen Light", "source": "ha", "manufacturer": "Philips", "model": "LWB010"}}, # Zigbee, no IP
                {"entity_id": "router.fritz_box_7590", "attributes": {"friendly_name": "FRITZ!Box 7590", "ip_address": "192.168.1.1", "source": "ha", "manufacturer": "AVM", "model": "FRITZ!Box 7590"}}
            ]
            
        headers = {
            "Authorization": f"Bearer {supervisor_token}",
            "Content-Type": "application/json",
        }
        
        devices = []
        try:
            response = requests.get(supervisor_url, headers=headers, timeout=10)
            if response.status_code == 200:
                states = response.json()
                for state in states:
                    # Very simple heuristic to find "devices" with interesting attributes
                    attrs = state.get('attributes', {})
                    if 'ip_address' in attrs or 'manufacturer' in attrs or 'model' in attrs:
                        devices.append({
                            "entity_id": state['entity_id'],
                            "attributes": attrs,
                            "ip": attrs.get('ip_address'),
                            # Try to find MAC if exposed, rarely is in states, but sometimes in device registry (which requires diff API)
                            # For now we rely on IP merging or just separate listing
                        })
            else:
                logger.error(f"Failed to fetch HA states: {response.status_code} {response.text}")
        except Exception as e:
            logger.error(f"Error communicating with Supervisor: {e}")
            
        return devices

    def _normalize_mac(self, mac):
        if not mac or mac == "Unknown": return None
        return mac.replace(":", "").lower()

    def _merge_devices(self, nmap_devices, ha_devices):
        """
        Merge separate lists of devices. 
        Priority: 
        - Match by IP (Nmap IP == HA IP)
        - Else append as new
        """
        merged = {d['ip']: d for d in nmap_devices if d.get('ip')}
        # Keep track of non-IP devices separately
        non_ip_devices = [d for d in nmap_devices if not d.get('ip')]

        for ha_dev in ha_devices:
            attrs = ha_dev.get('attributes', {})
            ip = attrs.get('ip_address')
            
            # Prepare HA device info
            new_dev_entry = {
                "ip": ip if ip else "N/A",
                "mac": "Unknown", # HA states rarely show MAC
                "vendor": attrs.get('manufacturer', 'Unknown'),
                "model": attrs.get('model', 'Unknown'),
                "hostname": attrs.get('friendly_name', ha_dev['entity_id']),
                "openPorts": [],
                "osMatch": "Unknown",
                "source": "Home Assistant"
            }

            if ip and ip in merged:
                # MERGE: We found this IP in Nmap results. Enrich it.
                existing = merged[ip]
                existing['source'] = 'Merged (Nmap + HA)'
                if existing['vendor'] == "Unknown" and new_dev_entry['vendor'] != "Unknown":
                    existing['vendor'] = new_dev_entry['vendor']
                if new_dev_entry['model'] != "Unknown":
                    existing['model'] = new_dev_entry['model'] # Add model field
                # Prefer user-friendly hostname from HA
                existing['hostname'] = f"{existing['hostname']} ({new_dev_entry['hostname']})"
            else:
                # NEW FOUND: Either no IP (Zigbee?) or Nmap missed it
                merged[ip if ip else f"no_ip_{ha_dev['entity_id']}"] = new_dev_entry

        return list(merged.values()) + non_ip_devices

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

    def check_secure_by_default(self, device):
        """Check for weak credentials and insecure defaults."""
        details = []
        passed = True
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])
        
        # 1. Telnet Check (Port 23) - Active Credential Test
        if any(p['port'] == 23 for p in open_ports):
            details.append("Telnet (port 23) is open.")
            if ip and ip != "N/A":
                creds_found = self._check_telnet_auth(ip)
                if creds_found:
                    passed = False
                    details.append(f"CRITICAL: Found weak Telnet credentials: {creds_found}")
                else:
                    passed = False # Open telnet is bad regardless
                    details.append("Telnet login accessible (Brute-force failed but service is insecure).")

        # 2. HTTP Check (Port 80/8080) - Unauth Checks
        http_ports = [p['port'] for p in open_ports if p['service'] == 'http' or p['port'] in [80, 8080]]
        for port in http_ports:
            if ip and ip != "N/A":
                unauth_info = self._check_http_auth(ip, port)
                if unauth_info:
                    passed = False
                    details.append(f"Insecure HTTP on port {port}: {unauth_info}")

        if not details:
            details.append("No obvious weak default access vectors found.")

        return {"passed": passed, "details": "; ".join(details)}

    def _check_telnet_auth(self, ip):
        """Try common credentials on Telnet."""
        # Simple socket-based brute force
        for user, password in self.common_creds:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((ip, 23))
                # Very basic Telnet negotiation skip (will fail on complex telnet servers, efficient for IoT)
                # Receive banner
                data = s.recv(1024) 
                
                # Send User
                s.sendall(user.encode() + b"\r\n")
                time.sleep(0.5)
                data = s.recv(1024)
                
                # Send Pass
                s.sendall(password.encode() + b"\r\n")
                time.sleep(0.5)
                data = s.recv(1024)
                
                # Check for success (prompt like #, $, >)
                # This is heuristic.
                resp = data.decode('utf-8', errors='ignore')
                if "#" in resp or "$" in resp or ">" in resp or "Success" in resp:
                    s.close()
                    return f"{user}/{password}"
                s.close()
            except Exception:
                pass
        return None

    def _check_http_auth(self, ip, port):
        """Check for unauthenticated access to standard endpoints."""
        endpoints = ['/', '/status', '/config', '/api', '/settings']
        for ep in endpoints:
            try:
                url = f"http://{ip}:{port}{ep}"
                r = requests.get(url, timeout=2)
                if r.status_code == 200:
                    # Filter out simple login pages
                    if "login" not in r.text.lower() and "password" not in r.text.lower():
                        return f"Unauthenticated access to {ep}"
            except Exception:
                pass
        return None

    def _check_vendor_specifics(self, device):
        """Identify and check specific vendor vulnerabilities."""
        warnings = []
        ip = device.get('ip')
        ports = [int(p['port']) for p in device.get('openPorts', [])]
        
        if not ip or ip == "N/A": return []

        # Tuya
        if 6668 in ports:
            warnings.append("Possible Tuya Device (Port 6668 open). Ensure default keys are replaced.")

        # TP-Link Kasa
        if 9999 in ports:
             warnings.append("TP-Link Kasa Device (Port 9999). Old protocols may be vulnerable to local control injection.")

        # Sonoff LAN Mode
        if 8081 in ports:
             warnings.append("Sonoff Device in LAN Mode (Port 8081). Ensure local network is trusted.")

        # Shelly
        if 80 in ports:
            try:
                r = requests.get(f"http://{ip}/status", timeout=1)
                if r.status_code == 200 and "mac" in r.text: # Shelly JSON signature
                    if "auth" not in r.json() or not r.json().get("auth"):
                         warnings.append("Shelly Device: Authentication is NOT enabled for local web interface.")
            except: pass

        # Philips Hue
        if 80 in ports:
             try:
                r = requests.get(f"http://{ip}/description.xml", timeout=1)
                if r.status_code == 200 and "Philips hue" in r.text:
                    warnings.append("Philips Hue Bridge detected. Ensure 'Link Button' authentication is strictly required.")
             except: pass
        
        return warnings

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
        if not vendor or vendor == "Unknown":
             return {"passed": True, "details": "Vendor unknown, skipping CVE check.", "cves": []}

        # Clean vendor string for search
        search_term = vendor.split('(')[0].strip() # Remove extra info like (Running Linux...)
        
        cves = []
        try:
            # Using cve.circl.lu API
            url = f"https://cve.circl.lu/api/search/{search_term}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', [])[:5]: # Check first 5 matches
                    if 'cvss' in item and item['cvss'] and float(item['cvss']) > 9.0:
                        cves.append({
                            "id": item.get('id', 'Unknown'),
                            "severity": "CRITICAL",
                            "description": item.get('summary', 'No description')[:100] + "..."
                        })
            
        except Exception as e:
            logger.error(f"CVE lookup failed: {e}")
            return {"passed": True, "details": "CVE lookup failed (network error).", "cves": []}

        if cves:
             return {"passed": False, "details": f"Found {len(cves)} critical CVEs associated with '{search_term}'.", "cves": cves}

        return {"passed": True, "details": f"No critical CVEs found for '{search_term}'.", "cves": []}

# For standalone testing
if __name__ == "__main__":
    scanner = CRAScanner()
    print(scanner.scan_subnet("192.168.1.0/24"))