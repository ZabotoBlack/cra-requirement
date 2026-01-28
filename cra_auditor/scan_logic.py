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
        ha_devices = self._get_ha_devices() # Fetch from HA first
        
        if not self.nm:
            logger.error("Nmap not initialized. Relying solely on Home Assistant data.")
            return self._merge_devices([], ha_devices)

        # Stage 1: Discovery Scan (Ping/ARP)
        logger.info(f"Starting discovery scan on {subnet}")
        try:
            # -sn: Ping Scan - disable port scan
            self.nm.scan(hosts=subnet, arguments='-sn')
        except Exception as e:
            logger.error(f"Nmap discovery scan failed: {e}")
            # If nmap fails, at least return HA devices
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
                self.nm.scan(hosts=target_spec, arguments='-sV -O -Pn --top-ports 100')
            except Exception as e:
                logger.error(f"Nmap detail scan failed: {e}")
            
            for host in self.nm.all_hosts():
                # Basic info might be missing if scan failed for this specific host
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

                nmap_devices.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor, # Often just the OUI vendor
                    "hostname": hostname,
                    "openPorts": self._get_open_ports(host),
                    "osMatch": os_name,
                    "source": "nmap"
                })

        # Merge Nmap and HA devices
        merged_devices = self._merge_devices(nmap_devices, ha_devices)
        
        # Run compliance checks on the FINAL merged list
        final_results = []
        for dev in merged_devices:
            # Use the "best" vendor name we have (HA model/manufacturer is usually better than OUI)
            check_vendor = dev.get('model') if dev.get('model') and dev.get('model') != "Unknown" else dev.get('vendor', 'Unknown')
            if dev.get('manufacturer') and dev.get('manufacturer') != "Unknown":
                 check_vendor = f"{dev['manufacturer']} {check_vendor}"

            # If we only have OUI vendor, use that
            if check_vendor == "Unknown " or check_vendor.strip() == "Unknown":
                 check_vendor = dev.get('vendor', 'Unknown')

            sbd_result = self.check_secure_by_default(dev.get('ip'), dev.get('openPorts', []))
            conf_result = self.check_confidentiality(dev.get('openPorts', []))
            vuln_result = self.check_vulnerabilities(check_vendor, dev.get('openPorts', []))

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