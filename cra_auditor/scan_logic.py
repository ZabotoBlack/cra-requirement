import nmap
import requests
import socket
import logging
import os
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Known vendor SBOM availability status (best-effort lookup)
# Values: "available" = vendor publishes SBOMs, "unavailable" = known to NOT publish, "unknown" = no data
VENDOR_SBOM_STATUS = {
    "Philips": "available",
    "Signify": "available",        # Philips Hue parent company
    "Siemens": "available",
    "Bosch": "available",
    "Schneider Electric": "available",
    "ABB": "available",
    "Honeywell": "available",
    "Cisco": "available",
    "Intel": "available",
    "Microsoft": "available",
    "Google": "available",
    "Apple": "available",
    "Samsung": "available",
    "Tuya": "unavailable",
    "Sonoff": "unavailable",
    "ITEAD": "unavailable",        # Sonoff parent
    "Shelly": "unavailable",
    "Allterco": "unavailable",     # Shelly parent
    "TP-Link": "unavailable",
    "Kasa": "unavailable",
    "Tapo": "unavailable",
    "IKEA": "unknown",
    "AVM": "unknown",
    "Espressif": "unknown",
    "Xiaomi": "unavailable",
    "Aqara": "unavailable",
    "Meross": "unavailable",
    "Govee": "unavailable",
    "Wyze": "unavailable",
    "Ring": "unknown",
    "Amazon": "unknown",
    "Yamaha": "unknown",
}

class CRAScanner:
    def __init__(self):
        self.nm = None
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.error("Nmap not found", exc_info=True)
        except Exception:
            logger.error("Unexpected error initializing nmap", exc_info=True)
            
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            logger.warning("Agent is NOT running as root. ARP scanning and MAC address detection will likely fail. Ensure 'privileged: true' is set in config.yaml.")
        else:
            logger.info("Agent is running as root/privileged. ARP scanning and MAC address detection enabled.")
            
        self.common_creds = [('admin', 'admin'), ('root', 'root'), ('user', '1234'), ('admin', '1234')]
        self.verify_ssl = False  # Configurable: set True to enforce SSL certificate verification during probes

    def scan_subnet(self, subnet, options=None):
        """
        Scans the given subnet for devices using a hybrid approach (Nmap + HA API).
        
        options: {
            "scan_type": "discovery" | "standard" | "deep",
            "auth_checks": bool,
            "vendors": ["tuya", "shelly", "hue", "kasa", "sonoff", "ikea"] | "all"
        }
        """
        if options is None: options = {}
        scan_type = options.get('scan_type', 'deep')
        auth_checks = options.get('auth_checks', True)
        selected_vendors = options.get('vendors', 'all') # 'all' or list of strings

        ha_devices = self._get_ha_devices() 
        
        if not self.nm:
            logger.error("Nmap not initialized. Relying solely on Home Assistant data.")
            return self._merge_devices([], ha_devices)

        # Scanned devices accumulator (IP -> Device Dict)
        scanned_devices = {}

        # Stage 1: Discovery Scan (Ping + ARP)
        logger.info(f"Starting discovery scan on {subnet}")
        try:
            self.nm.scan(hosts=subnet, arguments='-sn -PR')
            self._update_scanned_devices(scanned_devices, discovery_phase=True)
        except Exception as e:
            logger.error(f"Nmap discovery scan failed: {e}")
            return self._merge_devices([], ha_devices)

        hosts_to_scan = list(scanned_devices.keys())
        logger.info(f"Discovery complete. Found {len(hosts_to_scan)} live hosts.")

        nmap_devices = []
        
        # If discovery only, skip detailed scan
        if hosts_to_scan and scan_type != 'discovery':
            # Stage 2: Detailed Scan
            logger.info(f"Starting detailed scan mode: {scan_type}")
            
            target_spec = " ".join(hosts_to_scan)
            
            # Build Nmap Arguments based on Options
            # Base arguments
            nmap_args = "-Pn" # Treat as online

            # Vendor Specific Ports (collected first to build unified port list)
            vendor_ports = []
            if selected_vendors == 'all' or 'tuya' in selected_vendors:
                vendor_ports.append('6668')
            if selected_vendors == 'all' or 'sonoff' in selected_vendors:
                vendor_ports.append('8081')
            if selected_vendors == 'all' or 'kasa' in selected_vendors:
                vendor_ports.append('9999')

            # Scan Type Depth
            # Note: --top-ports and -p conflict (nmap ignores --top-ports when -p is set).
            # So we build a single -p specification that covers both.
            if scan_type == 'deep':
                nmap_args += " -sV -O --script=nbstat"
                # Top 1000 ports + vendor ports
                port_spec = "1-1024"
                if vendor_ports:
                    port_spec += "," + ",".join(vendor_ports)
                nmap_args += f" -p {port_spec}"
            elif scan_type == 'standard':
                nmap_args += " -sV --script=nbstat"
                # Top 100 ports approximation + vendor ports
                port_spec = "1-100"
                if vendor_ports:
                    port_spec += "," + ",".join(vendor_ports)
                nmap_args += f" -p {port_spec}"
            else:
                nmap_args += " -F" # Fast scan (top 100 ports) if unnamed type
            
            try:
                logger.info(f"Running Nmap with args: {nmap_args}")
                self.nm.scan(hosts=target_spec, arguments=nmap_args)
                self._update_scanned_devices(scanned_devices, discovery_phase=False)
                logger.info(f"Detailed scan complete. Updated {len(scanned_devices)} devices.")
            except Exception as e:
                logger.error(f"Nmap detail scan failed: {e}. Falling back to discovery results ({len(scanned_devices)} devices).")
        
        nmap_devices = list(scanned_devices.values())

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

            # ENHANCED CHECKS - Conditional
            sbd_result = {"passed": True, "details": "Skipped auth checks."}
            if auth_checks:
                sbd_result = self.check_secure_by_default(dev)
            
            conf_result = self.check_confidentiality(dev.get('openPorts', []))
            vuln_result = self.check_vulnerabilities(check_vendor, dev.get('openPorts', []))
            sbom_result = self.check_sbom_compliance(dev)
            
            # Vendor Specific Checks - Conditional
            vendor_warnings = self._check_vendor_specifics(dev, selected_vendors)
            if vendor_warnings:
                if sbd_result['details'] == "Skipped auth checks.":
                     sbd_result['details'] = ""
                     
                sbd_result['details'] += " " + "; ".join(vendor_warnings)
                sbd_result['passed'] = False
                
            status = "Compliant"
            if not sbd_result['passed'] or not vuln_result['passed']:
                status = "Non-Compliant"
            elif not conf_result['passed'] or not sbom_result['passed']:
                status = "Warning"

            dev.update({
                "status": status,
                "checks": {
                    "secureByDefault": sbd_result,
                    "dataConfidentiality": conf_result,
                    "vulnerabilities": vuln_result,
                    "sbomCompliance": sbom_result
                },
                "lastScanned": "Just now"
            })
            final_results.append(dev)
            
        logger.info(f"Detailed scan complete. Processed {len(final_results)} devices.")
        return final_results

    def _update_scanned_devices(self, scanned_devices, discovery_phase=False):
        """Helper to parse nmap results and update the devices dict."""
        for host in self.nm.all_hosts():
            # Filter out if no addresses found (rare but possible)
            if 'addresses' not in self.nm[host]:
                continue
                
            nmap_host = self.nm[host]
            # Use bracket access as existing tests mock __getitem__ but not .get()
            addresses = nmap_host['addresses']
            
            mac = addresses.get('mac', 'Unknown')
            ip = host
            if 'ipv4' in addresses:
                ip = addresses.get('ipv4')
            
            # If this is the second pass (detailed), we might already have this device.
            existing = scanned_devices.get(ip)
            
            # Hostname Resolution
            hostname = nmap_host.hostname()
            if not hostname and 'script' in nmap_host:
                # Try to extract from nbstat
                if 'nbstat' in nmap_host['script']:
                    import re
                    match = re.search(r"NetBIOS name:\s+([\w-]+)", nmap_host['script']['nbstat'])
                    if match:
                        hostname = match.group(1)
            
            if not hostname and discovery_phase:
                 # Try reverse DNS only in discovery or if missing
                 try:
                    hostname = socket.gethostbyaddr(ip)[0]
                 except Exception:
                    pass
            elif not hostname and existing and existing.get('hostname'):
                 # Keep existing hostname if new one is empty
                 hostname = existing.get('hostname')
            # Vendor
            vendor = "Unknown"
            if 'vendor' in nmap_host and mac != 'Unknown' and mac in nmap_host['vendor']:
                    vendor = nmap_host['vendor'][mac]
            
            os_name = self._get_os_match(host)
            open_ports = self._get_open_ports(host)
            
            # MERGE LOGIC: preserve existing data if new scan is incomplete
            if existing:
                if mac == 'Unknown' and existing.get('mac') != 'Unknown':
                    mac = existing.get('mac')
                
                if vendor == "Unknown" and existing.get('vendor') != "Unknown":
                    vendor = existing.get('vendor')
                
                if not hostname and existing.get('hostname'):
                    hostname = existing.get('hostname')
                
                if os_name == "Unknown" and existing.get('osMatch', "Unknown") != "Unknown":
                    os_name = existing.get('osMatch')
                
                # Ports: Detailed scan is usually authoritative.
                # But if detailed scan returned nothing (e.g. failed/filtered) AND we had ports (unlikely for discovery but consistent logic), we could keep.
                # For now, we assume detailed scan overwrite for ports is acceptable as discovery has none.

            device_data = {
                "ip": ip,
                "mac": mac,
                "vendor": vendor, 
                "hostname": hostname,
                "openPorts": open_ports,
                "osMatch": os_name,
                "source": "nmap"
            }
            
            scanned_devices[ip] = device_data

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

    def _check_vendor_specifics(self, device, selected_vendors='all'):
        """Identify and check specific vendor vulnerabilities."""
        warnings = []
        ip = device.get('ip')
        ports = [int(p['port']) for p in device.get('openPorts', [])]
        
        if not ip or ip == "N/A": return []
        
        # Tuya
        if (selected_vendors == 'all' or 'tuya' in selected_vendors) and 6668 in ports:
            warnings.append("Possible Tuya Device (Port 6668 open). Ensure default keys are replaced.")

        # TP-Link Kasa
        if (selected_vendors == 'all' or 'kasa' in selected_vendors) and 9999 in ports:
             warnings.append("TP-Link Kasa Device (Port 9999). Old protocols may be vulnerable to local control injection.")

        # Sonoff LAN Mode
        if (selected_vendors == 'all' or 'sonoff' in selected_vendors) and 8081 in ports:
             warnings.append("Sonoff Device in LAN Mode (Port 8081). Ensure local network is trusted.")

        # Shelly
        if (selected_vendors == 'all' or 'shelly' in selected_vendors) and 80 in ports:
            try:
                r = requests.get(f"http://{ip}/status", timeout=1)
                if r.status_code == 200 and "mac" in r.text: # Shelly JSON signature
                    if "auth" not in r.json() or not r.json().get("auth"):
                         warnings.append("Shelly Device: Authentication is NOT enabled for local web interface.")
            except Exception: pass

        # Philips Hue
        if (selected_vendors == 'all' or 'hue' in selected_vendors) and 80 in ports:
             try:
                r = requests.get(f"http://{ip}/description.xml", timeout=1)
                if r.status_code == 200 and "Philips hue" in r.text:
                    warnings.append("Philips Hue Bridge detected. Ensure 'Link Button' authentication is strictly required.")
             except Exception: pass
        
        # Ikea
        if (selected_vendors == 'all' or 'ikea' in selected_vendors) and 80 in ports:
             # Basic header check for Ikea gateway signature (heuristic)
             try:
                 r = requests.get(f"http://{ip}", timeout=1)
                 if "IKEA" in r.text or "Tradfri" in r.text:
                      warnings.append("IKEA Gateway detected. Ensure latest firmware to avoid known zigbee crash exploits.")
             except Exception: pass

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

    def check_sbom_compliance(self, device):
        """Check for SBOM availability per CRA Annex I §2(1).
        
        Two-layer approach:
        1. Device-level: probe well-known HTTP endpoints for SBOM files
        2. Vendor-level: lookup known vendor SBOM publication status
        """
        details = []
        sbom_found = False
        sbom_format = None
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])
        vendor = device.get('vendor', 'Unknown')
        
        # Layer 1: Device-level SBOM endpoint probing
        http_ports = [p['port'] for p in open_ports 
                      if p.get('service') in ('http', 'https') or p['port'] in (80, 443, 8080, 8443)]
        
        if ip and ip != "N/A" and http_ports:
            sbom_found, sbom_format = self._probe_sbom_endpoints(ip, http_ports)
            if sbom_found:
                details.append(f"SBOM endpoint found on device (format: {sbom_format}).")
        
        # Layer 2: Vendor-level SBOM status lookup
        vendor_status = self._lookup_vendor_sbom_status(vendor)
        
        if sbom_found:
            # Best case: device directly exposes SBOM
            return {
                "passed": True,
                "details": "; ".join(details),
                "sbom_found": True,
                "sbom_format": sbom_format
            }
        elif vendor_status == "available":
            details.append(f"Vendor '{vendor}' is known to publish SBOMs for their products.")
            return {
                "passed": True,
                "details": "; ".join(details),
                "sbom_found": False,
                "sbom_format": None
            }
        elif vendor_status == "unavailable":
            details.append(f"No SBOM endpoint found on device. Vendor '{vendor}' does not publish SBOMs.")
            return {
                "passed": False,
                "details": "; ".join(details) if details else f"No SBOM found. Vendor '{vendor}' has no known SBOM publication.",
                "sbom_found": False,
                "sbom_format": None
            }
        else:
            # Unknown vendor or vendor status
            if vendor == "Unknown":
                details.append("Vendor unknown — cannot determine SBOM availability.")
            else:
                details.append(f"No SBOM endpoint found on device. Vendor '{vendor}' SBOM status is unknown.")
            return {
                "passed": False,
                "details": "; ".join(details),
                "sbom_found": False,
                "sbom_format": None
            }

    def _probe_sbom_endpoints(self, ip, http_ports):
        """Probe well-known SBOM endpoints on a device.
        
        Returns (sbom_found: bool, sbom_format: str|None)
        """
        sbom_paths = [
            '/.well-known/sbom',
            '/sbom.json',
            '/sbom.xml',
            '/sbom',
        ]
        
        # CycloneDX and SPDX content-type indicators
        sbom_signatures = {
            'cyclonedx': 'CycloneDX',
            'spdx': 'SPDX',
            'bomFormat': 'CycloneDX',     # CycloneDX JSON key
            'SPDXVersion': 'SPDX',        # SPDX JSON key
            'DocumentNamespace': 'SPDX',  # SPDX JSON key
        }
        
        for port in http_ports:
            scheme = 'https' if port in (443, 8443) else 'http'
            for path in sbom_paths:
                url = f"{scheme}://{ip}:{port}{path}"
                try:
                    if not self.verify_ssl:
                        logger.warning(f"SBOM probe: SSL verification disabled for {url} (verify_ssl=False)")
                    r = requests.get(url, timeout=2, verify=self.verify_ssl)
                    if r.status_code == 200 and len(r.text) > 50:
                        # Check content for known SBOM format signatures
                        content = r.text[:2000]  # Only check first 2KB
                        for signature, fmt in sbom_signatures.items():
                            if signature in content:
                                return True, fmt
                        
                        # Check Content-Type header
                        ct = r.headers.get('Content-Type', '').lower()
                        if 'cyclonedx' in ct:
                            return True, 'CycloneDX'
                        elif 'spdx' in ct:
                            return True, 'SPDX'
                        
                        # Generic: looks like a valid document but unknown format
                        if r.headers.get('Content-Type', '').startswith(('application/json', 'application/xml', 'text/xml')):
                            return True, 'Unknown Format'
                except Exception as e:
                    logger.debug(f"SBOM probe failed for {url}: {e}")
        
        return False, None

    def _lookup_vendor_sbom_status(self, vendor):
        """Check if vendor is known to publish SBOMs.
        
        Returns 'available', 'unavailable', or 'unknown'.
        """
        if not vendor or vendor == "Unknown":
            return "unknown"
        
        # Check exact match first
        if vendor in VENDOR_SBOM_STATUS:
            return VENDOR_SBOM_STATUS[vendor]
        
        # Check partial match (e.g. "Philips Lighting" matches "Philips")
        vendor_lower = vendor.lower()
        for known_vendor, status in VENDOR_SBOM_STATUS.items():
            if known_vendor.lower() in vendor_lower or vendor_lower in known_vendor.lower():
                return status
        
        return "unknown"

# For standalone testing
if __name__ == "__main__":
    scanner = CRAScanner()
    print(scanner.scan_subnet("192.168.1.0/24"))