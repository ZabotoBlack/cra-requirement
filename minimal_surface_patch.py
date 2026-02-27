import re

file_path = "cra_auditor/scan_logic.py"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

target = """    def calculate_attack_surface_score(self, open_ports):
        \"\"\"Score device attack surface based on exposed open ports.

        CRA relevance: Annex I §1(3)(h) minimization of attack surface.
        \"\"\"
        open_ports = open_ports or []

        if not isinstance(open_ports, list):
            open_ports = []

        normalized_ports = []
        for port_info in open_ports:
            if isinstance(port_info, dict):
                port_value = port_info.get('port')
            else:
                port_value = port_info

            try:
                normalized_ports.append(int(port_value))
            except (TypeError, ValueError):
                continue

        open_ports_count = len(normalized_ports)
        score = open_ports_count

        if score <= 1:
            rating = "Low"
            details = f"{open_ports_count} ports open. Attack surface is minimal."
        elif score <= 4:
            rating = "Medium"
            details = f"{open_ports_count} ports open. Consider disabling unused services."
        else:
            rating = "High"
            details = f"{open_ports_count} ports open. Potentially excessive exposure; minimize unnecessary services."

        return {
            "score": score,
            "rating": rating,
            "openPortsCount": open_ports_count,
            "details": details
        }"""

replacement = target + """

    def check_minimal_attack_surface(self, device):
        \"\"\"Check if the device exposes a minimal attack surface per CRA Annex I §1(3)(e).

        Fails if the device exposes risky legacy services (UPnP, SMB) or discovery 
        services (mDNS) alongside an excessive number of other open ports.
        \"\"\"
        open_ports = device.get('openPorts', []) or []
        normalized_ports = []
        for p in open_ports:
            if not isinstance(p, dict):
                continue
            port = self._normalize_port(p.get('port'))
            if port is not None:
                normalized_ports.append(port)

        unique_ports = set(normalized_ports)
        other_ports = unique_ports - {5353}

        risky_ports_found = []
        
        # Check for UPnP (5000, 1900)
        if 5000 in unique_ports or 1900 in unique_ports:
            risky_ports_found.append('UPnP (port 5000/1900)')
            
        # Check for SMB (139, 445)
        if 139 in unique_ports or 445 in unique_ports:
            risky_ports_found.append('SMB (port 139/445)')
            
        # Check for mDNS (5353) combined with excessive attack surface
        if 5353 in unique_ports and len(other_ports) >= 5:
            risky_ports_found.append('mDNS (port 5353) alongside >= 5 other ports')
            
        if risky_ports_found:
            return {
                'passed': False,
                'details': f"Excessive or risky interfaces exposed: {', '.join(risky_ports_found)}. Minimise attack surface."
            }
            
        return {
            'passed': True,
            'details': "No excessively risky interfaces (UPnP, SMB) or unnecessarily exposed metadata services detected."
        }"""

if target in content:
    new_content = content.replace(target, replacement)
    
    # Second replacement inside scan_subnet
    target_scan = """                if vendor_warnings:
                    if sbd_result['details'].startswith("Skipped"):
                        sbd_result['details'] = ""
                    sep = " " if sbd_result['details'] else ""
                    sbd_result['details'] += sep + "; ".join(vendor_warnings)
                    sbd_result['passed'] = False

                status = "Compliant"
                if not sbd_result['passed'] or not https_result['passed'] or not vuln_result['passed'] or (not fw_result['passed'] and fw_result.get('version_cves')):
                    status = "Non-Compliant"
                elif not conf_result['passed'] or not sbom_result['passed'] or not fw_result['passed'] or not sec_txt_result['passed'] or not sec_log_result['passed']:
                    status = "Warning"
                elif attack_surface['rating'] == "High":
                    status = "Warning"

                _p = lambda r: "pass" if r.get('passed') else "FAIL"
                _log_scan_info(
                    f"[SCAN]     Secure={_p(sbd_result)}  Confid={_p(conf_result)}  "
                    f"AttackSurface={attack_surface['rating']}({attack_surface['openPortsCount']})  "
                    f"HTTPS={_p(https_result)}  CVE={_p(vuln_result)}  SBOM={_p(sbom_result)}  "
                    f"FW={_p(fw_result)}  SecTxt={_p(sec_txt_result)}  SecLog={_p(sec_log_result)}  => {status}"
                )

                dev.update({
                    "status": status,
                    "attackSurface": attack_surface,
                    "checks": {
                        "secureByDefault": sbd_result,
                        "dataConfidentiality": conf_result,
                        "httpsOnlyManagement": https_result,
                        "vulnerabilities": vuln_result,
                        "sbomCompliance": sbom_result,
                        "firmwareTracking": fw_result,
                        "securityTxt": sec_txt_result,
                        "securityLogging": sec_log_result
                    },
                    "lastScanned": scan_timestamp
                })
                final_results.append(dev)"""
                
    replacement_scan = """                if vendor_warnings:
                    if sbd_result['details'].startswith("Skipped"):
                        sbd_result['details'] = ""
                    sep = " " if sbd_result['details'] else ""
                    sbd_result['details'] += sep + "; ".join(vendor_warnings)
                    sbd_result['passed'] = False
                    
                mas_result = self.check_minimal_attack_surface(dev)

                status = "Compliant"
                if not sbd_result['passed'] or not https_result['passed'] or not vuln_result['passed'] or (not fw_result['passed'] and fw_result.get('version_cves')):
                    status = "Non-Compliant"
                elif not mas_result['passed']:
                    # Minimal Attack Surface failures are grounds for strict non-compliance under CRA requirements
                    status = "Non-Compliant"
                elif not conf_result['passed'] or not sbom_result['passed'] or not fw_result['passed'] or not sec_txt_result['passed'] or not sec_log_result['passed']:
                    status = "Warning"
                elif attack_surface['rating'] == "High":
                    status = "Warning"

                _p = lambda r: "pass" if r.get('passed') else "FAIL"
                _log_scan_info(
                    f"[SCAN]     Secure={_p(sbd_result)}  Confid={_p(conf_result)}  "
                    f"AttackSurface={attack_surface['rating']}({attack_surface['openPortsCount']})  "
                    f"MinSurface={_p(mas_result)}  "
                    f"HTTPS={_p(https_result)}  CVE={_p(vuln_result)}  SBOM={_p(sbom_result)}  "
                    f"FW={_p(fw_result)}  SecTxt={_p(sec_txt_result)}  SecLog={_p(sec_log_result)}  => {status}"
                )

                dev.update({
                    "status": status,
                    "attackSurface": attack_surface,
                    "checks": {
                        "secureByDefault": sbd_result,
                        "dataConfidentiality": conf_result,
                        "httpsOnlyManagement": https_result,
                        "vulnerabilities": vuln_result,
                        "sbomCompliance": sbom_result,
                        "firmwareTracking": fw_result,
                        "securityTxt": sec_txt_result,
                        "securityLogging": sec_log_result,
                        "minimalAttackSurface": mas_result
                    },
                    "lastScanned": scan_timestamp
                })
                final_results.append(dev)"""
                
    if target_scan in new_content:
        new_content = new_content.replace(target_scan, replacement_scan)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        print("Successfully applied both patches.")
    else:
        print("Applied first patch, but second target not found!")
else:
    print("First target content not found exactly!")
