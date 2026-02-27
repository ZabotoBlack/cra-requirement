import re

file_path = "cra_auditor/tests/test_scan_logic.py"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

target = """    def test_calculate_attack_surface_score_high(self):
        \"\"\"5+ ports should be rated High.\"\"\"
        result = self.scanner.calculate_attack_surface_score([21, 22, 23, 80, 443, 1883, 8080, 8443, 53, 1900])
        self.assertEqual(result['rating'], 'High')
        self.assertEqual(result['score'], 10)
        self.assertEqual(result['openPortsCount'], 10)

    def test_check_https_redirect_passes_on_real_3xx_redirects(self):"""

replacement = """    def test_calculate_attack_surface_score_high(self):
        \"\"\"5+ ports should be rated High.\"\"\"
        result = self.scanner.calculate_attack_surface_score([21, 22, 23, 80, 443, 1883, 8080, 8443, 53, 1900])
        self.assertEqual(result['rating'], 'High')
        self.assertEqual(result['score'], 10)
        self.assertEqual(result['openPortsCount'], 10)

    def test_check_minimal_attack_surface_passes_normal(self):
        \"\"\"Minimal attack surface shouldn't flag a normal device.\"\"\"
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]
        }
        result = self.scanner.check_minimal_attack_surface(device)
        self.assertTrue(result['passed'])

    def test_check_minimal_attack_surface_fails_smb(self):
        \"\"\"Minimal attack surface should flag SMBv1 (port 445).\"\"\"
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 445, "service": "microsoft-ds"}]
        }
        result = self.scanner.check_minimal_attack_surface(device)
        self.assertFalse(result['passed'])
        self.assertIn("SMB", result['details'])

    def test_check_minimal_attack_surface_fails_upnp(self):
        \"\"\"Minimal attack surface should flag UPnP (port 1900).\"\"\"
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 1900, "service": "upnp"}]
        }
        result = self.scanner.check_minimal_attack_surface(device)
        self.assertFalse(result['passed'])
        self.assertIn("UPnP", result['details'])

    def test_check_minimal_attack_surface_passes_mdns_alone(self):
        \"\"\"mDNS on port 5353 alone shouldn't flag unless attack surface is large.\"\"\"
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 80, "service": "http"}, {"port": 5353, "service": "mdns"}]
        }
        result = self.scanner.check_minimal_attack_surface(device)
        self.assertTrue(result['passed'])

    def test_check_minimal_attack_surface_fails_mdns_with_high_attack_surface(self):
        \"\"\"mDNS on port 5353 should flag if > 5 open ports are present.\"\"\"
        device = {
            "ip": "192.168.1.10",
            "openPorts": [
                {"port": 22}, {"port": 80}, {"port": 443}, {"port": 8080}, 
                {"port": 8443}, {"port": 1883}, {"port": 5353}
            ]
        }
        result = self.scanner.check_minimal_attack_surface(device)
        self.assertFalse(result['passed'])
        self.assertIn("mDNS", result['details'])

    def test_check_https_redirect_passes_on_real_3xx_redirects(self):"""

if target in content:
    new_content = content.replace(target, replacement)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    print("Successfully added unit tests.")
else:
    print("Target content not found exactly!")
