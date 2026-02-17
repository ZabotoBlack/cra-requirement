import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Ensure we can import scan_logic from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan_logic import CRAScanner

class TestCRAScanner(unittest.TestCase):

    @patch('scan_logic.nmap.PortScanner')
    def setUp(self, mock_nmap):
        # Setup the scanner with a mocked nmap object
        self.mock_nmap_cls = mock_nmap
        self.scanner = CRAScanner()
        self.scanner.nm = MagicMock()
        
    def test_init_nmap_success(self):
        """Test successful initialization."""
        self.assertIsNotNone(self.scanner.nm)

    @patch('scan_logic.logger')
    @patch('scan_logic.nmap.PortScanner', side_effect=Exception("Nmap missing"))
    def test_init_nmap_failure(self, mock_nmap, mock_logger):
        """Test graceful failure when nmap is missing."""
        scanner = CRAScanner()
        self.assertIsNone(scanner.nm)
        mock_logger.error.assert_called_with("Unexpected error initializing nmap", exc_info=True)

    def test_scan_arguments_discovery(self):
        """Verify arguments for Discovery scan."""
        self.scanner.nm.all_hosts.return_value = [] # No hosts found
        
        options = {"scan_type": "discovery"}
        self.scanner.scan_subnet("192.168.1.0/24", options)
        
        # Verify call to scan
        self.scanner.nm.scan.assert_called_with(hosts="192.168.1.0/24", arguments='-sn -PR')
        
    def test_scan_arguments_deep(self):
        """Verify arguments for Deep scan."""
        # Setup mock host data so discovery phase populates scanned_devices
        host_ip = "192.168.1.50"
        self.scanner.nm.all_hosts.return_value = [host_ip]

        mock_host_data = MagicMock()
        mock_host_data.hostname.return_value = "test-host"
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {'ipv4': host_ip, 'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'},
            'osmatch': [],
        }.get(key, {})
        mock_host_data.__contains__.side_effect = lambda key: key in ['addresses', 'vendor', 'osmatch']
        mock_host_data.all_protocols.return_value = []
        self.scanner.nm.__getitem__.return_value = mock_host_data

        options = {"scan_type": "deep"}
        self.scanner.scan_subnet("192.168.1.0/24", options)

        # Check that the SECOND scan was called with deep arguments
        # We expect at least two calls: 1. Discovery, 2. Detailed
        calls = self.scanner.nm.scan.call_args_list
        self.assertTrue(len(calls) >= 2)

        # Inspect the detailed scan call
        args, kwargs = calls[1]
        self.assertEqual(kwargs['hosts'], host_ip)
        self.assertIn("-sV -O", kwargs['arguments'])
        self.assertIn("--script=nbstat", kwargs['arguments'])

    def test_scan_arguments_vendor_specific(self):
        """Verify vendor specific port addition."""
        # Setup mock host data so discovery phase populates scanned_devices
        host_ip = "192.168.1.50"
        self.scanner.nm.all_hosts.return_value = [host_ip]

        mock_host_data = MagicMock()
        mock_host_data.hostname.return_value = "test-host"
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {'ipv4': host_ip, 'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'},
            'osmatch': [],
        }.get(key, {})
        mock_host_data.__contains__.side_effect = lambda key: key in ['addresses', 'vendor', 'osmatch']
        mock_host_data.all_protocols.return_value = []
        self.scanner.nm.__getitem__.return_value = mock_host_data

        options = {"scan_type": "standard", "vendors": ["tuya"]}
        self.scanner.scan_subnet("192.168.1.0/24", options)

        calls = self.scanner.nm.scan.call_args_list
        detailed_call = calls[1] # 0 is discovery, 1 is detailed

        args_str = detailed_call.kwargs['arguments']
        self.assertIn("6668", args_str, "Tuya port 6668 should be scanned")
        self.assertNotIn("8081", args_str, "Sonoff port shouldn't be scanned")

    def test_result_parsing_hostname_logic(self):
        """Test hostname extraction from Nmap results."""
        # Setup mock data for a host
        host_ip = "192.168.1.50"
        self.scanner.nm.all_hosts.return_value = [host_ip]
        
        # Mock nmap object dictionary access
        mock_host_data = MagicMock()
        mock_host_data.hostname.return_value = "" # No hostname from standard lookup
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {'ipv4': host_ip, 'mac': 'AA:BB:CC:DD:EE:FF'},
            'script': {'nbstat': "NetBIOS name: DESKTOP-TEST\n"},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'}
        }.get(key, {})
        mock_host_data.__contains__.side_effect = lambda key: key in ['addresses', 'script', 'vendor']
        
        self.scanner.nm.__getitem__.return_value = mock_host_data
        
        result = self.scanner.scan_subnet("192.168.1.0/24", {"scan_type": "discovery"})
        
        # Should have extracted hostname from nbstat script
        self.assertEqual(result[0]['hostname'], "DESKTOP-TEST")
        self.assertEqual(result[0]['vendor'], "TestVendor")

    @patch('scan_logic.CRAScanner._get_ha_devices')
    def test_merge_logic(self, mock_get_ha):
        """Test merging of Nmap and HA devices."""
        # HA Device
        mock_get_ha.return_value = [{
            "entity_id": "switch.ha_device",
            "attributes": {
                "friendly_name": "HA Switch",
                "ip_address": "192.168.1.50", # Matches Nmap
                "manufacturer": "HA_Vendor",
                "model": "HA_Model"
            }
        }]
        
        # Nmap Device
        host_ip = "192.168.1.50"
        self.scanner.nm.all_hosts.return_value = [host_ip]
        mock_host_data = MagicMock()
        mock_host_data.hostname.return_value = "Nmap_Host"
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {'ipv4': host_ip, 'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {}
        }.get(key, {})
        mock_host_data.__contains__.side_effect = lambda key: key in ['addresses', 'vendor']
        self.scanner.nm.__getitem__.return_value = mock_host_data
        
        results = self.scanner.scan_subnet("192.168.1.0/24", {"scan_type": "discovery"})
        
        self.assertEqual(len(results), 1)
        device = results[0]
        # Check merge priority
        self.assertEqual(device['mac'], "AA:BB:CC:DD:EE:FF") # From Nmap
        self.assertEqual(device['model'], "HA_Model") # From HA
        self.assertEqual(device['vendor'], "HA_Vendor") # Unknown in Nmap, so took HA
        self.assertIn("Nmap_Host", device['hostname'])
        self.assertIn("HA Switch", device['hostname']) # Logic is: f"{existing} ({new})"

    @patch('scan_logic.CRAScanner._check_telnet_auth')
    def test_check_secure_by_default_telnet(self, mock_check_auth):
        """Test weak credential detection logic (high level)."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 23, "service": "telnet", "protocol": "tcp"}]
        }
        
        # Simulate auth success
        mock_check_auth.return_value = "admin/admin"
        
        result = self.scanner.check_secure_by_default(device)
        
        self.assertFalse(result['passed'], "Should fail passed check")
        self.assertIn("CRITICAL: Found weak Telnet credentials", result['details'])


    def test_check_vendor_specifics_shelly(self):
        """Test Shelly specific check for auth."""
        device = {
            "ip": "192.168.1.20",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}],
            "vendor": "Shelly"
        }
        
        # Mock Shelly Status response without auth enabled
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"mac": "aabbcc", "auth": false}'
        mock_response.json.return_value = {"auth": False}
        self.scanner.session.get = MagicMock(return_value=mock_response)
        
        warnings = self.scanner._check_vendor_specifics(device, ["shelly"])
        
        self.assertTrue(len(warnings) > 0)
        self.assertIn("Authentication is NOT enabled", warnings[0])

    def test_check_confidentiality_unencrypted_ports(self):
        """Test that unencrypted ports are flagged."""
        open_ports = [
            {"port": 21, "service": "ftp", "protocol": "tcp"},
            {"port": 23, "service": "telnet", "protocol": "tcp"},
            {"port": 443, "service": "https", "protocol": "tcp"},
        ]
        result = self.scanner.check_confidentiality(open_ports)
        self.assertFalse(result['passed'])
        self.assertIn("ftp/21", result['details'])
        self.assertIn("telnet/23", result['details'])
        self.assertNotIn("443", result['details'])

    def test_check_confidentiality_all_encrypted(self):
        """Test that encrypted-only ports pass."""
        open_ports = [
            {"port": 443, "service": "https", "protocol": "tcp"},
            {"port": 8443, "service": "https-alt", "protocol": "tcp"},
        ]
        result = self.scanner.check_confidentiality(open_ports)
        self.assertTrue(result['passed'])

    @patch('scan_logic.CRAScanner._probe_udp_syslog', return_value=(True, 'open|filtered'))
    def test_check_security_logging_passes_on_udp_514(self, mock_udp_probe):
        """Security logging passes when UDP/514 appears reachable."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": []
        }

        result = self.scanner.check_security_logging(device)
        self.assertTrue(result['passed'])
        self.assertTrue(result['syslog_udp_514'])
        self.assertIn('UDP/514', result['details'])
        mock_udp_probe.assert_called_once_with("192.168.1.10")

    @patch('scan_logic.CRAScanner._probe_udp_syslog', return_value=(False, 'closed'))
    def test_check_security_logging_passes_on_http_log_endpoint(self, mock_udp_probe):
        """Security logging passes when a log API endpoint exists."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        self.scanner.session.get = MagicMock(return_value=mock_response)

        device = {
            "ip": "192.168.1.20",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}]
        }

        result = self.scanner.check_security_logging(device)
        self.assertTrue(result['passed'])
        self.assertFalse(result['syslog_udp_514'])
        self.assertTrue(len(result['logging_endpoints']) > 0)
        self.assertIn('/api/logs', result['logging_endpoints'][0])
        mock_udp_probe.assert_called_once_with("192.168.1.20")

    @patch('scan_logic.CRAScanner._probe_udp_syslog', return_value=(False, 'closed'))
    def test_check_security_logging_warns_when_not_detected(self, mock_udp_probe):
        """Security logging returns warning signal when no mechanism is externally detected."""
        self.scanner.session.get = MagicMock(side_effect=Exception("Connection refused"))
        device = {
            "ip": "192.168.1.30",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}]
        }

        result = self.scanner.check_security_logging(device)
        self.assertFalse(result['passed'])
        self.assertFalse(result['syslog_udp_514'])
        self.assertEqual(result['logging_endpoints'], [])
        self.assertIn('Warning', result['details'])
        mock_udp_probe.assert_called_once_with("192.168.1.30")

    def test_calculate_attack_surface_score_low(self):
        """0-1 ports should be rated Low."""
        result = self.scanner.calculate_attack_surface_score([])
        self.assertEqual(result['rating'], 'Low')
        self.assertEqual(result['score'], 0)
        self.assertEqual(result['openPortsCount'], 0)

    def test_calculate_attack_surface_score_medium(self):
        """2-4 ports should be rated Medium."""
        result = self.scanner.calculate_attack_surface_score([80, 443])
        self.assertEqual(result['rating'], 'Medium')
        self.assertEqual(result['score'], 2)
        self.assertEqual(result['openPortsCount'], 2)

    def test_calculate_attack_surface_score_high(self):
        """5+ ports should be rated High."""
        result = self.scanner.calculate_attack_surface_score([21, 22, 23, 80, 443, 1883, 8080, 8443, 53, 1900])
        self.assertEqual(result['rating'], 'High')
        self.assertEqual(result['score'], 10)
        self.assertEqual(result['openPortsCount'], 10)

    def test_check_https_redirect_passes_on_301_to_https(self):
        """HTTP management port should pass when it redirects to HTTPS."""
        mock_response = MagicMock()
        mock_response.status_code = 301
        mock_response.headers = {"Location": "https://192.168.1.10/login"}
        self.scanner.session.get = MagicMock(return_value=mock_response)

        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}]
        }

        result = self.scanner.check_https_redirect(device)
        self.assertTrue(result['passed'])
        self.assertEqual(result['failed_ports'], [])
        self.assertIn(80, result['checked_ports'])

    def test_check_https_redirect_fails_on_http_200(self):
        """HTTP management port should fail when served in cleartext."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        self.scanner.session.get = MagicMock(return_value=mock_response)

        device = {
            "ip": "192.168.1.20",
            "openPorts": [{"port": 8080, "service": "http", "protocol": "tcp"}]
        }

        result = self.scanner.check_https_redirect(device)
        self.assertFalse(result['passed'])
        self.assertIn(8080, result['failed_ports'])
        self.assertIn("without HTTPS redirect", result['details'])

    def test_check_https_redirect_skips_without_http_ports(self):
        """No HTTP management ports should be treated as skipped/passed."""
        device = {
            "ip": "192.168.1.30",
            "openPorts": [{"port": 22, "service": "ssh", "protocol": "tcp"}]
        }

        result = self.scanner.check_https_redirect(device)
        self.assertTrue(result['passed'])
        self.assertEqual(result['checked_ports'], [])
        self.assertIn("No HTTP management ports", result['details'])

    def test_check_vulnerabilities_critical_cve(self):
        """Test that critical CVEs are detected."""
        self.scanner._resolve_device_cpe = MagicMock(return_value="cpe:2.3:o:testvendor:testproduct:1.0:*:*:*:*:*:*:*")
        self.scanner.nvd_client.get_cves_for_cpe = MagicMock(return_value=[
            {"id": "CVE-2024-1234", "severity": "CRITICAL", "score": 9.8, "description": "Critical RCE vulnerability"}
        ])

        result = self.scanner.check_vulnerabilities("TestVendor", [])
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['cves']), 1)
        self.assertEqual(result['cves'][0]['severity'], "CRITICAL")

    def test_check_vulnerabilities_unknown_vendor(self):
        """Test that unknown vendor skips CVE check."""
        result = self.scanner.check_vulnerabilities("Unknown", [])
        self.assertTrue(result['passed'])
        self.assertIn("Vendor unknown", result['details'])

    def test_check_vulnerabilities_network_error(self):
        """Test graceful failure on CVE API network error."""
        self.scanner._resolve_device_cpe = MagicMock(return_value="cpe:2.3:o:testvendor:testproduct:*:*:*:*:*:*:*:*")
        self.scanner.nvd_client.get_cves_for_cpe = MagicMock(side_effect=Exception("Network error"))
        result = self.scanner.check_vulnerabilities("TestVendor", [])
        self.assertTrue(result['passed'])
        self.assertIn("network error", result['details'])

    @patch('scan_logic.CRAScanner.check_security_txt')
    @patch('scan_logic.CRAScanner.check_security_logging')
    @patch('scan_logic.CRAScanner.check_firmware_tracking')
    @patch('scan_logic.CRAScanner.check_sbom_compliance')
    @patch('scan_logic.CRAScanner.check_vulnerabilities')
    @patch('scan_logic.CRAScanner.check_https_redirect')
    @patch('scan_logic.CRAScanner.check_confidentiality')
    @patch('scan_logic.CRAScanner.check_secure_by_default')
    @patch('scan_logic.CRAScanner._get_ha_devices')
    def test_attack_surface_high_downgrades_compliant_to_warning(
        self,
        mock_get_ha,
        mock_sbd,
        mock_conf,
        mock_https,
        mock_vuln,
        mock_sbom,
        mock_fw,
        mock_sec_log,
        mock_sec_txt,
    ):
        """High attack surface should downgrade otherwise compliant device to Warning."""
        mock_get_ha.return_value = []
        mock_sbd.return_value = {"passed": True, "details": "ok"}
        mock_conf.return_value = {"passed": True, "details": "ok"}
        mock_https.return_value = {
            "passed": True,
            "details": "ok",
            "checked_ports": [80],
            "failed_ports": [],
            "inconclusive_ports": []
        }
        mock_vuln.return_value = {"passed": True, "details": "ok", "cves": []}
        mock_sbom.return_value = {"passed": True, "details": "ok", "sbom_found": False, "sbom_format": None}
        mock_fw.return_value = {
            "passed": True,
            "details": "ok",
            "firmware_version": None,
            "firmware_source": None,
            "update_available": None,
            "update_url": None,
            "version_cves": []
        }
        mock_sec_txt.return_value = {
            "passed": True,
            "details": "ok",
            "security_txt_found": False,
            "fields": None,
            "vendor_url": None
        }
        mock_sec_log.return_value = {
            "passed": True,
            "details": "ok",
            "syslog_udp_514": False,
            "syslog_probe_state": "closed",
            "logging_endpoints": []
        }

        host_ip = "192.168.1.51"
        self.scanner.nm.all_hosts.return_value = [host_ip]
        mock_host_data = MagicMock()
        mock_host_data.hostname.return_value = "exposed-host"
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {'ipv4': host_ip, 'mac': 'AA:BB:CC:DD:EE:11'},
            'vendor': {'AA:BB:CC:DD:EE:11': 'TestVendor'},
            'osmatch': [],
            'tcp': {
                21: {'state': 'open', 'name': 'ftp'},
                22: {'state': 'open', 'name': 'ssh'},
                23: {'state': 'open', 'name': 'telnet'},
                80: {'state': 'open', 'name': 'http'},
                443: {'state': 'open', 'name': 'https'},
            }
        }.get(key, {})
        mock_host_data.__contains__.side_effect = lambda key: key in ['addresses', 'vendor', 'osmatch', 'tcp']
        mock_host_data.all_protocols.return_value = ['tcp']
        self.scanner.nm.__getitem__.return_value = mock_host_data

        results = self.scanner.scan_subnet("192.168.1.0/24", {
            "scan_type": "standard",
            "auth_checks": True
        })

        self.assertTrue(len(results) > 0)
        device = results[0]
        self.assertIn('attackSurface', device)
        self.assertEqual(device['attackSurface']['rating'], 'High')
        self.assertEqual(device['attackSurface']['openPortsCount'], 5)
        self.assertEqual(device['status'], 'Warning')

    def test_vendor_check_tuya(self):
        """Test Tuya vendor detection by port."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 6668, "service": "unknown", "protocol": "tcp"}],
        }
        warnings = self.scanner._check_vendor_specifics(device, ['tuya'])
        self.assertTrue(any("Tuya" in w for w in warnings))

    def test_vendor_check_kasa(self):
        """Test TP-Link Kasa vendor detection by port."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 9999, "service": "unknown", "protocol": "tcp"}],
        }
        warnings = self.scanner._check_vendor_specifics(device, ['kasa'])
        self.assertTrue(any("Kasa" in w for w in warnings))

    def test_vendor_check_sonoff(self):
        """Test Sonoff vendor detection by port."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 8081, "service": "unknown", "protocol": "tcp"}],
        }
        warnings = self.scanner._check_vendor_specifics(device, ['sonoff'])
        self.assertTrue(any("Sonoff" in w for w in warnings))

    @patch('scan_logic.CRAScanner.check_security_txt')
    @patch('scan_logic.CRAScanner.check_security_logging')
    @patch('scan_logic.CRAScanner.check_firmware_tracking')
    @patch('scan_logic.CRAScanner.check_sbom_compliance')
    @patch('scan_logic.CRAScanner.check_vulnerabilities')
    @patch('scan_logic.CRAScanner.check_https_redirect')
    @patch('scan_logic.CRAScanner.check_confidentiality')
    @patch('scan_logic.CRAScanner.check_secure_by_default')
    @patch('scan_logic.CRAScanner._get_ha_devices')
    def test_https_check_integrated_and_can_set_non_compliant(
        self,
        mock_get_ha,
        mock_sbd,
        mock_conf,
        mock_https,
        mock_vuln,
        mock_sbom,
        mock_fw,
        mock_sec_log,
        mock_sec_txt,
    ):
        """HTTPS redirect check is included and drives strict non-compliance on failure."""
        mock_get_ha.return_value = []
        mock_sbd.return_value = {"passed": True, "details": "ok"}
        mock_conf.return_value = {"passed": True, "details": "ok"}
        mock_https.return_value = {
            "passed": False,
            "details": "HTTP management exposed without HTTPS redirect on ports: 80.",
            "checked_ports": [80],
            "failed_ports": [80],
            "inconclusive_ports": []
        }
        mock_vuln.return_value = {"passed": True, "details": "ok", "cves": []}
        mock_sbom.return_value = {"passed": True, "details": "ok", "sbom_found": False, "sbom_format": None}
        mock_fw.return_value = {
            "passed": True,
            "details": "ok",
            "firmware_version": None,
            "firmware_source": None,
            "update_available": None,
            "update_url": None,
            "version_cves": []
        }
        mock_sec_txt.return_value = {
            "passed": True,
            "details": "ok",
            "security_txt_found": False,
            "fields": None,
            "vendor_url": None
        }
        mock_sec_log.return_value = {
            "passed": True,
            "details": "ok",
            "syslog_udp_514": False,
            "syslog_probe_state": "closed",
            "logging_endpoints": []
        }

        host_ip = "192.168.1.50"
        self.scanner.nm.all_hosts.return_value = [host_ip]
        mock_host_data = MagicMock()
        mock_host_data.hostname.return_value = "test-host"
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {'ipv4': host_ip, 'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'},
            'osmatch': [],
        }.get(key, {})
        mock_host_data.__contains__.side_effect = lambda key: key in ['addresses', 'vendor', 'osmatch']
        mock_host_data.all_protocols.return_value = []
        self.scanner.nm.__getitem__.return_value = mock_host_data

        results = self.scanner.scan_subnet("192.168.1.0/24", {
            "scan_type": "standard",
            "auth_checks": True
        })

        self.assertTrue(len(results) > 0)
        device = results[0]
        self.assertIn('httpsOnlyManagement', device['checks'])
        self.assertFalse(device['checks']['httpsOnlyManagement']['passed'])
        self.assertEqual(device['status'], 'Non-Compliant')

    @patch('scan_logic.CRAScanner._get_ha_devices')
    def test_merge_no_ip_device(self, mock_get_ha):
        """Test merging HA device without IP (e.g. Zigbee)."""
        mock_get_ha.return_value = [{
            "entity_id": "light.zigbee_bulb",
            "attributes": {
                "friendly_name": "Zigbee Bulb",
                "manufacturer": "IKEA",
                "model": "TRADFRI"
                # No ip_address
            }
        }]
        self.scanner.nm.all_hosts.return_value = []
        results = self.scanner.scan_subnet("192.168.1.0/24", {"scan_type": "discovery"})
        zigbee = [d for d in results if d.get('model') == 'TRADFRI']
        self.assertEqual(len(zigbee), 1)
        self.assertEqual(zigbee[0]['ip'], 'N/A')
        self.assertEqual(zigbee[0]['source'], 'Home Assistant')

    @patch('scan_logic.nmap.PortScanner')
    def test_nmap_not_initialized(self, mock_nmap_cls):
        """Test fallback when nmap is unavailable."""
        mock_nmap_cls.side_effect = Exception("Nmap missing")
        scanner = CRAScanner()
        self.assertIsNone(scanner.nm)
        # Should still return HA devices (mock data in dev mode)
        results = scanner.scan_subnet("192.168.1.0/24")
        self.assertTrue(len(results) > 0)
        self.assertTrue(all(d.get('source') == 'Home Assistant' for d in results))


class TestScanPreservesDiscovery(unittest.TestCase):
    """Consolidated regression tests: discovery results must survive detailed scans."""

    def _run_preservation_test(self, scan_type, detailed_returns_hosts):
        """Helper: run a scan and verify discovery device is preserved."""
        with patch('scan_logic.nmap.PortScanner'):
            scanner = CRAScanner()
            mock_nm = MagicMock()
            scanner.nm = mock_nm

            current_hosts = []

            def scan_side_effect(*args, **kwargs):
                nonlocal current_hosts
                arguments = kwargs.get('arguments', '')
                if '-sn' in arguments:
                    current_hosts[:] = ['192.168.1.50']
                else:
                    current_hosts[:] = ['192.168.1.50'] if detailed_returns_hosts else []
                return None

            mock_nm.scan.side_effect = scan_side_effect
            mock_nm.all_hosts.side_effect = lambda: list(current_hosts)

            class MockHost(dict):
                def hostname(self): return "TestDevice"
                def all_protocols(self): return []

            def getitem(k):
                if k == '192.168.1.50' and k in current_hosts:
                    last_args = mock_nm.scan.call_args[1].get('arguments', '')
                    if '-sn' in last_args:
                        return MockHost({
                            'addresses': {'ipv4': '192.168.1.50', 'mac': 'AA:BB:CC:DD:EE:FF'},
                            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'},
                            'osmatch': [],
                        })
                    else:
                        return MockHost({
                            'addresses': {'ipv4': '192.168.1.50'},
                            'vendor': {},
                            'osmatch': [],
                        })
                return {}

            mock_nm.__getitem__.side_effect = getitem

            results = scanner.scan_subnet('192.168.1.0/24', {
                'scan_type': scan_type,
                'auth_checks': False,
                'vendors': 'all'
            })

            found = any(d.get('ip') == '192.168.1.50' for d in results)
            self.assertTrue(found, f"Device should survive {scan_type} scan")

            if scan_type != 'discovery':
                device = next(d for d in results if d.get('ip') == '192.168.1.50')
                self.assertEqual(device.get('mac'), 'AA:BB:CC:DD:EE:FF',
                                 "MAC should be preserved from discovery")

    def test_discovery_returns_devices(self):
        """Discovery-only scan returns discovered devices."""
        self._run_preservation_test('discovery', detailed_returns_hosts=False)

    def test_standard_scan_preserves_discovery(self):
        """Standard scan preserves devices even if detailed scan returns empty."""
        self._run_preservation_test('standard', detailed_returns_hosts=False)

    def test_deep_scan_preserves_discovery(self):
        """Deep scan preserves devices even if detailed scan returns empty."""
        self._run_preservation_test('deep', detailed_returns_hosts=False)

    def test_mac_preserved_across_phases(self):
        """MAC from discovery is preserved when detailed scan omits it."""
        self._run_preservation_test('standard', detailed_returns_hosts=True)


class TestSBOMCheck(unittest.TestCase):
    """Tests for SBOM compliance checking (CRA Annex I §2(1))."""

    @patch('scan_logic.nmap.PortScanner')
    def setUp(self, mock_nmap):
        self.scanner = CRAScanner()
        self.scanner.nm = MagicMock()

    def test_sbom_endpoint_found_cyclonedx(self):
        """SBOM endpoint returns CycloneDX document."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}' + ' ' * 50
        mock_response.headers = {'Content-Type': 'application/json'}
        self.scanner.session.get = MagicMock(return_value=mock_response)

        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}],
            "vendor": "TestVendor"
        }

        result = self.scanner.check_sbom_compliance(device)
        self.assertTrue(result['passed'])
        self.assertTrue(result['sbom_found'])
        self.assertEqual(result['sbom_format'], 'CycloneDX')

    def test_sbom_endpoint_found_spdx(self):
        """SBOM endpoint returns SPDX document."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"SPDXVersion": "SPDX-2.3", "dataLicense": "CC0-1.0"}' + ' ' * 50
        mock_response.headers = {'Content-Type': 'application/json'}
        self.scanner.session.get = MagicMock(return_value=mock_response)

        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}],
            "vendor": "TestVendor"
        }

        result = self.scanner.check_sbom_compliance(device)
        self.assertTrue(result['passed'])
        self.assertTrue(result['sbom_found'])
        self.assertEqual(result['sbom_format'], 'SPDX')

    def test_sbom_no_endpoint_known_vendor_available(self):
        """Vendor known to publish SBOMs passes even without device endpoint."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [],  # No HTTP ports to probe
            "vendor": "Philips"
        }

        result = self.scanner.check_sbom_compliance(device)
        self.assertTrue(result['passed'])
        self.assertFalse(result['sbom_found'])
        self.assertIn("Philips", result['details'])
        self.assertIn("publish SBOMs", result['details'])

    def test_sbom_no_endpoint_vendor_unavailable(self):
        """Vendor known to NOT publish SBOMs fails."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [],
            "vendor": "Tuya"
        }

        result = self.scanner.check_sbom_compliance(device)
        self.assertFalse(result['passed'])
        self.assertFalse(result['sbom_found'])
        self.assertIn("Tuya", result['details'])

    def test_sbom_no_http_ports_unknown_vendor(self):
        """Device with no HTTP ports and unknown vendor."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 22, "service": "ssh", "protocol": "tcp"}],
            "vendor": "Unknown"
        }

        result = self.scanner.check_sbom_compliance(device)
        self.assertFalse(result['passed'])
        self.assertIn("unknown", result['details'].lower())

    def test_sbom_network_error(self):
        """Network errors during SBOM probing handled gracefully."""
        self.scanner.session.get = MagicMock(side_effect=Exception("Connection refused"))
        device = {
            "ip": "192.168.1.10",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}],
            "vendor": "SomeNewVendor"
        }

        # Should not raise, should fall back to vendor lookup
        result = self.scanner.check_sbom_compliance(device)
        self.assertFalse(result['passed'])
        self.assertFalse(result['sbom_found'])

    @patch('scan_logic.CRAScanner._get_ha_devices')
    def test_sbom_integrated_in_scan(self, mock_get_ha):
        """SBOM check is included in scan_subnet output."""
        mock_get_ha.return_value = []
        host_ip = "192.168.1.50"
        self.scanner.nm.all_hosts.return_value = [host_ip]

        mock_host_data = MagicMock()
        mock_host_data.hostname.return_value = "test-host"
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {'ipv4': host_ip, 'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'},
            'osmatch': [],
        }.get(key, {})
        mock_host_data.__contains__.side_effect = lambda key: key in ['addresses', 'vendor', 'osmatch']
        mock_host_data.all_protocols.return_value = []
        self.scanner.nm.__getitem__.return_value = mock_host_data

        results = self.scanner.scan_subnet("192.168.1.0/24", {
            "scan_type": "standard",
            "auth_checks": False
        })

        self.assertTrue(len(results) > 0)
        device = results[0]
        self.assertIn('sbomCompliance', device['checks'])
        self.assertIn('passed', device['checks']['sbomCompliance'])
        self.assertIn('sbom_found', device['checks']['sbomCompliance'])
        self.assertIn('securityLogging', device['checks'])
        self.assertIn('passed', device['checks']['securityLogging'])

class TestFirmwareTracking(unittest.TestCase):
    """Tests for firmware version tracking (CRA Annex I §2(2))."""

    @patch('scan_logic.nmap.PortScanner')
    def setUp(self, mock_nmap):
        self.scanner = CRAScanner()
        self.scanner.nm = MagicMock()

    def test_firmware_from_nmap_service_version(self):
        """Firmware version extracted from Nmap -sV service data."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [
                {"port": 80, "service": "http", "protocol": "tcp", "product": "lighttpd", "version": "1.4.59"}
            ],
            "vendor": "Shelly"
        }

        result = self.scanner.check_firmware_tracking(device)
        self.assertTrue(result['passed'])
        self.assertEqual(result['firmware_version'], '1.4.59')
        self.assertIn('Nmap service scan', result['firmware_source'])
        self.assertIn('lighttpd', result['firmware_source'])

    def test_firmware_from_vendor_endpoint_shelly(self):
        """Version extracted from Shelly /settings endpoint."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"fw": "20230913-112003/v1.14.0-gcb84623", "mac": "aabbcc"}
        self.scanner.session.get = MagicMock(return_value=mock_response)

        device = {
            "ip": "192.168.1.20",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}],  # No product/version keys
            "vendor": "Shelly"
        }

        result = self.scanner.check_firmware_tracking(device)
        self.assertEqual(result['firmware_version'], '20230913-112003/v1.14.0-gcb84623')
        self.assertIn('Shelly API', result['firmware_source'])
        self.assertIsNotNone(result['update_url'])

    def test_firmware_from_ha_sw_version(self):
        """Version extracted from HA device sw_version attribute."""
        device = {
            "ip": "192.168.1.30",
            "openPorts": [],  # No ports, no Nmap version
            "vendor": "Philips",
            "sw_version": "1.50.2"
        }

        result = self.scanner.check_firmware_tracking(device)
        self.assertTrue(result['passed'])
        self.assertEqual(result['firmware_version'], '1.50.2')
        self.assertEqual(result['firmware_source'], 'Home Assistant')

    def test_firmware_unknown_vendor(self):
        """Unknown vendor and no version → not passed."""
        device = {
            "ip": "192.168.1.40",
            "openPorts": [],
            "vendor": "Unknown"
        }

        result = self.scanner.check_firmware_tracking(device)
        self.assertFalse(result['passed'])
        self.assertIsNone(result['firmware_version'])
        self.assertIn("Could not determine", result['details'])

    def test_firmware_with_version_cves(self):
        """Version-specific CVE lookup returns matching CVEs."""
        self.scanner._resolve_device_cpe = MagicMock(return_value="cpe:2.3:o:testvendor:httpd:1.2.3:*:*:*:*:*:*:*")
        self.scanner.nvd_client.get_cves_for_cpe = MagicMock(return_value=[
            {"id": "CVE-2024-5678", "severity": "HIGH", "score": 8.5, "description": "Buffer overflow in firmware v1.2.3"}
        ])

        device = {
            "ip": "192.168.1.50",
            "openPorts": [
                {"port": 80, "service": "http", "protocol": "tcp", "product": "httpd", "version": "1.2.3"}
            ],
            "vendor": "TestVendor"
        }

        result = self.scanner.check_firmware_tracking(device)
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['version_cves']), 1)
        self.assertEqual(result['version_cves'][0]['id'], 'CVE-2024-5678')
        self.assertEqual(result['version_cves'][0]['severity'], 'HIGH')

    def test_firmware_network_error(self):
        """Network errors during firmware probing handled gracefully."""
        self.scanner.session.get = MagicMock(side_effect=Exception("Connection refused"))
        device = {
            "ip": "192.168.1.60",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}],
            "vendor": "Shelly"
        }

        # Should not raise
        result = self.scanner.check_firmware_tracking(device)
        self.assertFalse(result['passed'])

    @patch('scan_logic.CRAScanner._get_ha_devices')
    def test_firmware_integrated_in_scan(self, mock_get_ha):
        """firmwareTracking key present in scan_subnet output."""
        mock_get_ha.return_value = []
        host_ip = "192.168.1.50"
        self.scanner.nm.all_hosts.return_value = [host_ip]

        mock_host_data = MagicMock()
        mock_host_data.hostname.return_value = "test-host"
        mock_host_data.__getitem__.side_effect = lambda key: {
            'addresses': {'ipv4': host_ip, 'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'},
            'osmatch': [],
        }.get(key, {})
        mock_host_data.__contains__.side_effect = lambda key: key in ['addresses', 'vendor', 'osmatch']
        mock_host_data.all_protocols.return_value = []
        self.scanner.nm.__getitem__.return_value = mock_host_data

        results = self.scanner.scan_subnet("192.168.1.0/24", {
            "scan_type": "standard",
            "auth_checks": False
        })

        self.assertTrue(len(results) > 0)
        device = results[0]
        self.assertIn('firmwareTracking', device['checks'])
        self.assertIn('passed', device['checks']['firmwareTracking'])
        self.assertIn('firmware_version', device['checks']['firmwareTracking'])
        self.assertIn('version_cves', device['checks']['firmwareTracking'])
        self.assertIn('securityLogging', device['checks'])


class TestHADeviceRegistry(unittest.TestCase):
    """Tests for HA Device Registry integration."""

    @patch('scan_logic.nmap.PortScanner')
    def setUp(self, mock_nmap):
        self.scanner = CRAScanner()
        self.scanner.nm = MagicMock()

    def test_device_registry_enriches_sw_version(self):
        """Device Registry sw_version flows through to merged device."""
        # Mock entity registry response
        entity_resp = MagicMock()
        entity_resp.status_code = 200
        entity_resp.json.return_value = [
            {"entity_id": "light.kitchen", "device_id": "dev_123"}
        ]
        # Mock device registry response
        device_resp = MagicMock()
        device_resp.status_code = 200
        device_resp.json.return_value = [
            {"id": "dev_123", "sw_version": "2.5.1", "manufacturer": "Philips", "model": "LCA001", "name": "Kitchen Light"}
        ]
        # Mock states response
        states_resp = MagicMock()
        states_resp.status_code = 200
        states_resp.json.return_value = [
            {"entity_id": "light.kitchen", "attributes": {"friendly_name": "Kitchen Light", "manufacturer": "Philips"}}
        ]

        call_count = [0]
        def mock_get(url, **kwargs):
            call_count[0] += 1
            if 'device_registry' in url:
                return device_resp
            elif 'entity_registry' in url:
                return entity_resp
            else:
                return states_resp

        self.scanner.session.get = mock_get

        with patch.dict(os.environ, {'SUPERVISOR_TOKEN': 'test-token'}):
            devices = self.scanner._get_ha_devices()

        # Should have at least one device with sw_version from registry
        ha_devs_with_sw = [d for d in devices if d.get('sw_version')]
        self.assertTrue(len(ha_devs_with_sw) > 0)
        self.assertEqual(ha_devs_with_sw[0]['sw_version'], '2.5.1')
        self.assertEqual(ha_devs_with_sw[0]['manufacturer'], 'Philips')

    def test_device_registry_failure_graceful(self):
        """Device Registry API failure doesn't break _get_ha_devices."""
        fail_resp = MagicMock()
        fail_resp.status_code = 404
        fail_resp.text = "Not Found"

        states_resp = MagicMock()
        states_resp.status_code = 200
        states_resp.json.return_value = [
            {"entity_id": "sensor.test", "attributes": {"ip_address": "192.168.1.5", "manufacturer": "Test"}}
        ]

        def mock_get(url, **kwargs):
            if 'device_registry' in url or 'entity_registry' in url:
                return fail_resp
            return states_resp

        self.scanner.session.get = mock_get

        with patch.dict(os.environ, {'SUPERVISOR_TOKEN': 'test-token'}):
            devices = self.scanner._get_ha_devices()

        # Should still return devices from states API
        self.assertTrue(len(devices) > 0)


class TestVendorResolution(unittest.TestCase):
    """Tests for resolved_vendor in SBOM/firmware checks."""

    @patch('scan_logic.nmap.PortScanner')
    def setUp(self, mock_nmap):
        self.scanner = CRAScanner()
        self.scanner.nm = MagicMock()

    def test_sbom_uses_resolved_vendor(self):
        """SBOM check uses resolved_vendor over raw vendor."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [],
            "vendor": "Unknown",
            "resolved_vendor": "Philips"
        }

        result = self.scanner.check_sbom_compliance(device)
        self.assertTrue(result['passed'])
        self.assertIn("Philips", result['details'])
        self.assertIn("publish SBOMs", result['details'])

    def test_firmware_uses_resolved_vendor(self):
        """Firmware check uses resolved_vendor for vendor endpoint probing."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"fw": "1.14.0"}
        self.scanner.session.get = MagicMock(return_value=mock_response)

        device = {
            "ip": "192.168.1.20",
            "openPorts": [{"port": 80, "service": "http", "protocol": "tcp"}],
            "vendor": "Unknown",
            "resolved_vendor": "Shelly"
        }

        result = self.scanner.check_firmware_tracking(device)
        self.assertEqual(result['firmware_version'], '1.14.0')
        self.assertIn('Shelly API', result['firmware_source'])

    def test_sbom_portal_url_returned(self):
        """SBOM result includes sbom_url for known vendors."""
        device = {
            "ip": "192.168.1.10",
            "openPorts": [],
            "vendor": "Siemens"
        }

        result = self.scanner.check_sbom_compliance(device)
        self.assertIn('sbom_url', result)
        self.assertEqual(result['sbom_url'], "https://sbom.siemens.com/")

    def test_merge_carries_manufacturer(self):
        """_merge_devices carries manufacturer from HA to existing Nmap device."""
        nmap_devices = [{
            "ip": "192.168.1.10",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Unknown",
            "hostname": "device1",
            "openPorts": [],
            "osMatch": "Unknown",
            "source": "Nmap"
        }]
        ha_devices = [{
            "entity_id": "light.test",
            "attributes": {"ip_address": "192.168.1.10", "friendly_name": "Test Light"},
            "manufacturer": "Philips",
            "model": "LCA001",
            "sw_version": "2.5.1"
        }]

        merged = self.scanner._merge_devices(nmap_devices, ha_devices)
        device = [d for d in merged if d['ip'] == '192.168.1.10'][0]
        self.assertEqual(device['manufacturer'], 'Philips')
        self.assertEqual(device['sw_version'], '2.5.1')
        self.assertEqual(device['vendor'], 'Philips')


class TestExpandedSBOMProbing(unittest.TestCase):
    """Tests for expanded SBOM endpoint paths."""

    @patch('scan_logic.nmap.PortScanner')
    def setUp(self, mock_nmap):
        self.scanner = CRAScanner()
        self.scanner.nm = MagicMock()

    def test_sbom_api_v1_path(self):
        """SBOM found at /api/v1/sbom path."""
        call_urls = []
        def mock_get(url, **kwargs):
            call_urls.append(url)
            resp = MagicMock()
            if url.endswith('/api/v1/sbom'):
                resp.status_code = 200
                resp.text = '{"bomFormat": "CycloneDX", "specVersion": "1.4"}' + ' ' * 50
                resp.headers = {'Content-Type': 'application/json'}
            else:
                resp.status_code = 404
                resp.text = ''
            return resp

        self.scanner.session.get = mock_get
        found, fmt = self.scanner._probe_sbom_endpoints("192.168.1.10", [80])
        self.assertTrue(found)
        self.assertEqual(fmt, 'CycloneDX')

    def test_sbom_well_known_csaf(self):
        """SBOM found at /.well-known/csaf path."""
        def mock_get(url, **kwargs):
            resp = MagicMock()
            if url.endswith('/.well-known/csaf'):
                resp.status_code = 200
                resp.text = '{"csaf_version": "2.0", "document": {}}' + ' ' * 50
                resp.headers = {'Content-Type': 'application/json'}
            else:
                resp.status_code = 404
                resp.text = ''
            return resp

        self.scanner.session.get = mock_get
        found, fmt = self.scanner._probe_sbom_endpoints("192.168.1.10", [443])
        self.assertTrue(found)
        # Should be detected as Unknown Format (no CycloneDX/SPDX signatures)
        self.assertEqual(fmt, 'Unknown Format')

    def test_sbom_probes_all_new_paths(self):
        """Verify all expanded SBOM paths are probed."""
        probed_urls = []
        def mock_get(url, **kwargs):
            probed_urls.append(url)
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ''
            return resp

        self.scanner.session.get = mock_get
        self.scanner._probe_sbom_endpoints("192.168.1.10", [80])

        # Check that new paths are probed
        probed_paths = [url.split(':80')[1] for url in probed_urls if ':80' in url]
        self.assertIn('/api/sbom', probed_paths)
        self.assertIn('/api/v1/sbom', probed_paths)
        self.assertIn('/bom.json', probed_paths)
        self.assertIn('/.well-known/csaf', probed_paths)
        self.assertIn('/.well-known/vex', probed_paths)


class TestExpandedFirmwareProbing(unittest.TestCase):
    """Tests for expanded vendor-specific firmware detection."""

    @patch('scan_logic.nmap.PortScanner')
    def setUp(self, mock_nmap):
        self.scanner = CRAScanner()
        self.scanner.nm = MagicMock()

    def test_firmware_from_avm_fritz_endpoint(self):
        """AVM/FRITZ!Box firmware version extracted from /jason_boxinfo.xml."""
        def mock_get(url, **kwargs):
            resp = MagicMock()
            if 'jason_boxinfo' in url:
                resp.status_code = 200
                resp.text = '<BoxInfo><Version>7.57</Version><Name>FRITZ!Box 7590</Name></BoxInfo>'
            else:
                resp.status_code = 404
                resp.text = ''
            return resp

        self.scanner.session.get = mock_get
        fw, src = self.scanner._probe_firmware_endpoints("192.168.1.1", [80], "AVM FRITZ!Box")
        self.assertEqual(fw, '7.57')
        self.assertIn('AVM API', src)

    def test_firmware_from_fritz_os_pattern(self):
        """AVM FRITZ!OS version pattern detected from system_status."""
        def mock_get(url, **kwargs):
            resp = MagicMock()
            if 'system_status' in url:
                resp.status_code = 200
                resp.text = '<html>FRITZ!OS: 7.57 running on FRITZ!Box 7590</html>'
            else:
                resp.status_code = 404
                resp.text = ''
            return resp

        self.scanner.session.get = mock_get
        fw, src = self.scanner._probe_firmware_endpoints("192.168.1.1", [80], "AVM")
        self.assertEqual(fw, '7.57')

    def test_firmware_from_esphome_header(self):
        """ESPHome firmware version from X-Esphome-Version header."""
        def mock_get(url, **kwargs):
            resp = MagicMock()
            if url.endswith('/'):
                resp.status_code = 200
                resp.text = '<html>ESPHome</html>'
                resp.headers = {'X-Esphome-Version': '2023.12.0'}
            else:
                resp.status_code = 404
                resp.text = ''
                resp.headers = {}
            return resp

        self.scanner.session.get = mock_get
        fw, src = self.scanner._probe_firmware_endpoints("192.168.1.30", [80], "ESPHome")
        self.assertEqual(fw, '2023.12.0')
        self.assertIn('ESPHome header', src)

    def test_firmware_from_tasmota_status(self):
        """Tasmota firmware version from Status 2 JSON."""
        def mock_get(url, **kwargs):
            resp = MagicMock()
            if 'cmnd=Status' in url:
                resp.status_code = 200
                resp.json.return_value = {"StatusFWR": {"Version": "13.3.0(tasmota)"}}
            else:
                resp.status_code = 404
                resp.text = ''
            return resp

        self.scanner.session.get = mock_get
        fw, src = self.scanner._probe_firmware_endpoints("192.168.1.40", [80], "Tasmota")
        self.assertEqual(fw, '13.3.0(tasmota)')
        self.assertIn('Tasmota API', src)

    def test_firmware_from_sonoff_zeroconf(self):
        """Sonoff firmware version from DIY Mode /zeroconf/info."""
        def mock_post(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"data": {"fwVersion": "3.5.0"}}
            return resp

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.text = ''
            return resp

        self.scanner.session.get = mock_get
        self.scanner.session.post = mock_post
        fw, src = self.scanner._probe_firmware_endpoints("192.168.1.50", [80], "Sonoff")
        self.assertEqual(fw, '3.5.0')
        self.assertIn('Sonoff DIY API', src)

    def test_firmware_from_upnp_description(self):
        """Firmware version extracted from UPnP /description.xml."""
        def mock_get(url, **kwargs):
            resp = MagicMock()
            if 'description.xml' in url:
                resp.status_code = 200
                resp.text = '''<?xml version="1.0"?>
                <root xmlns="urn:schemas-upnp-org:device-1-0">
                  <device>
                    <friendlyName>My Router</friendlyName>
                    <firmwareVersion>3.14.2</firmwareVersion>
                    <modelNumber>RT-AC68U</modelNumber>
                  </device>
                </root>'''
            else:
                resp.status_code = 404
                resp.text = ''
            return resp

        self.scanner.session.get = mock_get
        fw, src = self.scanner._probe_firmware_endpoints("192.168.1.1", [80], "Unknown")
        self.assertEqual(fw, '3.14.2')
        self.assertIn('UPnP XML', src)

    def test_firmware_generic_http_scrape(self):
        """Firmware version scraped from HTTP page content via regex."""
        call_count = [0]
        def mock_get(url, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            resp.headers = {}
            # All specific endpoints return 404
            if url.endswith('/'):
                resp.status_code = 200
                resp.text = '<html><body>Device Info: Firmware Version: 4.2.1-build123</body></html>'
            elif 'description.xml' in url or 'rootDesc' in url or 'gatedesc' in url or 'DeviceDescription' in url or 'dmr' in url:
                resp.status_code = 404
                resp.text = ''
            else:
                resp.status_code = 404
                resp.text = ''
                resp.json.side_effect = ValueError("No JSON")
            return resp

        self.scanner.session.get = mock_get
        fw, src = self.scanner._probe_firmware_endpoints("192.168.1.60", [80], "SomeUnknownVendor")
        self.assertEqual(fw, '4.2.1-build123')
        self.assertIn('HTTP content scraping', src)

    def test_firmware_nested_json_structure(self):
        """Firmware version found in nested JSON structure."""
        def mock_get(url, **kwargs):
            resp = MagicMock()
            if url.endswith(('/firmware', '/api/firmware', '/device/info', '/system/info',
                            '/api/system', '/api/device', '/api/v1/device/info',
                            '/status', '/api/status')):
                resp.status_code = 200
                resp.json.return_value = {"system": {"version": "5.0.3", "uptime": 12345}}
            else:
                resp.status_code = 404
                resp.text = ''
                resp.json.side_effect = ValueError
            return resp

        self.scanner.session.get = mock_get
        fw, src = self.scanner._probe_firmware_endpoints("192.168.1.70", [80], "SomeVendor")
        self.assertEqual(fw, '5.0.3')
        self.assertIn('Device API', src)
        self.assertIn('system.version', src)


if __name__ == '__main__':
    unittest.main()
