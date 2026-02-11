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


    @patch('scan_logic.requests.get')
    def test_check_vendor_specifics_shelly(self, mock_get):
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
        mock_get.return_value = mock_response
        
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

    @patch('scan_logic.requests.get')
    def test_check_vulnerabilities_critical_cve(self, mock_get):
        """Test that critical CVEs are detected."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"id": "CVE-2024-1234", "cvss": "9.8", "summary": "Critical RCE vulnerability in vendor firmware"}
            ]
        }
        mock_get.return_value = mock_response

        result = self.scanner.check_vulnerabilities("TestVendor", [])
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['cves']), 1)
        self.assertEqual(result['cves'][0]['severity'], "CRITICAL")

    def test_check_vulnerabilities_unknown_vendor(self):
        """Test that unknown vendor skips CVE check."""
        result = self.scanner.check_vulnerabilities("Unknown", [])
        self.assertTrue(result['passed'])
        self.assertIn("Vendor unknown", result['details'])

    @patch('scan_logic.requests.get', side_effect=Exception("Network error"))
    def test_check_vulnerabilities_network_error(self, mock_get):
        """Test graceful failure on CVE API network error."""
        result = self.scanner.check_vulnerabilities("TestVendor", [])
        self.assertTrue(result['passed'])
        self.assertIn("network error", result['details'])

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


if __name__ == '__main__':
    unittest.main()
