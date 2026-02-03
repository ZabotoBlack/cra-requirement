import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Adjust path to import scan_logic
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scan_logic import CRAScanner

class TestDiscoveryScan(unittest.TestCase):
    @patch('nmap.PortScanner')
    def test_discovery_scan_returns_devices(self, MockPortScanner):
        # Setup mock
        mock_nm = MockPortScanner.return_value
        
        # Mock scan() method
        mock_nm.scan.return_value = None
        
        # Mock all_hosts()
        mock_nm.all_hosts.return_value = ['192.168.1.100']
        
        # Mock getting item from scanner (nm['192.168.1.100'])
        mock_host = MagicMock()
        mock_host.__getitem__.side_effect = lambda k: {
            'addresses': {'ipv4': '192.168.1.100', 'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'},
            'osmatch': [],
        }[k]
        mock_host.hostname.return_value = "test-device"
        mock_host.__contains__.side_effect = lambda k: k in {
            'addresses': {'ipv4': '192.168.1.100', 'mac': 'AA:BB:CC:DD:EE:FF'},
            'vendor': {'AA:BB:CC:DD:EE:FF': 'TestVendor'},
            'osmatch': [],
        }

        # Configure __getitem__ behavior of scanner
        mock_nm.__getitem__.side_effect = lambda x: mock_host if x == '192.168.1.100' else {}
        
        # Initialize Scanner
        scanner = CRAScanner()
        
        # Mock verify_logic imports within scan_logic or side effects if any
        # Since we are testing scan_subnet, let's just run it
        
        options = {
            'scan_type': 'discovery',
            'auth_checks': False,
            'vendors': 'all'
        }
        
        # Execute
        results = scanner.scan_subnet('192.168.1.0/24', options)
        
        # Verify
        print(f"\nResults found: {len(results)}")
        found = False
        for dev in results:
            print(f"Device: {dev}")
            if dev['ip'] == '192.168.1.100':
                found = True
                self.assertEqual(dev['mac'], 'AA:BB:CC:DD:EE:FF')
                self.assertEqual(dev['vendor'], 'TestVendor')
        
        self.assertTrue(found, "Should have found the mocked device in discovery mode")

if __name__ == '__main__':
    unittest.main()
