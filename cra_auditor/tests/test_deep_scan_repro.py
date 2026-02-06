import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Adjust path to import scan_logic
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scan_logic import CRAScanner

class TestDeepScanRepro(unittest.TestCase):
    @patch('scan_logic.nmap.PortScanner')
    def test_deep_scan_preserves_discovery(self, MockPortScanner):
        # Setup mock
        mock_nm = MockPortScanner.return_value
        
        # State to track current "scan results" in the mock
        self.current_hosts = []
        
        def scan_side_effect(*args, **kwargs):
            arguments = kwargs.get('arguments', '')
            if '-sn' in arguments:
                # Discovery Scan
                print("Mock: Discovery Scan Executed")
                self.current_hosts = ['192.168.1.99']
            else:
                # Deep Scan
                # Simulate that for some reason (e.g. strict firewall) nmap returns empty list or no "interesting" hosts
                print(f"Mock: Deep Scan Executed with args: {arguments}")
                # Ensure we are actually testing deep scan args
                if '-O' in arguments and '--top-ports 1000' in arguments:
                     print("Mock: Verified Deep Scan arguments present.")
                
                self.current_hosts = [] 
            return None

        mock_nm.scan.side_effect = scan_side_effect
        mock_nm.all_hosts.side_effect = lambda: self.current_hosts
        
        # mock_nm['ip'] behavior
        def getitem_side_effect(k):
             return {} # Default return

        class NmapHostDict(dict):
            def hostname(self):
                return "Deep-Hidden-Device"
            def all_protocols(self):
                return []
        
        def complex_getitem(k):
             if k == '192.168.1.99' and k in self.current_hosts:
                d = NmapHostDict({
                    'addresses': {'ipv4': '192.168.1.99', 'mac': 'CC:CC:CC:CC:CC:CC'},
                    'vendor': {'CC:CC:CC:CC:CC:CC': 'DeepVendor'},
                    'osmatch': [],
                    'status': {'state': 'up'},
                    'script': {}
                })
                return d
             return {}
        
        mock_nm.__getitem__.side_effect = complex_getitem

        # Initialize Scanner
        scanner = CRAScanner()
        
        options = {
            'scan_type': 'deep',
            'auth_checks': False,
            'vendors': 'all'
        }
        
        # Execute
        results = scanner.scan_subnet('192.168.1.0/24', options)
        
        print(f"Final Results: {len(results)}")
        
        found_nmap_device = any(d.get('ip') == '192.168.1.99' for d in results)

        if not found_nmap_device:
            print("VERIFICATION FAILED: Deep scan wiped out discovery results.")
        else:
            print("VERIFICATION PASSED: Deep scan preserved discovery results.")
            
        self.assertTrue(found_nmap_device, "Should have returned devices found in discovery.")

if __name__ == '__main__':
    unittest.main()
