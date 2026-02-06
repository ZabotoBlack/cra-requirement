import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Adjust path to import scan_logic
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scan_logic import CRAScanner

class TestStandardScanRepro(unittest.TestCase):
    @patch('scan_logic.nmap.PortScanner')
    def test_standard_scan_drops_devices(self, MockPortScanner):
        # Setup mock
        mock_nm = MockPortScanner.return_value
        
        # We need to simulate behavior where scan() is called twice.
        # 1. Discovery Scan (-sn -PR) -> Finds 192.168.1.50
        # 2. Standard Scan (-Pn -sV ...) -> Finds NOTHING (simulating strict filter or failure)
        
        # State to track current "scan results" in the mock
        self.current_hosts = []
        
        def scan_side_effect(*args, **kwargs):
            arguments = kwargs.get('arguments', '')
            if '-sn' in arguments:
                # Discovery Scan
                print("Mock: Discovery Scan Executed")
                self.current_hosts = ['192.168.1.50']
            else:
                # Standard/Detailed Scan
                # Simulate that for some reason (e.g. no ports open) nmap returns empty list or no "interesting" hosts
                print("Mock: Standard Scan Executed (Simulating failure/empty)")
                self.current_hosts = [] 
            return None

        mock_nm.scan.side_effect = scan_side_effect
        
        # mock_nm.all_hosts() returns whatever is in self.current_hosts
        mock_nm.all_hosts.side_effect = lambda: self.current_hosts
        
        # mock_nm['ip'] behavior
        def getitem_side_effect(k):
            if k == '192.168.1.50':
                # Return data ONLY if it's currently "scanned"
                if '192.168.1.50' in self.current_hosts:
                    return {
                        'addresses': {'ipv4': '192.168.1.50', 'mac': 'AA:AA:AA:AA:AA:AA'},
                        'vendor': {'AA:AA:AA:AA:AA:AA': 'SmartThing'},
                        'osmatch': [],
                        'status': {'state': 'up', 'reason': 'arp-response'}
                    }
            return {}
            
        mock_nm.__getitem__.side_effect = getitem_side_effect
        
        # Hostname mock
        mock_host_obj = MagicMock()
        mock_host_obj.hostname.return_value = "Smart-Device"
        
        # We also need to mock the intermediate object access if logic does self.nm[host]...
        # The logic does: if 'addresses' not in self.nm[host]
        # So __getitem__ returning the dict is enough if we assume it returns a dict-like object.
        # However, scan_logic calls .hostname() on the result of __getitem__. 
        # So __getitem__ must return an object that has .hostname() AND allows dict access.
        
        # Let's verify how scan_logic uses it:
        # self.nm[host]['addresses'] -> dict access
        # self.nm[host].hostname() -> method call
        
        # So we need a Mock that behaves like a dict but also has methods.
        class NmapHostDict(dict):
            def hostname(self):
                return "Smart-Device"
            def all_protocols(self):
                return []
        
        def complex_getitem(k):
             if k == '192.168.1.50' and k in self.current_hosts:
                d = NmapHostDict({
                    'addresses': {'ipv4': '192.168.1.50', 'mac': 'AA:AA:AA:AA:AA:AA'},
                    'vendor': {'AA:AA:AA:AA:AA:AA': 'SmartThing'},
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
            'scan_type': 'standard',
            'auth_checks': False,
            'vendors': 'all'
        }
        
        # Execute
        results = scanner.scan_subnet('192.168.1.0/24', options)
        
        print(f"Final Results: {len(results)}")
        
        # ASSERT: We expect to find the device from Discovery, even if Standard scan failed to find ports.
        found_nmap_device = any(d.get('ip') == '192.168.1.50' for d in results)

        if not found_nmap_device:
            print("REPRODUCTION SUCCESSFUL: Standard scan wiped out discovery results (192.168.1.50 missing).")
        else:
            print("REPRODUCTION FAILED: Devices were found.")
            
        self.assertTrue(found_nmap_device, "Should have returned devices found in discovery.")

if __name__ == '__main__':
    unittest.main()
