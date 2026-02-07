import unittest
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scan_logic import CRAScanner

class TestMacLossRepro(unittest.TestCase):
    @patch('scan_logic.nmap.PortScanner')
    def test_mac_preservation(self, MockPortScanner):
        mock_nm = MockPortScanner.return_value
        self.current_hosts = []
        
        def scan_side_effect(*args, **kwargs):
            arguments = kwargs.get('arguments', '')
            if '-sn' in arguments:
                # Discovery: Finds IP + MAC
                self.current_hosts = ['192.168.1.50']
            else:
                # Standard: Finds IP but NO MAC (simulated)
                self.current_hosts = ['192.168.1.50']
            return None

        mock_nm.scan.side_effect = scan_side_effect
        mock_nm.all_hosts.side_effect = lambda: self.current_hosts
        
        # Mocks
        def complex_getitem(k):
             if k == '192.168.1.50' and k in self.current_hosts:
                # Check args of last call to distinguish
                # Or just rely on state.
                # In Discovery, we return MAC.
                # In Standard, we return NO MAC.
                
                # We can check what mock_nm.scan was last called with?
                # Or simpler: The test logic calls scan(-sn), then scan(-Pn).
                # We can replicate strictly based on "Discovery" logic in client?
                # But here we are inside the side_effect logic.
                
                # Let's check the args based on call count or just inspect arguments passed to scan?
                # But getitem is called AFTER scan.
                # We can inspect the last call arguments of scan.
                
                last_call_args = mock_nm.scan.call_args[1].get('arguments', '')
                
                if '-sn' in last_call_args:
                    return {
                        'addresses': {'ipv4': '192.168.1.50', 'mac': 'AA:BB:CC:DD:EE:FF'},
                        'vendor': {'AA:BB:CC:DD:EE:FF': 'GoodVendor'},
                        'osmatch': []
                    }
                else:
                    # Standard Scan (-Pn) - Simulate missing MAC
                    return {
                        'addresses': {'ipv4': '192.168.1.50'}, # NO MAC
                        'osmatch': [],
                        'vendor': {}
                    }
             return {}
        
        # We need a Mock object that supports .hostname() and []
        class MockHost(dict):
            def hostname(self): return "Device1"
            def all_protocols(self): return []

        mock_nm.__getitem__.side_effect = lambda k: MockHost(complex_getitem(k))

        scanner = CRAScanner()
        results = scanner.scan_subnet('192.168.1.0/24', {'scan_type': 'standard'})
        
        if not results:
            print("FAILED: No results returned.")
            self.fail("No results")
            
        device = results[0]
        print(f"Device MAC: {device.get('mac')}")
        
        if device.get('mac') == 'AA:BB:CC:DD:EE:FF':
            print("PASSED: MAC preserved.")
        else:
            print("FAILED: MAC lost (became Unknown or None).")
            
        self.assertEqual(device.get('mac'), 'AA:BB:CC:DD:EE:FF', "MAC address should be preserved from discovery scan.")

if __name__ == '__main__':
    unittest.main()
