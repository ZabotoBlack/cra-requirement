import sys
import os
import logging

# Ensure we can import scan_logic from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan_logic import CRAScanner

class MockNmap:
    def scan(self, hosts, arguments):
        return {}
    def all_hosts(self):
        return ['192.168.1.100']
    
    def __getitem__(self, key):
        if key == '192.168.1.100':
            class Host:
                def __contains__(self, k):
                    return k in ['addresses', 'vendor', 'osmatch']
                def __getitem__(self, k):
                    if k == 'addresses':
                        return {'mac': '00:11:22:33:44:55', 'ipv4': '192.168.1.100'}
                    if k == 'vendor':
                        return {'00:11:22:33:44:55': 'Mock Vendor'}
                    return {}
                def hostname(self):
                    return ''
                def all_protocols(self):
                    return []
            return Host()
        return {}

def test_scan_subnet():
    """Verify that the discovery scan returns the expected mocked results."""
    scanner = CRAScanner()
    scanner.nm = MockNmap()

    res = scanner.scan_subnet("192.168.1.0/24", {"profile": "discovery"})
    
    assert isinstance(res, list), "Result should be a list of devices"
    assert len(res) > 0, "Expected at least one device in the result"
