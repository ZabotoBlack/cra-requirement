import sys
import logging
logging.basicConfig(level=logging.DEBUG)

from scan_logic import CRAScanner
import nmap

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

scanner = CRAScanner()
scanner.nm = MockNmap()

try:
    res = scanner.scan_subnet("192.168.1.0/24", {"profile": "discovery"})
    print("SUCCESS", len(res))
except Exception as e:
    import traceback
    traceback.print_exc()
