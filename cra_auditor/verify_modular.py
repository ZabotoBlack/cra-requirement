import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scan_logic import CRAScanner
import logging
from unittest.mock import MagicMock

# Setup Logger
logging.basicConfig(level=logging.INFO)

scanner = CRAScanner()
scanner.nm = MagicMock()
scanner.nm.all_hosts.return_value = ['192.168.1.100'] # Mock finding a host
# Mock host details
mock_host = MagicMock()
mock_host.__getitem__.side_effect = lambda x: {'ipv4': '192.168.1.100', 'mac': '00:11:22:33:44:55'} if x == 'addresses' else {}
mock_host.__contains__.side_effect = lambda x: x in ['addresses', 'vendor']
mock_host.hostname.return_value = "mock-device"
mock_host.all_protocols.return_value = [] # For get_open_ports
scanner.nm.__getitem__.return_value = mock_host 

print("\n--- Test 1: Defaults (Deep Scan) ---")
options = {}
try:
    scanner.scan_subnet("192.168.1.0/24", options)
    # Check calling args
    args, kwargs = scanner.nm.scan.call_args
    print(f"Call Args: {kwargs.get('arguments')}")
    if "-sV -O --top-ports 1000" in kwargs.get('arguments', ''):
        print("PASS: Defaults used deep scan.")
    else:
        print("FAIL: Defaults did not use deep scan.")
except Exception as e:
    print(f"Error: {e}")

print("\n--- Test 2: Discovery Only ---")
options = {"scan_type": "discovery"}
scanner.nm.scan.reset_mock()
scanner.nm.all_hosts.return_value = ['192.168.1.100']
try:
    scanner.scan_subnet("192.168.1.0/24", options)
    # Discovery only runs the first scan (-sn -PR)
    # The SECOND scan (detailed) should NOT run.
    if scanner.nm.scan.call_count == 1:
         # verify the ONE call was discovery
         args, kwargs = scanner.nm.scan.call_args
         if "-sn -PR" in kwargs.get('arguments', ''):
             print("PASS: Discovery mode ran only discovery scan.")
         else:
             print("FAIL: Discovery mode ran wrong args.")
    else:
        print(f"FAIL: Discovery mode called scan {scanner.nm.scan.call_count} times.")
except Exception as e:
    print(f"Error: {e}")
    
print("\n--- Test 3: Vendor Specific (Tuya Only) ---")
options = {"scan_type": "standard", "vendors": ["tuya"]}
scanner.nm.scan.reset_mock()
scanner.nm.all_hosts.return_value = ['192.168.1.100']
try:
    scanner.scan_subnet("192.168.1.0/24", options)
    # Detailed scan should run
    # Should have -p containing 6668, but NOT 8081 (Sonoff) or 9999 (Kasa)
    # We need to find the call where hosts='192.168.1.100'
    calls = scanner.nm.scan.call_args_list
    found = False
    for call in calls:
        kwargs = call.kwargs
        if 'hosts' in kwargs and kwargs['hosts'] == '192.168.1.100':
            args = kwargs['arguments']
            print(f"Detailed Scan Args: {args}")
            if "6668" in args and "8081" not in args and "9999" not in args:
                print("PASS: Correctly filtered output for Tuya only.")
                found = True
    if not found:
        print("FAIL: Did not find detailed scan call.")
except Exception as e:
    print(f"Error: {e}")

print("\n--- Test 4: No Vendors (Empty List) ---")
options = {"scan_type": "standard", "vendors": []}
scanner.nm.scan.reset_mock()
scanner.nm.all_hosts.return_value = ['192.168.1.100']
try:
    scanner.scan_subnet("192.168.1.0/24", options)
    # detailed scan should run
    # -p should NOT contain 6668, 8081, 9999
    calls = scanner.nm.scan.call_args_list
    found = False
    for call in calls:
        kwargs = call.kwargs
        if 'hosts' in kwargs and kwargs['hosts'] == '192.168.1.100':
            found = True
            args = kwargs['arguments']
            print(f"Detailed Scan Args: {args}")
            if "6668" not in args and "8081" not in args and "9999" not in args:
                print("PASS: Correctly skipped all vendor ports.")
            else:
                print(f"FAIL: Vendor ports found in args: {args}")
            break
    if not found:
        print("FAIL: Did not find detailed scan call.")
except Exception as e:
    print(f"Error: {e}")
