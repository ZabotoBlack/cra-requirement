from scan_logic import CRAScanner
import logging

# Setup Logger to see output
logging.basicConfig(level=logging.INFO)

scanner = CRAScanner()

# Mock Device 1: Tuya Device
tuya_device = {
    "ip": "192.168.1.100",
    "openPorts": [{"port": 6668, "service": "tuya", "protocol": "tcp"}],
    "vendor": "Tuya Smart Inc."
}

# Mock Device 2: Shelly Device (Mocking the HTTP check requires mocking requests.get, 
# but we can test the port trigger effectively or just the secure_by_default logic if we assume response)
# For this script we mainly check pass-through.
# To test actual logic we might need to mock scanner._check_http_auth or run against real generic ports.

print("--- Testing Tuya Detection ---")
warnings = scanner._check_vendor_specifics(tuya_device)
print(f"Tuya Warnings: {warnings}")

print("\n--- Testing Telnet Check Logic ---")
telnet_device = {
    "ip": "192.168.1.101",
    "openPorts": [{"port": 23, "service": "telnet", "protocol": "tcp"}]
}
# We expect check_secure_by_default to fail because port 23 is open
res = scanner.check_secure_by_default(telnet_device)
print(f"Telnet Result: {res}")

print("\n--- Testing Kasa Detection ---")
kasa_device = {
    "ip": "192.168.1.102",
    "openPorts": [{"port": 9999, "service": "unknown", "protocol": "tcp"}]
}
warnings = scanner._check_vendor_specifics(kasa_device)
print(f"Kasa Warnings: {warnings}")
