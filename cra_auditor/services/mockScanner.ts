import { Device, ComplianceStatus, ScanReport } from '../types';

// Mock data for simulation
const VENDORS = ['Espressif', 'Raspberry Pi Trading', 'Ubiquiti', 'Sonos', 'Philips Hue', 'Unknown China OEM', 'Apple', 'Google'];
const COMMON_CREDS = ['admin/admin', 'root/root', 'root/1234', 'admin/password'];

const getRandomInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;

const generateRandomIP = (subnet: string) => {
  return `${subnet}.${getRandomInt(2, 254)}`;
};

const generateRandomMAC = (vendor: string) => {
  // Mock OUI based on vendor (simplified)
  const oui = vendor === 'Espressif' ? '24:6F:28' : vendor === 'Apple' ? 'BC:D1:19' : '00:1A:2B';
  return `${oui}:${getRandomInt(10, 99)}:${getRandomInt(10, 99)}:${getRandomInt(10, 99)}`;
};

// SIMULATION: "Secure by Default" Check
const checkSecureByDefault = (vendor: string) => {
  const isInsecure = Math.random() < 0.3; // 30% chance of default creds
  if (isInsecure && vendor !== 'Apple' && vendor !== 'Google') {
    const cred = COMMON_CREDS[getRandomInt(0, COMMON_CREDS.length - 1)];
    return { passed: false, details: `Authentication successful with ${cred}` };
  }
  return { passed: true, details: 'No default credentials accepted' };
};

// SIMULATION: "Protection of Data Confidentiality" Check
const checkConfidentiality = (vendor: string) => {
  const openPorts = [];
  const services = [
    { port: 80, service: 'http', encrypted: false },
    { port: 443, service: 'https', encrypted: true },
    { port: 22, service: 'ssh', encrypted: true },
    { port: 23, service: 'telnet', encrypted: false },
    { port: 21, service: 'ftp', encrypted: false },
  ];

  // Randomly assign ports
  if (Math.random() > 0.5) openPorts.push(services[0]); // HTTP
  if (Math.random() > 0.2) openPorts.push(services[1]); // HTTPS
  if (vendor === 'Raspberry Pi Trading' || vendor === 'Ubiquiti') openPorts.push(services[2]); // SSH
  if (Math.random() < 0.15) openPorts.push(services[3]); // Telnet (Bad)
  if (Math.random() < 0.1) openPorts.push(services[4]); // FTP (Bad)

  const hasUnencrypted = openPorts.some(p => !p.encrypted);
  
  return {
    passed: !hasUnencrypted,
    openPorts,
    details: hasUnencrypted 
      ? `Unencrypted services found: ${openPorts.filter(p => !p.encrypted).map(p => p.service.toUpperCase()).join(', ')}` 
      : 'All exposed services use encryption'
  };
};

// SIMULATION: "Absence of Known Vulnerabilities" Check
const checkVulnerabilities = (vendor: string) => {
  const hasCVE = Math.random() < 0.25;
  const cves = [];
  
  if (hasCVE) {
    cves.push({
      id: `CVE-${new Date().getFullYear()}-${getRandomInt(1000, 9999)}`,
      severity: Math.random() > 0.5 ? 'CRITICAL' : 'HIGH',
      description: `Remote Code Execution vulnerability in ${vendor} firmware network stack.`
    });
  }

  return {
    passed: cves.length === 0,
    cves
  };
};

export const runSimulatedScan = async (subnet: string): Promise<ScanReport> => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const deviceCount = getRandomInt(5, 12);
      const devices: Device[] = [];

      for (let i = 0; i < deviceCount; i++) {
        const vendor = VENDORS[getRandomInt(0, VENDORS.length - 1)];
        const authCheck = checkSecureByDefault(vendor);
        const confCheck = checkConfidentiality(vendor);
        const vulnCheck = checkVulnerabilities(vendor);

        let status = ComplianceStatus.COMPLIANT;
        if (!authCheck.passed || !vulnCheck.passed) {
          status = ComplianceStatus.NON_COMPLIANT;
        } else if (!confCheck.passed) {
          status = ComplianceStatus.WARNING;
        }

        devices.push({
          mac: generateRandomMAC(vendor),
          ip: generateRandomIP(subnet),
          vendor,
          hostname: `${vendor.replace(/\s/g, '-').toLowerCase()}-device-${i}`,
          status,
          checks: {
            secureByDefault: authCheck,
            dataConfidentiality: confCheck,
            vulnerabilities: vulnCheck as any // Cast for mock simplicity
          },
          lastScanned: new Date().toISOString()
        });
      }

      const summary = {
        total: devices.length,
        compliant: devices.filter(d => d.status === ComplianceStatus.COMPLIANT).length,
        warning: devices.filter(d => d.status === ComplianceStatus.WARNING).length,
        nonCompliant: devices.filter(d => d.status === ComplianceStatus.NON_COMPLIANT).length
      };

      resolve({
        timestamp: new Date().toISOString(),
        targetRange: `${subnet}.0/24`,
        devices,
        summary
      });
    }, 2500); // Simulate network latency
  });
};
