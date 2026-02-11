export enum ComplianceStatus {
  COMPLIANT = 'Compliant',
  WARNING = 'Warning',
  NON_COMPLIANT = 'Non-Compliant'
}

export interface ScanOptions {
  scan_type: 'discovery' | 'standard' | 'deep';
  auth_checks: boolean;
  vendors: string[] | 'all';
}


export interface PortScan {
  port: number;
  service: string;
  encrypted: boolean;
}

export interface Vulnerability {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface Device {
  mac: string;
  ip: string;
  vendor: string;
  model?: string;
  hostname: string;
  source?: string;
  status: ComplianceStatus;
  checks: {
    secureByDefault: {
      passed: boolean;
      details: string; // e.g., "Default credentials admin/admin found"
    };
    dataConfidentiality: {
      passed: boolean;
      details: string;
    };
    vulnerabilities: {
      passed: boolean;
      cves: Vulnerability[];
    };
    sbomCompliance: {
      passed: boolean;
      details: string;
      sbom_found: boolean;
      sbom_format: string | null;
    };
  };
  lastScanned: string;
  osMatch: string;
  openPorts: PortScan[];
}

export interface ScanReport {
  timestamp: string;
  targetRange: string;
  devices: Device[];
  summary: {
    total: number;
    compliant: number;
    warning: number;
    nonCompliant: number;
  };
}

export interface ScanHistoryItem {
  id: number;
  timestamp: string;
  target_range: string;
  summary: {
    total: number;
    compliant: number;
    warning: number;
    nonCompliant: number;
  };
}

export type ViewState = 'dashboard' | 'devices' | 'history';
