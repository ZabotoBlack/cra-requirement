export enum ComplianceStatus {
  DISCOVERED = 'Discovered',
  COMPLIANT = 'Compliant',
  WARNING = 'Warning',
  NON_COMPLIANT = 'Non-Compliant'
}

export interface ScanFeatureFlags {
  network_discovery?: boolean;
  port_scan?: boolean;
  os_detection?: boolean;
  service_version?: boolean;
  netbios_info?: boolean;
  compliance_checks?: boolean;
  auth_brute_force?: boolean;
  web_crawling?: boolean;
  port_range?: string;
}

export interface ScanOptions {
  scan_type: 'discovery' | 'standard' | 'deep';
  profile?: 'discovery' | 'standard' | 'deep';
  auth_checks?: boolean;
  vendors?: string[] | 'all';
  features?: ScanFeatureFlags;
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

export interface FrontendConfig {
  gemini_enabled: boolean;
  nvd_enabled: boolean;
  version: string;
}

export type UserMode = 'basic' | 'intermediate' | 'expert';

export interface DefaultSubnetResponse {
  subnet: string | null;
  source: 'auto' | 'fallback-required';
  message?: string;
}

export interface LogsResponse {
  logs: string[];
}

export interface ScanProgress {
  completed: number;
  total: number;
  remaining: number;
  stage?: string | null;
  message?: string | null;
}

export interface ScanStatus {
  scanning: boolean;
  error?: string;
  timeoutDetected?: boolean;
  cancelRequested?: boolean;
  elapsedSeconds?: number;
  progress?: ScanProgress;
  lastScan?: {
    outcome?: 'completed' | 'aborted' | 'timeout' | 'failed' | string | null;
    reason?: string | null;
    finishedAt?: number | null;
  };
}

export interface Device {
  mac: string;
  ip: string;
  vendor: string;
  model?: string;
  hostname: string;
  source?: string;
  status: ComplianceStatus | string;
  attackSurface?: {
    score: number;
    rating: 'Low' | 'Medium' | 'High';
    openPortsCount: number;
    details: string;
  };
  checks: Partial<{
    secureByDefault: {
      passed: boolean;
      details: string; // e.g., "Default credentials admin/admin found"
    };
    dataConfidentiality: {
      passed: boolean;
      details: string;
    };
    httpsOnlyManagement: {
      passed: boolean;
      details: string;
      checked_ports: number[];
      failed_ports: number[];
      inconclusive_ports: number[];
    };
    vulnerabilities: {
      passed: boolean;
      details?: string;
      cpe?: string;
      cves: Vulnerability[];
    };
    sbomCompliance: {
      passed: boolean;
      details: string;
      sbom_found: boolean;
      sbom_format: string | null;
    };
    firmwareTracking: {
      passed: boolean;
      details: string;
      firmware_version: string | null;
      firmware_source: string | null;
      update_available: boolean | null;
      update_url: string | null;
      version_cves: Vulnerability[];
    };
    securityTxt: {
      passed: boolean;
      details: string;
      security_txt_found: boolean;
      fields: {
        contact: string | null;
        expires: string | null;
        encryption: string | null;
        policy: string | null;
        preferred_languages: string | null;
      } | null;
      vendor_url: string | null;
    };
    securityLogging: {
      passed: boolean;
      details: string;
      syslog_udp_514: boolean;
      syslog_probe_state: string;
      logging_endpoints: string[];
    };
  }>;
  lastScanned: string;
  osMatch: string;
  openPorts: PortScan[];
}

export interface ScanReport {
  timestamp: string;
  targetRange: string;
  scanProfile?: 'discovery' | 'standard' | 'deep';
  scanFeatures?: ScanFeatureFlags;
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
