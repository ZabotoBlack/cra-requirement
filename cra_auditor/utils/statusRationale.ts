import { ComplianceStatus, Device } from '../types';

export type ComplianceCheckId =
  | 'secureByDefault'
  | 'httpsOnlyManagement'
  | 'vulnerabilities'
  | 'minimalAttackSurface'
  | 'dataConfidentiality'
  | 'sbomCompliance'
  | 'firmwareTracking'
  | 'securityTxt'
  | 'securityLogging';

export const STRICT_CHECK_IDS: ComplianceCheckId[] = [
  'secureByDefault',
  'httpsOnlyManagement',
  'vulnerabilities',
  'minimalAttackSurface',
];

export const ADVISORY_CHECK_IDS: ComplianceCheckId[] = [
  'dataConfidentiality',
  'sbomCompliance',
  'firmwareTracking',
  'securityTxt',
  'securityLogging',
];

export interface DeviceStatusRationale {
  strictFailures: ComplianceCheckId[];
  advisoryFailures: ComplianceCheckId[];
  highAttackSurface: boolean;
  firmwareHasVersionCVEs: boolean;
  expectedStatus: ComplianceStatus | string;
}

export const deriveDeviceStatusRationale = (device: Device): DeviceStatusRationale => {
  const checks = device.checks || {};

  const strictFailures = STRICT_CHECK_IDS.filter((checkId) => checks[checkId]?.passed === false);
  const advisoryFailures = ADVISORY_CHECK_IDS.filter((checkId) => checks[checkId]?.passed === false);

  const firmwareResult = checks.firmwareTracking;
  const firmwareHasVersionCVEs = Boolean(
    firmwareResult?.passed === false
      && Array.isArray(firmwareResult.version_cves)
      && firmwareResult.version_cves.length > 0,
  );

  const highAttackSurface = device.attackSurface?.rating === 'High';

  let expectedStatus: ComplianceStatus | string = ComplianceStatus.COMPLIANT;
  const hasStrictFailure = strictFailures.length > 0;

  if (hasStrictFailure || firmwareHasVersionCVEs) {
    expectedStatus = ComplianceStatus.NON_COMPLIANT;
  } else if (advisoryFailures.length > 0 || highAttackSurface) {
    expectedStatus = ComplianceStatus.WARNING;
  }

  if (device.status === ComplianceStatus.DISCOVERED) {
    expectedStatus = ComplianceStatus.DISCOVERED;
  }

  return {
    strictFailures,
    advisoryFailures,
    highAttackSurface,
    firmwareHasVersionCVEs,
    expectedStatus,
  };
};
