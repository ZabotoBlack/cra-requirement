import { ComplianceStatus } from '../types';

type StatusTranslationKey =
  | 'status.compliant'
  | 'status.warningLabel'
  | 'status.nonCompliantLabel'
  | 'status.discovered';

/** Map backend compliance enum values to translated UI labels. */
export const localizeStatus = (
  status: string,
  t: (key: StatusTranslationKey) => string,
): string => {
  if (status === ComplianceStatus.COMPLIANT) return t('status.compliant');
  if (status === ComplianceStatus.WARNING) return t('status.warningLabel');
  if (status === ComplianceStatus.NON_COMPLIANT) return t('status.nonCompliantLabel');
  if (status === ComplianceStatus.DISCOVERED) return t('status.discovered');
  return status;
};
