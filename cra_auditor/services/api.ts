import { ScanReport, ScanOptions, DefaultSubnetResponse, LogsResponse } from '../types';

/** Start a new scan job with subnet and normalized scan options. */
export const startScan = async (subnet: string, options: ScanOptions): Promise<void> => {
  const response = await fetch('api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ subnet, options }),
  });

  if (!response.ok) {
    if (response.status === 409) {
      throw new Error('Scan already in progress');
    }
    throw new Error('Failed to start scan');
  }
};

/** Get current scanner state used by the polling loop. */
export const getScanStatus = async (): Promise<{ scanning: boolean; error?: string } | null> => {
  try {
    const response = await fetch('api/status');
    if (!response.ok) return null;
    const data = await response.json();
    return { scanning: data.scanning, error: data.error };
  } catch (e) {
    return null;
  }
};

/** Fetch the latest scan report snapshot. */
export const getReport = async (): Promise<ScanReport | null> => {
  try {
    const response = await fetch('api/report');
    if (!response.ok) return null;
    return await response.json();
  } catch (e) {
    return null;
  }
};

/** Load frontend feature flags exposed by the backend. */
export const getConfig = async (): Promise<{ gemini_enabled: boolean; nvd_enabled: boolean; version: string }> => {
  try {
    const response = await fetch('api/config');
    if (!response.ok) return { gemini_enabled: false, nvd_enabled: false, version: 'unknown' };
    return await response.json();
  } catch (e) {
    return { gemini_enabled: false, nvd_enabled: false, version: 'unknown' };
  }
};

/** Request auto-detected local subnet for convenience in basic mode. */
export const getDefaultSubnet = async (): Promise<DefaultSubnetResponse | null> => {
  try {
    const response = await fetch('api/network/default');
    if (!response.ok) return null;
    return await response.json();
  } catch (e) {
    return null;
  }
};

/** Retrieve recent runtime logs for expert diagnostics panels. */
export const getLogs = async (limit: number = 150): Promise<LogsResponse | null> => {
  try {
    const response = await fetch(`api/logs?limit=${limit}`);
    if (!response.ok) return null;
    return await response.json();
  } catch (e) {
    return null;
  }
};

/** List historical scan summaries with optional query and sorting parameters. */
export const getHistory = async (search: string = '', sort_by: string = 'timestamp', order: string = 'desc'): Promise<any[]> => {
  try {
    const params = new URLSearchParams({ search, sort_by, order });
    const response = await fetch(`api/history?${params}`);
    if (!response.ok) return [];
    return await response.json();
  } catch (e) {
    return [];
  }
};

/** Fetch full report payload for a specific historical scan ID. */
export const getHistoryDetail = async (id: number): Promise<ScanReport | null> => {
  try {
    const response = await fetch(`api/history/${id}`);
    if (!response.ok) return null;
    return await response.json();
  } catch (e) {
    return null;
  }
};

/** Delete a historical scan entry by ID. */
export const deleteHistory = async (id: number): Promise<boolean> => {
  try {
    const response = await fetch(`api/history/${id}`, { method: 'DELETE' });
    return response.ok;
  } catch (e) {
    return false;
  }
};
