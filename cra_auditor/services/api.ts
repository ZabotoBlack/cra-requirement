import { ScanReport } from '../types';

export const startScan = async (subnet: string): Promise<void> => {
  const response = await fetch('api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ subnet }),
  });

  if (!response.ok) {
    if (response.status === 409) {
      throw new Error('Scan already in progress');
    }
    throw new Error('Failed to start scan');
  }
};

export const getScanStatus = async (): Promise<boolean> => {
  try {
    const response = await fetch('api/status');
    if (!response.ok) return false;
    const data = await response.json();
    return data.scanning;
  } catch (e) {
    return false;
  }
};

export const getReport = async (): Promise<ScanReport | null> => {
  try {
    const response = await fetch('api/report');
    if (!response.ok) return null;
    return await response.json();
  } catch (e) {
    return null;
  }
};
