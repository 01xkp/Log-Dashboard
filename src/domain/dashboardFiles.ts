/**
 * Keeps the dashboard's initial and server-refresh source policy explicit.
 * Server mode must not make demo data look like production data.
 */

export type DashboardFileSource = 'sample' | 'local' | 'server';

export interface DashboardFileTime {
  readonly source: DashboardFileSource;
  readonly receivedAt: string | null;
  readonly uploadedAt: string | null;
}

export function createInitialDashboardEntries<T extends { readonly source: DashboardFileSource }>(
  hasApi: boolean,
  sampleEntries: readonly T[],
): T[] {
  return hasApi ? [] : [...sampleEntries];
}

export function mergeServerEntries<T extends { readonly source: DashboardFileSource }>(
  serverEntries: readonly T[],
  existingEntries: readonly T[],
): T[] {
  return [
    ...serverEntries,
    ...existingEntries.filter((entry) => entry.source === 'local'),
  ];
}

/**
 * `uploaded_at` is the App-declared upload time. It makes a server list row
 * correspond to the time visible in the App, while `received_at` remains the
 * authoritative server ordering and filtering timestamp.
 */
export function preferredDashboardLogTime(file: DashboardFileTime): string | null {
  return file.source === 'server' ? file.uploadedAt ?? file.receivedAt : file.receivedAt;
}

export function shouldShowServerReceivedTime(file: DashboardFileTime): boolean {
  if (file.source !== 'server' || !file.uploadedAt || !file.receivedAt) {
    return false;
  }

  return Date.parse(file.uploadedAt) !== Date.parse(file.receivedAt);
}
