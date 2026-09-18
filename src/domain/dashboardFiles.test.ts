import { describe, expect, it } from 'vitest';
import {
  createInitialDashboardEntries,
  mergeServerEntries,
  preferredDashboardLogTime,
  shouldShowServerReceivedTime,
  type DashboardFileSource,
} from './dashboardFiles';

interface Entry {
  readonly source: DashboardFileSource;
  readonly id: string;
}

describe('dashboard file source policy', () => {
  const samples: readonly Entry[] = [{ source: 'sample', id: 'demo-1' }];

  it('starts empty when a real API is configured', () => {
    expect(createInitialDashboardEntries(true, samples)).toEqual([]);
  });

  it('keeps demo samples for local-only analysis mode', () => {
    expect(createInitialDashboardEntries(false, samples)).toEqual(samples);
  });

  it('replaces server rows without reintroducing demo rows', () => {
    const current: readonly Entry[] = [
      { source: 'sample', id: 'demo-1' },
      { source: 'server', id: 'old-server' },
      { source: 'local', id: 'imported-1' },
    ];
    const next: readonly Entry[] = [{ source: 'server', id: 'new-server' }];

    expect(mergeServerEntries(next, current)).toEqual([
      { source: 'server', id: 'new-server' },
      { source: 'local', id: 'imported-1' },
    ]);
  });

  it('uses the App upload time for a server log while retaining its receive time', () => {
    const serverLog = {
      source: 'server' as const,
      uploadedAt: '2026-09-18T05:56:46.666498Z',
      receivedAt: '2026-09-18T05:49:25Z',
    };

    expect(preferredDashboardLogTime(serverLog)).toBe('2026-09-18T05:56:46.666498Z');
    expect(shouldShowServerReceivedTime(serverLog)).toBe(true);
  });

  it('falls back to the receive time for local logs and older server responses', () => {
    expect(preferredDashboardLogTime({
      source: 'local',
      uploadedAt: null,
      receivedAt: '2026-09-18T05:49:25Z',
    })).toBe('2026-09-18T05:49:25Z');
    expect(preferredDashboardLogTime({
      source: 'server',
      uploadedAt: null,
      receivedAt: '2026-09-18T05:49:25Z',
    })).toBe('2026-09-18T05:49:25Z');
    expect(shouldShowServerReceivedTime({
      source: 'server',
      uploadedAt: '2026-09-18T05:49:25.000Z',
      receivedAt: '2026-09-18T05:49:25Z',
    })).toBe(false);
  });
});
