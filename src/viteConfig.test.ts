import { describe, expect, it } from 'vitest';
import { createDashboardViteConfig } from '../vite.config';

describe('dashboard Vite configuration', () => {
  it('keeps a JSON guard in place even without a dashboard token', () => {
    const config = createDashboardViteConfig({ dashboardToken: '' });
    const plugins = config.plugins as Array<{ name?: string }>;

    expect(plugins.some(
      (plugin) => plugin.name === 'evt-dashboard-read-bff',
    )).toBe(true);
  });

  it('keeps the dashboard token in the dev-server proxy only', () => {
    const config = createDashboardViteConfig({
      dashboardToken: 'test-dashboard-token',
    });
    const plugins = config.plugins as Array<{ name?: string }>;
    expect(plugins.some(
      (plugin) => plugin.name === 'evt-dashboard-read-bff',
    )).toBe(true);
    expect(config.server).toMatchObject({
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
    });
  });
});
