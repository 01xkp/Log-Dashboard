import { defineConfig, loadEnv, type UserConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import Components from 'unplugin-vue-components/vite';
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers';
import { createDashboardReadBff } from './src/server/dashboardApiBff';

const dashboardApiTarget = 'https://log.moreuos.com';

interface DashboardViteConfigOptions {
  dashboardToken?: string;
}

export function createDashboardViteConfig(
  options: DashboardViteConfigOptions = {},
): UserConfig {
  const dashboardToken = options.dashboardToken?.trim() ?? '';

  return {
    plugins: [
      vue(),
      Components({
        resolvers: [ElementPlusResolver({ importStyle: 'css' })],
        dts: false,
      }),
      createDashboardReadBff({
        dashboardToken,
        target: dashboardApiTarget,
      }),
    ],
    server: dashboardToken
      ? {
          host: '127.0.0.1',
          port: 5173,
          strictPort: true,
        }
      : undefined,
    test: {
      environment: 'node',
    },
  };
}

export default defineConfig(({ mode }) => {
  const environment = loadEnv(mode, '.', '');
  return createDashboardViteConfig({
    dashboardToken: environment.EVT_LOG_DASHBOARD_TOKEN,
  });
});
