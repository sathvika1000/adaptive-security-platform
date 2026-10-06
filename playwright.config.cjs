const {defineConfig} = require('@playwright/test');
module.exports = defineConfig({
  testDir: './tests/browser', testMatch: '**/*.spec.cjs',
  timeout: 30000, expect: {timeout: 10000}, workers: 1,
  fullyParallel: false, forbidOnly: Boolean(process.env.CI), retries: 0,
  reporter: [['list'], ['html', {open: 'never'}]],
  use: {baseURL: 'http://127.0.0.1:8037', browserName: 'chromium',
    viewport: {width: 1440, height: 1000}, trace: 'retain-on-failure',
    screenshot: 'only-on-failure'},
  webServer: [
    {command: 'python tests/browser/serve_fixture.py 8037', url: 'http://127.0.0.1:8037/ready',
      reuseExistingServer: false, timeout: 30000},
    {command: 'python tests/browser/serve_fixture.py 8038 --named', url: 'http://127.0.0.1:8038/ready',
      reuseExistingServer: false, timeout: 30000},
  ],
});
