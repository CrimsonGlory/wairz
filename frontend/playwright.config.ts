import { defineConfig, devices } from '@playwright/test';

// Must match the API_KEY written into CI .env (e2e-tests.yml) and the
// docker-compose backend. Auth is open only when API_KEY is empty.
const E2E_API_KEY = process.env.E2E_API_KEY || process.env.API_KEY || 'ci-only-api-key';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false, // tests depend on project state
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // sequential — tests modify shared state
  // list + html: list prints failures when the job is cancelled mid-run;
  // html alone left CI logs with only progress glyphs.
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'html',
  expect: {
    timeout: 10000,
  },
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    // Seed the SPA's API key before any document script runs. The backend
    // requires X-API-Key when API_KEY is set; the static bundle has no
    // VITE_API_KEY unless baked at image build, so localStorage is the
    // operator path (src/api/client.ts::getApiKey).
    storageState: {
      cookies: [],
      origins: [
        {
          origin: 'http://localhost:3000',
          localStorage: [{ name: 'wairz.apiKey', value: E2E_API_KEY }],
        },
      ],
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: undefined, // assume frontend + backend already running
});
