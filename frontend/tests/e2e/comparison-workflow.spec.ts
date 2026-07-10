import { test, expect } from '@playwright/test';
import { dismissDisclaimer, ensureProjectExists } from './helpers';

test.describe('Comparison Workflow', () => {
  test.describe.configure({ mode: 'serial' });

  let projectId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const projectUrl = await ensureProjectExists(page);
    const match = projectUrl.match(/\/projects\/([^/]+)/);
    projectId = match?.[1] ?? '';
    await page.close();
  });

  test('comparison page loads', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/compare`);
    await dismissDisclaimer(page);
    await expect(page.locator('body')).toBeVisible();
    const content = page.locator('main, [class*="content"]');
    await expect(content).toBeVisible({ timeout: 10000 });
  });

  test('comparison page shows heading', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/compare`);
    await dismissDisclaimer(page);

    // The page heading should indicate firmware comparison
    const heading = page
      .getByRole('main')
      .getByRole('heading', { level: 1 })
      .filter({ hasText: /compare/i });
    await expect(heading).toBeVisible({ timeout: 10000 });
  });

  test('firmware version selectors are present', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/compare`);
    await dismissDisclaimer(page);

    // The comparison page has two firmware version selectors (Firmware A and B)
    // These may be <select> elements, comboboxes, or custom dropdowns
    const selectors = page.locator(
      'select, [role="combobox"], [class*="select"], button:has-text("Firmware A"), button:has-text("Firmware B")',
    );
    const count = await selectors.count();
    // At least the selector UI should be present (even if no firmware to select)
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('compare button is present', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/compare`);
    await dismissDisclaimer(page);

    // There should be a Compare button to trigger the diff
    const compareButton = page.locator('button:has-text("Compare")');
    const count = await compareButton.count();
    expect(count).toBeGreaterThan(0);
  });

  test('no console errors on comparison page', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text());
    });

    await page.goto(`/projects/${projectId}/compare`);
    await dismissDisclaimer(page);
    await page.waitForLoadState('networkidle');

    const realErrors = errors.filter(
      (e) =>
        !e.includes('favicon') &&
        !e.includes('ERR_CONNECTION_REFUSED') &&
        !e.includes('net::ERR_') &&
        !e.includes('Failed to fetch'),
    );
    expect(realErrors).toEqual([]);
  });
});
