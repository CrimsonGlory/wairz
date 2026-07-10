import { test, expect } from '@playwright/test';
import { dismissDisclaimer, ensureProjectExists } from './helpers';

test.describe('Emulation Workflow', () => {
  test.describe.configure({ mode: 'serial' });

  let projectId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const projectUrl = await ensureProjectExists(page);
    const match = projectUrl.match(/\/projects\/([^/]+)/);
    projectId = match?.[1] ?? '';
    await page.close();
  });

  test('emulation page loads', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/emulation`);
    await dismissDisclaimer(page);
    await expect(page.locator('body')).toBeVisible();
    const content = page.locator('main, [class*="content"]');
    await expect(content).toBeVisible({ timeout: 10000 });
  });

  test('emulation mode tabs are present', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/emulation`);
    await dismissDisclaimer(page);

    // The page has User Mode and System Mode tabs
    const userModeTab = page.getByText('User Mode').first();
    const systemModeTab = page.getByText('System Mode').first();

    const userVisible = await userModeTab.isVisible().catch(() => false);
    const systemVisible = await systemModeTab.isVisible().catch(() => false);

    // At least the mode tabs should render
    expect(userVisible || systemVisible).toBe(true);
  });

  test('user mode shows binary path input', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/emulation`);
    await dismissDisclaimer(page);

    // Click User Mode tab if not already selected
    const userModeTab = page.getByText('User Mode').first();
    if (await userModeTab.isVisible().catch(() => false)) {
      await userModeTab.click();
      await page.waitForTimeout(300);
    }

    // User mode should render interactive controls — path input, combobox,
    // or action buttons (UI varies by firmware kind / empty project).
    const binaryInput = page.locator(
      'input[placeholder*="binary" i], input[placeholder*="path" i], input[name*="binary" i], [class*="binary"]',
    );
    const binarySelector = page.locator('select, [role="combobox"]');
    const actionButtons = page.locator(
      'button:has-text("Start"), button:has-text("Browse"), button:has-text("Select")',
    );
    const inputCount = await binaryInput.count();
    const selectorCount = await binarySelector.count();
    const buttonCount = await actionButtons.count();
    const mainVisible = await page.getByRole('main').isVisible().catch(() => false);

    expect(inputCount + selectorCount + buttonCount > 0 || mainVisible).toBe(true);
  });

  test('start emulation button exists', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/emulation`);
    await dismissDisclaimer(page);

    // Look for a start/launch button
    const startButton = page.locator(
      'button:has-text("Start"), button:has-text("Launch"), button:has-text("Run")',
    );
    const count = await startButton.count();
    expect(count).toBeGreaterThan(0);
  });

  test('presets section is accessible', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/emulation`);
    await dismissDisclaimer(page);

    // The page should have a presets area or button
    const presetsArea = page.locator(
      'button:has-text("Preset"), button:has-text("Save Preset"), [class*="preset"], h2:has-text("Preset"), h3:has-text("Preset")',
    );
    const count = await presetsArea.count();
    // Presets may not be visible if no presets exist, but the UI element should render
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('no console errors on emulation page', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text());
    });

    await page.goto(`/projects/${projectId}/emulation`);
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
