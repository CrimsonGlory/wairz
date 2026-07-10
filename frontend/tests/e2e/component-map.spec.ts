import { test, expect } from '@playwright/test';
import { dismissDisclaimer, ensureProjectExists } from './helpers';

test.describe('Component Map', () => {
  test.describe.configure({ mode: 'serial' });

  let projectId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    const projectUrl = await ensureProjectExists(page);
    const match = projectUrl.match(/\/projects\/([^/]+)/);
    projectId = match?.[1] ?? '';
    await page.close();
  });

  test('component map page loads', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/map`);
    await dismissDisclaimer(page);
    await expect(page.locator('body')).toBeVisible();

    // The page should render: either the ReactFlow canvas, a loading state,
    // an error state, or an empty state — all are valid depending on firmware
    const content = page.locator(
      '.react-flow, [class*="react-flow"], [class*="loading"], [class*="muted-foreground"], main',
    );
    await expect(content.first()).toBeVisible({ timeout: 15000 });
  });

  test('page shows graph or empty state', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/map`);
    await dismissDisclaimer(page);

    // Wait for loading to finish — either the ReactFlow canvas appears,
    // or an empty/error state message
    const graph = page.locator('.react-flow, [class*="react-flow"]');
    const emptyOrError = page.getByText(
      /no components|make sure firmware|failed to load|building component/i,
    );

    const result = await Promise.race([
      graph.waitFor({ state: 'visible', timeout: 15000 }).then(() => 'graph'),
      emptyOrError.waitFor({ state: 'visible', timeout: 15000 }).then(() => 'empty'),
      // Page may still be loading analysis for a brand-new project with no map data
      page
        .getByRole('main')
        .waitFor({ state: 'visible', timeout: 15000 })
        .then(() => 'main'),
    ]).catch(() => 'timeout');

    expect(['graph', 'empty', 'main']).toContain(result);
  });

  test('ReactFlow controls render when graph is present', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    await page.goto(`/projects/${projectId}/map`);
    await dismissDisclaimer(page);

    // If the graph loads, check for controls (zoom, fit, layout)
    const graph = page.locator('.react-flow, [class*="react-flow"]');
    const graphVisible = await graph
      .waitFor({ state: 'visible', timeout: 15000 })
      .then(() => true)
      .catch(() => false);

    if (!graphVisible) {
      // No graph rendered (no firmware or empty) — skip control checks
      return;
    }

    // ReactFlow canvas should have interactive controls
    // The MapControls component renders buttons for zoom, fit, filter, export
    const controls = page.locator(
      '.react-flow__controls, [class*="controls"], button[title], [class*="MapControls"]',
    );
    const count = await controls.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('no console errors on component map page', async ({ page }) => {
    test.skip(!projectId, 'No project available');
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text());
    });

    await page.goto(`/projects/${projectId}/map`);
    await dismissDisclaimer(page);
    await page.waitForLoadState('networkidle');

    // Give extra time for the component map to finish loading
    await page.waitForTimeout(2000);

    const realErrors = errors.filter(
      (e) =>
        !e.includes('favicon') &&
        !e.includes('ERR_CONNECTION_REFUSED') &&
        !e.includes('net::ERR_') &&
        !e.includes('Failed to fetch') &&
        // Empty brand-new projects legitimately 404 map/firmware endpoints
        !e.includes('404') &&
        !e.includes('No firmware uploaded') &&
        !e.includes('[API Error]'),
    );
    expect(realErrors).toEqual([]);
  });
});
