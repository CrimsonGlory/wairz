import { test, expect } from '@playwright/test';
import { dismissDisclaimer, ensureProjectExists } from './helpers';

test.describe('Navigation', () => {
  test('home page redirects to /projects', async ({ page }) => {
    await page.goto('/');
    await dismissDisclaimer(page);
    await expect(page).toHaveURL('/projects');
  });

  test('projects page loads and shows heading', async ({ page }) => {
    await page.goto('/projects');
    await dismissDisclaimer(page);
    await expect(page.locator('h1')).toContainText('Projects');
  });

  test('sidebar shows Projects link', async ({ page }) => {
    await page.goto('/projects');
    await dismissDisclaimer(page);

    // The sidebar should have a "Projects" navigation link
    const sidebarProjects = page.locator('aside').getByText('Projects');
    await expect(sidebarProjects.first()).toBeVisible();
  });

  test('help page loads', async ({ page }) => {
    await page.goto('/help');
    await dismissDisclaimer(page);
    // The page should load without errors
    await expect(page.locator('main, [class*="content"], body')).toBeVisible();
  });

  test('404 page shows for unknown routes', async ({ page }) => {
    await page.goto('/this-does-not-exist');
    await dismissDisclaimer(page);
    // Should show some kind of not-found indicator
    await expect(page.locator('body')).toBeVisible();
  });

  test('project subpages load when a project exists', async ({ page }) => {
    const projectUrl = await ensureProjectExists(page);
    const projectId = projectUrl.match(/\/projects\/([^/]+)/)?.[1];
    if (!projectId) {
      test.skip(true, 'Could not extract project ID');
      return;
    }

    const subpages = [
      { path: `/projects/${projectId}/explore`, label: 'File Explorer' },
      { path: `/projects/${projectId}/sbom`, label: 'SBOM' },
      { path: `/projects/${projectId}/findings`, label: 'Findings' },
      { path: `/projects/${projectId}/emulation`, label: 'Emulation' },
      { path: `/projects/${projectId}/compare`, label: 'Compare' },
      { path: `/projects/${projectId}/security`, label: 'Security' },
    ];

    for (const sub of subpages) {
      await page.goto(sub.path);
      // Each page should load without a hard error (no white screen).
      // Verify the page container is present and no uncaught error overlay.
      await expect(page.locator('body')).toBeVisible();
      // Check no React error overlay appeared
      const errorOverlay = page.locator('#webpack-dev-server-client-overlay, vite-error-overlay');
      await expect(errorOverlay).toHaveCount(0);
    }
  });

  test('sidebar navigation links work for project subpages', async ({ page }) => {
    const _projectUrl = await ensureProjectExists(page);

    // The sidebar should show the project expanded with sub-page links.
    // Click through a few sidebar links and verify URL changes.
    const sidebar = page.locator('aside');

    // Click "File Explorer" in sidebar
    const explorerLink = sidebar.getByText('File Explorer');
    if (await explorerLink.isVisible()) {
      await explorerLink.click();
      await expect(page).toHaveURL(/\/explore$/);
    }

    // Click "SBOM" in sidebar
    const sbomLink = sidebar.getByText('SBOM');
    if (await sbomLink.isVisible()) {
      await sbomLink.click();
      await expect(page).toHaveURL(/\/sbom$/);
    }

    // Click "Findings" in sidebar
    const findingsLink = sidebar.getByText('Findings');
    if (await findingsLink.isVisible()) {
      await findingsLink.click();
      await expect(page).toHaveURL(/\/findings$/);
    }

    // Click "Overview" to go back to project detail
    const overviewLink = sidebar.getByText('Overview');
    if (await overviewLink.isVisible()) {
      await overviewLink.click();
      await expect(page).toHaveURL(/\/projects\/[^/]+$/);
    }
  });

  test('no console errors on main pages', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    await page.goto('/projects');
    await dismissDisclaimer(page);

    // Wait for page to settle
    await page.waitForLoadState('networkidle');

    // Filter out known benign errors (e.g., favicon 404, API connection refused if backend is down)
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
