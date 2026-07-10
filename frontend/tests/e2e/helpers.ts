import { type Page, expect } from '@playwright/test';

/**
 * Dismiss the WAIRZ disclaimer dialog if it appears.
 * The dialog shows on first visit per session and must be acknowledged
 * before interacting with the app.
 */
export async function dismissDisclaimer(page: Page): Promise<void> {
  const button = page.getByRole('button', { name: 'I Understand' });
  // The dialog may or may not appear depending on session state.
  // Wait briefly for it; if it doesn't show, move on.
  try {
    await button.waitFor({ state: 'visible', timeout: 3000 });
    await button.click();
    await button.waitFor({ state: 'hidden', timeout: 2000 });
  } catch {
    // Dialog did not appear — already dismissed in this session
  }
}

/**
 * Create a new project via the UI and return the project detail URL.
 * Assumes the caller has already navigated to /projects or any page
 * where the sidebar is visible.
 */
export async function createProject(
  page: Page,
  name: string,
): Promise<string> {
  await page.goto('/projects');
  await dismissDisclaimer(page);

  // Click "New Project" button
  await page.getByRole('button', { name: 'New Project' }).click();

  // Fill in the project name in the dialog
  await page.getByLabel('Name').fill(name);

  // Click "Create Project"
  await page.getByRole('button', { name: 'Create Project' }).click();

  // The dialog moves to the firmware upload step. Skip it.
  await page.getByRole('button', { name: 'Skip' }).click();

  // Now we're on the "Project Created" step. Click "Go to Project".
  await page.getByRole('button', { name: 'Go to Project' }).click();

  // Wait for the project detail page to load
  await expect(page.locator('h1')).toContainText(name, { timeout: 10000 });

  return page.url();
}

/**
 * Navigate to /projects and ensure at least one project exists.
 * If the project list is empty, creates a default test project.
 * Returns the URL of an existing project's detail page.
 */
export async function ensureProjectExists(page: Page): Promise<string> {
  await page.goto('/projects');
  await dismissDisclaimer(page);

  // Wait for the page heading (banner also has an h1 "Projects" — scope to main)
  const projectHeading = page
    .getByRole('main')
    .getByRole('heading', { name: 'Projects', exact: true });
  await expect(projectHeading).toBeVisible({ timeout: 10000 });

  // Check if there are any project cards (links to /projects/<uuid>)
  const projectLinks = page.locator('a[href^="/projects/"]');
  const count = await projectLinks.count();

  if (count > 0) {
    // Click the first project
    await projectLinks.first().click();
    await page.waitForURL(/\/projects\/[^/]+$/);
    return page.url();
  }

  // No projects exist — create one
  return createProject(page, 'E2E Default Project');
}

/**
 * Poll until a selector's text content matches the expected string.
 * Useful for waiting on asynchronous status transitions.
 */
export async function waitForStatus(
  page: Page,
  selector: string,
  expectedText: string,
  timeout = 30000,
): Promise<void> {
  await expect(page.locator(selector)).toContainText(expectedText, { timeout });
}
