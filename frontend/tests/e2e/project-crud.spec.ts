import { test, expect } from '@playwright/test';
import { dismissDisclaimer } from './helpers';

test.describe('Project CRUD', () => {
  test.describe.configure({ mode: 'serial' });
  const projectName = `E2E Test Project ${Date.now()}`;
  let projectUrl = '';

  test('create a new project and verify it appears', async ({ page }) => {
    await page.goto('/projects');
    await dismissDisclaimer(page);

    // Click "New Project" button
    await page.getByRole('button', { name: 'New Project' }).click();

    // The dialog should open with "New Project" title
    await expect(page.getByRole('heading', { name: 'New Project' })).toBeVisible();

    // Fill in the project name
    await page.getByLabel('Name').fill(projectName);

    // Optionally fill description
    await page.getByLabel('Description').fill('Created by Playwright E2E tests');

    // Click "Create Project"
    await page.getByRole('button', { name: 'Create Project' }).click();

    // Dialog should advance to firmware upload step
    await expect(
      page.getByRole('heading', { name: 'Upload Firmware' }),
    ).toBeVisible({ timeout: 10000 });

    // Skip firmware upload
    await page.getByRole('button', { name: 'Skip' }).click();

    // Should show "Project Created" step
    await expect(
      page.getByRole('heading', { name: 'Project Created' }),
    ).toBeVisible();

    // Click "Go to Project"
    await page.getByRole('button', { name: 'Go to Project' }).click();

    // Should navigate to the project detail page
    await expect(page).toHaveURL(/\/projects\/[a-f0-9-]+$/);
    projectUrl = page.url();
    await expect(
      page.getByRole('main').getByRole('heading', { level: 1 }),
    ).toContainText(projectName);
  });

  test('project appears in the projects list', async ({ page }) => {
    await page.goto('/projects');
    await dismissDisclaimer(page);

    // Wait for the project list to load
    await page.waitForLoadState('networkidle');

    // The project we created should appear somewhere on the page
    await expect(page.getByText(projectName).first()).toBeVisible({
      timeout: 10000,
    });
  });

  test('project detail page shows project info', async ({ page }) => {
    test.skip(!projectUrl, 'No project URL from create test');
    // Direct navigation is more reliable than re-finding a list card
    await page.goto(projectUrl);
    await dismissDisclaimer(page);
    await expect(page).toHaveURL(/\/projects\/[a-f0-9-]+$/);

    // Verify key elements are present (banner also has h1 "Projects")
    await expect(
      page.getByRole('main').getByRole('heading', { level: 1 }),
    ).toContainText(projectName);

    // Detail page should show the empty-project upload affordance and/or a status chip.
    // Badge class names vary (shadcn Badge vs custom chips) — don't hard-require a class.
    const uploadCard = page.getByText('Upload Firmware').first();
    const statusChip = page
      .getByRole('main')
      .locator('[class*="badge"], [class*="Badge"], [data-status]')
      .first();
    await expect(uploadCard.or(statusChip).first()).toBeVisible({ timeout: 10000 });

    // Back control should return to the projects list (link or button)
    const back = page.getByRole('link', { name: /back/i }).or(
      page.getByRole('button', { name: /back/i }),
    );
    if (await back.first().isVisible().catch(() => false)) {
      await back.first().click();
      await expect(page).toHaveURL(/\/projects\/?$/, { timeout: 10000 });
    } else {
      // Sidebar Projects link as fallback
      await page.locator('aside').getByText('Projects').first().click();
      await expect(page).toHaveURL(/\/projects\/?$/, { timeout: 10000 });
    }
  });

  test('create project with empty name is prevented', async ({ page }) => {
    await page.goto('/projects');
    await dismissDisclaimer(page);

    await page.getByRole('button', { name: 'New Project' }).click();
    await expect(page.getByRole('heading', { name: 'New Project' })).toBeVisible();

    // The "Create Project" button should be disabled when name is empty
    const createBtn = page.getByRole('button', { name: 'Create Project' });
    await expect(createBtn).toBeDisabled();

    // Type a space and verify still disabled (trimmed = empty)
    await page.getByLabel('Name').fill('   ');
    await expect(createBtn).toBeDisabled();

    // Cancel dialog
    await page.getByRole('button', { name: 'Cancel' }).click();
  });

  test('cancel create project dialog closes it', async ({ page }) => {
    await page.goto('/projects');
    await dismissDisclaimer(page);

    await page.getByRole('button', { name: 'New Project' }).click();
    await expect(page.getByRole('heading', { name: 'New Project' })).toBeVisible();

    await page.getByRole('button', { name: 'Cancel' }).click();

    // Dialog should be gone
    await expect(
      page.getByRole('heading', { name: 'New Project' }),
    ).not.toBeVisible();
  });
});
