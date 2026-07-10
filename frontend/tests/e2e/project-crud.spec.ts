import { test, expect } from '@playwright/test';
import { dismissDisclaimer } from './helpers';

test.describe('Project CRUD', () => {
  const projectName = `E2E Test Project ${Date.now()}`;

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
    await page.goto('/projects');
    await dismissDisclaimer(page);

    // Click into the project
    await page.getByText(projectName).first().click();
    await expect(page).toHaveURL(/\/projects\/[a-f0-9-]+$/);

    // Verify key elements are present (banner also has h1 "Projects")
    await expect(
      page.getByRole('main').getByRole('heading', { level: 1 }),
    ).toContainText(projectName);

    // Status badge should be visible (created, ready, etc.)
    const statusBadge = page.locator('[class*="badge"], [class*="Badge"]').first();
    await expect(statusBadge).toBeVisible();

    // The "Upload Firmware" card should be visible since no firmware was uploaded
    await expect(
      page.getByText('Upload Firmware').first(),
    ).toBeVisible();

    // Back button should work
    await page.getByRole('link', { name: 'Back' }).click();
    await expect(page).toHaveURL('/projects');
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
