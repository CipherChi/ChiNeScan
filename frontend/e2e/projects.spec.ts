import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { basename, parse, relative, resolve, sep } from 'node:path';

const runId = process.env.CHINESCAN_E2E_RUN_ID ?? 'local';
const codeProjectName = `E2E code project ${runId}`;
const codeCaseTitle = `E2E linked project case ${runId}`;
const malwareProjectName = `E2E malware project ${runId}`;
const logProjectName = (run: number) => `E2E log project ${runId} ${run}`;

type Fixture = { url: string; email: string; password: string };
function fixtures(): Record<string, Fixture> {
  return JSON.parse(process.env.CHINESCAN_BROWSER_TEST_URLS ?? '{}') as Record<string, Fixture>;
}
async function signIn(page: import('@playwright/test').Page, fixture: Fixture) {
  await page.goto(fixture.url);
  await page.getByLabel('Email').fill(fixture.email);
  await page.getByLabel('Password').fill(fixture.password);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
}
async function capture(page: import('@playwright/test').Page, filename: string) {
  const directory = process.env.CHINESCAN_BROWSER_SCREENSHOT_DIR;
  if (!directory) throw new Error('Project E2E screenshot directory was not configured.');
  mkdirSync(directory, { recursive: true });
  await page.screenshot({ path: resolve(directory, filename), fullPage: true });
}

async function approveProjectFolder(
  page: import('@playwright/test').Page,
  projectName: string,
  targetPath?: string,
) {
  await page.getByRole('button', { name: 'Add project' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toHaveAccessibleName('Select a project folder');
  await expect(dialog).toBeVisible();
  if (targetPath) {
    const response = await page.evaluate(async () => {
      const result = await fetch('/api/fs/picker-roots');
      return { ok: result.ok, body: await result.json() as { items: Array<{ name: string }> } };
    });
    expect(response.ok).toBeTruthy();
    const roots = response.body.items;
    expect(roots.length).toBeGreaterThan(0);
    await dialog.getByRole('button', { name: `Open ${roots[0].name}`, exact: true }).click();
    const parts = relative(parse(roots[0].name).root, targetPath).split(sep).filter(Boolean);
    for (const part of parts.slice(0, -1)) {
      await dialog.getByRole('button', { name: `Open ${part}`, exact: true }).click();
    }
    const targetItem = dialog.getByRole('listitem').filter({ hasText: basename(targetPath) });
    await targetItem.getByRole('button', { name: 'Select this folder' }).click();
  } else {
    await dialog.getByRole('button', { name: 'Select this folder' }).first().click();
  }
  await dialog.getByRole('button', { name: 'Review folder' }).click();
  await expect(dialog.getByText('Approve this folder for assessment?')).toBeVisible();
  if (targetPath) await expect(dialog.getByText(targetPath, { exact: true })).toBeVisible();
  await dialog.getByLabel('Project name').fill(projectName);
  await dialog.getByRole('button', { name: 'Approve folder' }).click();
}

async function removeProjectRecord(page: import('@playwright/test').Page, projectName: string) {
  await page.getByRole('row').filter({ hasText: projectName }).getByRole('button', { name: 'Open project' }).click();
  await page.getByRole('button', { name: 'Remove project' }).click();
  await page.getByLabel(new RegExp(`Type ${projectName} to confirm`)).fill(projectName);
  await page.getByRole('button', { name: 'Remove project record' }).click();
  await expect(page.getByRole('row').filter({ hasText: projectName })).toHaveCount(0);
}

async function folderHash(directory: string): Promise<string> {
  const hash = createHash('sha256');
  async function visit(current: string, relative: string) {
    for (const entry of (await readdir(current, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const entryPath = resolve(current, entry.name);
      const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        hash.update(`directory:${entryRelative}\0`);
        await visit(entryPath, entryRelative);
      } else if (entry.isFile()) {
        hash.update(`file:${entryRelative}\0`);
        hash.update(await readFile(entryPath));
      } else {
        hash.update(`other:${entryRelative}\0`);
      }
    }
  }
  await visit(directory, '');
  return hash.digest('hex');
}

test('add project, assess code, create linked case and remove record without touching files', async ({ page }) => {
  const fixture = fixtures().standard;
  const projectFolder = process.env.CHINESCAN_BROWSER_PROJECT_FIXTURE;
  expect(projectFolder).toBeTruthy();
  const originalFolderHash = await folderHash(projectFolder!);
  await signIn(page, fixture);
  await page.getByRole('button', { name: 'Projects', exact: true }).click();
  await approveProjectFolder(page, codeProjectName);
  await capture(page, 'picker.png');
  await expect(page.getByRole('heading', { name: codeProjectName })).toBeVisible();
  await capture(page, 'project-page.png');
  const assessmentRequests: string[] = [];
  page.on('response', (response) => {
    const url = new URL(response.url());
    const match = url.pathname.match(/^\/api\/projects\/[^/]+(?:\/code-jobs)?$/);
    if (!match) return;
    const route = url.pathname.replace(/^\/api\/projects\/[^/]+/, '/api/projects/:id');
    assessmentRequests.push(`${response.request().method()} ${route} -> ${response.status()}`);
  });
  page.on('requestfailed', (request) => {
    const url = new URL(request.url());
    if (!/^\/api\/projects\/[^/]+(?:\/code-jobs)?$/.test(url.pathname)) return;
    const route = url.pathname.replace(/^\/api\/projects\/[^/]+/, '/api/projects/:id');
    assessmentRequests.push(`${request.method()} ${route} -> request failed`);
  });
  await page.getByRole('button', { name: 'Assess code' }).click();
  const partial = page.getByText('Partial result');
  try {
    await expect(partial).toBeVisible({ timeout: 60_000 });
  } catch (error) {
    const recentJobRows = await page.getByRole('region', { name: 'Recent jobs' }).getByRole('listitem').count().catch(() => -1);
    const assessmentHistoryRows = await page.getByRole('region', { name: 'Assessment history' }).locator('.project-scan-row').count().catch(() => -1);
    const apiEvents = assessmentRequests.slice(-20).join('\n') || '[no matching API responses]';
    throw new Error(`${String(error)}\nAssessment diagnostics (sanitized routes/status and row counts only):\n${apiEvents}\nRecent job rows: ${recentJobRows}\nAssessment history rows: ${assessmentHistoryRows}`);
  }
  await capture(page, 'partial-banner.png');
  await expect(page.getByRole('heading', { name: /Persisted findings/ })).toBeVisible();
  const caseLink = page.getByRole('button', { name: 'Create or link case' }).first();
  await expect(caseLink).toBeVisible();
  await caseLink.click();
  await expect(page.getByRole('heading', { name: 'Create a case' })).toBeVisible();
  await page.getByLabel('Case title').fill(codeCaseTitle);
  await page.getByRole('button', { name: 'Create case' }).click();
  await expect(page.getByText('Case created and saved.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Projects', exact: true }).click();
  await page.getByRole('row').filter({ hasText: codeProjectName }).getByRole('button', { name: 'Open project' }).click();
  await expect(page.getByText(codeCaseTitle)).toBeVisible();
  await page.getByRole('button', { name: 'Remove project' }).click();
  await page.getByLabel(new RegExp(`Type ${codeProjectName} to confirm`)).fill(codeProjectName);
  await page.getByRole('button', { name: 'Remove project record' }).click();
  await expect(page.getByRole('row').filter({ hasText: codeProjectName })).toHaveCount(0);
  expect(existsSync(resolve(projectFolder!, 'app.py'))).toBe(true);
  expect(existsSync(resolve(projectFolder!, 'worker.py'))).toBe(true);
  expect(await folderHash(projectFolder!)).toBe(originalFolderHash);
});

test('project picker shows local folders when allowed-roots is empty', async ({ page }) => {
  const fixture = fixtures().emptyRoots;
  await signIn(page, fixture);
  await page.getByRole('button', { name: 'Projects', exact: true }).click();
  await page.getByRole('button', { name: 'Add project' }).click();
  const dialog = page.getByRole('dialog', { name: 'Select a project folder' });
  await expect(dialog.getByRole('heading', { name: 'Local drives and allowed roots' })).toBeVisible();
  await expect(dialog.getByRole('button', { name: /^Open / }).first()).toBeVisible();
});

test('project malware acknowledgement gates scanning, shows partial findings, and cancel starts nothing', async ({ page }) => {
  const fixture = fixtures().standard;
  await signIn(page, fixture);
  await page.getByRole('button', { name: 'Projects', exact: true }).click();
  await approveProjectFolder(page, malwareProjectName);
  await expect(page.getByRole('heading', { name: malwareProjectName })).toBeVisible();

  const startedJobs: string[] = [];
  page.on('request', (request) => {
    if (request.method() === 'POST' && /\/api\/projects\/[^/]+\/malware-jobs$/.test(request.url())) startedJobs.push(request.url());
  });
  await page.getByRole('button', { name: 'Scan for malware' }).click();
  const dialog = page.getByRole('dialog', { name: 'Before scanning this project' });
  await expect(dialog).toBeVisible();
  await capture(page, 'malware-modal.png');
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).not.toBeVisible();
  expect(startedJobs).toHaveLength(0);

  await page.getByRole('button', { name: 'Scan for malware' }).click();
  const acknowledgement = page.waitForResponse((response) => response.url().endsWith('/api/malware/acknowledgements') && response.status() === 201);
  await page.getByRole('checkbox', { name: /understand the VM and containment risk/i }).check();
  await page.getByRole('button', { name: 'Confirm scan' }).click();
  await acknowledgement;
  await expect(page.getByRole('status').filter({ hasText: /Project malware scan (succeeded|partial)/ })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByRole('list', { name: 'Project malware findings' })).toContainText(/Download Pipe Shell/i);
  await capture(page, 'malware-project-section.png');
  await expect(page.getByText('Partial malware scan')).toBeVisible();
  await capture(page, 'malware-partial-banner.png');
  expect(startedJobs).toHaveLength(1);
  await page.getByRole('button', { name: '← All projects' }).click();
  await removeProjectRecord(page, malwareProjectName);
});

test('project log suggestions and analysis work twice and removal preserves files', async ({ page }) => {
  const fixture = fixtures().standard;
  const projectFolder = process.env.CHINESCAN_BROWSER_PROJECT_FIXTURE;
  expect(projectFolder).toBeTruthy();
  const originalFolderHash = await folderHash(projectFolder!);
  await signIn(page, fixture);

  for (let run = 1; run <= 2; run += 1) {
    await page.getByRole('button', { name: 'Projects', exact: true }).click();
    await approveProjectFolder(page, logProjectName(run));
    await expect(page.getByRole('heading', { name: logProjectName(run) })).toBeVisible();
    await capture(page, `project-log-locations-${run}.png`);

    await page.getByRole('button', { name: 'Suggest locations' }).click();
    const suggestions = page.getByRole('region', { name: 'Log location suggestions' });
      const logsSuggestion = suggestions.getByRole('listitem').filter({ hasText: /^logs\s*Confirm$/ });
      await expect(logsSuggestion).toBeVisible();
    await capture(page, `project-log-suggestions-${run}.png`);
      await logsSuggestion.getByRole('button', { name: 'Confirm' }).click();
    await expect(page.getByRole('checkbox', { name: 'logs' })).toBeVisible();
    await page.getByRole('button', { name: 'Analyze logs' }).click();
    await expect(page.getByRole('region', { name: 'Log locations' }).getByRole('status')).toContainText(/Log analysis succeeded|Log analysis partial/);
    await expect(page.getByText('Repeated authentication failures')).toBeVisible({ timeout: 60_000 });
    await capture(page, `project-log-alerts-${run}.png`);

    const handleRemoveDialog = async (dialog: import('@playwright/test').Dialog) => {
      if (dialog.type() === 'confirm') await dialog.accept();
      else await dialog.accept('logs');
    };
    page.on('dialog', handleRemoveDialog);
    await page.getByRole('button', { name: 'Remove', exact: true }).click();
    page.off('dialog', handleRemoveDialog);
    await expect(page.getByText('No log locations linked yet.')).toBeVisible();
    expect(await folderHash(projectFolder!)).toBe(originalFolderHash);
    await page.getByRole('button', { name: '← All projects' }).click();
  }
  for (const projectName of [logProjectName(1), logProjectName(2)]) {
    await removeProjectRecord(page, projectName);
  }
});
