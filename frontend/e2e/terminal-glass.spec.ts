import { expect, test } from '@playwright/test';

const urls = JSON.parse(process.env.CHINESCAN_BROWSER_TEST_URLS ?? '{}') as {
  standard?: { url: string; email: string; password: string };
};

test('Modules page terminal glass renders, remains keyboard operable, and reports frame rate', async ({ page }) => {
  const fixture = urls.standard;
  expect(fixture).toBeDefined();
  if (!fixture) throw new Error('Standard local browser fixture is unavailable.');
  await page.goto(fixture.url);
  await page.getByLabel('Email').fill(fixture.email);
  await page.getByLabel('Password').fill(fixture.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  const modules = page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Modules' });
  await modules.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Modules' })).toBeVisible();
  await expect(page.locator('.terminal-generated')).toContainText('╭─┐');
  await expect(page.locator('.module-card').first()).toBeVisible();
  await page.locator('.motion-toggle').selectOption('reduced');
  await expect(page.locator('.terminal-ambient')).toHaveClass(/is-static/);
  await page.screenshot({ path: 'test-results/modules-terminal-glass.png', fullPage: true });
  await page.locator('.motion-toggle').selectOption('full');
  await expect.poll(async () => page.locator('.terminal-scene').getAttribute('data-fps'), { timeout: 7000 }).not.toBeNull();
  const fps = await page.locator('.terminal-scene').getAttribute('data-fps');
  const renderer = await page.evaluate(() => {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('webgl2') ?? canvas.getContext('webgl');
    const info = context?.getExtension('WEBGL_debug_renderer_info');
    return info && context ? String(context.getParameter(info.UNMASKED_RENDERER_WEBGL)) : 'unavailable';
  });
  if (Number(fps) < 40) {
    await expect(page.locator('.terminal-scene')).toHaveAttribute('data-quality', 'reduced', { timeout: 5000 });
  }
  const quality = await page.locator('.terminal-scene').getAttribute('data-quality') ?? 'full';
  console.log(`Terminal scene measured FPS: ${fps ?? 'unavailable'}; quality mode: ${quality}; WebGL renderer: ${renderer}`);
});
