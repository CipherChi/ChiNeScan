import { readFile, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function checkSource(text, filename) {
  if (/\.html?$/i.test(filename) && /<script\b(?![^>]*\bsrc\s*=)[^>]*>/i.test(text)) {
    throw new Error('Inline script tag is incompatible with strict CSP.');
  }
  if (/\.html?$/i.test(filename) && /<script\b[^>]*\bsrc\s*=\s*["'](?:https?:)?\/\//i.test(text)) {
    throw new Error('Script assets must be local.');
  }
  if (/\beval\s*\(/.test(text) || /new\s+Function\s*\(/.test(text)) {
    throw new Error(`Dynamic code execution found in ${filename}`);
  }
  if (/\bsetTimeout\s*\(\s*(["'`])/.test(text) || /\bsetInterval\s*\(\s*(["'`])/.test(text)) {
    throw new Error(`String timer callback found in ${filename}`);
  }
}

async function inspect(path) {
  for (const entry of await readdir(path, { withFileTypes: true })) {
    const child = join(path, entry.name);
    if (entry.isDirectory()) await inspect(child);
    else if (/\.(?:js|mjs|cjs|ts|tsx)$/.test(entry.name) && !/\.test\.(?:js|mjs|cjs|ts|tsx)$/.test(entry.name)) {
      const content = await readFile(child, 'utf8');
      checkSource(content, child);
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  checkSource(html, 'index.html');
  await inspect(fileURLToPath(new URL('../src', import.meta.url)));
  try {
    await inspect(fileURLToPath(new URL('../dist/assets', import.meta.url)));
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  console.log('Strict-CSP source and built-asset check passed: no inline scripts, eval, Function constructor, or string timers.');
}
