import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createWriteStream, type WriteStream } from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FullConfig } from '@playwright/test';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const pythonHarness = resolve(repoRoot, 'tests/browser/serve.py');
const children: ChildProcess[] = [];
let dataRoot = '';
const DIAGNOSTIC_LIMIT = 4_000;
const STARTUP_TIMEOUT_MS = 120_000;
const READINESS_TIMEOUT_MS = 45_000;
const READINESS_REQUEST_TIMEOUT_MS = 5_000;
const backendLog = resolve(repoRoot, 'frontend/test-results/backend.log');
let backendLogHandle: WriteStream | undefined;

interface TestCredentials {
  email: string;
  password: string;
}

function appendBounded(current: string, chunk: string): string {
  return (current + chunk).slice(-DIAGNOSTIC_LIMIT);
}

async function stopOwned(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return;
  if (process.platform === 'win32' && child.pid) {
    // `py.exe` may launch a separate python.exe; terminate only this fixture's process tree.
    const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
      stdio: 'ignore', windowsHide: true,
    });
    await new Promise<void>((resolvePromise) => killer.once('exit', () => resolvePromise()));
  } else {
    child.kill('SIGTERM');
  }
  if (child.exitCode === null) {
    await Promise.race([
      new Promise<void>((resolvePromise) => child.once('exit', () => resolvePromise())),
      new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 5_000)),
    ]);
  }
  if (child.exitCode === null && process.platform !== 'win32') child.kill('SIGKILL');
}

function makeCredentials(): TestCredentials {
  return {
    email: `browser-${randomBytes(4).toString('hex')}@example.test`,
    password: randomBytes(24).toString('base64url'),
  };
}

async function start(
  ttl: number,
  credentials: TestCredentials,
  holdScanUntilExpiry = false,
  emptyAccount = false,
  projectsEnabled = false,
  missingManagedStorage = false,
  githubImportEnabled = false,
): Promise<{ url: string; email: string; password: string; credentialFile: string; dataDirectory: string; githubRepositoryUrl: string | null }> {
  await mkdir(dirname(backendLog), { recursive: true });
  backendLogHandle ??= createWriteStream(backendLog, { flags: 'w' });
  const directory = resolve(dataRoot, `instance-${children.length}-ttl-${ttl}`);
  const python = 'uv';
  const args = ['run', 'python', pythonHarness, '--data-dir', directory, '--ttl', String(ttl)];
  if (holdScanUntilExpiry) args.push('--hold-scan-until-expiry');
  if (emptyAccount) args.push('--empty-account');
  if (projectsEnabled) args.push('--projects-enabled');
  if (missingManagedStorage) args.push('--missing-managed-storage');
  if (githubImportEnabled) args.push('--github-import-enabled');
  const childEnv: NodeJS.ProcessEnv = {
      ...process.env,
      PYTHONPATH: [repoRoot, process.env.PYTHONPATH].filter(Boolean).join(delimiter),
      CHINESCAN_CONFIG_PATH: resolve(directory, 'config.toml'),
      CHINESCAN_DATABASE_PATH: resolve(directory, 'records.sqlite3'),
      CHINESCAN_REPORTS_DIR: resolve(directory, 'reports'),
  };
  if (githubImportEnabled) {
    childEnv.CHINESCAN_TEST_GITHUB_IMPORT = '1';
    childEnv.CHINESCAN_BROWSER_TEST_MODE = '1';
  } else {
    delete childEnv.CHINESCAN_TEST_GITHUB_IMPORT;
    delete childEnv.CHINESCAN_BROWSER_TEST_MODE;
  }
  const child = spawn(python, args, {
    cwd: repoRoot,
    env: childEnv,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  children.push(child);
  let stdout = '';
  let stderr = '';
  let credentialsPipeFailed = false;
  child.stdout?.setEncoding('utf8');
  child.stderr?.setEncoding('utf8');
  const label = `instance-${children.length - 1}`;
  child.stdout?.on('data', (chunk: string) => {
    stdout = appendBounded(stdout, chunk);
    const sanitized = chunk.replace(/"(?:url|github_repository_url)"\s*:\s*"[^"]*"/g, '"endpoint":"[redacted]"');
    backendLogHandle?.write(`[${label}] stdout ${sanitized}`);
  });
  child.stderr?.on('data', (chunk: string) => {
    stderr = appendBounded(stderr, chunk);
    backendLogHandle?.write(`[${label}] stderr ${redactDiagnostic(chunk)}`);
  });
  try {
    if (!child.stdin) throw new Error('Dashboard fixture credential pipe is unavailable.');
    child.stdin.on('error', () => { credentialsPipeFailed = true; });
    child.stdin.end(emptyAccount ? '' : `${JSON.stringify(credentials)}\n`);
    const startedAt = Date.now();
    const deadline = startedAt + STARTUP_TIMEOUT_MS;
    let endpoint: { url: string; github_repository_url?: string } | undefined;
    while (Date.now() < deadline && !endpoint) {
      if (child.exitCode !== null || child.signalCode !== null) {
        throw new Error(`Dashboard fixture exited early (code=${child.exitCode}, signal=${child.signalCode}).`);
      }
      if (credentialsPipeFailed) throw new Error('Dashboard fixture could not receive test credentials.');
      const lineEnd = stdout.indexOf('\n');
      if (lineEnd >= 0) endpoint = JSON.parse(stdout.slice(0, lineEnd)) as typeof endpoint;
      else await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
    if (!endpoint) {
      const lineEnd = stdout.indexOf('\n');
      if (lineEnd >= 0) endpoint = JSON.parse(stdout.slice(0, lineEnd)) as typeof endpoint;
    }
    if (!endpoint) {
      throw new Error(`Dashboard fixture did not announce a listening URL within ${STARTUP_TIMEOUT_MS / 1000} seconds (elapsed ${((Date.now() - startedAt) / 1000).toFixed(1)}s).`);
    }

    // The child prints only the URL. Require HTTP readiness before sharing credentials with tests.
    const readyDeadline = Date.now() + Math.min(READINESS_TIMEOUT_MS, STARTUP_TIMEOUT_MS);
    let lastStatus = 'no response';
    let lastBody = 'no response';
    while (Date.now() < readyDeadline) {
      if (child.exitCode !== null || child.signalCode !== null) {
        throw new Error(`Dashboard fixture exited before HTTP readiness (code=${child.exitCode}).`);
      }
      try {
        const response = await fetch(`${endpoint.url}/api/auth/session`, {
          signal: AbortSignal.timeout(READINESS_REQUEST_TIMEOUT_MS),
        });
        lastStatus = String(response.status);
        const body = await response.text();
        lastBody = redactDiagnostic(body);
        let payload: unknown;
        try { payload = JSON.parse(body) as unknown; } catch { payload = null; }
        if (
          response.status === 200 &&
          payload !== null && typeof payload === 'object' &&
          'authenticated' in payload && payload.authenticated === false &&
          'email_masked' in payload && payload.email_masked === null &&
          'signup_available' in payload && typeof payload.signup_available === 'boolean'
        ) {
          return { ...endpoint, ...credentials, credentialFile: resolve(directory, 'operator.json'), dataDirectory: directory, githubRepositoryUrl: githubImportEnabled ? endpoint.github_repository_url ?? null : null };
        }
      } catch (error) {
        lastStatus = 'request error';
        lastBody = redactDiagnostic(String(error));
      }
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
    throw new Error(
      `Dashboard fixture did not become ready within ${READINESS_TIMEOUT_MS / 1000} seconds; ` +
      `last status=${lastStatus}, body=${lastBody}.`,
    );
  } catch (error) {
    await stopOwned(child);
    throw new Error(`${String(error)}\nFixture stderr (last ${DIAGNOSTIC_LIMIT} chars):\n${stderr}`);
  }
}

function redactDiagnostic(value: string): string {
  return value
    .replace(/("?(?:password|passwd|pwd|hash|token|secret|credential)[^"\s]*"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^,}\s]+)/gi, '$1[REDACTED]')
    .replace(/\$argon2(?:id|i|d)\$[^\s"']+/gi, '[REDACTED]')
    .replace(/(?:[A-Za-z]:\\|\\\\)[^\s"'<>`,;)}\]]+/g, '[PATH]')
    .replace(/\/(?:Users|home|root|tmp|var\/tmp)\/[^\s"'<>`,;)}\]]+/g, '[PATH]')
    .slice(0, 1_000);
}

export default async function globalSetup(_config: FullConfig) {
  const runId = randomBytes(5).toString('hex');
  dataRoot = await mkdtemp(resolve(tmpdir(), 'chinescan-playwright-'));
  try {
    const urls = {
      standard: await start(1800, makeCredentials(), false, false, true),
      expiry: await start(15, makeCredentials(), true),
      signup: await start(1800, makeCredentials(), false, true),
      emptyRoots: await start(1800, makeCredentials()),
      diagnosticsDegraded: await start(1800, makeCredentials(), false, false, false, true),
      githubEnabled: await start(1800, makeCredentials(), false, false, false, false, true),
      githubDisabled: await start(1800, makeCredentials()),
    };
    process.env.CHINESCAN_BROWSER_TEST_URLS = JSON.stringify(urls);
    process.env.CHINESCAN_E2E_RUN_ID = runId;
    process.env.CHINESCAN_BROWSER_PROJECT_FIXTURE = resolve(dataRoot, 'instance-0-ttl-1800-approved-project');
    process.env.CHINESCAN_BROWSER_GITHUB_URL = String(urls.githubEnabled.githubRepositoryUrl);
    process.env.CHINESCAN_BROWSER_GITHUB_DATA_DIR = urls.githubEnabled.dataDirectory;
    process.env.CHINESCAN_BROWSER_DISABLED_FIXTURE_URL = urls.githubDisabled.url;
    process.env.CHINESCAN_BROWSER_GITHUB_FIXTURE_URL = urls.githubEnabled.url;
    process.env.CHINESCAN_BROWSER_SCREENSHOT_DIR = resolve(tmpdir(), 'chinescan-projects-e2e-screenshots');
    process.env.CHINESCAN_BROWSER_PHASE6C_SCREENSHOTS = resolve(tmpdir(), 'chinescan-phase6c-screenshots');
    const statusScreenshotDirectory = resolve(tmpdir(), 'chinescan-phase5a-status-screenshots');
    await mkdir(statusScreenshotDirectory, { recursive: true });
    process.env.CHINESCAN_BROWSER_STATUS_SCREENSHOTS = statusScreenshotDirectory;
  } catch (error) {
    await Promise.all(children.map(stopOwned));
    await rm(dataRoot, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    throw error;
  }
  return async () => {
    await Promise.all(children.map(stopOwned));
    delete process.env.CHINESCAN_BROWSER_TEST_URLS;
    delete process.env.CHINESCAN_E2E_RUN_ID;
    delete process.env.CHINESCAN_BROWSER_PROJECT_FIXTURE;
    delete process.env.CHINESCAN_BROWSER_GITHUB_URL;
    delete process.env.CHINESCAN_BROWSER_GITHUB_DATA_DIR;
    delete process.env.CHINESCAN_BROWSER_DISABLED_FIXTURE_URL;
    delete process.env.CHINESCAN_BROWSER_GITHUB_FIXTURE_URL;
    delete process.env.CHINESCAN_BROWSER_SCREENSHOT_DIR;
    delete process.env.CHINESCAN_BROWSER_PHASE6C_SCREENSHOTS;
    delete process.env.CHINESCAN_BROWSER_STATUS_SCREENSHOTS;
    await rm(dataRoot, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    await new Promise<void>((resolvePromise) => {
      if (!backendLogHandle) return resolvePromise();
      backendLogHandle.end(resolvePromise);
      backendLogHandle = undefined;
    });
  };
}
