import { act, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { MAX_RETRY_INTERVAL_MS, SystemStatus } from './SystemStatus';

type CheckFixture = {
  id: string;
  label: string;
  state: 'PASS' | 'WARN' | 'FAIL';
  detail: string;
  action_hint: string;
};

function checkFixture(overrides: Partial<CheckFixture> = {}): CheckFixture {
  return {
    id: 'database',
    label: 'Local database',
    state: 'FAIL',
    detail: 'Database access failed.',
    action_hint: 'Check local database availability.',
    ...overrides,
  };
}

function jsonResponse<T>(value: T, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function successfulFetch(checkState: CheckFixture['state'] = 'PASS'): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
    const path = String(input);
    if (path === '/api/health') {
      return jsonResponse({ status: 'ok', version: '0.1.0', uptime_seconds: 42 });
    }
    if (path === '/api/ready') {
      return jsonResponse({ checks: [checkFixture({ state: checkState })] });
    }
    if (path === '/api/diagnostics') {
      return jsonResponse({
        status: checkState === 'FAIL' ? 'failed' : checkState === 'WARN' ? 'degraded' : 'ok',
        version: '0.1.0',
        operator_state: 'active',
        allowed_roots: { valid: 2, ignored: 1 },
        scan_bounds: { max_files: 5000 },
        recent_errors: [],
      });
    }
    throw new Error(`Unexpected API request: ${path}`);
  });
}

it('renders healthy status and accessible live updates', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(successfulFetch());
  const { container } = render(<SystemStatus onUnauthorized={vi.fn()} />);

  expect(await screen.findByText('[PASS]')).toBeInTheDocument();
  expect(screen.getByText('Connected to local service')).toBeInTheDocument();
  expect(screen.getByText('Version 0.1.0')).toBeInTheDocument();
  expect(container.querySelector('[aria-live="polite"]')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Check system status now' })).toBeEnabled();
});

it('shows completed endpoint results when readiness stalls and records the timeout', async () => {
  vi.useFakeTimers();
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const path = String(input);
    if (path === '/api/ready') {
      return await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      });
    }
    if (path === '/api/health') return jsonResponse({ status: 'ok', version: '0.1.0', uptime_seconds: 42 });
    return jsonResponse({ status: 'ok', version: '0.1.0', operator_state: 'active', allowed_roots: { valid: 1, ignored: 0 }, scan_bounds: {}, recent_errors: [] });
  });
  render(<SystemStatus onUnauthorized={vi.fn()} />);
  await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
  expect(screen.getByText('Connected to local service')).toBeInTheDocument();
  expect(screen.getByText(/Health: received · readiness: timed out · diagnostics: received/)).toBeInTheDocument();
});

it('renders degraded readiness with its action hint', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(successfulFetch('WARN'));
  render(<SystemStatus onUnauthorized={vi.fn()} />);

  expect(await screen.findByText('[WARN]')).toBeInTheDocument();
  expect(screen.getByText('Action: Check local database availability.')).toBeInTheDocument();
});

it('renders failing readiness checks from a 503 response and diagnostics summaries', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const path = String(input);
    if (path === '/api/health') {
      return jsonResponse({ status: 'ok', version: '0.1.0', uptime_seconds: 42 });
    }
    if (path === '/api/ready') {
      return jsonResponse({ checks: [checkFixture()] }, 503);
    }
    if (path === '/api/diagnostics') {
      return jsonResponse({
        status: 'failed',
        version: '0.1.0',
        operator_state: 'active',
        allowed_roots: { valid: 2, ignored: 1 },
        scan_bounds: { max_files: 5000 },
        recent_errors: [],
      });
    }
    throw new Error(`Unexpected API request: ${path}`);
  });

  render(<SystemStatus onUnauthorized={vi.fn()} />);

  expect(await screen.findByText('[FAIL]')).toBeInTheDocument();
  expect(screen.getByText('Database access failed.')).toBeInTheDocument();
  expect(screen.getByText('Action: Check local database availability.')).toBeInTheDocument();
  await waitFor(() => expect(screen.getByText('Operator state:')).toBeInTheDocument());
  expect(screen.getByText(/Allowed roots:/).textContent).toBe('Allowed roots: 2 valid, 1 ignored');
  expect(screen.getByText('Connected to local service')).toBeInTheDocument();
});

it('uses non-decreasing exponential retry intervals capped at 60 seconds', async () => {
  vi.useFakeTimers();
  const request = vi.fn(async () => { throw new TypeError('offline'); });
  vi.spyOn(globalThis, 'fetch').mockImplementation(request);
  render(<SystemStatus onUnauthorized={vi.fn()} />);

  await act(async () => { await Promise.resolve(); });
  expect(screen.getByText('Service offline')).toBeInTheDocument();
  let elapsed = 0;
  let interval = 1000;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await act(async () => { await vi.advanceTimersByTimeAsync(interval - 1); });
    expect(request).toHaveBeenCalledTimes((attempt + 1) * 3);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    await act(async () => { await Promise.resolve(); });
    elapsed += interval;
    expect(request).toHaveBeenCalledTimes((attempt + 2) * 3);
    interval = Math.min(interval * 2, MAX_RETRY_INTERVAL_MS);
  }
  expect(interval).toBe(MAX_RETRY_INTERVAL_MS);
  expect(elapsed).toBe(183_000);
});

it('Check now starts one refresh, disables while in flight, then re-enables', async () => {
  const releases: Array<() => void> = [];
  let totalRequests = 0;
  let manualRequests = 0;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    totalRequests += 1;
    if (totalRequests > 3) {
      manualRequests += 1;
      await new Promise<void>((resolve) => { releases.push(resolve); });
    }
    const response = await successfulFetch()(input);
    return response;
  });
  render(<SystemStatus onUnauthorized={vi.fn()} />);
  expect(await screen.findByText('Connected to local service')).toBeInTheDocument();
  const checkButton = screen.getByRole('button', { name: 'Check system status now' });
  await act(async () => { checkButton.click(); });
  expect(checkButton).toBeDisabled();
  expect(manualRequests).toBe(3);
  await act(async () => { releases.forEach((release) => release()); });
  expect(await screen.findByRole('status')).toHaveTextContent('System check complete: connected');
  expect(checkButton).toBeEnabled();
  expect(manualRequests).toBe(3);
});

it('resets retry delay after recovery', async () => {
  vi.useFakeTimers();
  let requestCount = 0;
  let shouldFail = true;
  const request = vi.fn(async (input: RequestInfo | URL) => {
    requestCount += 1;
    if (shouldFail && requestCount <= 6) throw new TypeError('offline');
    if (shouldFail && requestCount > 6) throw new TypeError('offline');
    return successfulFetch()(input);
  });
  vi.spyOn(globalThis, 'fetch').mockImplementation(request);
  render(<SystemStatus onUnauthorized={vi.fn()} />);
  await act(async () => { await Promise.resolve(); });
  await act(async () => { await vi.advanceTimersByTimeAsync(1_000); });
  await act(async () => { await Promise.resolve(); });
  expect(requestCount).toBe(6);

  shouldFail = false;
  await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
  expect(screen.getByText('Connected to local service')).toBeInTheDocument();
  shouldFail = true;
  await act(async () => { screen.getByRole('button', { name: 'Check system status now' }).click(); });
  await act(async () => { await Promise.resolve(); });
  const countAfterFailure = requestCount;
  await act(async () => { await vi.advanceTimersByTimeAsync(999); });
  expect(requestCount).toBe(countAfterFailure);
  await act(async () => { await vi.advanceTimersByTimeAsync(1); });
  expect(requestCount).toBe(countAfterFailure + 3);
});

it('stops polling and clears timers on unmount', async () => {
  vi.useFakeTimers();
  vi.spyOn(globalThis, 'fetch').mockImplementation(successfulFetch());
  const { unmount } = render(<SystemStatus onUnauthorized={vi.fn()} />);
  await act(async () => { await Promise.resolve(); });
  expect(screen.getByText('Connected to local service')).toBeInTheDocument();
  unmount();
  const callsBeforeAdvance = vi.mocked(fetch).mock.calls.length;
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(vi.mocked(fetch)).toHaveBeenCalledTimes(callsBeforeAdvance);
  expect(vi.getTimerCount()).toBe(0);
});

it('redirects an unauthenticated session through the unauthorized callback', async () => {
  const onUnauthorized = vi.fn();
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    new Response('{}', { status: 401, headers: { 'Content-Type': 'application/json' } }),
  );
  render(<SystemStatus onUnauthorized={onUnauthorized} />);
  await waitFor(() => expect(onUnauthorized).toHaveBeenCalledTimes(1));
});
