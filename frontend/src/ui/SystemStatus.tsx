import { useEffect, useRef, useState } from 'react';
import { UnauthorizedError } from '../api';

type Check = {
  id: string;
  label: string;
  state: 'PASS' | 'WARN' | 'FAIL';
  detail: string;
  action_hint: string;
};
type Health = { status: string; version: string; uptime_seconds: number };
type ErrorSummary = {
  error_code: string;
  route: string;
  request_id: string;
  timestamp: string;
  message: string;
};
type Diagnostics = {
  status: string;
  version: string;
  operator_state: string;
  allowed_roots: { valid: number; ignored: number };
  scan_bounds: Record<string, number>;
  recent_errors: ErrorSummary[];
};
type RequestState = 'not checked' | 'received' | 'failed' | 'rate limited' | 'timed out';
type Snapshot = { health: Health | null; checks: Check[]; diagnostics: Diagnostics | null; online: boolean | null; requestStates: { health: RequestState; readiness: RequestState; diagnostics: RequestState } };
class RateLimitedError extends Error {}

const HEALTHY_POLL_INTERVAL_MS = 30_000;
const INITIAL_RETRY_INTERVAL_MS = 1_000;
const REQUEST_TIMEOUT_MS = 5_000;
export const MAX_RETRY_INTERVAL_MS = 60_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function decodeHealth(value: unknown): Health {
  if (!isRecord(value) || typeof value.status !== 'string' || typeof value.version !== 'string' || typeof value.uptime_seconds !== 'number') {
    throw new Error('Health response was invalid.');
  }
  return { status: value.status, version: value.version, uptime_seconds: value.uptime_seconds };
}

function decodeChecks(value: unknown): Check[] {
  if (!isRecord(value) || !Array.isArray(value.checks)) throw new Error('Readiness response was invalid.');
  const checks: Check[] = [];
  for (const item of value.checks) {
    if (!isRecord(item) || typeof item.id !== 'string' || typeof item.label !== 'string' ||
      (item.state !== 'PASS' && item.state !== 'WARN' && item.state !== 'FAIL') ||
      typeof item.detail !== 'string' || typeof item.action_hint !== 'string') {
      throw new Error('Readiness check response was invalid.');
    }
    checks.push({ id: item.id, label: item.label, state: item.state, detail: item.detail, action_hint: item.action_hint });
  }
  return checks;
}

function decodeDiagnostics(value: unknown): Diagnostics {
  if (!isRecord(value) || typeof value.status !== 'string' || typeof value.version !== 'string' ||
    typeof value.operator_state !== 'string' || !isRecord(value.allowed_roots) ||
    typeof value.allowed_roots.valid !== 'number' || typeof value.allowed_roots.ignored !== 'number' ||
    !isRecord(value.scan_bounds) || !Array.isArray(value.recent_errors)) {
    throw new Error('Diagnostics response was invalid.');
  }
  const scanBounds: Record<string, number> = {};
  for (const [key, bound] of Object.entries(value.scan_bounds)) {
    if (typeof bound !== 'number') throw new Error('Scan bounds response was invalid.');
    scanBounds[key] = bound;
  }
  const recentErrors: ErrorSummary[] = [];
  for (const error of value.recent_errors) {
    if (!isRecord(error) || typeof error.error_code !== 'string' || typeof error.route !== 'string' ||
      typeof error.request_id !== 'string' || typeof error.timestamp !== 'string' || typeof error.message !== 'string') {
      throw new Error('Recent errors response was invalid.');
    }
    recentErrors.push({ error_code: error.error_code, route: error.route, request_id: error.request_id, timestamp: error.timestamp, message: error.message });
  }
  return {
    status: value.status,
    version: value.version,
    operator_state: value.operator_state,
    allowed_roots: { valid: value.allowed_roots.valid, ignored: value.allowed_roots.ignored },
    scan_bounds: scanBounds,
    recent_errors: recentErrors,
  };
}

async function get<T>(url: string, signal: AbortSignal, decode: (value: unknown) => T): Promise<{ value: T; status: number }> {
  const response = await fetch(url, { credentials: 'same-origin', signal });
  if (response.status === 401) throw new UnauthorizedError();
  if (response.status === 429) throw new RateLimitedError();
  if (response.status >= 500 && !(url === '/api/ready' && response.status === 503)) {
    throw new Error('The local service returned an error.');
  }
  const value: unknown = await response.json();
  return { value: decode(value), status: response.status };
}

export function SystemStatus({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [snapshot, setSnapshot] = useState<Snapshot>({ health: null, checks: [], diagnostics: null, online: null, requestStates: { health: 'not checked', readiness: 'not checked', diagnostics: 'not checked' } });
  const [checking, setChecking] = useState(false);
  const [announcement, setAnnouncement] = useState('');
  const refreshRef = useRef<(() => Promise<void>) | null>(null);
  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    let retryDelay = INITIAL_RETRY_INTERVAL_MS;
    let inFlight = false;
    let activeController: AbortController | null = null;
    const schedule = (delay: number) => {
      if (!stopped) timer = window.setTimeout(() => { void poll(); }, delay);
    };
    const poll = async (manual = false): Promise<void> => {
      if (stopped || inFlight) return;
      inFlight = true;
      setChecking(true);
      const controller = new AbortController();
      activeController = controller;
      const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      if (manual) {
        if (timer !== undefined) window.clearTimeout(timer);
        setAnnouncement('Checking system status now.');
      }
      try {
        const results = await Promise.allSettled([
          get('/api/health', controller.signal, decodeHealth),
          get('/api/ready', controller.signal, decodeChecks),
          get('/api/diagnostics', controller.signal, decodeDiagnostics),
        ]);
        if (stopped) return;
        if (results.some((item) => item.status === 'rejected' && item.reason instanceof UnauthorizedError)) { onUnauthorized(); return; }
        const [health, ready, diagnostics] = results;
        const stateOf = (item: PromiseSettledResult<unknown>): RequestState => item.status === 'fulfilled'
          ? 'received' : item.reason instanceof RateLimitedError ? 'rate limited'
            : item.reason instanceof DOMException && item.reason.name === 'AbortError' ? 'timed out' : 'failed';
        setSnapshot((current) => ({
          health: health.status === 'fulfilled' ? health.value.value as Health : current.health,
          checks: ready.status === 'fulfilled' ? ready.value.value as Check[] : current.checks,
          diagnostics: diagnostics.status === 'fulfilled' ? diagnostics.value.value as Diagnostics : current.diagnostics,
          online: health.status === 'fulfilled' ? health.value.status < 500 : false,
          requestStates: { health: stateOf(health), readiness: stateOf(ready), diagnostics: stateOf(diagnostics) },
        }));
        const failed = [health, ready, diagnostics].some((item) => item.status === 'rejected');
        if (manual) setAnnouncement(failed
          ? `System check complete with partial results: health ${stateOf(health)}; readiness ${stateOf(ready)}; diagnostics ${stateOf(diagnostics)}.`
          : 'System check complete: connected to the local service.');
        if (failed) {
          const delay = retryDelay;
          retryDelay = Math.min(retryDelay * 2, MAX_RETRY_INTERVAL_MS);
          schedule(delay);
        } else {
          retryDelay = INITIAL_RETRY_INTERVAL_MS;
          schedule(HEALTHY_POLL_INTERVAL_MS);
        }
      } catch (reason) {
        if (reason instanceof UnauthorizedError) { onUnauthorized(); return; }
        if (reason instanceof RateLimitedError) {
          setSnapshot((current) => ({ ...current, online: true }));
          retryDelay = INITIAL_RETRY_INTERVAL_MS;
          if (manual) setAnnouncement('System check was rate limited; the service is reachable.');
          schedule(HEALTHY_POLL_INTERVAL_MS);
        } else if (!stopped) {
          setSnapshot((current) => ({ ...current, online: false }));
          if (manual) setAnnouncement('System check complete: service offline.');
          const delay = retryDelay;
          retryDelay = Math.min(retryDelay * 2, MAX_RETRY_INTERVAL_MS);
          schedule(delay);
        }
      } finally {
        window.clearTimeout(timeout);
        if (activeController === controller) activeController = null;
        inFlight = false;
        if (!stopped) setChecking(false);
      }
    };
    refreshRef.current = () => poll(true);
    void poll();
    return () => {
      stopped = true;
      activeController?.abort();
      if (timer !== undefined) window.clearTimeout(timer);
      refreshRef.current = null;
    };
  }, [onUnauthorized]);
  return <div className="status-workspace" aria-live="polite">
    <section className="panel status-connectivity" aria-label="Connectivity"><strong>{snapshot.online === null ? 'Checking local service' : snapshot.online ? 'Connected to local service' : 'Service offline'}</strong><span>{snapshot.online === null ? 'Checking service health and readiness.' : snapshot.online ? 'Polling for service health and readiness.' : 'The local service is unavailable. Retrying automatically.'}</span><button type="button" aria-label="Check system status now" onClick={() => { void refreshRef.current?.(); }} disabled={checking}>{checking ? 'Checking…' : 'Check now'}</button><span role="status" aria-live="polite">{announcement}</span></section>
    <section className="panel status-panel"><div className="panel-heading"><h2>System checks</h2><span>Version {snapshot.health?.version ?? 'Unavailable'}</span></div><p>Request results · Health: {snapshot.requestStates.health} · readiness: {snapshot.requestStates.readiness} · diagnostics: {snapshot.requestStates.diagnostics}</p><ul className="status-checks">{snapshot.checks.map((check) => <li key={check.id}><div><strong>{check.label}</strong><p>{check.detail}</p>{check.action_hint && <small>Action: {check.action_hint}</small>}</div><span className={`status-badge status-${check.state.toLowerCase()}`}>[{check.state}]</span></li>)}</ul></section>
    {snapshot.diagnostics && <div className="status-grid"><section className="panel status-panel"><h2>Local configuration</h2><p>Operator state: <strong>{snapshot.diagnostics.operator_state}</strong></p><p>Allowed roots: {snapshot.diagnostics.allowed_roots.valid} valid, {snapshot.diagnostics.allowed_roots.ignored} ignored</p><h3>Scan bounds</h3><dl>{Object.entries(snapshot.diagnostics.scan_bounds).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{value}</dd></div>)}</dl></section><section className="panel status-panel"><h2>Recent errors</h2>{snapshot.diagnostics.recent_errors.length ? <ul>{snapshot.diagnostics.recent_errors.map((item) => <li key={item.request_id}><strong>{item.error_code}</strong> {item.route}<p>{item.message}</p></li>)}</ul> : <p>No recent errors.</p>}</section></div>}
  </div>;
}
