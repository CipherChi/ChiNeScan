import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { Finding, Scan } from '../types';
import reportParityFixtureJson from '../test-fixtures/report-parity.json';

const reportParityFixture = reportParityFixtureJson as unknown as { scan: Scan; findings: Finding[] };

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }));
}

describe('dashboard authentication and overview', () => {
  beforeEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); window.localStorage.clear(); });

  it('shows sign in after an unauthorized session check and loads stored metrics after login', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ detail: 'Authentication required.' }, 401);
      if (path === '/api/auth/login') return json({ email: 'analyst@example.test', csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({
        scan_count: 3,
        finding_count: 7,
        findings_by_severity: { critical: 1, high: 2, medium: 2, low: 1, info: 1 },
        findings_by_verdict: { confirmed: 2, likely: 1, lead: 4 },
        top_fix_first: [{ title: 'Confirmed auth gap', severity: 'high', location: 'src/api.ts:20' }],
        recent_scans: [],
      });
      if (path.startsWith('/api/findings?')) return json({ items: [], total: 0, limit: 20, offset: 0 });
      throw new Error(`Unexpected API call: ${path} ${init?.method ?? 'GET'}`);
    });

    render(<App/>);
    expect(await screen.findByRole('heading', { name: 'Welcome back' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /create account|register|sign up/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /create account|register|sign up/i })).not.toBeInTheDocument();
    expect(screen.queryByText('STORED SCANS')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'analyst@example.test' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'safe local password' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    expect(screen.getAllByText('ChiNeScan').length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText(/GNET|GNetScan/i)).not.toBeInTheDocument();
    expect(await screen.findByText('3', { selector: 'strong' })).toBeInTheDocument();
    expect(await screen.findByText('7', { selector: 'strong' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Findings by verdict' })).toBeInTheDocument();
    expect(screen.getByText('Confirmed auth gap')).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/overview', expect.anything()));
  });

  it('persists the animation preference, pauses in hidden tabs, and hides decoration from assistive tech', async () => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: false });
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ authenticated: true, email_masked: 'a***@example.test', signup_available: false });
      if (path === '/api/auth/csrf') return json({ csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({ scan_count: 0, finding_count: 0, findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings_by_verdict: { confirmed: 0, likely: 0, lead: 0 }, top_fix_first: [], recent_scans: [] });
      if (path.startsWith('/api/findings?')) return json({ items: [], total: 0, limit: 20, offset: 0 });
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    await screen.findByRole('heading', { name: 'Overview' });
    let ambient = document.querySelector('.terminal-ambient');
    expect(ambient).toHaveAttribute('aria-hidden', 'true');
    fireEvent.change(screen.getByRole('combobox', { name: 'Background animation' }), { target: { value: 'off' } });
    expect(screen.getByRole('combobox', { name: 'Background animation' })).toHaveValue('off');
    expect(window.localStorage.getItem('chinescan-terminal-motion')).toBe('off');
    fireEvent.change(screen.getByRole('combobox', { name: 'Background animation' }), { target: { value: 'full' } });
    ambient = document.querySelector('.terminal-ambient');
    expect(ambient).toHaveClass('is-active');
    Object.defineProperty(document, 'hidden', { configurable: true, value: true });
    fireEvent(document, new Event('visibilitychange'));
    await waitFor(() => expect(ambient).not.toHaveClass('is-active'));
  });

  it('uses reduced-motion settings and migrates the previous local preference', async () => {
    window.localStorage.setItem('gnet-scan-terminal-motion', 'on');
    vi.stubGlobal('matchMedia', () => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ authenticated: true, email_masked: 'a***@example.test', signup_available: false });
      if (path === '/api/auth/csrf') return json({ csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({ scan_count: 0, finding_count: 0, findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, recent_scans: [] });
      if (path.startsWith('/api/findings?')) return json({ items: [], total: 0, limit: 20, offset: 0 });
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    await screen.findByRole('heading', { name: 'Overview' });
    expect(window.localStorage.getItem('chinescan-terminal-motion')).toBe('full');
    expect(document.querySelector('.terminal-ambient')).not.toHaveClass('is-active');
    expect(document.querySelector('.terminal-ambient')).toHaveAttribute('aria-hidden', 'true');
  });

  it('keeps navigation keyboard-operable and persists the Reduced setting', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ authenticated: true, email_masked: 'a***@example.test', signup_available: false });
      if (path === '/api/auth/csrf') return json({ csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({ scan_count: 0, finding_count: 0, findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, recent_scans: [] });
      if (path === '/api/modules') return json([]);
      if (path.startsWith('/api/findings?')) return json({ items: [], total: 0, limit: 20, offset: 0 });
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    await screen.findByRole('heading', { name: 'Overview' });
    const user = userEvent.setup();
    const modules = screen.getByRole('button', { name: 'Modules' });
    modules.focus(); await user.keyboard('{Enter}');
    expect(await screen.findByRole('heading', { name: 'Modules' })).toBeInTheDocument();
    const setting = screen.getByRole('combobox', { name: 'Background animation' });
    fireEvent.change(setting, { target: { value: 'reduced' } });
    expect(window.localStorage.getItem('chinescan-terminal-motion')).toBe('reduced');
  });

  it('shows module status and authorization requirements from the backend registry', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ authenticated: true, email_masked: 'a***@example.test', signup_available: false });
      if (path === '/api/auth/csrf') return json({ csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({ scan_count: 0, finding_count: 0, findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, recent_scans: [] });
      if (path === '/api/modules') return json([
        { name: 'Network Scanner', status: 'planned', does_today: 'No network scanner is implemented.', not_assessed: ['Network exposure'], authorization_guards: ['Explicit target authorization confirmation'] },
        { name: 'Website Auditor', status: 'planned', does_today: 'No auditor yet.', not_assessed: ['Web headers'], authorization_guards: ['Explicit authorization'] },
        { name: 'SSL Analyzer', status: 'planned', does_today: 'No TLS analyzer yet.', not_assessed: ['TLS'], authorization_guards: ['Handshake only'] },
        { name: 'File Analyzer', status: 'partial', does_today: 'Static triage.', not_assessed: ['Archive listing'], authorization_guards: ['Operator local'] },
        { name: 'Vulnerability Reporter', status: 'partial', does_today: 'Local reports.', not_assessed: ['Complete coverage'], authorization_guards: ['Authenticated operator'] },
        { name: 'Security Dashboard', status: 'partial', does_today: 'Authenticated dashboard.', not_assessed: ['Alerts panel', 'Per-module scores'], authorization_guards: ['Authenticated operator'] },
      ]);
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    await screen.findByRole('heading', { name: 'Overview' });
    fireEvent.click(screen.getByRole('button', { name: 'Modules' }));
    expect(await screen.findByText('Explicit target authorization confirmation')).toBeInTheDocument();
    expect(screen.getAllByText('planned', { selector: '.module-planned' })).toHaveLength(3);
    expect(screen.getByText('Alerts panel')).toBeInTheDocument();
    expect(screen.getAllByText(/does not run assessments yet/i)).toHaveLength(3);
  });

  it('shows complete-export limit failures without creating a downloadable partial file', async () => {
    const scanSummary = {
      scan_id: 'scan-limit', started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:01:00Z',
      status: 'complete', scanner: 'builtin', project_types: ['python'], finding_count: 0,
      coverage_gap_count: 0,
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ authenticated: true, email_masked: 'a***@example.test', signup_available: false });
      if (path === '/api/auth/csrf') return json({ csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({ scan_count: 1, finding_count: 0, findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, recent_scans: [scanSummary] });
      if (path.startsWith('/api/findings?')) return json({ items: [], total: 0, limit: 20, offset: 0 });
      if (path.startsWith('/api/scans/scan-limit/report/full-json')) return json({ detail: 'Complete JSON report exceeds the 20 MB export limit.' }, 413);
      if (path.startsWith('/api/scans/scan-limit/report/json')) return json({ summary: { total_stored_findings: 4, available_finding_records: 4, grouped_issue_total: 3, returned_grouped_findings: 2, processing_failure_count: 1 }, report_omissions: { omitted_preview_groups: 1, omitted_preview_occurrences: 2, reason: 'per-category group cap' } });
      if (path === '/api/scans/scan-limit') return json({ ...scanSummary, finding_ids: [], coverage: { examined: {}, excluded: {}, gaps: [] }, failures: {}, code_assessment: null });
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    await screen.findByRole('heading', { name: 'Overview' });
    fireEvent.click(await screen.findByText('scan-lim')); // recent scan table uses the first eight characters
    fireEvent.click(await screen.findByRole('button', { name: 'Download complete JSON' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('No file was downloaded');
    expect(fetchMock).toHaveBeenCalledWith('/api/scans/scan-limit/report/full-json', { credentials: 'same-origin' });
    fireEvent.click(screen.getByRole('button', { name: 'Download JSON preview' }));
    expect(await screen.findByRole('status')).toHaveTextContent('4 scan-linked finding IDs; 4 available records; 3 grouped issues; 2 groups returned. 1 group and 2 occurrences omitted (per-category group cap). 1 processing failure');
  });

  it('renders the shared report-parity fixture with the same score, coverage, explanation, and legacy state', async () => {
    const { scan, findings } = reportParityFixture;
    const summary = {
      scan_id: scan.scan_id,
      started_at: scan.started_at,
      finished_at: scan.finished_at,
      status: scan.status,
      scanner: scan.scanner,
      project_types: scan.project_types,
      finding_count: findings.length,
      coverage_gap_count: scan.coverage?.gaps.length ?? 0,
    };
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ authenticated: true, email_masked: 'a***@example.test', signup_available: false });
      if (path === '/api/auth/csrf') return json({ csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({ scan_count: 1, finding_count: findings.length, findings_by_severity: { critical: 0, high: 1, medium: 1, low: 0, info: 0 }, recent_scans: [summary] });
      if (path.startsWith('/api/findings?')) return json({ items: findings.map(({ finding_id, title, severity, category, confidence, scanner, rule_id }) => ({ finding_id, title, severity, category, confidence, scanner, rule_id })), total: findings.length, limit: 20, offset: 0 });
      if (path === `/api/scans/${scan.scan_id}`) return json({ ...scan, finding_count: findings.length, coverage_gap_count: scan.coverage?.gaps.length ?? 0, failures: {} });
      const finding = findings.find((item) => path === `/api/findings/${item.finding_id}`);
      if (finding) return json(JSON.parse(JSON.stringify(finding).replaceAll('redaction-canary', '[REDACTED]')));
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    await screen.findByRole('heading', { name: 'Overview' });
    fireEvent.click(await screen.findByText(scan.scan_id.slice(0, 8)));
    await screen.findByRole('heading', { name: 'Scan details' });
    expect(screen.getByText(`${scan.scan_id}`)).toBeInTheDocument();
    expect(screen.getByText('Code pattern risk: 36/100', { exact: false })).toBeInTheDocument();
    expect(screen.getByText(/signal-score-v2/)).toBeInTheDocument();
    expect(screen.getByText(/2 observed → 2 counted × 18; contribution 36/)).toBeInTheDocument();
    expect(screen.getByText(/generated: 3 excluded/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: findings[0].finding_id.slice(0, 12) + ' →' }));
    await screen.findByRole('heading', { name: 'Finding details' });
    expect(screen.getByText(/potential impact if the preconditions hold/)).toBeInTheDocument();
    expect(screen.getByText(/data provenance is unresolved/)).toBeInTheDocument();
    expect(screen.getByText('signal-quality-v2')).toBeInTheDocument();
    expect(screen.getByText('src/query.py:4')).toBeInTheDocument();
    expect(screen.getAllByText('src/query.py:8').length).toBeGreaterThan(0);
    expect(screen.getByText('Attacker-controlled query input reaches this call.')).toBeInTheDocument();
    expect(screen.getByText('A reachable injection could expose or alter records handled by this query.')).toBeInTheDocument();
    expect(screen.getByText(/Submit a quote-bearing value and verify it is treated as data\./)).toBeInTheDocument();
    expect(screen.getByText("db.query('SELECT * FROM items WHERE id = ?', [value])")).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('redaction-canary');
    fireEvent.click(screen.getByRole('button', { name: 'Close details' }));
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Main navigation' })).getByRole('button', { name: /findings/i }));
    fireEvent.click(await screen.findByText(findings[1].title));
    expect(await screen.findByRole('heading', { name: 'Explanation unavailable' })).toBeInTheDocument();
  });

  it('renders API finding titles containing markup as text', async () => {
    const title = '<script>alert(1)</script>';
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ authenticated: true, email_masked: 'a***@example.test', signup_available: false });
      if (path === '/api/auth/csrf') return json({ csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({ scan_count: 0, finding_count: 1, findings_by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, recent_scans: [] });
      if (path.startsWith('/api/findings?')) return json({ items: [{ finding_id: 'finding-xss', title, severity: 'high', category: 'code', confidence: 'high', scanner: 'fixture', rule_id: 'XSS' }], total: 1, limit: 20, offset: 0 });
      if (path === '/api/findings/finding-xss') return json({ finding_id: 'finding-xss', title, severity: 'high', category: 'code', confidence: 'high', verdict: 'confirmed', scanner: 'fixture', rule_id: 'XSS', source_location: { file: 'handler.ts', line: 4, excerpt: 'const body = await req.json()' }, sink_location: { file: 'handler.ts', line: 8, excerpt: 'await admin.from("items").insert(body)' }, controls_considered: ['No getUser check found in handler'], exploitability_conditions: ['Unauthenticated requests reach this handler'], project_impact: 'Anonymous users can insert project records.', remediation_before: 'await admin.from("items").insert(body)', remediation_after: 'const user = await requireUser(req); await userClient.from("items").insert(validated)', verification_step: 'Send an unauthenticated POST and expect 401.' });
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    await screen.findByRole('heading', { name: 'Overview' });
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Main navigation' })).getByRole('button', { name: /findings/i }));
    const finding = await screen.findByText(title);
    expect(finding).toBeInTheDocument();
    expect(document.querySelector('script')).toBeNull();
    fireEvent.click(finding);
    expect(await screen.findByRole('heading', { name: 'Finding details' })).toBeInTheDocument();
    expect(screen.getAllByText(title).length).toBeGreaterThan(1);
    expect(screen.getByText('confirmed verdict · high confidence is a heuristic category, not a probability or proof of exploitability.')).toBeInTheDocument();
    expect(screen.getByText('handler.ts:4')).toBeInTheDocument();
    expect(screen.getAllByText('handler.ts:8').length).toBeGreaterThan(0);
    expect(screen.getByText('Anonymous users can insert project records.')).toBeInTheDocument();
    expect(screen.getByText(/Send an unauthenticated POST and expect 401\./)).toBeInTheDocument();
  });

  it('renders an honest empty state when persisted scans are absent', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ authenticated: true, email_masked: 'a***@example.test', signup_available: false });
      if (path === '/api/auth/csrf') return json({ csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({
        scan_count: 0, finding_count: 0,
        findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        recent_scans: [],
      });
      if (path.startsWith('/api/findings?')) return json({ items: [], total: 0, limit: 20, offset: 0 });
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    expect(await screen.findByText('No scans yet')).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Main navigation' })).getByRole('button', { name: /findings/i }));
    expect(await screen.findByText('No matching finding records')).toBeInTheDocument();
  });

  it('explains that signup is disabled when an operator already exists', async () => {
    window.history.replaceState({}, '', '/signup');
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input) === '/api/auth/session') return json({ authenticated: false, email_masked: null, signup_available: false });
      throw new Error(`Unexpected API call: ${String(input)}`);
    });
    render(<App/>);
    expect(await screen.findByRole('heading', { name: 'Operator account already exists' })).toBeInTheDocument();
    expect(screen.getByText(/supports one local operator account/i)).toBeInTheDocument();
    window.history.replaceState({}, '', '/');
  });

  it('shows local forgot-password recovery instructions and completes reset with a token', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ detail: 'Authentication required.' }, 401);
      if (path === '/api/auth/forgot-password') return json({ status: 'If the account exists, use the local recovery command to continue.' }, 202);
      if (path === '/api/auth/reset-password') return json({ status: 'Password reset. Sign in with your new password.' });
      throw new Error(`Unexpected API call: ${path}`);
    });
    render(<App/>);
    await screen.findByRole('heading', { name: 'Welcome back' });
    fireEvent.click(screen.getByRole('button', { name: 'Forgot password?' }));
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'operator@example.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Continue recovery locally' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Enter reset token' }));
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'operator@example.test' } });
    fireEvent.change(screen.getByLabelText('Reset token'), { target: { value: 'synthetic-reset-token-value-1234567890' } });
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'new-synthetic-password-9281' } });
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'new-synthetic-password-9281' } });
    fireEvent.click(screen.getByRole('button', { name: 'Reset password' }));
    expect(await screen.findByText('Password reset. You can now sign in with the new password.')).toBeInTheDocument();
  });
});
