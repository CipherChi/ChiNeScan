import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  }));
}

describe('dashboard authentication and overview', () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  it('shows sign in after an unauthorized session check and loads stored metrics after login', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ detail: 'Authentication required.' }, 401);
      if (path === '/api/auth/login') return json({ email: 'analyst@example.test', csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({
        scan_count: 3,
        finding_count: 7,
        findings_by_severity: { critical: 1, high: 2, medium: 2, low: 1, info: 1 },
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
    expect(await screen.findByText('3', { selector: 'strong' })).toBeInTheDocument();
    expect(await screen.findByText('7', { selector: 'strong' })).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/overview', expect.anything()));
  });

  it('renders API finding titles containing markup as text', async () => {
    const title = '<script>alert(1)</script>';
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/auth/session') return json({ authenticated: true, email_masked: 'a***@example.test', signup_available: false });
      if (path === '/api/auth/csrf') return json({ csrf_token: 'csrf-value' });
      if (path === '/api/overview') return json({ scan_count: 0, finding_count: 1, findings_by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, recent_scans: [] });
      if (path.startsWith('/api/findings?')) return json({ items: [{ finding_id: 'finding-xss', title, severity: 'high', category: 'code', confidence: 'high', scanner: 'fixture', rule_id: 'XSS' }], total: 1, limit: 20, offset: 0 });
      if (path === '/api/findings/finding-xss') return json({ finding_id: 'finding-xss', title, severity: 'high', category: 'code', confidence: 'high', scanner: 'fixture', rule_id: 'XSS' });
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
    expect(await screen.findByText('No persisted finding records')).toBeInTheDocument();
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
