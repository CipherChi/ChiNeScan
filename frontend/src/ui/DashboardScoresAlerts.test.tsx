import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { DashboardScoresAlerts } from './DashboardScoresAlerts';

function reply(value: unknown) { return Promise.resolve(new Response(JSON.stringify(value), { status: 200, headers: { 'Content-Type': 'application/json' } })); }

describe('dashboard scores and alerts', () => {
  it('shows transparent scores and lets keyboard users follow a module link', async () => {
    setCsrfToken('csrf');
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).includes('/dashboard/scores') ? reply([{ module: 'Code Assessment', score: 88, checks_completed: 5, checks_total: 7, checks_not_assessed: 2, coverage_fraction: 0.71, coverage_penalty: 14.3, finding_penalty: 0, findings: [], formula: 'coverage formula', why_this_score: 'Based on 5 checks, 2 not assessed.', inputs: {} }]) : reply([]));
    const onNavigate = vi.fn();
    render(<DashboardScoresAlerts onNavigate={onNavigate} onUnauthorized={vi.fn()} />);
    expect(await screen.findByText('88/100')).toBeInTheDocument();
    expect(screen.getByText('Based on 5 checks, 2 not assessed')).toBeInTheDocument();
    const findings = screen.getByRole('button', { name: 'Findings' });
    findings.focus();
    await userEvent.keyboard('{Enter}');
    expect(onNavigate).toHaveBeenCalledWith('findings');
    const cases = screen.getByRole('button', { name: 'Cases' });
    cases.focus();
    await userEvent.keyboard(' ');
    expect(onNavigate).toHaveBeenCalledWith('cases');
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Alerts' })).toBeInTheDocument());
  });
});
