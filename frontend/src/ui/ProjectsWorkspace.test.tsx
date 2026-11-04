import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import type { LogJob, ProjectDetail, ProjectLogLocation, ProjectSummary } from '../types';
import { ProjectsWorkspace } from './ProjectsWorkspace';

function makeProject(overrides: Partial<ProjectSummary> = {}): ProjectSummary {
  return { project_id: 'p1', name: 'Example', kind: 'local', configured_by: 'ui', origin_label: 'This device', created_at: '', last_scan: null, last_scan_refs: [], ...overrides };
}

function makeDetail(overrides: Partial<ProjectDetail> = {}): ProjectDetail {
  return { ...makeProject(overrides), recent_jobs: [], malware_jobs: [], findings_count: 0, findings: [], linked_cases: [], recent_scans: [], log_locations: [], log_alerts: [], log_events: [], log_timeline: [], ...overrides };
}

function makeLocation(overrides: Partial<ProjectLogLocation> = {}): ProjectLogLocation {
  return { location_id: 'loc1', project_id: 'p1', name: 'logs', scope: 'project', created_at: '', ...overrides };
}

function makeLogJob(overrides: Partial<LogJob> = {}): LogJob {
  return { job_id: 'job1', source_id: 'project:p1', source_name: 'Project logs', status: 'queued', created_at: '', started_at: null, finished_at: null, scan_id: null, event_count: 0, alert_count: 0, error_count: 0, error: null, diagnostics: [], project_id: 'p1', location_ids: ['loc1'], skipped_counts: {}, ...overrides };
}

const roots = [{ directory_id: 'root-id', name: 'approved', selectable: false }];
const page = { directory_id: 'root-id', name: 'approved', selectable: false, breadcrumbs: [roots[0]], items: [{ directory_id: 'child-id', name: 'source', selectable: true }], next_cursor: 'next', truncated: false };
function reply(value: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })); }

describe('projects workspace', () => {
  beforeEach(() => { vi.restoreAllMocks(); setCsrfToken('csrf'); });
  afterEach(() => { vi.useRealTimers(); });

  it('opens the shared folder approval picker and supports keyboard dismissal', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => String(input).startsWith('/api/fs/picker-roots') ? reply({ items: [] }) : reply([]));
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Add project' }));
    const dialog = await screen.findByRole('dialog', { name: 'Select a project folder' });
    expect(dialog).toBeInTheDocument();
    const close = within(dialog).getByRole('button', { name: 'Close folder picker' });
    await waitFor(() => expect(document.activeElement).toBe(close));
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Cancel' }));
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: 'Select a project folder' })).not.toBeInTheDocument();
  });

  it('reviews the resolved folder and explicitly approves the project', async () => {
    let approved = false;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects/approve-folder' && init?.method === 'POST') { approved = true; return reply(makeProject({ configured_by: 'dashboard' }), 201); }
      if (path === '/api/projects') return reply(approved ? [makeProject({ configured_by: 'dashboard' })] : []);
      if (path === '/api/projects/p1') return reply(makeDetail({ configured_by: 'dashboard' }));
      if (path === '/api/fs/picker-roots') return reply({ items: roots });
      if (path.startsWith('/api/fs/picker-list')) return reply({ ...page, next_cursor: null });
      if (path.startsWith('/api/fs/picker-preview')) return reply({ directory_id: 'child-id', name: 'source', resolved_path: 'C:\\work\\source' });
      return reply({});
    });
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Add project' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Open approved' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Select this folder' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Select this folder' }));
    fireEvent.click(screen.getByRole('button', { name: 'Review folder' }));
    expect(await screen.findByText('C:\\work\\source')).toBeInTheDocument();
    expect(screen.getByText('Approve this folder for assessment?')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Approve folder' }));
    await waitFor(() => expect(approved).toBe(true));
    expect(fetchMock).toHaveBeenCalledWith('/api/projects/approve-folder', expect.objectContaining({ method: 'POST' }));
  });

  it('shows persisted partial counts and requires typed removal confirmation', async () => {
    const project = makeProject({ last_scan: 'scan1', last_scan_refs: ['scan1'] });
    const detail = makeDetail({ ...project, recent_scans: [{ scan_id: 'scan1', status: 'partial', finding_count: 1, skipped_counts: { max_files: 2 } }] });
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'DELETE') return reply(detail);
      if (path === '/api/projects/p1' && init?.method === 'DELETE') return reply({ status: 'removed' });
      return reply({});
    });
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    expect(await screen.findByText(/Skipped counts: max_files: 2/)).toBeInTheDocument();
    expect(screen.getByText('No log locations linked yet.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Remove project' }));
    expect(screen.getByRole('dialog', { name: 'Remove Example?' })).toHaveTextContent('Files in the folder are never touched.');
    const button = within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove project record' });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Type Example to confirm/), { target: { value: 'Example' } });
    expect(button).toBeEnabled();
  });

  it('shows bounded suggestions and marks EVTX as unsupported', async () => {
    const project = makeProject();
    const detail = makeDetail();
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'POST') return reply(detail);
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [], total: 0, limit: 50, offset: 0 });
      if (path === '/api/projects/p1/log-suggestions') return reply({ partial: true, visited: 5000, items: [{ suggestion_id: 'suggestion-123456789', label: 'archive.evtx', unsupported: true }] });
      return reply({});
    });
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Suggest locations' }));
    expect(await screen.findByText(/Suggestions are partial/)).toBeInTheDocument();
    expect(screen.getByText('Unsupported format')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument();
  });

  it('shows populated log locations, states that removal keeps files, and enforces one selection', async () => {
    const project = makeProject();
    const location = makeLocation();
    const detail = makeDetail({ log_locations: [location] });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'DELETE') return reply(detail);
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [], total: 0, limit: 0, offset: 0 });
      return reply({});
    });
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    const locations = await screen.findByRole('region', { name: 'Log locations' });
    expect(within(locations).getAllByText('logs')).toHaveLength(2);
    const analyze = within(locations).getByRole('button', { name: 'Analyze logs' });
    expect(analyze).toBeEnabled();
    fireEvent.click(within(locations).getByRole('checkbox', { name: 'logs' }));
    expect(analyze).toBeDisabled();
    fireEvent.click(within(locations).getByRole('button', { name: 'Remove' }));
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('Files are never touched; scans and findings are kept.'));
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/log-locations/loc1'))).toBe(false);
  });

  it('shows external no-roots, denied, and truncated add-dialog states', async () => {
    const project = makeProject();
    let browseMode: 'truncated' | 'denied' = 'truncated';
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'POST') return reply(makeDetail());
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [], total: 0, limit: 0, offset: 0 });
      if (path.startsWith('/api/projects/p1/browse')) {
        if (browseMode === 'denied' && path.includes('directory_id')) return reply({ detail: 'Directory selection is unavailable.' }, 404);
        return reply({ directory_id: 'project-root', name: 'Example', items: [{ directory_id: 'child', name: 'logs', selectable: true }], truncated: browseMode === 'truncated' });
      }
      if (path === '/api/fs/roots?capability=log_location') return reply({ items: [] });
      return reply({});
    });
    render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    const locationSection = await screen.findByRole('region', { name: 'Log locations' });
    fireEvent.click(within(locationSection).getByRole('button', { name: 'Add location' }));
    expect(await screen.findByText(/Folder listing is truncated/)).toBeInTheDocument();
    const dialog = screen.getByRole('dialog', { name: 'Add a log folder' });
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(dialog.contains(document.activeElement)).toBe(true);
    fireEvent.click(within(dialog).getByLabelText('Outside this project (approved roots)'));
    expect(await screen.findByRole('alert')).toHaveTextContent(/No approved folders are available/);
    browseMode = 'denied';
    fireEvent.click(within(dialog).getByLabelText('Inside this project'));
    expect(await screen.findByRole('alert')).toHaveTextContent(/Directory selection is unavailable/);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: 'Add a log folder' })).not.toBeInTheDocument();
  });

  it('shows the location-now-denied result from a failed project log job', async () => {
    const project = makeProject();
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'POST') return reply(makeDetail({ log_locations: [makeLocation()] }));
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [], total: 0, limit: 0, offset: 0 });
      if (path === '/api/projects/p1/log-jobs') return reply(makeLogJob(), 202);
      if (path === '/api/log/jobs/job1') return reply(makeLogJob({ status: 'failed', error_code: 'location_denied', error: 'A selected log location is no longer approved or available.' }));
      return reply({});
    });
    const view = render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    await screen.findByRole('button', { name: 'Analyze logs' });
    vi.useFakeTimers();
    fireEvent.click(screen.getByRole('button', { name: 'Analyze logs' }));
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    expect(screen.getByText(/Location now denied:/)).toBeInTheDocument();
    view.unmount();
  });

  it('waits for a project log job to finish, then refreshes project alerts', async () => {
    const project = makeProject();
    const location = makeLocation();
    let details = makeDetail({ log_locations: [location] });
    let projectJobStatus: LogJob['status'] = 'queued';
    let statusPolls = 0;
    let projectDetailReads = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'POST') { projectDetailReads += 1; return reply(details); }
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [makeLogJob({ status: projectJobStatus })], total: 1, limit: 50, offset: 0 });
      if (path === '/api/projects/p1/log-jobs') return reply(makeLogJob(), 202);
      if (path === '/api/log/jobs/job1') {
        statusPolls += 1;
        projectJobStatus = 'succeeded';
        details = { ...details, log_alerts: [{ alert_id: 'a1', title: 'Repeated authentication failures', severity: 'high' }] };
        return reply(makeLogJob({ status: 'succeeded' }));
      }
      return reply({});
    });
    const view = render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    await screen.findByRole('button', { name: 'Analyze logs' });
    vi.useFakeTimers();
    fireEvent.click(screen.getByRole('button', { name: 'Analyze logs' }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(statusPolls).toBe(0);
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    expect(statusPolls).toBe(1);
    expect(projectDetailReads).toBe(2);
    expect(screen.getByText('Log analysis succeeded.')).toBeInTheDocument();
    expect(screen.getByText('Repeated authentication failures')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(statusPolls).toBe(1);
    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
    vi.useRealTimers();
  });

  it('backs off while running, refreshes once on success, and cancels polling on unmount', async () => {
    const project = makeProject();
    let reads = 0;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'POST') return reply(makeDetail({ log_locations: [makeLocation()] }));
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [], total: 0, limit: 50, offset: 0 });
      if (path === '/api/projects/p1/log-jobs') return reply(makeLogJob(), 202);
      if (path === '/api/log/jobs/job1') {
        reads += 1;
        return reply(makeLogJob({ status: reads < 3 ? 'running' : 'succeeded' }));
      }
      return reply({});
    });
    const view = render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    await screen.findByRole('button', { name: 'Analyze logs' });
    vi.useFakeTimers();
    const detailsBefore = fetchMock.mock.calls.filter(([input]) => String(input) === '/api/projects/p1').length;
    fireEvent.click(screen.getByRole('button', { name: 'Analyze logs' }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    expect(reads).toBe(1);
    expect(screen.getByText('Log analysis is running.')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(799); });
    expect(reads).toBe(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(reads).toBe(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(1599); });
    expect(reads).toBe(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(reads).toBe(3);
    const detailsAfter = fetchMock.mock.calls.filter(([input]) => String(input) === '/api/projects/p1').length;
    expect(detailsAfter - detailsBefore).toBe(1);
    expect(screen.getByText('Log analysis succeeded.')).toBeInTheDocument();
    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
    vi.useRealTimers();
  });

  it('does not poll again after unmount while a job is still running', async () => {
    const project = makeProject();
    let polls = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'POST') return reply(makeDetail({ log_locations: [makeLocation()] }));
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [], total: 0, limit: 0, offset: 0 });
      if (path === '/api/projects/p1/log-jobs') return reply(makeLogJob(), 202);
      if (path === '/api/log/jobs/job1') { polls += 1; return reply(makeLogJob({ status: 'running' })); }
      return reply({});
    });
    const view = render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    await screen.findByRole('button', { name: 'Analyze logs' });
    vi.useFakeTimers();
    fireEvent.click(screen.getByRole('button', { name: 'Analyze logs' }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    expect(polls).toBe(1);
    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(polls).toBe(1);
  });

  it.each(['failed', 'partial'] as const)('announces and refreshes for a %s terminal result', async (status) => {
    const project = makeProject();
    let reads = 0;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'POST') return reply(makeDetail({ log_locations: [makeLocation()] }));
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [], total: 0, limit: 0, offset: 0 });
      if (path === '/api/projects/p1/log-jobs') return reply(makeLogJob(), 202);
      if (path === '/api/log/jobs/job1') { reads += 1; return reply(makeLogJob({ status, error: status === 'failed' ? 'Analysis failed.' : null })); }
      return reply({});
    });
    const view = render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    await screen.findByRole('button', { name: 'Analyze logs' });
    vi.useFakeTimers();
    const before = fetchMock.mock.calls.filter(([input]) => String(input) === '/api/projects/p1').length;
    fireEvent.click(screen.getByRole('button', { name: 'Analyze logs' }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(400); });
    expect(reads).toBe(1);
    expect(screen.getByText(`Log analysis ${status}${status === 'partial' ? '; skipped 0' : ''}.`)).toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([input]) => String(input) === '/api/projects/p1').length - before).toBe(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(reads).toBe(1);
    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
    vi.useRealTimers();
  });

  it('retries transient polling failures with bounded backoff and a safe message', async () => {
    const project = makeProject();
    let reads = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/projects') return reply([project]);
      if (path === '/api/projects/p1' && init?.method !== 'POST') return reply(makeDetail({ log_locations: [makeLocation()] }));
      if (path === '/api/log/jobs?limit=50&offset=0') return reply({ items: [], total: 0, limit: 0, offset: 0 });
      if (path === '/api/projects/p1/log-jobs') return reply(makeLogJob(), 202);
      if (path === '/api/log/jobs/job1') { reads += 1; throw new Error('private path C:\\fixture\\secret'); }
      return reply({});
    });
    const view = render(<ProjectsWorkspace onUnauthorized={vi.fn()} onOpenScan={vi.fn()} onCreateCase={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open project' }));
    await screen.findByRole('button', { name: 'Analyze logs' });
    vi.useFakeTimers();
    fireEvent.click(screen.getByRole('button', { name: 'Analyze logs' }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(400 + 800 + 1600); });
    expect(reads).toBe(3);
    expect(screen.getByText('Unable to confirm log analysis status. Review recent log jobs or refresh the project.')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('C:\\fixture\\secret');
    view.unmount();
    expect(vi.getTimerCount()).toBe(0);
    vi.useRealTimers();
  });
});
