import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { CodeJobsWorkspace } from './CodeJobsWorkspace';

const unauthorized = vi.fn();
const job = { job_id: 'job-1', project_id: 'fixture', project_name: 'Fixture', status: 'succeeded' as const, created_at: '2026-10-26T10:00:00Z', started_at: '2026-10-26T10:00:01Z', finished_at: '2026-10-26T10:00:02Z', scan_id: 'scan-1', error: null, warning: 'Scan reports could not be saved.' };
function response(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })); }

describe('code assessment workspace', () => {
  beforeEach(() => { vi.restoreAllMocks(); unauthorized.mockReset(); setCsrfToken('csrf-test'); });

  it('validates project selection, starts a job, and links persisted scan results', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/code/projects') return response([{ project_id: 'fixture', display_name: 'Fixture' }]);
      if (path === '/api/code/jobs/job-1') return response(job);
      if (path === '/api/code/jobs' && init?.method === 'POST') return response(job, 202);
      if (path.startsWith('/api/code/jobs')) return response({ items: [job], total: 1, limit: 50, offset: 0 });
      throw new Error(`Unexpected call: ${path}`);
    });
    const openScan = vi.fn();
    render(<CodeJobsWorkspace onUnauthorized={unauthorized} onOpenScan={openScan} onCreateCase={vi.fn()}/>);
    const start = await screen.findByRole('button', { name: 'Start assessment' });
    expect(start).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Approved project'), { target: { value: 'fixture' } });
    fireEvent.click(start);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/code/jobs', expect.objectContaining({ method: 'POST' })));
    fireEvent.click(await screen.findByRole('button', { name: 'Job details' }));
    expect(await screen.findByText('Job ID')).toBeInTheDocument();
    expect(await screen.findAllByText('Scan reports could not be saved.')).toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledWith('/api/code/jobs/job-1', expect.anything());
    fireEvent.click(await screen.findByRole('button', { name: /Open scan findings/ }));
    expect(openScan).toHaveBeenCalledWith('scan-1');
  });

  it('shows queue-full failure and handles session expiry', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/code/projects') return response([{ project_id: 'fixture', display_name: 'Fixture' }]);
      if (path.startsWith('/api/code/jobs') && init?.method !== 'POST') return response({ items: [], total: 0, limit: 50, offset: 0 });
      if (init?.method === 'POST') return response({ detail: 'The code assessment queue is full.' }, 429);
      return response({}, 401);
    });
    render(<CodeJobsWorkspace onUnauthorized={unauthorized} onOpenScan={vi.fn()} onCreateCase={vi.fn()}/>);
    fireEvent.change(await screen.findByLabelText('Approved project'), { target: { value: 'fixture' } });
    fireEvent.click(screen.getByRole('button', { name: 'Start assessment' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('queue is full');
    vi.restoreAllMocks();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', { status: 401 }));
    render(<CodeJobsWorkspace onUnauthorized={unauthorized} onOpenScan={vi.fn()} onCreateCase={vi.fn()}/>);
    await waitFor(() => expect(unauthorized).toHaveBeenCalled());
  });

  it('refreshes projects on selector focus and reports either list request failure', async () => {
    let projectRequests = 0;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/code/projects') { projectRequests += 1; return response([{ project_id: 'fixture', display_name: 'Fixture' }]); }
      if (path.startsWith('/api/code/jobs')) return response({ items: [], total: 0, limit: 50, offset: 0 });
      throw new Error(`Unexpected call: ${path}`);
    });
    render(<CodeJobsWorkspace onUnauthorized={unauthorized} onOpenScan={vi.fn()} onCreateCase={vi.fn()}/>);
    const selector = await screen.findByLabelText('Approved project');
    await waitFor(() => expect(projectRequests).toBe(1));
    fireEvent.focus(selector);
    await waitFor(() => expect(projectRequests).toBe(2));
    expect(fetchMock).toHaveBeenCalledWith('/api/code/jobs?limit=50&offset=0', expect.anything());

    vi.restoreAllMocks();
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/code/projects') return response({ detail: 'project endpoint failed' }, 503);
      if (path.startsWith('/api/code/jobs')) return response({ items: [], total: 0, limit: 50, offset: 0 });
      throw new Error(`Unexpected call: ${path}`);
    });
    render(<CodeJobsWorkspace onUnauthorized={unauthorized} onOpenScan={vi.fn()} onCreateCase={vi.fn()}/>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Projects could not be loaded');
  });

  it('immediately selects a folder after approval', async () => {
    let approved = false;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/code/projects') return response(approved ? [{ project_id: 'p1', display_name: 'web-project' }] : []);
      if (path.startsWith('/api/code/jobs')) return response({ items: [], total: 0, limit: 50, offset: 0 });
      if (path === '/api/fs/picker-roots') return response({ items: [{ directory_id: 'drive-id', name: 'C:\\', selectable: false }] });
      if (path.startsWith('/api/fs/picker-list')) return response({ directory_id: 'drive-id', name: 'C:\\', selectable: false, breadcrumbs: [], items: [{ directory_id: 'folder-id', name: 'web-project', selectable: true }], next_cursor: null, truncated: false });
      if (path.startsWith('/api/fs/picker-preview')) return response({ directory_id: 'folder-id', name: 'web-project', resolved_path: 'C:\\work\\web-project' });
      if (path === '/api/projects/approve-folder' && init?.method === 'POST') { approved = true; return response({ project_id: 'p1', name: 'web-project', kind: 'local', configured_by: 'dashboard', origin_label: 'This device', created_at: '', last_scan: null, last_scan_refs: [] }, 201); }
      throw new Error(`Unexpected call: ${path}`);
    });
    render(<CodeJobsWorkspace onUnauthorized={unauthorized} onOpenScan={vi.fn()} onCreateCase={vi.fn()}/>);
    fireEvent.click(await screen.findByRole('button', { name: 'Select folder' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Open C:\\' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Select this folder' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Review folder' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Approve folder' }));
    await waitFor(() => expect(screen.getByLabelText('Approved project')).toHaveValue('p1'));
    expect(screen.getByRole('button', { name: 'Start assessment' })).toBeEnabled();
    expect(fetchMock).toHaveBeenCalledWith('/api/code/projects', expect.anything());
  });
});
