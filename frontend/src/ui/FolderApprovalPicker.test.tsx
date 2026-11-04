import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { FolderApprovalPicker } from './FolderApprovalPicker';

const project = { project_id: 'p1', name: 'web-project', kind: 'local' as const, configured_by: 'dashboard' as const, origin_label: 'This device', created_at: '', last_scan: null, last_scan_refs: [] };
const roots = { items: [{ directory_id: 'drive-id', name: 'C:\\', selectable: false }] };
const page = { directory_id: 'drive-id', name: 'C:\\', selectable: false, breadcrumbs: [], items: [{ directory_id: 'folder-id', name: 'web-project', selectable: true }], next_cursor: null, truncated: false };
function response(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })); }

describe('shared folder approval picker', () => {
  beforeEach(() => { vi.restoreAllMocks(); setCsrfToken('csrf-test'); });

  it('shows the resolved path and requires explicit confirmation before registration', async () => {
    const onApproved = vi.fn();
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === '/api/fs/picker-roots') return response(roots);
      if (path.startsWith('/api/fs/picker-list')) return response(page);
      if (path.startsWith('/api/fs/picker-preview')) return response({ directory_id: 'folder-id', name: 'web-project', resolved_path: 'C:\\work\\web-project' });
      if (path === '/api/projects/approve-folder' && init?.method === 'POST') return response(project, 201);
      throw new Error(`Unexpected request: ${path}`);
    });
    render(<FolderApprovalPicker onClose={vi.fn()} onUnauthorized={vi.fn()} onApproved={onApproved} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open C:\\' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Select this folder' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Review folder' }));
    expect(await screen.findByText('C:\\work\\web-project')).toBeInTheDocument();
    expect(screen.getByText('Approve this folder for assessment?')).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalledWith('/api/projects/approve-folder', expect.anything());
    fireEvent.click(screen.getByRole('button', { name: 'Approve folder' }));
    await waitFor(() => expect(onApproved).toHaveBeenCalledWith(project));
    expect(fetchMock).toHaveBeenCalledWith('/api/projects/approve-folder', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ directory_id: 'folder-id', name: 'web-project', approved: true, purpose: 'project' }),
    }));
  });

  it('shows backend validation errors without approving the folder', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input);
      if (path === '/api/fs/picker-roots') return response(roots);
      if (path.startsWith('/api/fs/picker-list')) return response(page);
      if (path.startsWith('/api/fs/picker-preview')) return response({ detail: { code: 'system_directory', message: 'Windows system folders cannot be approved.' } }, 422);
      return response({});
    });
    render(<FolderApprovalPicker onClose={vi.fn()} onUnauthorized={vi.fn()} onApproved={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Open C:\\' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Select this folder' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Review folder' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Windows system folders cannot be approved.');
    expect(fetchMock).not.toHaveBeenCalledWith('/api/projects/approve-folder', expect.anything());
  });
});
