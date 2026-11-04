import type { ApprovedFolder, CaseData, CaseSummary, CodeJob, CodeProject, Finding, FolderPreview, Overview, Page, Scan, LogSource, LogSourceRegistryStatus, LogJob, LogAlert, LogEvent, LogTimeline, MalwareAnalysis, MalwareCapability, MalwareJob, MalwareSample, ProjectDetail, ProjectSummary, ProjectLogLocation, ProjectLogSuggestion, ProjectLogJob, ProjectMalwareJob, MalwareHostHint, FsDirectory, FsPage, GitHubImportCapabilities, GitHubImportPreview, GitHubImportJob, ChainInfo, ChainJob, ChainGraph } from './types';

let csrfToken = '';
export function setCsrfToken(token: string) { csrfToken = token; }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body) headers.set('Content-Type', 'application/json');
  if (init?.method && init.method !== 'GET' && csrfToken) headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  if (response.status === 401) {
    if (path === '/api/auth/login') {
      const detail = await response.json().catch(() => ({}));
      throw new Error(typeof detail.detail === 'string' ? detail.detail : 'Invalid email or password.');
    }
    throw new UnauthorizedError();
  }
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    const code = typeof detail.detail?.code === 'string' ? detail.detail.code : undefined;
    const message = typeof detail.detail === 'string'
      ? detail.detail
      : typeof detail.detail?.message === 'string' ? detail.detail.message : 'The request could not be completed.';
    throw new ApiError(message, code);
  }
  return response.json() as Promise<T>;
}

export class UnauthorizedError extends Error {}
export class ApiError extends Error { constructor(message: string, readonly code?: string) { super(message); } }
export const api = {
  chainChains: () => request<ChainInfo[]>('/api/chain/chains'),
  chainStart: (body: { address: string; chain: string; depth: number; min_amount: string; allow_network: boolean; import_text?: string; import_format?: 'csv'|'json' }) => request<ChainJob>('/api/chain/jobs', { method: 'POST', body: JSON.stringify(body) }),
  chainJobs: () => request<Page<ChainJob>>('/api/chain/jobs?limit=50&offset=0'),
  chainJob: (id: string) => request<ChainJob>(`/api/chain/jobs/${encodeURIComponent(id)}`),
  chainGraph: (id: string) => request<ChainGraph>(`/api/chain/traces/${encodeURIComponent(id)}/graph`),
  chainExportUrl: (id: string, fmt: string) => `/api/chain/traces/${encodeURIComponent(id)}/export/${encodeURIComponent(fmt)}`,
  session: () => request<{ authenticated: boolean; email_masked: string | null; signup_available: boolean }>('/api/auth/session'),
  csrf: () => request<{ csrf_token: string }>('/api/auth/csrf'),
  login: (email: string, password: string) => request<{ email: string; csrf_token: string }>('/api/auth/login', {
    method: 'POST', body: JSON.stringify({ email, password }),
  }),
  signup: (email: string, password: string) => request<{ email: string; csrf_token: string }>('/api/auth/signup', {
    method: 'POST', body: JSON.stringify({ email, password }),
  }),
  forgotPassword: (email: string) => request<{ status: string }>('/api/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (email: string, token: string, password: string) => request<{ status: string }>('/api/auth/reset-password', { method: 'POST', body: JSON.stringify({ email, token, password }) }),
  logout: () => request<{ status: string }>('/api/auth/logout', { method: 'POST' }),
  overview: () => request<Overview>('/api/overview'),
  scans: (offset: number, status: string) => {
    const query = new URLSearchParams({ limit: '20', offset: String(offset), sort: 'started_at', order: 'desc' });
    if (status) query.set('status', status);
    return request<Page<Scan>>(`/api/scans?${query}`);
  },
  scan: (id: string) => request<Scan & { finding_ids: string[] }>(`/api/scans/${encodeURIComponent(id)}`),
  importScanityReport: (id: string, reportText: string) => request<{ scan_id: string; imported: number; source: 'scanity' }>(`/api/scans/${encodeURIComponent(id)}/external-reports`, { method: 'POST', body: reportText }),
  findings: (offset: number, severity: string) => {
    const query = new URLSearchParams({ limit: '20', offset: String(offset), sort: 'severity', order: 'desc' });
    if (severity) query.set('severity', severity);
    return request<Page<Finding>>(`/api/findings?${query}`);
  },
  finding: (id: string) => request<Finding>(`/api/findings/${encodeURIComponent(id)}`),
  codeProjects: () => request<CodeProject[]>('/api/code/projects'),
  folderPickerRoots: () => request<{ items: FsDirectory[] }>('/api/fs/picker-roots'),
  folderPickerList: (directoryId: string, cursor?: string | null) => {
    const query = new URLSearchParams({ directory_id: directoryId, limit: '100' });
    if (cursor) query.set('cursor', cursor);
    return request<FsPage>(`/api/fs/picker-list?${query}`);
  },
  folderPickerPreview: (directoryId: string) => request<FolderPreview>(`/api/fs/picker-preview?${new URLSearchParams({ directory_id: directoryId })}`),
  approveFolder: (directoryId: string, name: string, purpose: 'project' | 'logs' | 'malware' = 'project') => request<ApprovedFolder>('/api/projects/approve-folder', {
    method: 'POST', body: JSON.stringify({ directory_id: directoryId, name, approved: true, purpose }),
  }),
  fsRoots: (capability: 'project_directory' | 'log_location') => request<{ items: FsDirectory[] }>(`/api/fs/roots?${new URLSearchParams({ capability })}`),
  fsList: (capability: 'project_directory' | 'log_location', directoryId: string, cursor?: string | null) => {
    const query = new URLSearchParams({ capability, directory_id: directoryId, limit: '100' });
    if (cursor) query.set('cursor', cursor);
    return request<FsPage>(`/api/fs/list?${query}`);
  },
  projects: () => request<ProjectSummary[]>('/api/projects'),
  githubImportCapabilities: () => request<GitHubImportCapabilities>('/api/github/status'),
  previewGitHubImport: (url: string, ref?: string) => request<GitHubImportPreview>('/api/github/previews', { method: 'POST', body: JSON.stringify({ url, ref: ref || null }) }),
  startGitHubImport: (preview_id: string, name: string, replacement?: { replace_project_id: string; replace_confirmation: string }) => request<GitHubImportJob>('/api/github/imports', { method: 'POST', body: JSON.stringify({ preview_id, name, ...replacement }) }),
  githubImportJob: (jobId: string) => request<GitHubImportJob>(`/api/github/imports/${encodeURIComponent(jobId)}`),
  cancelGitHubImport: (jobId: string) => request<GitHubImportJob>(`/api/github/imports/${encodeURIComponent(jobId)}/cancel`, { method: 'POST', body: '{}' }),
  project: (id: string) => request<ProjectDetail>(`/api/projects/${encodeURIComponent(id)}`),
  addProject: (name: string, directory_id: string) => request<ProjectSummary>('/api/projects', { method: 'POST', body: JSON.stringify({ name, directory_id }) }),
  removeProject: (id: string, confirmation: string) => request<{ status: string }>(`/api/projects/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ confirmation }) }),
  projectBrowse: (id: string, directoryId?: string) => request<{ directory_id: string; name: string; selectable?: boolean; breadcrumbs?: FsDirectory[]; items?: FsDirectory[]; next_cursor?: string | null; truncated?: boolean }>(`/api/projects/${encodeURIComponent(id)}/browse${directoryId ? `?directory_id=${encodeURIComponent(directoryId)}` : ''}`),
  projectLogLocations: (id: string) => request<ProjectLogLocation[]>(`/api/projects/${encodeURIComponent(id)}/log-locations`),
  addProjectLogLocation: (id: string, name: string, directory_id: string, scope: 'project' | 'external' = 'project') => request<ProjectLogLocation>(`/api/projects/${encodeURIComponent(id)}/log-locations`, { method: 'POST', body: JSON.stringify({ name, directory_id, scope }) }),
  removeProjectLogLocation: (id: string, location: string, confirmation: string) => request<{ status: string }>(`/api/projects/${encodeURIComponent(id)}/log-locations/${encodeURIComponent(location)}`, { method: 'DELETE', body: JSON.stringify({ confirmation }) }),
  projectLogSuggestions: (id: string) => request<{ items: ProjectLogSuggestion[]; visited: number; partial: boolean }>(`/api/projects/${encodeURIComponent(id)}/log-suggestions`, { method: 'POST', body: '{}' }),
  confirmProjectLogSuggestion: (id: string, suggestion_id: string, name: string) => request<ProjectLogLocation>(`/api/projects/${encodeURIComponent(id)}/log-suggestions/confirm`, { method: 'POST', body: JSON.stringify({ suggestion_id, name }) }),
  startProjectLogJob: (id: string, location_ids?: string[]) => request<ProjectLogJob>(`/api/projects/${encodeURIComponent(id)}/log-jobs`, { method: 'POST', body: JSON.stringify({ location_ids }) }),
  malwareHostHint: () => request<MalwareHostHint>('/api/malware/host-hint'),
  acknowledgeProjectMalwareRisk: (projectId: string) => request<{ token: string; expires_at: string }>('/api/malware/acknowledgements', { method: 'POST', body: JSON.stringify({ project_id: projectId, confirmed: true }) }),
  startProjectMalwareJob: (projectId: string, acknowledgement_token: string) => request<ProjectMalwareJob>(`/api/projects/${encodeURIComponent(projectId)}/malware-jobs`, { method: 'POST', body: JSON.stringify({ acknowledgement_token, profile: 'builtin_static' }) }),
  projectMalwareJob: (projectId: string, jobId: string) => request<ProjectMalwareJob>(`/api/projects/${encodeURIComponent(projectId)}/malware-jobs/${encodeURIComponent(jobId)}`),
  startProjectCodeJob: (id: string) => request<CodeJob>(`/api/projects/${encodeURIComponent(id)}/code-jobs`, { method: 'POST', body: '{}' }),
  codeJobs: () => request<Page<CodeJob>>('/api/code/jobs?limit=50&offset=0'),
  codeJob: (id: string) => request<CodeJob>(`/api/code/jobs/${encodeURIComponent(id)}`),
  startCodeJob: (project_id: string) => request<CodeJob>('/api/code/jobs', { method: 'POST', body: JSON.stringify({ project_id }) }),
  malwareCapability: () => request<MalwareCapability>('/api/malware/capability'),
  malwareSamples: () => request<MalwareSample[]>('/api/malware/samples'),
  malwareJobs: () => request<Page<MalwareJob>>('/api/malware/jobs?limit=50&offset=0'),
  startMalwareRegistryJob: (registry_id: string) => request<MalwareJob>('/api/malware/jobs', { method: 'POST', body: JSON.stringify({ registry_id, profile: 'builtin_static' }) }),
  startManagedMalwareJob: (sample_id: string) => request<MalwareJob>('/api/malware/jobs', { method: 'POST', body: JSON.stringify({ sample_id, profile: 'builtin_static' }) }),
  malwareJob: (id: string) => request<MalwareJob>(`/api/malware/jobs/${encodeURIComponent(id)}`),
  malwareAnalysis: (id: string) => request<MalwareAnalysis>(`/api/malware/analyses/${encodeURIComponent(id)}`),
  logSources: () => request<LogSource[]>('/api/log/sources'),
  logSourcesStatus: () => request<LogSourceRegistryStatus>('/api/log/sources/status'),
  logJobs: () => request<Page<LogJob>>('/api/log/jobs?limit=50&offset=0'),
  logJob: (id: string) => request<LogJob>(`/api/log/jobs/${encodeURIComponent(id)}`),
  startLogJob: (source_id: string) => request<LogJob>('/api/log/jobs', { method: 'POST', body: JSON.stringify({ source_id }) }),
  logAlerts: (scan: string, offset = 0, severity = '') => { const query = new URLSearchParams({ limit: '20', offset: String(offset) }); if (severity) query.set('severity', severity); return request<Page<LogAlert>>(`/api/log/analyses/${encodeURIComponent(scan)}/alerts?${query}`); },
  logAlert: (scan: string, id: string) => request<LogAlert>(`/api/log/analyses/${encodeURIComponent(scan)}/alerts/${encodeURIComponent(id)}`),
  logEvents: (scan: string, offset = 0, source = '') => { const query = new URLSearchParams({ limit: '20', offset: String(offset) }); if (source) query.set('source', source); return request<Page<LogEvent>>(`/api/log/analyses/${encodeURIComponent(scan)}/events?${query}`); },
  logEvent: (scan: string, id: string) => request<LogEvent>(`/api/log/analyses/${encodeURIComponent(scan)}/events/${encodeURIComponent(id)}`),
  logTimeline: (scan: string, offset = 0) => request<Page<LogTimeline>>(`/api/log/analyses/${encodeURIComponent(scan)}/timeline?limit=20&offset=${offset}`),
  cases: (offset = 0, status = '', severity = '') => {
    const query = new URLSearchParams({ limit: '20', offset: String(offset), sort: 'updated_at', order: 'desc' });
    if (status) query.set('status', status); if (severity) query.set('severity', severity);
    return request<Page<CaseSummary>>(`/api/cases?${query}`);
  },
  case: (id: string) => request<CaseData>(`/api/cases/${encodeURIComponent(id)}`),
  createCase: (scan_id: string, title: string, description: string, severity: string) => request<CaseData>('/api/cases', { method: 'POST', body: JSON.stringify({ scan_id, title: title || null, description, severity }) }),
  addCaseNote: (id: string, body: string) => request<CaseData>(`/api/cases/${encodeURIComponent(id)}/notes`, { method: 'POST', body: JSON.stringify({ body }) }),
  updateCaseStatus: (id: string, status: string) => request<CaseData>(`/api/cases/${encodeURIComponent(id)}/status`, { method: 'POST', body: JSON.stringify({ status }) }),
  linkCaseRecord: (id: string, record_type: string, record_id: string) => request<CaseData>(`/api/cases/${encodeURIComponent(id)}/links`, { method: 'POST', body: JSON.stringify({ record_type, record_id }) }),
};
