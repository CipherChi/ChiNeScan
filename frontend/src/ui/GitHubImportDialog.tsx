import { useEffect, useRef, useState } from 'react';
import { api, ApiError, UnauthorizedError } from '../api';
import type { GitHubImportCapabilities, GitHubImportJob, GitHubImportPreview, ProjectSummary } from '../types';

type Props = { onClose: () => void; onUnauthorized: () => void; onFinished: () => void | Promise<void> };
const terminal = new Set<GitHubImportJob['status']>(['succeeded', 'failed', 'cancelled', 'incomplete']);
const enableExample = '# Enable public GitHub imports explicitly\ngithub_import_enabled = true\n# github_import_timeout_seconds = 120\n# github_import_max_bytes = 524288000\n# github_import_max_files = 50000\n# github_import_max_projects = 20';

function safeError(reason: unknown): string {
  if (reason instanceof Error) return reason.message;
  return 'The request could not be completed.';
}

export function GitHubImportDialog({ onClose, onUnauthorized, onFinished }: Props) {
  const [capabilities, setCapabilities] = useState<GitHubImportCapabilities | null>(null);
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [url, setUrl] = useState('');
  const [ref, setRef] = useState('');
  const [name, setName] = useState('');
  const [replaceConfirmation, setReplaceConfirmation] = useState('');
  const [preview, setPreview] = useState<GitHubImportPreview | null>(null);
  const [job, setJob] = useState<GitHubImportJob | null>(null);
  const [error, setError] = useState('');
  const [errorCode, setErrorCode] = useState('');
  const [announcement, setAnnouncement] = useState('');
  const [busy, setBusy] = useState(false);
  const dialog = useRef<HTMLDivElement>(null);
  const polling = useRef(0);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const jobStarted = Boolean(job);

  useEffect(() => {
    const node = dialog.current;
    if (!node) return;
    const focusable = () => Array.from(node.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled])'));
    focusable()[0]?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !jobStarted) onCloseRef.current();
      if (event.key !== 'Tab') return;
      const list = focusable();
      const first = list[0]; const last = list[list.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    document.addEventListener('keydown', keydown);
    return () => document.removeEventListener('keydown', keydown);
  }, [jobStarted]);

  useEffect(() => {
    let active = true;
    void Promise.all([api.githubImportCapabilities(), api.projects()]).then(([result, currentProjects]) => { if (active) { setCapabilities(result); setProjects(currentProjects); } }).catch((reason: unknown) => {
      if (reason instanceof UnauthorizedError) onUnauthorized(); else if (active) setError(safeError(reason));
    });
    return () => { active = false; };
  }, [onUnauthorized]);

  useEffect(() => {
    if (!job || terminal.has(job.status)) return;
    let active = true;
    const delay = Math.min(8000, 800 * (2 ** Math.min(polling.current, 3)));
    const timer = window.setTimeout(() => {
      void api.githubImportJob(job.job_id).then(async (next) => {
        if (!active) return;
        polling.current += 1;
        setJob(next);
        if (terminal.has(next.status)) {
          const message = next.status === 'succeeded' ? 'GitHub import completed. The project list was refreshed.' : `GitHub import ${next.status}: ${next.error_code ?? 'unknown error'}.`;
          setAnnouncement(message);
          if (next.status === 'succeeded') await onFinished();
        }
      }).catch((reason: unknown) => {
        if (reason instanceof UnauthorizedError) onUnauthorized(); else if (active) setError(safeError(reason));
        polling.current += 1;
      });
    }, delay);
    return () => { active = false; window.clearTimeout(timer); };
  }, [job, onFinished, onUnauthorized]);

  async function createPreview() {
    setBusy(true); setError(''); setErrorCode(''); setPreview(null); setJob(null); polling.current = 0;
    try {
      const result = await api.previewGitHubImport(url.trim(), ref.trim() || undefined);
      setPreview(result); setName(name || result.url.split('/').at(-1) || 'Imported repository');
      setAnnouncement('Preview ready. Review the fetch limits before importing.');
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized(); else { setError(safeError(reason)); setErrorCode(reason instanceof ApiError ? reason.code ?? '' : ''); }
    } finally { setBusy(false); }
  }

  async function startImport() {
    if (!preview || !name.trim()) return;
    setBusy(true); setError(''); setErrorCode('');
    const replacement = projects.find((project) => project.kind === 'github' && project.origin_url === preview.url);
    if (replacement && replaceConfirmation !== replacement.name) { setError('Type the existing project name to confirm replacement. The existing project stays available until verification succeeds.'); setBusy(false); return; }
    try { setJob(await api.startGitHubImport(preview.preview_id, name.trim(), replacement ? { replace_project_id: replacement.project_id, replace_confirmation: replaceConfirmation } : undefined)); setAnnouncement('Import queued.'); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else { setError(safeError(reason)); setErrorCode(reason instanceof ApiError ? reason.code ?? '' : ''); } }
    finally { setBusy(false); }
  }

  async function cancel() {
    if (!job) return;
    try { setJob(await api.cancelGitHubImport(job.job_id)); setAnnouncement('Cancellation requested.'); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else { setError(safeError(reason)); setErrorCode(reason instanceof ApiError ? reason.code ?? '' : ''); } }
  }

  const title = errorCode.includes('invalid_url') ? 'Invalid GitHub URL' : errorCode.includes('git_missing') ? 'Git is missing' : errorCode.includes('repo_not_found_or_private') ? 'Repository not found or private' : errorCode.includes('quota_exceeded') ? 'Import size limit exceeded' : errorCode.includes('path_too_long') ? 'Import location path is too long' : errorCode.includes('quarantined_or_missing_files') || job?.status === 'incomplete' ? 'Import incomplete' : 'Import could not continue';
  const jobTitle = job?.status === 'succeeded' ? 'Import complete' : job?.status === 'incomplete' ? 'Import incomplete' : job?.error_code === 'git_missing' ? 'Git is missing' : job?.error_code === 'repo_not_found_or_private' ? 'Repository not found or private' : job?.error_code === 'quota_exceeded' ? 'Import size limit exceeded' : job?.error_code === 'path_too_long' ? 'Import location path is too long' : job?.status === 'failed' ? 'Import failed' : `Import ${job?.status ?? ''}`;
  return <div className="project-dialog-backdrop"><div className="project-dialog" role="dialog" aria-modal="true" aria-labelledby="github-import-title" ref={dialog}>
    <h2 id="github-import-title">Import from GitHub</h2>
    {!capabilities && !error && <p role="status">Checking GitHub import settings…</p>}
    {capabilities && !capabilities.enabled && <section role="status"><h3>GitHub import is disabled</h3><p>Add this example to your local config.toml and restart ChiNeScan. The setting is not changed here.</p><pre>{enableExample}</pre></section>}
    {capabilities?.enabled && !job && <>
      {!capabilities.git_available && <p role="alert">Git is missing. Install Git and restart ChiNeScan before importing.</p>}
      <label htmlFor="github-import-url">Public GitHub repository URL</label><input id="github-import-url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://github.com/owner/repository" maxLength={300} />
      <label htmlFor="github-import-ref">Optional branch, tag, or commit</label><input id="github-import-ref" value={ref} onChange={(event) => setRef(event.target.value)} maxLength={100} />
      <div className="project-actions"><button className="secondary-button" onClick={onClose}>Close</button><button className="primary-button" disabled={busy || !url.trim() || !capabilities.git_available} onClick={() => void createPreview()}>Preview</button></div>
    </>}
    {preview && !job && <section aria-label="Import preview"><h3>Review import</h3><dl><dt>Repository</dt><dd>{preview.url}</dd><dt>Ref</dt><dd>{preview.ref ?? 'Default branch'}</dd><dt>Fetch</dt><dd>Depth {preview.fetch_depth}; submodules and Git LFS disabled; blob limit {preview.blob_limit_bytes.toLocaleString()} bytes.</dd><dt>Caps</dt><dd>{preview.max_bytes.toLocaleString()} project bytes; {preview.git_metadata_allowance_bytes.toLocaleString()} separate Git metadata allowance; {preview.max_files.toLocaleString()} files; {preview.max_projects} projects; {preview.expires_in_seconds / 60} minutes.</dd></dl><label htmlFor="github-import-name">Project name</label><input id="github-import-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={120} /><p>Repository files are only scanned; nothing from the repository is executed or installed.</p>{projects.find((project) => project.kind === 'github' && project.origin_url === preview.url) && <><p>Re-importing replaces the clone for this project only after the new import verifies. Existing scan history is kept.</p><label htmlFor="github-replace-confirm">Type the existing project name to confirm replacement</label><input id="github-replace-confirm" value={replaceConfirmation} onChange={(event) => setReplaceConfirmation(event.target.value)} /></>}<div className="project-actions"><button className="secondary-button" onClick={() => setPreview(null)}>Back</button><button className="primary-button" disabled={!name.trim() || busy || Boolean(projects.find((project) => project.kind === 'github' && project.origin_url === preview.url) && replaceConfirmation !== projects.find((project) => project.kind === 'github' && project.origin_url === preview.url)?.name)} onClick={() => void startImport()}>Import</button></div></section>}
    {job && <section aria-label="Import progress"><h3>{jobTitle}</h3><p>Phase: {job.phase}</p>{job.message && <p>{job.message}</p>}{job.status === 'failed' && job.error_code === 'repo_not_found_or_private' && <p>Only public repositories are supported.</p>}{job.status === 'incomplete' && <p>Some files may have been quarantined or become unreadable. Review the import and system security history; do not disable Defender.</p>}{job.status === 'succeeded' && <p>Project created. Commit {job.commit_sha}.</p>}{!terminal.has(job.status) && <button className="secondary-button" onClick={() => void cancel()}>Cancel import</button>}<button className="secondary-button" onClick={onClose}>Close</button></section>}
    {error && <div role="alert" aria-live="assertive"><strong>{title}</strong><p>{error}</p></div>}
    <div className="visually-hidden" role="status" aria-live="polite">{announcement}</div>
  </div></div>;
}
