import { useCallback, useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { ApprovedFolder, CodeJob, CodeProject, Page } from '../types';
import { FolderApprovalPicker } from './FolderApprovalPicker';

export function CodeJobsWorkspace({ onUnauthorized, onOpenScan, onCreateCase }: {
  onUnauthorized: () => void; onOpenScan: (id: string) => void; onCreateCase: (id: string) => void;
}) {
  const [projects, setProjects] = useState<CodeProject[]>([]);
  const [jobs, setJobs] = useState<Page<CodeJob> | null>(null);
  const [selected, setSelected] = useState('');
  const [detail, setDetail] = useState<CodeJob | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [pickerOpen, setPickerOpen] = useState(false);
  const load = useCallback(async (): Promise<CodeProject[] | null> => {
    const [projectResult, jobResult] = await Promise.allSettled([api.codeProjects(), api.codeJobs()]);
    const errors: string[] = [];
    if (projectResult.status === 'fulfilled') setProjects(projectResult.value);
    else if (projectResult.reason instanceof UnauthorizedError) onUnauthorized();
    else { setProjects([]); errors.push(`Projects could not be loaded: ${projectResult.reason instanceof Error ? projectResult.reason.message : 'request failed.'}`); }
    if (jobResult.status === 'fulfilled') {
      setJobs(jobResult.value);
      setDetail((current) => current ? jobResult.value.items.find((item) => item.job_id === current.job_id) ?? current : null);
    } else if (jobResult.reason instanceof UnauthorizedError) onUnauthorized();
    else { setJobs(null); errors.push(`Assessment jobs could not be loaded: ${jobResult.reason instanceof Error ? jobResult.reason.message : 'request failed.'}`); }
    setError(errors.join(' '));
    return projectResult.status === 'fulfilled' ? projectResult.value : null;
  }, [onUnauthorized]);
  useEffect(() => { void load(); }, [load]);
  const active = jobs?.items.some((job) => job.status === 'queued' || job.status === 'running') ?? false;
  useEffect(() => {
    if (!active) return;
    const timer = window.setTimeout(() => { void load(); }, 2000);
    return () => window.clearTimeout(timer);
  }, [active, jobs, load]);
  async function start(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!selected) return;
    setBusy(true); setError('');
    try { await api.startCodeJob(selected); await load(); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to start assessment.'); }
    finally { setBusy(false); }
  }
  async function openDetail(id: string) {
    try { setDetail(await api.codeJob(id)); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to load job details.'); }
  }
  return <section className="panel table-panel" aria-label="Code assessments">
    <div className="panel-heading"><div><h2>Local code assessments</h2><p>Built-in checks only · no project scripts or dependencies are run</p></div><span className="data-chip">Operator approved</span></div>
    {error && <div className="alert-error" role="alert"><span>!</span><div><strong>Assessment request</strong><p>{error}</p></div></div>}
    <form onSubmit={start} className="job-start-form"><label htmlFor="approved-project">Approved project</label><select id="approved-project" value={selected} onFocus={() => void load()} onChange={(event) => setSelected(event.target.value)} required><option value="">Select a project</option>{projects.map((project) => <option key={project.project_id} value={project.project_id}>{project.display_name}</option>)}</select><button type="button" className="secondary-button" onClick={() => setPickerOpen(true)}>Select folder</button><button className="primary-button" disabled={!selected || busy || projects.length === 0}>{busy ? 'Starting…' : 'Start assessment'}</button></form>
    {!projects.length && <div className="empty-state"><h3>No approved projects available</h3><p>Select a local folder to approve it for assessment.</p></div>}
    {!jobs?.items.length ? <div className="empty-state"><h3>No assessment jobs</h3><p>Started jobs and their persisted results will remain available here.</p></div> : <div className="table-scroll"><table><thead><tr><th>PROJECT</th><th>JOB</th><th>STATE</th><th>SUBMITTED</th><th>RESULT</th><th>DETAIL</th></tr></thead><tbody>{jobs.items.map((job) => <tr key={job.job_id}><td>{job.project_name}</td><td className="mono">{job.job_id.slice(0, 8)}</td><td><span className="status">{job.status}</span>{job.error && <small className="sub-id">{job.error}</small>}{job.warning && <small className="sub-id">{job.warning}</small>}</td><td>{new Date(job.created_at).toLocaleString()}</td><td>{job.scan_id ? <><button className="text-button" onClick={() => onOpenScan(job.scan_id!)}>Open scan findings →</button><button className="text-button" onClick={() => onCreateCase(job.scan_id!)}>Create case</button></> : '—'}</td><td><button className="text-button" onClick={() => void openDetail(job.job_id)}>Job details</button></td></tr>)}</tbody></table></div>}
    {detail && <section className="job-detail" aria-label="Job details"><h3>Job details</h3><dl><dt>Job ID</dt><dd className="mono">{detail.job_id}</dd><dt>State</dt><dd>{detail.status}</dd><dt>Submitted</dt><dd>{new Date(detail.created_at).toLocaleString()}</dd><dt>Started</dt><dd>{detail.started_at ? new Date(detail.started_at).toLocaleString() : 'Not started'}</dd><dt>Finished</dt><dd>{detail.finished_at ? new Date(detail.finished_at).toLocaleString() : 'Not finished'}</dd><dt>Scan ID</dt><dd className="mono">{detail.scan_id ?? 'Not available'}</dd></dl>{detail.error && <p role="status">{detail.error}</p>}{detail.warning && <p role="status">{detail.warning}</p>}</section>}
    {pickerOpen && <FolderApprovalPicker onClose={() => setPickerOpen(false)} onUnauthorized={onUnauthorized} onApproved={async (project: ApprovedFolder) => {
      setPickerOpen(false);
      const available = await load();
      if (available?.some((item) => item.project_id === project.project_id)) setSelected(project.project_id);
      else {
        setProjects((items) => [...items, { project_id: project.project_id, display_name: project.name }]);
        setSelected(project.project_id);
      }
    }} />}
  </section>;
}
