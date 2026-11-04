import { useCallback, useEffect, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { ApprovedFolder, CaseSummary, LogAlert, LogEvent, LogJob, LogSource, LogSourceRegistryStatus, LogTimeline, Page } from '../types';
import { FolderApprovalPicker } from './FolderApprovalPicker';

export function LogJobsWorkspace({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [sources, setSources] = useState<LogSource[]>([]);
  const [registryStatus, setRegistryStatus] = useState<LogSourceRegistryStatus | null>(null);
  const [jobs, setJobs] = useState<Page<LogJob> | null>(null);
  const [selected, setSelected] = useState('');
  const [alerts, setAlerts] = useState<Page<LogAlert> | null>(null);
  const [events, setEvents] = useState<Page<LogEvent> | null>(null);
  const [timeline, setTimeline] = useState<Page<LogTimeline> | null>(null);
  const [alertDetail, setAlertDetail] = useState<LogAlert | null>(null);
  const [eventDetail, setEventDetail] = useState<LogEvent | null>(null);
  const [cases, setCases] = useState<Page<CaseSummary> | null>(null);
  const [caseId, setCaseId] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [folderPickerOpen, setFolderPickerOpen] = useState(false);
  const [approvedFolder, setApprovedFolder] = useState<ApprovedFolder | null>(null);
  const [alertOffset, setAlertOffset] = useState(0);
  const [eventOffset, setEventOffset] = useState(0);
  const [timelineOffset, setTimelineOffset] = useState(0);
  const [alertSeverity, setAlertSeverity] = useState('');
  const [eventSource, setEventSource] = useState('');

  const load = useCallback(async () => {
    try {
      const [available, status, page, casePage] = await Promise.all([api.logSources(), api.logSourcesStatus(), api.logJobs(), api.cases()]);
      setSources(available); setRegistryStatus(status); setJobs(page); setCases(casePage);
      setSelected((current) => current || page.items.find((job) => job.scan_id)?.scan_id || '');
    } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to load log analyses.'); }
  }, [onUnauthorized]);
  useEffect(() => { void load(); }, [load]);
  const active = jobs?.items.some((job) => job.status === 'queued' || job.status === 'running') ?? false;
  useEffect(() => { if (!active) return; const timer = window.setTimeout(() => void load(), 2000); return () => window.clearTimeout(timer); }, [active, jobs, load]);

  useEffect(() => {
    if (!selected) { setAlerts(null); setEvents(null); setTimeline(null); return; }
    Promise.all([api.logAlerts(selected, alertOffset, alertSeverity), api.logEvents(selected, eventOffset, eventSource), api.logTimeline(selected, timelineOffset)]).then(([a, e, t]) => {
      setAlerts(a); setEvents(e); setTimeline(t);
    }).catch((reason: unknown) => { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to load analysis results.'); });
  }, [selected, onUnauthorized, alertOffset, eventOffset, timelineOffset, alertSeverity, eventSource]);

  async function start(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!selectedSource) return;
    setBusy(true); setError('');
    try { await api.startLogJob(selectedSource); await load(); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to start log analysis.'); }
    finally { setBusy(false); }
  }
  async function analyzeApprovedFolder() {
    if (!approvedFolder?.log_location_id) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const job = await api.startProjectLogJob(approvedFolder.project_id, [approvedFolder.log_location_id]);
      setJobs((current) => current ? { ...current, items: [job, ...current.items.filter((item) => item.job_id !== job.job_id)] } : null);
      setNotice(`Log analysis queued for ${approvedFolder.name}.`);
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Log analysis could not start.');
    } finally { setBusy(false); }
  }
  const [selectedSource, setSelectedSource] = useState('');
  async function link(type: 'alert' | 'event', id: string) {
    if (!caseId) return;
    try { await api.linkCaseRecord(caseId, type, id); setNotice(`${type === 'alert' ? 'Alert' : 'Event'} linked to case.`); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to link record.'); }
  }
  async function showAlert(id: string) {
    try { setAlertDetail(await api.logAlert(selected, id)); setEventDetail(null); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to load alert.'); }
  }
  async function showEvent(id: string) {
    try { setEventDetail(await api.logEvent(selected, id)); setAlertDetail(null); }
    catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to load event.'); }
  }
  async function createCase() {
    if (!selected) return;
    try {
      const created = await api.createCase(selected, 'Log analysis investigation', '', 'medium');
      const page = await api.cases(); setCases(page); setCaseId(created.case.case_id);
      setNotice('Case created from this log analysis.');
    } catch (reason) { if (reason instanceof UnauthorizedError) onUnauthorized(); else setError(reason instanceof Error ? reason.message : 'Unable to create case.'); }
  }

  return <section className="panel table-panel" aria-label="Log analysis">
    <div className="panel-heading"><div><h2>Local log analysis</h2><p>Configured local sources · bounded read-only ingestion · no uploads</p></div><span className="data-chip">Operator configured</span></div>
    {error && <div className="alert-error" role="alert"><span>!</span><div><strong>Log analysis</strong><p>{error}</p></div></div>}{notice && <p role="status" className="case-notice">{notice}</p>}
    <form onSubmit={start} className="job-start-form"><label htmlFor="approved-log-source">Approved log source</label><select id="approved-log-source" value={selectedSource} onChange={(event) => setSelectedSource(event.target.value)} required><option value="">Select a source</option>{sources.map((source) => <option key={source.source_id} value={source.source_id}>{source.display_name}</option>)}</select><button className="primary-button" disabled={!selectedSource || busy || sources.length === 0}>{busy ? 'Starting…' : 'Analyze logs'}</button></form>
    <div className="project-actions"><button className="secondary-button" onClick={() => setFolderPickerOpen(true)}>Select folder</button>{approvedFolder && <><span role="status">Approved log folder: {approvedFolder.name}</span><button className="primary-button" disabled={busy || !approvedFolder.log_location_id} onClick={() => void analyzeApprovedFolder()}>{busy ? 'Starting…' : 'Analyze selected folder'}</button></>}</div>
    {!sources.length && <div className="empty-state"><h3>{registryStatus?.status === 'missing' ? 'Registry file not found' : registryStatus?.status === 'unreadable' ? 'Registry file is unreadable' : registryStatus?.status === 'invalid' ? 'Registry file is invalid' : registryStatus?.status === 'empty' ? 'Registry is valid but has no sources' : 'No approved log sources'}</h3><p>{registryStatus?.reason ?? 'Configure sources in the operator log-source file, then reload this page.'}</p></div>}
    {!jobs?.items.length ? <div className="empty-state"><h3>No log analysis jobs</h3><p>Queued results and partial-ingestion diagnostics will remain available here.</p></div> : <div className="table-scroll"><table><thead><tr><th>SOURCE</th><th>STATE</th><th>EVENTS</th><th>ALERTS</th><th>DIAGNOSTICS</th><th>RESULT</th></tr></thead><tbody>{jobs.items.map((job) => <tr key={job.job_id}><td>{job.source_name}<small className="sub-id">{job.job_id.slice(0, 8)}</small></td><td><span className="status">{job.status}</span>{job.error && <small className="sub-id">{job.error}</small>}{job.diagnostics.map((message) => <small className="sub-id" key={message}>{message}</small>)}</td><td>{job.event_count}</td><td>{job.alert_count}</td><td>{job.error_count || '—'}</td><td>{job.scan_id && <button className="text-button" onClick={() => setSelected(job.scan_id!)}>Open results →</button>}</td></tr>)}</tbody></table></div>}
    {selected && <>
      <div className="job-start-form"><label htmlFor="log-analysis-result">Persisted analysis</label><select id="log-analysis-result" value={selected} onChange={(event) => setSelected(event.target.value)}>{jobs?.items.filter((job) => job.scan_id).map((job) => <option key={job.scan_id} value={job.scan_id!}>{job.source_name} · {job.scan_id!.slice(0, 8)} · {job.status}</option>)}</select><button className="secondary-button" onClick={() => void createCase()}>Create case from analysis</button><label htmlFor="log-case">Link records to case</label><select id="log-case" value={caseId} onChange={(event) => setCaseId(event.target.value)}><option value="">Select case</option>{cases?.items.map((item) => <option key={item.case_id} value={item.case_id}>{item.title}</option>)}</select></div>
      <div className="log-results-grid"><section><div className="log-heading"><h3>Alerts ({alerts?.total ?? 0})</h3><select aria-label="Filter alert severity" value={alertSeverity} onChange={(event) => { setAlertSeverity(event.target.value); setAlertOffset(0); }}><option value="">All severities</option>{['critical','high','medium','low','info'].map((value) => <option key={value}>{value}</option>)}</select></div>{alerts?.items.map((item) => <article className="log-result" key={item.alert_id}><strong>{item.title}</strong><small>{item.severity} · {item.rule_id}</small><p className="evidence-text">{item.description}</p><small className="mono">{item.alert_id}</small><button className="text-button" onClick={() => void showAlert(item.alert_id)}>Alert details</button><button className="text-button" disabled={!caseId} onClick={() => void link('alert', item.alert_id)}>Link alert to case</button></article>)}{alerts && <SmallPages data={alerts} offset={alertOffset} onPage={setAlertOffset}/>}</section>
      <section><div className="log-heading"><h3>Events ({events?.total ?? 0})</h3><select aria-label="Filter event source" value={eventSource} onChange={(event) => { setEventSource(event.target.value); setEventOffset(0); }}><option value="">All sources</option>{[...new Set(events?.items.map((item) => item.source) ?? [])].map((value) => <option key={value}>{value}</option>)}</select></div>{events?.items.map((item) => <article className="log-result" key={item.event_id}><strong>{item.kind}</strong><small>{new Date(item.occurred_at).toLocaleString()} · {item.source}</small><p className="evidence-text">{item.summary}</p><small className="mono">{item.event_id}</small><button className="text-button" onClick={() => void showEvent(item.event_id)}>Event details</button><button className="text-button" disabled={!caseId} onClick={() => void link('event', item.event_id)}>Link event to case</button></article>)}{events && <SmallPages data={events} offset={eventOffset} onPage={setEventOffset}/>}</section>
      <section className="log-timeline"><h3>Timeline ({timeline?.total ?? 0})</h3><ol>{timeline?.items.map((item) => <li key={item.entry_id}><time>{new Date(item.occurred_at).toLocaleString()}</time><p className="evidence-text">{item.description}</p></li>)}</ol>{timeline && <SmallPages data={timeline} offset={timelineOffset} onPage={setTimelineOffset}/>}</section></div>
      {(alertDetail || eventDetail) && <section className="job-detail" aria-label={alertDetail ? 'Alert details' : 'Event details'}><h3>{alertDetail ? 'Alert details' : 'Event details'}</h3><dl>{Object.entries(alertDetail ?? eventDetail ?? {}).map(([key, value]) => <div className="log-detail-value" key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd className="evidence-text">{Array.isArray(value) ? value.join(', ') : String(value ?? '—')}</dd></div>)}</dl></section>}
    </>}
    {folderPickerOpen && <FolderApprovalPicker purpose="logs" onClose={() => setFolderPickerOpen(false)} onUnauthorized={onUnauthorized} onApproved={(project) => { setApprovedFolder(project); setFolderPickerOpen(false); setNotice('Folder approved. Log analysis will read supported local log files only.'); }} />}
  </section>;
}

function SmallPages<T>({ data, offset, onPage }: { data: Page<T>; offset: number; onPage: (offset: number) => void }) { return <div className="case-pagination"><span>Showing {data.total ? offset + 1 : 0}–{Math.min(offset + data.items.length, data.total)} of {data.total}</span><div><button onClick={() => onPage(Math.max(0, offset - 20))} disabled={offset === 0}>Previous</button><button onClick={() => onPage(offset + 20)} disabled={offset + 20 >= data.total}>Next</button></div></div>; }
