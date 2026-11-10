import { useCallback, useEffect, useRef, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { DashboardAlert, ModuleScore } from '../types';

type Section = 'scans' | 'findings' | 'cases' | 'malware';
export function DashboardScoresAlerts({ onNavigate, onUnauthorized }: { onNavigate: (section: Section) => void; onUnauthorized: () => void }) {
  const [scores, setScores] = useState<ModuleScore[]>([]);
  const [alerts, setAlerts] = useState<DashboardAlert[]>([]);
  const [error, setError] = useState('');
  const [working, setWorking] = useState('');
  const refreshRef = useRef<() => void>(() => undefined);
  const load = useCallback(async () => {
    try {
      const [scoreRows, alertRows] = await Promise.all([api.dashboardScores(), api.alerts()]);
      setScores(scoreRows); setAlerts(alertRows); setError('');
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError('Scores or alerts could not be loaded. Retry this view.');
    }
  }, [onUnauthorized]);
  refreshRef.current = () => { void load(); };
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (typeof window.EventSource === 'undefined') return;
    let source: EventSource | undefined;
    let timer = 0;
    let attempts = 0;
    let cursor = 0;
    let closed = false;
    const connect = () => {
      if (closed) return;
      source = new EventSource(`/api/alerts/events?after=${cursor}`, { withCredentials: true });
      source.onopen = () => { attempts = 0; };
      source.addEventListener('alert', (event) => { const id = Number((event as MessageEvent).lastEventId); if (Number.isSafeInteger(id)) cursor = Math.max(cursor, id); refreshRef.current(); });
      source.addEventListener('session-expired', () => { source?.close(); onUnauthorized(); });
      source.onerror = () => {
        source?.close();
        if (closed) return;
        attempts += 1;
        const ceiling = Math.min(30_000, 1_000 * 2 ** Math.min(attempts - 1, 5));
        timer = window.setTimeout(connect, ceiling + Math.floor(Math.random() * 250));
      };
    };
    connect();
    return () => { closed = true; window.clearTimeout(timer); source?.close(); };
  }, [onUnauthorized]);
  async function transition(alert: DashboardAlert, action: 'acknowledge' | 'snooze' | 'resolve') {
    setWorking(alert.alert_id); setError('');
    try {
      if (action === 'acknowledge') await api.acknowledgeAlert(alert.alert_id);
      else if (action === 'snooze') await api.snoozeAlert(alert.alert_id, new Date(Date.now() + 60 * 60_000).toISOString());
      else await api.resolveAlert(alert.alert_id);
      await load();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError('The alert state could not be updated. Refresh and try again.');
    } finally { setWorking(''); }
  }
  return <div className="dashboard-intelligence">
    <section className="panel score-panel" aria-labelledby="module-scores-heading">
      <div className="panel-heading"><div><h2 id="module-scores-heading">Per-module scores</h2><p>Findings and assessment coverage are included in each explanation.</p></div></div>
      {scores.length ? <div className="score-grid">{scores.map((item) => <article data-glass className="score-tile" key={item.module}>
        <div className="score-tile-heading"><h3>{item.module}</h3><strong aria-label={item.score === null ? 'Not scored' : `Score ${item.score} out of 100`}>{item.score === null ? 'Not scored' : `${item.score}/100`}</strong></div>
        <p className="score-coverage">Based on {item.checks_completed} checks, {item.checks_not_assessed} not assessed</p>
        <p className="score-why">{item.why_this_score}</p>
        <details><summary>Score inputs and formula</summary><p>{item.formula}</p><ul>{item.findings.map((finding, index) => <li key={`${finding.severity}-${index}`}>{finding.explanation}: −{finding.penalty.toFixed(1)}</li>)}</ul>{item.inputs?.reason && <p>{item.inputs.reason}</p>}</details>
        <div className="score-links" aria-label={`${item.module} related views`}>
          <button type="button" onClick={() => onNavigate('scans')}>Scans</button>
          <button type="button" onClick={() => onNavigate('findings')}>Findings</button>
          <button type="button" onClick={() => onNavigate('cases')}>Cases</button>
          <button type="button" onClick={() => onNavigate('malware')}>Malware triage</button>
        </div>
      </article>)}</div> : <p className="score-empty">Loading module scores…</p>}
    </section>
    <section className="panel alert-panel" aria-labelledby="alerts-heading" aria-live="polite">
      <div className="panel-heading"><div><h2 id="alerts-heading">Alerts</h2><p>Rule-based local alerts. State changes are recorded in the local audit trail.</p></div></div>
      {error && <p aria-live="polite" className="alert-load-error">{error} <button type="button" onClick={() => void load()}>Retry</button></p>}
      {alerts.length ? <ul className="dashboard-alert-list">{alerts.map((alert) => <li data-glass className="dashboard-alert" key={alert.alert_id}>
        <div className="dashboard-alert-copy"><span className={`alert-severity ${alert.severity}`}>{alert.severity}</span><div><h3>{alert.title}</h3><p>{alert.description}</p><small>{alert.module} · {alert.state}{alert.snoozed_until ? ` until ${new Date(alert.snoozed_until).toLocaleString()}` : ''}</small></div></div>
        <div className="alert-actions">{alert.state !== 'resolved' && <>
          {alert.state !== 'acknowledged' && <button type="button" disabled={working === alert.alert_id} onClick={() => void transition(alert, 'acknowledge')}>Acknowledge</button>}
          <button type="button" disabled={working === alert.alert_id} onClick={() => void transition(alert, 'snooze')}>Snooze 1 hour</button>
          <button type="button" disabled={working === alert.alert_id} onClick={() => void transition(alert, 'resolve')}>Resolve</button>
        </>}</div>
      </li>)}</ul> : <p className="score-empty">No active alerts.</p>}
    </section>
  </div>;
}
