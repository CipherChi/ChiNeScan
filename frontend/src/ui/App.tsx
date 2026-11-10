import { useCallback, useEffect, useState } from 'react';
import { api, safeLocalUrl, setCsrfToken, UnauthorizedError } from '../api';
import type { Finding, ModuleCapability, Overview, Page, Scan } from '../types';
import { CasesWorkspace } from './CasesWorkspace';
import { CodeJobsWorkspace } from './CodeJobsWorkspace';
import { ChainTraceWorkspace } from './ChainTraceWorkspace';
import { LogJobsWorkspace } from './LogJobsWorkspace';
import { MalwareWorkspace } from './MalwareWorkspace';
import { ProjectsWorkspace } from './ProjectsWorkspace';
import { ScanityReportImport } from './ScanityReportImport';
import { SystemStatus } from './SystemStatus';
import { DashboardScoresAlerts } from './DashboardScoresAlerts';
import { TerminalBackdrop } from './TerminalBackdrop';
import { useGlassTracking } from './glass';

type Section = 'overview' | 'scans' | 'findings' | 'cases' | 'jobs' | 'projects' | 'logs' | 'malware' | 'chain' | 'status' | 'modules';
type Detail = { kind: 'scan'; id: string } | { kind: 'finding'; id: string } | null;
type AuthPage = 'login' | 'signup' | 'forgot' | 'forgot-confirmed' | 'reset';

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : 'Something went wrong. Please try again.';
}
function dateOf(value: string | null) {
  if (!value) return 'In progress';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

export function App() {
  const [ready, setReady] = useState(false);
  const [email, setEmail] = useState('');
  const [signupAvailable, setSignupAvailable] = useState(true);
  const [error, setError] = useState('');
  const [section, setSection] = useState<Section>('overview');
  const [overview, setOverview] = useState<Overview | null>(null);
  const [scanPage, setScanPage] = useState<Page<Scan> | null>(null);
  const [findingPage, setFindingPage] = useState<Page<Finding> | null>(null);
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState('');
  const [detail, setDetail] = useState<Detail>(null);
  const [detailData, setDetailData] = useState<Scan | Finding | null>(null);
  const [busy, setBusy] = useState(false);
  const [authPage, setAuthPage] = useState<AuthPage>(routeFromPath());
  const [caseScanId, setCaseScanId] = useState('');
  const [modules, setModules] = useState<ModuleCapability[]>([]);
  const loadModules = useCallback(async () => setModules(await api.modules()), []);
  const [backgroundMode, setBackgroundMode] = useState<'full' | 'reduced' | 'off'>(() => {
    try {
      const legacy = window.localStorage.getItem('gnet-scan-terminal-motion');
      const saved = window.localStorage.getItem('chinescan-terminal-motion') ?? legacy;
      if (saved === 'off') return 'off';
      if (saved === 'reduced') return 'reduced';
      if (legacy !== null && window.localStorage.getItem('chinescan-terminal-motion') === null) window.localStorage.setItem('chinescan-terminal-motion', 'full');
      return 'full';
    }
    catch { return 'full'; }
  });
  useGlassTracking();

  const signOut = useCallback(() => {
    setCsrfToken(''); setEmail(''); setOverview(null); setScanPage(null); setFindingPage(null);
    setDetail(null); setDetailData(null); setAuthPage('login'); window.history.replaceState({}, '', '/');
  }, []);

  useEffect(() => {
    api.session().then(async (session) => {
      setSignupAvailable(session.signup_available);
      if (session.authenticated) {
        setEmail(session.email_masked ?? 'Operator');
        const csrf = await api.csrf();
        setCsrfToken(csrf.csrf_token);
      }
    }).catch((reason: unknown) => {
      if (!(reason instanceof UnauthorizedError)) setError(messageOf(reason));
    }).finally(() => setReady(true));
  }, []);

  const loadSection = useCallback(async (selected: Section, offset = 0, filterValue = '') => {
    if (!email) return;
    setBusy(true); setError('');
    try {
      if (selected === 'overview') setOverview(await api.overview());
      if (selected === 'scans') setScanPage(await api.scans(offset, filterValue));
      if (selected === 'findings') setFindingPage(await api.findings(offset, filterValue));
    } catch (reason) {
      if (reason instanceof UnauthorizedError) signOut();
      else setError(messageOf(reason));
    } finally { setBusy(false); }
  }, [email, signOut]);

  useEffect(() => { if (email) void loadSection(section, page * 20, filter); }, [email, section, page, filter, loadSection]);

  useEffect(() => {
    if (!detail) { setDetailData(null); return; }
    const load = detail.kind === 'scan' ? api.scan(detail.id) : api.finding(detail.id);
    load.then(setDetailData).catch((reason: unknown) => {
      if (reason instanceof UnauthorizedError) signOut(); else setError(messageOf(reason));
    });
  }, [detail, signOut]);

  async function submitLogin(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError('');
    const form = new FormData(event.currentTarget);
    try {
      const session = await api.login(String(form.get('email')), String(form.get('password')));
      setCsrfToken(session.csrf_token); setEmail(session.email);
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function logout() {
    setBusy(true); setError('');
    try { await api.logout(); signOut(); }
    catch (reason) { if (reason instanceof UnauthorizedError) signOut(); else setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  if (!ready) return <CenteredState title="Connecting to ChiNeScan" detail="Checking your local session…" />;
  if (!email) return authPage === 'signup'
    ? !signupAvailable
      ? <SignupDisabled onBack={() => navigateAuth('login', setAuthPage)}/>
      : <Signup busy={busy} error={error} onBack={() => navigateAuth('login', setAuthPage)} onSubmit={async (operatorEmail, password) => {
      setBusy(true); setError('');
      try { const session = await api.signup(operatorEmail, password); setCsrfToken(session.csrf_token); setEmail(session.email); window.history.replaceState({}, '', '/'); }
      catch (reason) { setError(messageOf(reason)); }
      finally { setBusy(false); }
    }}/>
    : authPage === 'forgot'
      ? <ForgotPassword busy={busy} error={error} onBack={() => navigateAuth('login', setAuthPage)} onSubmit={async (operatorEmail) => {
        setBusy(true); setError('');
        try { await api.forgotPassword(operatorEmail); setAuthPage('forgot-confirmed'); }
        catch { setAuthPage('forgot-confirmed'); }
        finally { setBusy(false); }
      }}/>
      : authPage === 'reset'
        ? <ResetPassword busy={busy} error={error} onBack={() => navigateAuth('login', setAuthPage)} onSuccess={() => { setError(''); navigateAuth('login', setAuthPage); }}/>
        : authPage === 'forgot-confirmed'
          ? <RecoveryInstructions onBack={() => navigateAuth('login', setAuthPage)} onReset={() => navigateAuth('reset', setAuthPage)}/>
          : <Login error={error} busy={busy} signupAvailable={signupAvailable} onSubmit={submitLogin} onRetry={() => window.location.reload()} onSignup={() => { navigateAuth('signup', setAuthPage); setError(''); }} onForgot={() => { navigateAuth('forgot', setAuthPage); setError(''); }} />;

  const title = section === 'chain' ? 'On-chain tracing' : section === 'overview' ? 'Overview' : section === 'scans' ? 'Scan history' : section === 'findings' ? 'Findings' : section === 'cases' ? 'Cases' : section === 'jobs' ? 'Code assessments' : section === 'projects' ? 'Projects' : section === 'malware' ? 'Malware triage' : section === 'status' ? 'System status' : section === 'modules' ? 'Modules' : 'Log analysis';
  const nav = (id: Section, label: string, glyph: string) => <button data-glass className={`nav-link ${section === id ? 'active' : ''}`} key={id} onClick={() => { setSection(id); setPage(0); setFilter(''); setDetail(null); }}><span className="nav-glyph" aria-hidden="true">{glyph}</span>{label}{id === 'scans' && overview ? <span className="nav-count">{overview.scan_count}</span> : null}</button>;

  return <div className="app-shell">
    <svg className="glass-filter-defs" aria-hidden="true" focusable="false"><filter id="glass-refraction"><feTurbulence type="fractalNoise" baseFrequency=".012 .025" numOctaves="2" seed="8"/><feDisplacementMap in="SourceGraphic" scale="3"/></filter></svg>
    <TerminalBackdrop mode={backgroundMode}/>
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark" aria-hidden="true"><span>C</span><i /></div><div><strong>ChiNeScan</strong><small>LOCAL SECURITY WORKSTATION</small></div></div>
      <div className="nav-caption">WORKSPACE</div>
      <nav aria-label="Main navigation">{nav('overview', 'Overview', '⌂')}{nav('projects', 'Projects', '▧')}{nav('jobs', 'Code assessments', '⌘')}{nav('logs', 'Log analysis', '≋')}{nav('malware', 'Malware triage', '◇')}{nav('chain', 'On-chain tracing', '◎')}{nav('scans', 'Scans', '⌕')}{nav('findings', 'Findings', '◈')}{nav('cases', 'Cases', '▤')}{nav('modules', 'Modules', '▦')}{nav('status', 'System status', '◉')}</nav>
      <div className="sidebar-bottom"><div className="local-indicator"><span />LOCAL INSTANCE</div><p>Assessment data stays on this device.</p><div className="profile"><div className="avatar">{email.slice(0, 1).toUpperCase()}</div><div className="profile-name"><strong>{email}</strong><small>Local operator</small></div><button className="icon-button" onClick={logout} disabled={busy} aria-label="Sign out" title="Sign out">↗</button></div></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div className="breadcrumbs"><span>ChiNeScan</span><b>/</b><strong>{title}</strong></div><div className="topbar-right"><label className="motion-control">Background<select className="motion-toggle" aria-label="Background animation" value={backgroundMode} onChange={(event) => { const next = event.target.value as 'full' | 'reduced' | 'off'; setBackgroundMode(next); try { window.localStorage.setItem('chinescan-terminal-motion', next); } catch { /* Storage can be unavailable in hardened browser contexts. */ } }}><option value="full">Full</option><option value="reduced">Reduced</option><option value="off">Off</option></select></label><span className="secure-pill"><span>●</span> Loopback secured</span><div className="top-avatar">{email.slice(0, 1).toUpperCase()}</div></div></header>
      <section className="page-content">
        <div className="page-heading"><div><div className="eyebrow">LOCAL ANALYST WORKSPACE</div><h1>{title}</h1><p>{section === 'overview' ? 'A clear view of your locally stored assessment activity.' : section === 'scans' ? 'Review completed and partial local assessments.' : section === 'findings' ? 'Triage heuristic findings with evidence and uncertainty in view.' : section === 'cases' ? 'Investigate persisted scans with notes, links, timelines, and reports.' : section === 'jobs' ? 'Start and review bounded assessments of operator-approved local projects.' : section === 'projects' ? 'Organize approved code folders and review their assessment history.' : section === 'malware' ? 'Static triage of operator-registered samples. No execution.' : section === 'status' ? 'Check local service connectivity, readiness, and recent errors.' : section === 'modules' ? 'Review what each module can assess today and where its coverage stops.' : 'Analyze operator-approved local exports with bounded parsing and local detections.'}</p></div>{section !== 'overview' && section !== 'cases' && section !== 'jobs' && section !== 'logs' && section !== 'projects' && section !== 'status' && section !== 'modules' && <div className="list-controls"><label className="filter-control"><span aria-hidden="true">⌕</span><select aria-label={section === 'scans' ? 'Filter scan status' : 'Filter finding severity'} value={filter} onChange={(event) => { setPage(0); setFilter(event.target.value); }}><option value="">All {section === 'scans' ? 'statuses' : 'severities'}</option>{section === 'scans' ? <><option value="complete">Complete</option><option value="partial">Partial</option></> : <>{['critical','high','medium','low','info'].map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}</>}</select></label></div>}</div>
        {error && <div className="alert-error" role="alert"><span>!</span><div><strong>We couldn’t load this view</strong><p>{error}</p></div><button onClick={() => void loadSection(section, page * 20, filter)}>Retry</button></div>}
        {busy && <div className="loading-line" aria-label="Loading"><span /></div>}
        {section === 'overview' && overview && <DashboardScoresAlerts onUnauthorized={signOut} onNavigate={(target) => { setSection(target); setPage(0); setFilter(''); setDetail(null); }} />}
        {section === 'overview' && <OverviewPanel data={overview} onScans={() => setSection('scans')} onFindings={() => setSection('findings')} onOpen={(id) => setDetail({ kind: 'scan', id })} />}
        {section === 'scans' && <ScanTable data={scanPage} page={page} onPage={setPage} onOpen={(id) => setDetail({ kind: 'scan', id })} />}
        {section === 'findings' && <FindingTable data={findingPage} page={page} onPage={setPage} onOpen={(id) => setDetail({ kind: 'finding', id })} />}
        {section === 'jobs' && <CodeJobsWorkspace onUnauthorized={signOut} onOpenScan={(id) => { setSection('scans'); setDetail({ kind: 'scan', id }); }} onCreateCase={(id) => { setCaseScanId(id); setSection('cases'); }} />}
        {section === 'chain' && <ChainTraceWorkspace onUnauthorized={signOut} onOpenScan={(id) => { setSection('scans'); setDetail({ kind: 'scan', id }); }} />}
        {section === 'projects' && <ProjectsWorkspace onUnauthorized={signOut} onOpenScan={(id) => { setSection('scans'); setDetail({ kind: 'scan', id }); }} onCreateCase={(id) => { setCaseScanId(id); setSection('cases'); }} />}
        {section === 'logs' && <LogJobsWorkspace onUnauthorized={signOut} />}
        {section === 'malware' && <MalwareWorkspace onUnauthorized={signOut} onOpenProjects={() => setSection('projects')} />}
        {section === 'cases' && <CasesWorkspace onUnauthorized={signOut} initialScanId={caseScanId}/>}
        {section === 'status' && <SystemStatus onUnauthorized={signOut} />}
        {section === 'modules' && <ModulesWorkspace modules={modules} onLoad={loadModules} onUnauthorized={signOut} />}
      </section>
    </main>
    {detail && <DetailPanel detail={detailData} kind={detail.kind} onClose={() => setDetail(null)} onOpenFinding={(id) => setDetail({ kind: 'finding', id })} onRefreshScan={async (id) => { setDetailData(await api.scan(id)); }} onUnauthorized={signOut} onCreateCase={(id) => { setCaseScanId(id); setDetail(null); setSection('cases'); }} />}
  </div>;
}

function ModulesWorkspace({ modules, onLoad, onUnauthorized }: { modules: ModuleCapability[]; onLoad: () => Promise<void>; onUnauthorized: () => void }) {
  useEffect(() => {
    onLoad().catch((reason: unknown) => {
      if (reason instanceof UnauthorizedError) onUnauthorized();
    });
  }, [onLoad, onUnauthorized]);
  const planned = modules.filter((item) => item.status === 'planned');
  return <div className="modules-grid" aria-label="Module capabilities">
    {modules.filter((item) => ['Network Scanner', 'Website Auditor', 'SSL Analyzer', 'File Analyzer', 'Vulnerability Reporter', 'Security Dashboard'].includes(item.name)).map((item) => <article data-glass className="panel module-card" key={item.name}>
      <div className="module-title"><h2>{item.name}</h2><span className={`status-badge module-${item.status}`}>{item.status}</span></div>
      <p>{item.does_today}</p>
      {item.status === 'planned' && <p className="module-planned-note">Planned: this module does not run assessments yet.</p>}
      <h3>Not assessed</h3><ul>{item.not_assessed.map((value) => <li key={value}>{value}</li>)}</ul>
      <h3>Authorization guards</h3><ul>{item.authorization_guards.map((value) => <li key={value}>{value}</li>)}</ul>
    </article>)}
    {planned.length > 0 && <p className="module-scope-note">Planned network modules require explicit authorization, address blocking with redirect re-checks, and passive GET/HEAD or handshake-only checks.</p>}
  </div>;
}

function Login({ error, busy, signupAvailable, onSubmit, onRetry, onSignup, onForgot }: { error: string; busy: boolean; signupAvailable: boolean; onSubmit: (event: React.FormEvent<HTMLFormElement>) => void; onRetry: () => void; onSignup: () => void; onForgot: () => void }) {
  return <AuthShell><div className="login-label">LOCAL SECURITY WORKSPACE</div><h1>Welcome back</h1><p>Sign in to access your local assessment data.</p><form onSubmit={onSubmit}><label htmlFor="login-email">Email</label><input id="login-email" name="email" type="email" autoComplete="email" required maxLength={254}/><label htmlFor="login-password">Password</label><input id="login-password" name="password" type="password" autoComplete="current-password" required maxLength={1024}/>{error && <div className="login-error" role="alert" aria-live="assertive">{error}<button type="button" onClick={onRetry}>Retry session check</button></div>}<button className="primary-button" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}<span aria-hidden="true">→</span></button></form><button type="button" className="signup-link" onClick={onForgot}>Forgot password?</button>{signupAvailable ? <button type="button" className="signup-link" onClick={onSignup}>Create operator account</button> : <p role="status" aria-live="polite">An operator account is already configured. Sign in or use forgot password to recover access.</p>}<AuthFooter/></AuthShell>;
}

function SignupDisabled({ onBack }: { onBack: () => void }) {
  return <AuthShell><div className="login-label">LOCAL SECURITY WORKSPACE</div><h1>Operator account already exists</h1><p>ChiNeScan supports one local operator account. Sign in or use forgot password to recover access.</p><button className="primary-button" onClick={onBack}>Back to sign in</button><AuthFooter/></AuthShell>;
}

function Signup({ busy, error, onBack, onSubmit }: { busy: boolean; error: string; onBack: () => void; onSubmit: (email: string, password: string) => void }) {
  const [mismatch, setMismatch] = useState(false);
  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const data = new FormData(event.currentTarget);
    const password = String(data.get('password')); const confirmation = String(data.get('confirm-password'));
    setMismatch(password !== confirmation);
    if (password === confirmation && password.length >= 12) onSubmit(String(data.get('email')), password);
  }
  return <AuthShell><div className="login-label">LOCAL SECURITY WORKSPACE</div><h1>Create operator account</h1><p>The first local operator account unlocks this workspace.</p><form onSubmit={submit}><label htmlFor="signup-email">Email</label><input id="signup-email" name="email" type="email" autoComplete="email" required maxLength={254}/><label htmlFor="signup-password">Password</label><input id="signup-password" name="password" type="password" autoComplete="new-password" required minLength={12} maxLength={1024} aria-describedby="password-requirement"/><small id="password-requirement">Use at least 12 characters.</small><label htmlFor="confirm-password">Confirm password</label><input id="confirm-password" name="confirm-password" type="password" autoComplete="new-password" required maxLength={1024} aria-invalid={mismatch} aria-describedby={mismatch ? 'confirm-error' : undefined}/>{mismatch && <small id="confirm-error" role="alert" aria-live="assertive">Passwords do not match.</small>}{error && <div className="login-error" role="alert" aria-live="assertive">{error}</div>}<button className="primary-button" disabled={busy}>{busy ? 'Creating account…' : 'Create account'}<span aria-hidden="true">→</span></button></form><button type="button" className="signup-link" onClick={onBack}>Back to sign in</button><AuthFooter/></AuthShell>;
}

function routeFromPath(): AuthPage {
  return window.location.pathname === '/signup' ? 'signup' : window.location.pathname === '/forgot-password' ? 'forgot' : window.location.pathname === '/reset-password' ? 'reset' : 'login';
}
function navigateAuth(page: AuthPage, setPage: (page: AuthPage) => void) {
  const path = page === 'login' || page === 'forgot-confirmed' ? '/' : page === 'forgot' ? '/forgot-password' : page === 'reset' ? '/reset-password' : '/signup';
  window.history.pushState({}, '', path); setPage(page);
}
function AuthShell({ children }: { children: React.ReactNode }) {
  return <div className="login-page"><div className="login-orb orb-one"/><div className="login-orb orb-two"/><section className="login-card"><div className="login-brand"><div className="brand-mark"><span>C</span><i /></div><span>ChiNeScan</span></div>{children}</section><footer className="login-footer">ChiNeScan <span>•</span> Local analyst console</footer></div>;
}
function AuthFooter() { return <div className="login-foot"><span>◉</span> Available from this device only</div>; }
function ForgotPassword({ busy, error, onBack, onSubmit }: { busy: boolean; error: string; onBack: () => void; onSubmit: (email: string) => void }) {
  return <AuthShell><div className="login-label">LOCAL ACCOUNT RECOVERY</div><h1>Forgot password?</h1><p>Enter your operator email to see local recovery instructions.</p><form onSubmit={(event) => { event.preventDefault(); onSubmit(String(new FormData(event.currentTarget).get('email'))); }}><label htmlFor="forgot-email">Email</label><input id="forgot-email" name="email" type="email" autoComplete="email" required maxLength={254}/>{error && <div className="login-error" role="alert">{error}</div>}<button className="primary-button" disabled={busy}>{busy ? 'Checking…' : 'Continue'}<span aria-hidden="true">→</span></button></form><button className="signup-link" onClick={onBack}>Back to sign in</button><AuthFooter/></AuthShell>;
}
function RecoveryInstructions({ onBack, onReset }: { onBack: () => void; onReset: () => void }) {
  return <AuthShell><div className="login-label">LOCAL ACCOUNT RECOVERY</div><h1>Continue recovery locally</h1><p>If the account exists, run <code>uv run chinescan web reset-password --email your@email</code> in the ChiNeScan terminal. Enter the one-time token printed there on the reset page within 15 minutes.</p><button className="primary-button" onClick={onReset}>Enter reset token <span aria-hidden="true">→</span></button><button className="signup-link" onClick={onBack}>Back to sign in</button><AuthFooter/></AuthShell>;
}
function ResetPassword({ busy, error, onBack, onSuccess }: { busy: boolean; error: string; onBack: () => void; onSuccess: () => void }) {
  const [fieldError, setFieldError] = useState(''); const [complete, setComplete] = useState(false);
  return <AuthShell><div className="login-label">LOCAL ACCOUNT RECOVERY</div><h1>Reset password</h1>{complete ? <><p>Password reset. You can now sign in with the new password.</p><button className="primary-button" onClick={onSuccess}>Back to sign in</button></> : <><p>Use the one-time token from the local ChiNeScan terminal.</p><form onSubmit={async (event) => { event.preventDefault(); const form = new FormData(event.currentTarget); const email = String(form.get('email')); const token = String(form.get('token')); const password = String(form.get('password')); if (password !== String(form.get('confirm-password'))) { setFieldError('Passwords do not match.'); return; } if (password.length < 12) { setFieldError('Use at least 12 characters.'); return; } setFieldError(''); try { await api.resetPassword(email, token, password); setComplete(true); } catch { setFieldError('Reset could not be completed. Request a new local token.'); } }}><label htmlFor="reset-email">Email</label><input id="reset-email" name="email" type="email" autoComplete="email" required maxLength={254}/><label htmlFor="reset-token">Reset token</label><input id="reset-token" name="token" autoComplete="off" required minLength={32} maxLength={256}/><label htmlFor="reset-password">New password</label><input id="reset-password" name="password" type="password" autoComplete="new-password" required minLength={12} maxLength={1024} aria-describedby="reset-requirement"/><small id="reset-requirement">Use at least 12 characters.</small><label htmlFor="reset-confirm">Confirm password</label><input id="reset-confirm" name="confirm-password" type="password" autoComplete="new-password" required maxLength={1024} aria-invalid={fieldError === 'Passwords do not match.'} aria-describedby={fieldError === 'Passwords do not match.' ? 'reset-confirm-error' : undefined}/>{fieldError === 'Passwords do not match.' && <small id="reset-confirm-error" role="alert">{fieldError}</small>}{fieldError && fieldError !== 'Passwords do not match.' && <div className="login-error" role="alert">{fieldError}</div>}{error && <div className="login-error" role="alert">{error}</div>}<button className="primary-button" disabled={busy}>{busy ? 'Resetting…' : 'Reset password'}<span aria-hidden="true">→</span></button></form><button className="signup-link" onClick={onBack}>Back to sign in</button><AuthFooter/></>}</AuthShell>;
}

function CenteredState({ title, detail }: { title: string; detail: string }) { return <div className="center-state"><div className="spinner"/><h1>{title}</h1><p>{detail}</p></div>; }

function OverviewPanel({ data, onScans, onFindings, onOpen }: { data: Overview | null; onScans: () => void; onFindings: () => void; onOpen: (id: string) => void }) {
  if (!data) return <div className="skeleton-card"/>;
  const severities: Array<keyof Overview['findings_by_severity']> = ['critical', 'high', 'medium', 'low', 'info'];
  const verdictSummary = <section className="panel"><div className="panel-heading"><div><h2>Findings by verdict</h2><p>Leads are kept separate from confirmed and likely issues.</p></div></div><div className="severity-list">{(['confirmed', 'likely', 'lead'] as const).map((verdict) => <div className="severity-row" key={verdict}><span>{verdict}</span><div className="severity-track"/><strong>{data.findings_by_verdict?.[verdict] ?? 0}</strong></div>)}</div></section>;
  const topFixFirst = data.top_fix_first ?? [];
  const fixFirst = <section className="panel"><div className="panel-heading"><div><h2>Fix first</h2><p>Confirmed and likely findings only</p></div></div>{topFixFirst.length ? <ol>{topFixFirst.map((item, index) => <li key={`${item.location}-${index}`}><strong>{item.title}</strong> · {item.severity} · <code>{item.location}</code></li>)}</ol> : <p>No confirmed or likely findings are queued for fixes.</p>}</section>;
  return <>{verdictSummary}{fixFirst}<div className="welcome-strip"><div className="welcome-symbol">✳</div><div><strong>Your local workspace is ready</strong><p>Data shown here is read from your configured ChiNeScan database.</p></div><span className="connected"><i/> Connected</span></div><div className="metric-grid"><Metric label="STORED SCANS" value={data.scan_count} icon="⌕" tone="blue" onClick={onScans}/><Metric label="STORED FINDINGS" value={data.finding_count} icon="◈" tone="violet" onClick={onFindings}/><Metric label="CRITICAL FINDINGS" value={data.findings_by_severity.critical} icon="↑" tone="red" onClick={onFindings}/></div><div className="overview-grid"><section className="panel recent-panel"><div className="panel-heading"><div><h2>Recent scans</h2><p>Your latest locally stored assessments</p><p className="evidence-note">Matches are leads rather than proof; no matches do not prove safety.</p></div><button className="text-button" onClick={onScans}>View all <span>→</span></button></div>{data.recent_scans.length ? <div className="table-scroll"><table><thead><tr><th>SCAN</th><th>TYPE</th><th>STARTED</th><th>FINISHED</th><th>FINDINGS</th><th>VERDICT</th><th>GAPS</th><th>STATUS</th></tr></thead><tbody>{data.recent_scans.map((scan) => <tr data-glass key={scan.scan_id} role="button" aria-label={`Open scan ${scan.scan_id}`} onClick={() => onOpen(scan.scan_id)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onOpen(scan.scan_id); } }}><td><span className="scan-icon">⌕</span><span className="mono">{scan.scan_id.slice(0, 8)}</span></td><td>{scan.project_types[0] ?? scan.scanner}</td><td>{dateOf(scan.started_at)}</td><td>{dateOf(scan.finished_at)}</td><td>{scan.finding_count}</td><td>{scan.verdict ?? '—'}</td><td>{scan.coverage_gap_count ?? 0}</td><td><Status status={scan.status}/></td></tr>)}</tbody></table></div> : <Empty title="No scans yet" text="Stored local assessments will appear here."/>}</section><section className="panel severity-panel"><div className="panel-heading"><div><h2>Findings by severity</h2><p>Counts from persisted findings</p></div></div><div className="severity-list">{severities.map((severity) => <div className="severity-row" key={severity}><SeverityPill severity={severity}/><div className="severity-track"><i className={`severity-fill ${severity}`} style={{ width: `${data.finding_count ? Math.max(4, data.findings_by_severity[severity] / data.finding_count * 100) : 0}%` }}/></div><strong>{data.findings_by_severity[severity]}</strong></div>)}</div><button className="secondary-button" onClick={onFindings}>Explore findings <span>→</span></button></section></div><div className="scope-note"><span>ⓘ</span><p><strong>Local-only workspace</strong> · No background jobs or network assessments are started from this dashboard.</p></div></>;
}

function Metric({ label, value, icon, tone, onClick }: { label: string; value: number; icon: string; tone: string; onClick: () => void }) { return <button data-glass className="metric-card" onClick={onClick}><div className={`metric-icon ${tone}`}>{icon}</div><span>{label}</span><strong>{value.toLocaleString()}</strong><small>From stored records <b>→</b></small></button>; }

function ScanTable({ data, page, onPage, onOpen }: { data: Page<Scan> | null; page: number; onPage: (page: number) => void; onOpen: (id: string) => void }) {
  if (!data) return <div className="skeleton-card"/>;
  return <section className="panel table-panel"><div className="panel-heading"><div><h2>Assessment records</h2><p>{data.total} stored scans. Matches are leads rather than proof; no matches do not prove safety.</p></div><span className="data-chip">Local database</span></div>{data.items.length ? <><div className="table-scroll"><table><thead><tr><th>SCAN ID</th><th>ASSESSMENT</th><th>STARTED</th><th>FINISHED</th><th>FINDINGS</th><th>VERDICT</th><th>GAPS</th><th>STATUS</th></tr></thead><tbody>{data.items.map((scan) => <tr data-glass role="button" aria-label={`Open scan ${scan.scan_id}`} key={scan.scan_id} onClick={() => onOpen(scan.scan_id)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onOpen(scan.scan_id); } }}><td className="mono">{scan.scan_id}</td><td>{scan.project_types.join(', ') || scan.scanner}</td><td>{dateOf(scan.started_at)}</td><td>{dateOf(scan.finished_at)}</td><td>{scan.finding_count}</td><td>{scan.verdict ?? '—'}</td><td>{scan.coverage_gap_count ?? 0}</td><td><Status status={scan.status}/></td></tr>)}</tbody></table></div><Pagination total={data.total} page={page} onPage={onPage}/></> : <Empty title="No scan records" text="Run an assessment from the local CLI to see it here."/>}</section>;
}

function FindingTable({ data, page, onPage, onOpen }: { data: Page<Finding> | null; page: number; onPage: (page: number) => void; onOpen: (id: string) => void }) {
  if (!data) return <div className="skeleton-card"/>;
  const emptyTitle = data.total === 0 ? 'No matching finding records' : 'No finding records on this page';
  const emptyText = data.total > 0
    ? 'The current page has no rows; use the page controls to review matching results.'
    : data.total_stored === 0
      ? 'No finding records are persisted.'
      : data.total_stored !== undefined
        ? `${data.total_stored} records are stored, but none match the active filters. Change the filters to review them.`
        : 'No rows match the active filters. The total stored count is unavailable for this response.';
  return <section className="panel table-panel"><div className="panel-heading"><div><h2>Finding records</h2><p>{data.total_stored ?? 'Unknown'} total stored · {data.total} matching active filters · {data.items.length} on this page</p></div><span className="data-chip">Reviewed evidence</span></div>{data.items.length ? <><div className="table-scroll"><table><thead><tr><th>FINDING</th><th>SEVERITY</th><th>CATEGORY</th><th>SCANNER</th><th>RULE</th></tr></thead><tbody>{data.items.map((item) => <tr data-glass role="button" aria-label={`Open finding ${item.title}`} key={item.finding_id} onClick={() => onOpen(item.finding_id)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onOpen(item.finding_id); } }}><td><span className="finding-dot"/><strong>{item.title}</strong><small className="sub-id">{item.finding_id.slice(0, 12)}</small></td><td><SeverityPill severity={item.severity}/></td><td>{item.category}</td><td>{item.scanner}</td><td className="mono">{item.rule_id}</td></tr>)}</tbody></table></div><Pagination total={data.total} page={page} onPage={onPage}/></> : <Empty title={emptyTitle} text={emptyText}/>}</section>;
}

function DetailPanel({ detail, kind, onClose, onCreateCase, onOpenFinding, onRefreshScan, onUnauthorized }: { detail: Scan | Finding | null; kind: 'scan' | 'finding'; onClose: () => void; onCreateCase: (id: string) => void; onOpenFinding: (id: string) => void; onRefreshScan: (id: string) => Promise<void>; onUnauthorized: () => void }) {
  return <div className="detail-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><aside className="detail-panel" aria-label={`${kind} details`}><div className="detail-header"><div><div className="eyebrow">RECORD DETAILS</div><h2>{kind === 'scan' ? 'Scan details' : 'Finding details'}</h2></div><button className="close-button" onClick={onClose} aria-label="Close details">×</button></div>{!detail ? <div className="detail-loading"><div className="spinner"/>Loading record…</div> : kind === 'scan' ? <ScanDetail scan={detail as Scan} onCreateCase={() => onCreateCase((detail as Scan).scan_id)} onOpenFinding={onOpenFinding} onRefreshScan={onRefreshScan} onUnauthorized={onUnauthorized}/> : <FindingDetail finding={detail as Finding}/>}</aside></div>;
}

function ScanDetail({ scan, onCreateCase, onOpenFinding, onRefreshScan, onUnauthorized }: {
  scan: Scan;
  onCreateCase: () => void;
  onOpenFinding: (id: string) => void;
  onRefreshScan: (id: string) => Promise<void>;
  onUnauthorized: () => void;
}) {
  const risk = scan.code_assessment?.vibe_coding_risk;
  const [exportError, setExportError] = useState('');
  const [exporting, setExporting] = useState('');
  const [previewInfo, setPreviewInfo] = useState('');
  async function downloadReport(format: 'json' | 'full-json' | 'markdown') {
    setExportError('');
    setExporting(format);
    try {
      const url = safeLocalUrl(`/api/scans/${encodeURIComponent(scan.scan_id)}/report/${format}`);
      if (!url) throw new Error('The report URL is not a local ChiNeScan route.');
      const response = await fetch(url, { credentials: 'same-origin' });
      if (response.status === 401) { onUnauthorized(); return; }
      if (!response.ok) {
        let detail = `Export failed with HTTP ${response.status}.`;
        try {
          const payload = await response.json() as { detail?: string };
          if (payload.detail) detail = payload.detail;
        } catch { /* Keep the HTTP status if the error was not JSON. */ }
        throw new Error(`${detail} No file was downloaded.`);
      }
      const blob = await response.blob();
      if (format === 'json') {
        try {
          const payload = JSON.parse(await blob.text()) as { findings?: unknown[]; summary?: { total_findings?: number; total_stored_findings?: number; available_finding_records?: number; processing_failure_count?: number; grouped_findings?: number; grouped_issue_total?: number; returned_grouped_findings?: number }; report_omissions?: { omitted_preview_groups?: number; omitted_preview_occurrences?: number; reason?: string }; report_truncated?: boolean };
          const summary = payload.summary;
          const omissions = payload.report_omissions;
          const omittedGroups = omissions?.omitted_preview_groups ?? 'Unknown';
          const omittedOccurrences = omissions?.omitted_preview_occurrences ?? 'Unknown';
          const failures = summary?.processing_failure_count ?? 'Unknown';
          setPreviewInfo(summary
            ? `${summary.total_stored_findings ?? 'Unknown'} scan-linked finding IDs; ${summary.available_finding_records ?? 'Unknown'} available records; ${summary.grouped_issue_total ?? summary.grouped_findings ?? 'Unknown'} grouped issues; ${summary.returned_grouped_findings ?? 'Unknown'} groups returned. ${omittedGroups} ${omittedGroups === 1 ? 'group' : 'groups'} and ${omittedOccurrences} ${omittedOccurrences === 1 ? 'occurrence' : 'occurrences'} omitted (${omissions?.reason ?? 'reason unavailable'}). ${failures} processing ${failures === 1 ? 'failure' : 'failures'} were recorded. Use Download complete JSON when within its limits, or Download all findings (JSONL) for a bounded complete stream.`
            : Array.isArray(payload.findings)
              ? `${payload.findings.length} individual findings were returned. Grouped issue counts are not applicable to this report format; the response does not declare separate failure or omission metadata.`
              : 'This legacy preview has no findings or omission metadata. Treat unavailable totals as unknown; use JSONL for complete retrieval.');
        } catch { setPreviewInfo('Preview downloaded, but its count metadata could not be read. Treat it as incomplete.'); }
      }
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = `scan-${scan.scan_id}.${format === 'full-json' ? 'json' : format}`;
      anchor.click();
      URL.revokeObjectURL(objectUrl);
    } catch (reason) {
      setExportError(messageOf(reason));
    } finally { setExporting(''); }
  }
  function downloadJsonl() {
    const url = safeLocalUrl(`/api/scans/${encodeURIComponent(scan.scan_id)}/findings.jsonl`);
    if (!url) { setExportError('The retrieval URL is not a local ChiNeScan route.'); return; }
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `scan-${scan.scan_id}-findings.jsonl`;
    anchor.click();
  }
  return <div className="detail-body">
    <div className="detail-id">SCAN ID<span className="mono">{scan.scan_id}</span></div>
    <dl>
      <DetailValue label="Status"><Status status={scan.status}/></DetailValue>
      <DetailValue label="Scanner">{scan.scanner}</DetailValue>
      <DetailValue label="Started">{dateOf(scan.started_at)}</DetailValue>
      <DetailValue label="Finished">{dateOf(scan.finished_at)}</DetailValue>
      <DetailValue label="Project type">{scan.project_types.join(', ') || 'Not recorded'}</DetailValue>
      <DetailValue label="Findings">{scan.finding_count}</DetailValue>
    </dl>
    {scan.verdict && <section className="evidence-section">
      <h3>Verdict</h3><p>{scan.verdict}</p>
      <p className="evidence-note">Matches are leads rather than proof; no matches do not prove safety.</p>
    </section>}
    {scan.code_assessment && <section className="evidence-section">
      <h3>Code assessment</h3>
      <p>{scan.code_assessment.files_scanned} files scanned · {scan.code_assessment.files_excluded} excluded</p>
      {risk && <>
        <p><strong>{risk.name}: {risk.score === null ? 'insufficient evidence' : `${risk.score}/100`}</strong> ({risk.confidence}) · {risk.interpretation}</p>
        <p>{risk.confidence_rationale || 'Legacy score: no contribution rationale was stored.'}</p>
        {risk.algorithm_version && <p>Algorithm: {risk.algorithm_version}</p>}
        <div className="score-ledger">
          {risk.contributions.length ? risk.contributions.map((item) => <article className="score-contribution" key={item.signal_id}>
            <strong>{item.description}</strong>
            <span>{item.raw_count} observed → {item.effective_count} counted × {item.weight}; contribution {item.contribution}</span>
            <small>{item.adjustment}</small>
            {item.evidence.map((evidence, index) => <small key={`${evidence.file}-${index}`}>
              {evidence.file}:{evidence.line_numbers.join(', ')} · {evidence.code_excerpt}
            </small>)}
          </article>) : <p>Detailed score breakdown unavailable for this legacy scan.</p>}
        </div>
        <p>{risk.disclaimer}</p>
        <ul className="explanation-list">{risk.coverage_limitations.map((item, index) => <li key={index}>{item}</li>)}</ul>
      </>}
    </section>}
    {!!scan.code_assessment?.excluded_paths.length && <section className="evidence-section">
      <h3>Excluded path examples</h3>
      <ul>{scan.code_assessment.excluded_paths.slice(0, 20).map((item, index) => <li key={index}>{item}</li>)}</ul>
    </section>}
    <section className="evidence-section">
      <h3>Coverage</h3>
      <p>{scan.coverage_gap_count ?? 0} coverage gap(s) · execution status does not guarantee complete coverage</p>
      <ul>{scan.coverage?.gaps?.map((gap, index) => <li key={`${gap.code}-${index}`}>
        {gap.code}: {gap.reason} ({gap.count})
      </li>) ?? <li>Coverage details are not recorded.</li>}</ul>
      {scan.coverage?.excluded && Object.entries(scan.coverage.excluded).map(([reason, count]) => <p key={reason}>{reason}: {count} excluded</p>)}
      {scan.coverage?.languages_detected && <><h4>Language coverage</h4><ul>{Object.entries(scan.coverage.languages_detected).map(([language, detected]) => <li key={language}>{language}: {detected} detected; {scan.coverage?.files_scanned_by_language?.[language] ?? 0} scanned; {scan.coverage?.language_analyzer_status?.[language] ?? 'analyzer status unavailable'}</li>)}</ul></>}
      {!!scan.coverage?.not_assessed?.length && <><h4>Not assessed</h4><ul>{scan.coverage.not_assessed.map((item) => <li key={item}>{item}</li>)}</ul></>}
    </section>
    {!!scan.finding_count && <section className="evidence-section">
      <h3>Persisted findings</h3>
      <p>{scan.finding_count} scan-linked finding IDs. Showing up to 20 links; use the paged findings view for individual records or the JSONL download for complete streamed retrieval.</p>
      {scan.finding_ids?.slice(0, 20).map((id) => <button className="text-button" key={id} onClick={() => onOpenFinding(id)}>{id.slice(0, 12)} →</button>)}
    </section>}
    <section className="evidence-section">
      <h3>Reports</h3>
      <div className="report-actions">
        <button className="text-button" type="button" disabled={!!exporting} onClick={() => void downloadReport('json')}>{exporting === 'json' ? 'Preparing preview…' : 'Download JSON preview'}</button>
        <button className="text-button" type="button" disabled={!!exporting} onClick={() => void downloadReport('full-json')}>{exporting === 'full-json' ? 'Preparing complete JSON…' : 'Download complete JSON'}</button>
        <button className="text-button" type="button" onClick={downloadJsonl}>Download all findings (JSONL)</button>
        <button className="text-button" type="button" disabled={!!exporting} onClick={() => void downloadReport('markdown')}>{exporting === 'markdown' ? 'Preparing Markdown…' : 'Download Markdown'}</button>
      </div>
      {exportError && <p className="login-error" role="alert">{exportError}</p>}
      {previewInfo && <p role="status">{previewInfo}</p>}
    </section>
    {scan.code_assessment && <ScanityReportImport scanId={scan.scan_id} onUnauthorized={onUnauthorized} onImported={() => void onRefreshScan(scan.scan_id)}/>}
    {scan.failures && Object.keys(scan.failures).length ? <section className="evidence-section">
      <h3>Errors / failures</h3><ul>{Object.entries(scan.failures).map(([name, error]) => <li key={name}>{name}: {error}</li>)}</ul>
    </section> : <section className="evidence-section"><h3>Errors / failures</h3><p>No scanner failures were recorded.</p></section>}
    <button className="primary-button" onClick={onCreateCase}>Create case from this scan</button>
    <div className="evidence-note">Target paths and raw scan payloads are hidden in this dashboard view.</div>
  </div>;
}
function FindingDetail({ finding }: { finding: Finding }) { const explanation = finding.explanation; return <div className="detail-body"><div className="detail-id">FINDING ID<span className="mono">{finding.finding_id}</span></div><h3 className="finding-title">{finding.title}</h3><SeverityPill severity={finding.severity}/><p className="evidence-note">{finding.verdict ?? 'lead'} verdict · {finding.confidence} confidence is a heuristic category, not a probability or proof of exploitability.</p><dl><DetailValue label="Category">{finding.category}</DetailValue><DetailValue label="Confidence">{finding.confidence}</DetailValue><DetailValue label="Scanner">{finding.scanner}</DetailValue><DetailValue label="Rule">{finding.rule_id}</DetailValue><DetailValue label="Contributing rules">{finding.contributing_rule_ids?.join(', ') || finding.rule_id}</DetailValue>{finding.location && <DetailValue label="Location"><span className="mono evidence-text">{finding.location}</span></DetailValue>}{finding.exposure && <DetailValue label="Exposure">{finding.exposure}</DetailValue>}{explanation?.classification_policy_version && <DetailValue label="Classification policy">{explanation.classification_policy_version}</DetailValue>}{finding.cwe_ids?.length ? <DetailValue label="CWE">{finding.cwe_ids.join(', ')}</DetailValue> : null}</dl>{(finding.entry_point || finding.source_location || finding.sink_location) && <section className="evidence-section"><h3>Reachability evidence</h3>{finding.entry_point && <p>Entry point: <span className="mono">{finding.entry_point.file}:{finding.entry_point.line}</span></p>}{finding.source_location && <div>Source: <span className="mono">{finding.source_location.file}:{finding.source_location.line}</span>{finding.source_location.excerpt && <pre className="evidence-text">{finding.source_location.excerpt}</pre>}</div>}{finding.sink_location && <div>Sink: <span className="mono">{finding.sink_location.file}:{finding.sink_location.line}</span>{finding.sink_location.excerpt && <pre className="evidence-text">{finding.sink_location.excerpt}</pre>}</div>}</section>}{finding.description && <section className="evidence-section"><h3>What the scanner saw</h3><p className="evidence-text">{finding.description}</p></section>}{finding.code_excerpt && <section className="evidence-section"><h3>Relevant code (secrets redacted)</h3><pre className="evidence-text">{finding.code_excerpt}</pre></section>}{explanation ? <><ExplanationList title="Why it matched" text={explanation.match_reason}/><ExplanationList title="Established by the source" items={explanation.established}/><ExplanationList title="Inferred, not verified" items={explanation.inferred}/><ExplanationList title="Why this severity" text={explanation.severity_rationale}/><ExplanationList title="Why this confidence" text={explanation.confidence_rationale}/><ExplanationList title="Exposure basis" text={explanation.exposure_rationale}/><ExplanationList title="What would need to be true for harm" items={explanation.attack_prerequisites}/><ExplanationList title="Possible impact if those conditions hold" text={explanation.conditional_impact}/><ExplanationList title="What to check next" items={explanation.verification_steps}/><ExplanationList title="False-positive considerations" items={explanation.false_positive_considerations}/><ExplanationList title="Analysis limitations" items={explanation.limitations}/></> : <section className="evidence-section"><h3>Explanation unavailable</h3><p>This is a legacy finding. The original analysis did not store a versioned rationale, so no historical evidence or severity explanation is inferred.</p></section>}{finding.remediation && <section className="evidence-section"><h3>Remediation guidance</h3><p className="evidence-text">{finding.remediation}</p>{explanation?.remediation_rationale && <small>{explanation.remediation_rationale}</small>}</section>}<ExplanationList title="Exploitability conditions" items={finding.exploitability_conditions}/><ExplanationList title="Controls considered" items={finding.controls_considered}/><ExplanationList title="Project impact" text={finding.project_impact}/><ExplanationList title="Why not higher" text={finding.why_not_higher}/><ExplanationList title="What would raise it" text={finding.what_would_raise_it}/>{(finding.remediation_before || finding.remediation_after) && <section className="evidence-section"><h3>Patch for observed code</h3>{finding.remediation_before && <><strong>Before</strong><pre className="evidence-text">{finding.remediation_before}</pre></>}{finding.remediation_after && <><strong>After</strong><pre className="evidence-text">{finding.remediation_after}</pre></>}{finding.verification_step && <p>Verify: {finding.verification_step}</p>}</section>}{finding.tags?.length ? <section className="evidence-section"><h3>Tags</h3><div className="tag-list">{finding.tags.map((tag) => <span key={tag}>{tag}</span>)}</div></section> : null}<div className="evidence-note">Source and evidence are rendered as text. Values are redacted before the browser receives them.</div></div>; }
function ExplanationList({ title, text, items }: { title: string; text?: string | null; items?: string[] }) { if (!text && !items?.length) return null; return <section className="evidence-section"><h3>{title}</h3>{text && <p className="evidence-text">{text}</p>}{items?.length ? <ul className="explanation-list">{items.map((item, index) => <li key={`${title}-${index}`}>{item}</li>)}</ul> : null}</section>; }
function DetailValue({ label, children }: { label: string; children: React.ReactNode }) { return <div className="detail-value"><dt>{label}</dt><dd>{children}</dd></div>; }
function Status({ status }: { status: string }) { const tone = status === 'complete' ? 'green' : status === 'partial' ? 'amber' : 'neutral'; return <span className={`status ${tone}`}><i/>{status}</span>; }
function SeverityPill({ severity }: { severity: string }) { return <span className={`severity-pill ${severity}`}><i/>{severity}</span>; }
function Pagination({ total, page, onPage }: { total: number; page: number; onPage: (page: number) => void }) { const max = Math.max(0, Math.ceil(total / 20) - 1); return <div className="pagination"><span>Showing {total ? page * 20 + 1 : 0}–{Math.min((page + 1) * 20, total)} of {total}</span><div><button onClick={() => onPage(Math.max(0, page - 1))} disabled={page === 0} aria-label="Previous page">←</button><span>Page {page + 1} of {max + 1}</span><button onClick={() => onPage(Math.min(max, page + 1))} disabled={page >= max} aria-label="Next page">→</button></div></div>; }
function Empty({ title, text }: { title: string; text: string }) { return <div className="empty-state"><div className="empty-mark">⌕</div><h3>{title}</h3><p>{text}</p></div>; }
