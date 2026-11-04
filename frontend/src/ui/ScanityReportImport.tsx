import { useState } from 'react';
import { api, UnauthorizedError } from '../api';

const MAX_BYTES = 2 * 1024 * 1024;

export function ScanityReportImport({ scanId, onUnauthorized, onImported }: {
  scanId: string;
  onUnauthorized: () => void;
  onImported: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function importReport() {
    if (!file) return;
    setBusy(true); setError(''); setNotice('');
    try {
      if (file.size > MAX_BYTES) throw new Error('Choose a report smaller than 2 MB.');
      const text = await file.text();
      if (new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new Error('Choose a report smaller than 2 MB.');
      const result = await api.importScanityReport(scanId, text);
      setNotice(`${result.imported} Scanity finding(s) imported into External scanner results.`);
      setFile(null);
      const input = document.getElementById(`scanity-report-${scanId}`) as HTMLInputElement | null;
      if (input) input.value = '';
      onImported();
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Report import failed.');
    } finally { setBusy(false); }
  }

  return <section className="evidence-section" aria-label="Import external report">
    <h3>Import external report</h3>
    <p>Import a JSON or SARIF export. The file is treated as untrusted data, displayed as text, and never executed or followed. Maximum size: 2 MB.</p>
    <label htmlFor={`scanity-report-${scanId}`}>Scanity JSON/SARIF file</label>
    <input id={`scanity-report-${scanId}`} type="file" accept=".json,.sarif,.sarif.json,application/json" onChange={(event) => { setError(''); setNotice(''); setFile(event.target.files?.[0] ?? null); }} />
    <button className="secondary-button" disabled={!file || busy} onClick={() => void importReport()}>{busy ? 'Importing…' : 'Import report'}</button>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
  </section>;
}
