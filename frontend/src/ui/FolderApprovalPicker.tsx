import { useEffect, useRef, useState } from 'react';
import { api, UnauthorizedError } from '../api';
import type { ApprovedFolder, FolderPreview, FsDirectory, FsPage } from '../types';

type Purpose = 'project' | 'logs' | 'malware';

export function FolderApprovalPicker({
  onClose,
  onUnauthorized,
  onApproved,
  purpose = 'project',
}: {
  onClose: () => void;
  onUnauthorized: () => void;
  onApproved: (project: ApprovedFolder) => void;
  purpose?: Purpose;
}) {
  const dialog = useRef<HTMLDivElement>(null);
  const [roots, setRoots] = useState<FsDirectory[]>([]);
  const [page, setPage] = useState<FsPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [items, setItems] = useState<FsDirectory[]>([]);
  const [selected, setSelected] = useState<FsDirectory | null>(null);
  const [preview, setPreview] = useState<FolderPreview | null>(null);
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    api.folderPickerRoots().then((result) => {
      if (active) setRoots(result.items);
    }).catch((reason: unknown) => {
      if (!active) return;
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Local folders could not be loaded.');
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [onUnauthorized]);

  useEffect(() => {
    const node = dialog.current;
    if (!node) return;
    const focusable = () => Array.from(node.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), [tabindex="0"]',
    ));
    focusable()[0]?.focus();
    const trap = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { onClose(); return; }
      if (event.key !== 'Tab') return;
      const controls = focusable();
      if (!controls.length) return;
      if (event.shiftKey && document.activeElement === controls[0]) {
        event.preventDefault(); controls.at(-1)?.focus();
      } else if (!event.shiftKey && document.activeElement === controls.at(-1)) {
        event.preventDefault(); controls[0].focus();
      }
    };
    document.addEventListener('keydown', trap);
    return () => document.removeEventListener('keydown', trap);
  }, [onClose, preview]);

  async function browse(directory: FsDirectory, append = false) {
    setLoading(true); setError('');
    try {
      const result = await api.folderPickerList(directory.directory_id, append ? cursor : null);
      setPage(result);
      setSelected({ directory_id: result.directory_id, name: result.name, selectable: result.selectable });
      setItems(append ? [...items, ...result.items] : result.items);
      setCursor(result.next_cursor);
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'Folder contents could not be loaded.');
    } finally { setLoading(false); }
  }

  async function prepareConfirmation() {
    if (!selected?.selectable) return;
    setLoading(true); setError('');
    try {
      const next = await api.folderPickerPreview(selected.directory_id);
      setPreview(next); setName(next.name);
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'The selected folder could not be validated.');
    } finally { setLoading(false); }
  }

  async function approve() {
    if (!preview || !name.trim()) return;
    setSaving(true); setError('');
    try {
      onApproved(await api.approveFolder(preview.directory_id, name.trim(), purpose));
    } catch (reason) {
      if (reason instanceof UnauthorizedError) onUnauthorized();
      else setError(reason instanceof Error ? reason.message : 'The folder could not be approved.');
    } finally { setSaving(false); }
  }

  const title = purpose === 'logs' ? 'Select a log folder' : purpose === 'malware' ? 'Select a project folder for static triage' : 'Select a project folder';
  return <div className="project-dialog-backdrop">
    <div className="project-dialog folder-picker" role="dialog" aria-modal="true" aria-labelledby="folder-approval-title" ref={dialog}>
      <div className="dialog-heading"><div><h2 id="folder-approval-title">{preview ? 'Approve folder' : title}</h2><p>{preview ? 'Review the resolved folder before approving it.' : 'Browse local folders on this device. System folders and network locations are unavailable.'}</p></div><button aria-label="Close folder picker" className="close-button" onClick={onClose}>×</button></div>
      {error && <div role="alert" aria-live="assertive" className="alert-error">{error}</div>}
      {preview ? <section aria-label="Folder approval confirmation">
        <p><strong>Approve this folder for assessment?</strong></p>
        <p className="mono folder-resolved-path">{preview.resolved_path}</p>
        <label htmlFor="approved-folder-name">Project name</label>
        <input id="approved-folder-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={120} />
        <div className="project-actions"><button className="secondary-button" onClick={() => setPreview(null)}>Back</button><button className="secondary-button" onClick={onClose}>Cancel</button><button className="primary-button" disabled={!name.trim() || saving} onClick={() => void approve()}>{saving ? 'Approving…' : 'Approve folder'}</button></div>
      </section> : <>
        {loading && !roots.length && <p role="status">Loading local folders…</p>}
        {!loading && !roots.length && !error && <p role="status">No safe local folders are available to browse.</p>}
        {roots.length > 0 && !page && <section aria-label="Local drives and allowed roots"><h3>Local drives and allowed roots</h3><ul className="folder-list">{roots.map((root) => <li key={root.directory_id}><button className="text-button" onClick={() => void browse(root)}>Open {root.name}</button>{root.selectable && <button className="secondary-button" onClick={() => setSelected(root)}>Select this folder</button>}</li>)}</ul></section>}
        {page && <section aria-label="Folder contents"><nav aria-label="Folder breadcrumbs" className="folder-breadcrumbs">{page.breadcrumbs.map((crumb, index) => <button key={`${crumb.directory_id}-${index}`} className="text-button" onClick={() => void browse(crumb)}>{crumb.name}</button>)}</nav>{page.truncated && <p role="status">Folder listing reached its directory-entry cap; results may be incomplete.</p>}{items.length ? <ul className="folder-list">{items.map((item) => <li key={item.directory_id}><button className="text-button" onClick={() => void browse(item)}>Open {item.name}</button>{item.selectable && <button className="secondary-button" onClick={() => setSelected(item)}>Select this folder</button>}</li>)}</ul> : <p className="empty-copy">No subfolders in this folder.</p>}{cursor && <button className="secondary-button" disabled={loading} onClick={() => void browse({ directory_id: page.directory_id, name: page.name, selectable: page.selectable }, true)}>Load more</button>}</section>}
        {selected && <p role="status">Selected: {selected.name}</p>}
        <div className="project-actions"><button className="secondary-button" onClick={onClose}>Cancel</button><button className="primary-button" disabled={!selected?.selectable || loading} onClick={() => void prepareConfirmation()}>Review folder</button></div>
      </>}
    </div>
  </div>;
}
