import { lazy, Suspense, useEffect, useState } from 'react';

type Mode = 'full' | 'reduced' | 'off';
type Props = { mode: Mode };

const TerminalBackdropScene = lazy(() => import('./TerminalBackdropScene').then((module) => ({ default: module.TerminalBackdropScene })));

function hasWebGL(): boolean {
  try {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('webgl2') ?? canvas.getContext('webgl');
    const loseContext = context?.getExtension('WEBGL_lose_context');
    loseContext?.loseContext();
    return context !== null;
  } catch {
    return false;
  }
}

/** Decorative only. Must never display status, results, hashes or claims. */
export function TerminalBackdrop({ mode }: Props) {
  const [webglAvailable, setWebglAvailable] = useState(false);
  const [systemReduced, setSystemReduced] = useState(() => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false);
  const [visible, setVisible] = useState(() => !document.hidden);

  useEffect(() => {
    const onVisibility = () => setVisible(!document.hidden);
    document.addEventListener('visibilitychange', onVisibility);
    return () => document.removeEventListener('visibilitychange', onVisibility);
  }, []);

  useEffect(() => {
    if (mode !== 'off') setWebglAvailable(hasWebGL());
  }, [mode]);

  useEffect(() => {
    const query = window.matchMedia?.('(prefers-reduced-motion: reduce)');
    const onMotion = () => setSystemReduced(Boolean(query?.matches));
    query?.addEventListener?.('change', onMotion);
    return () => query?.removeEventListener?.('change', onMotion);
  }, []);

  if (mode === 'off') return null;
  const sceneMode = systemReduced ? 'reduced' : mode;
  return <div className={`terminal-ambient ${sceneMode === 'reduced' ? 'is-static' : ''} ${sceneMode === 'full' && visible ? 'is-active' : ''}`} aria-hidden="true">
    <div className="ambient-grid"/><div className="terminal-glow"/><div className="terminal-scanlines"/>
    <div className="terminal-generated" aria-hidden="true"><span>╭─┐  ·░▒  0x·A·7  ┌─╮</span><span>│ ╲  ░·▓  ╱ │</span><span>└─╯  ⌁ ▒░  ╰─┘</span><span>$ <i className="terminal-cursor">_</i></span></div>
    {webglAvailable && <Suspense fallback={null}><TerminalBackdropScene mode={sceneMode}/></Suspense>}
  </div>;
}
