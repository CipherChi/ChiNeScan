import { useEffect } from 'react';

/** Adds pointer-position CSS variables to semantic controls/cards marked data-glass. */
export function useGlassTracking() {
  useEffect(() => {
    const move = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const surface = target.closest<HTMLElement>('[data-glass], .status-badge, .status, .severity-pill, .text-button, .secondary-button, .primary-button, .panel, .welcome-strip');
      if (!surface) return;
      const rect = surface.getBoundingClientRect();
      surface.style.setProperty('--glass-x', `${event.clientX - rect.left}px`);
      surface.style.setProperty('--glass-y', `${event.clientY - rect.top}px`);
    };
    const keyboardActivate = (event: KeyboardEvent) => {
      if (event.key !== ' ') return;
      const target = event.target;
      if (!(target instanceof Element)) return;
      const row = target.closest<HTMLElement>('tr[role="button"]');
      if (row) { event.preventDefault(); row.click(); }
    };
    document.addEventListener('pointermove', move, { passive: true });
    document.addEventListener('keydown', keyboardActivate);
    return () => { document.removeEventListener('pointermove', move); document.removeEventListener('keydown', keyboardActivate); };
  }, []);
}
