import { render } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TerminalBackdrop } from './TerminalBackdrop';

const { sceneLoad } = vi.hoisted(() => ({ sceneLoad: vi.fn() }));
vi.mock('./TerminalBackdropScene', () => {
  sceneLoad();
  return { TerminalBackdropScene: () => <div data-testid="webgl-scene"/> };
});

const forbidden = /\[OK\]|guard|authoriz|passed|sha\d*|progress|\d+%|scan|sample/i;

describe('decorative terminal backdrop', () => {
  beforeEach(() => { sceneLoad.mockClear(); });

  it('keeps the abstract decorative text free of status-like claims', () => {
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
    const { container } = render(<TerminalBackdrop mode="full"/>);
    const layer = container.querySelector('.terminal-ambient');
    expect(layer).toHaveAttribute('aria-hidden', 'true');
    expect(layer?.textContent ?? '').not.toMatch(forbidden);
  });

  it('does not probe WebGL or load the Three.js scene in Off mode', () => {
    const getContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext');
    const { container } = render(<TerminalBackdrop mode="off"/>);
    expect(container.querySelector('.terminal-ambient')).toBeNull();
    expect(getContext).not.toHaveBeenCalled();
    expect(sceneLoad).not.toHaveBeenCalled();
  });
});
