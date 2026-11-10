import { describe, expect, it } from 'vitest';
import { checkSource } from '../../scripts/check-csp.mjs';

describe('strict CSP source check', () => {
  it('rejects inline script tags', () => {
    expect(() => checkSource('<script>run()</script>', 'index.html')).toThrow(/Inline script/);
  });

  it('rejects eval and the Function constructor', () => {
    const evalCall = ['ev', 'al', '(', '"1")'].join('');
    const functionConstructor = ['new ', 'Function', '("return 1")'].join('');
    expect(() => checkSource(evalCall, 'source.js')).toThrow(/Dynamic code/);
    expect(() => checkSource(functionConstructor, 'source.js')).toThrow(/Dynamic code/);
  });

  it('rejects string timer callbacks', () => {
    const stringTimer = ['setTimeout(', '"run()", 1)'].join('');
    expect(() => checkSource(stringTimer, 'source.js')).toThrow(/String timer/);
  });

  it('accepts clean local source', () => {
    expect(() => checkSource('<script type="module" src="/src/main.tsx"></script>', 'index.html')).not.toThrow();
    expect(() => checkSource('setTimeout(() => run(), 1)', 'source.js')).not.toThrow();
  });
});
