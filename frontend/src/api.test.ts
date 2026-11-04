import { describe, expect, it } from 'vitest';
import { safeLocalUrl } from './api';

describe('safeLocalUrl', () => {
  it('rejects active and external schemes before using API data in href or src', () => {
    expect(safeLocalUrl('javascript:alert(1)')).toBeNull();
    expect(safeLocalUrl('data:text/html,<script>alert(1)</script>')).toBeNull();
    expect(safeLocalUrl('//example.invalid/x')).toBeNull();
    expect(safeLocalUrl('https://example.invalid/x')).toBeNull();
  });

  it('accepts same-origin API paths', () => {
    expect(safeLocalUrl('/api/scans/scan-1/report/html')).toBe('/api/scans/scan-1/report/html');
  });
});
