import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { ChainTraceGraph } from './ChainTraceGraph';
import type { ChainGraph } from '../types';

const graph: ChainGraph = {
  scan_id: 'scan', chain: 'ethereum',
  nodes: [
    { address: 'wallet-a', depth: 0 },
    { address: 'wallet-b', depth: 1, label: { address: 'wallet-b', chain: 'ethereum', category: 'exchange', name: 'Example Desk', source: 'local-list', date: '2026-01-02' } },
  ],
  edges: [{ chain: 'ethereum', tx_hash: 'tx-1', block_time: 1_700_000_000, sender: 'wallet-a', receiver: 'wallet-b', asset: 'ETH', amount: '2.5', kind: 'transfer' }],
  findings: [{ finding_id: 'finding-1', title: 'cash out lead', rule_id: 'cash_out', location: 'chain:ethereum:wallet-b', evidence: 'reference_only', confidence: 'POSSIBLE' }],
};

it('opens an accessible node panel with transfers, label provenance and findings', () => {
  render(<ChainTraceGraph graph={graph} />);
  fireEvent.click(screen.getByRole('button', { name: 'Wallet wallet-b' }));
  expect(screen.getByRole('complementary', { name: 'Wallet transfers' })).toBeInTheDocument();
  expect(screen.getByText('Example Desk · exchange')).toBeInTheDocument();
  expect(screen.getByText(/local-list · Date: 2026-01-02/)).toBeInTheDocument();
  expect(screen.getByText(/tx-1/)).toBeInTheDocument();
  expect(screen.getByText(/ETH 2\.5/)).toBeInTheDocument();
  expect(screen.getByText('cash out lead')).toBeInTheDocument();
  fireEvent.keyDown(window, { key: 'Escape' });
  expect(screen.queryByRole('complementary', { name: 'Wallet transfers' })).not.toBeInTheDocument();
});

it('supports keyboard opening and announces the large-graph cap', () => {
  const large = { ...graph, nodes: Array.from({ length: 501 }, (_, index) => ({ address: `node-${index}`, depth: 0 })) };
  render(<ChainTraceGraph graph={large} />);
  expect(screen.getByRole('status')).toHaveTextContent('Showing 500 of 501 nodes');
  const first = screen.getByRole('button', { name: 'Wallet node-0' });
  first.focus();
  fireEvent.keyDown(first, { key: 'Enter' });
  expect(screen.getByRole('complementary', { name: 'Wallet transfers' })).toBeInTheDocument();
});
