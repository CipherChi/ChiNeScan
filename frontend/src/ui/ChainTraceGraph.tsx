import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import type { ChainGraph, ChainNode } from '../types';

const labelColors: Record<string, string> = {
  exchange: '#e7aa46', mixer: '#bd75cc', bridge: '#668ce5', sanctioned: '#d75e5e', scam: '#d75e5e', other: '#8c98a8',
};

export function ChainTraceGraph({ graph }: { graph: ChainGraph }) {
  const nodes = graph.nodes.slice(0, 500);
  const [selected, setSelected] = useState<ChainNode | null>(null);
  const panelRef = useRef<HTMLElement>(null);
  const columns = Math.max(1, ...nodes.map((node) => node.depth + 1));
  const byDepth = new Map<number, ChainNode[]>();
  nodes.forEach((node) => byDepth.set(node.depth, [...(byDepth.get(node.depth) ?? []), node]));
  const xFor = (depth: number) => 70 + depth * (760 / Math.max(1, columns - 1));
  const yFor = (node: ChainNode) => {
    const level = byDepth.get(node.depth) ?? [];
    return 30 + level.indexOf(node) * 48;
  };
  const height = Math.max(160, ...Array.from(byDepth.values(), (level) => 60 + level.length * 48));
  useEffect(() => {
    if (!selected) return;
    panelRef.current?.focus();
    const closeOnEscape = (event: globalThis.KeyboardEvent) => {
      if (event.key === 'Escape') setSelected(null);
    };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [selected]);
  function activate(event: KeyboardEvent<SVGGElement>, node: ChainNode) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      setSelected(node);
    }
  }
  const transfers = selected ? graph.edges.filter((edge) => edge.sender === selected.address || edge.receiver === selected.address) : [];
  const nodeFindings = selected ? (graph.findings ?? []).filter((finding) => finding.location === `chain:${graph.chain}:${selected.address}`) : [];
  return <div className="chain-graph-layout">
    <div className="chain-graph-scroll">
      <svg role="img" aria-label="Wallet transfer graph" viewBox={`0 0 900 ${height}`} className="chain-graph">
        {graph.edges.slice(0, 5000).map((edge, i) => {
          const source = nodes.find((node) => node.address === edge.sender);
          const target = nodes.find((node) => node.address === edge.receiver);
          if (!source || !target) return null;
          return <line key={`${edge.tx_hash}-${i}`} x1={xFor(source.depth)} y1={yFor(source)} x2={xFor(target.depth)} y2={yFor(target)} stroke="#678" strokeWidth={Math.min(5, 1 + Math.log10(Number(edge.amount) + 1))} />;
        })}
        {nodes.map((node) => <g key={node.address} role="button" tabIndex={0} aria-label={`Wallet ${node.address}`} onClick={() => setSelected(node)} onKeyDown={(event) => activate(event, node)}>
          <circle cx={xFor(node.depth)} cy={yFor(node)} r="10" fill={labelColors[node.label?.category ?? node.category ?? ''] ?? '#51a58b'} />
          <text x={xFor(node.depth) + 18} y={yFor(node) + 4}>{node.address.slice(0, 8)}…{node.address.slice(-4)}</text>
        </g>)}
      </svg>
    </div>
    {graph.nodes.length > 500 && <p role="status">Showing 500 of {graph.nodes.length} nodes.</p>}
    {!graph.nodes.length && <p>No graph nodes were recorded.</p>}
    {selected && <aside className="chain-node-panel" aria-label="Wallet transfers" tabIndex={-1} ref={panelRef}>
      <button type="button" className="text-button" onClick={() => setSelected(null)} aria-label="Close wallet details">Close</button>
      <h3 className="mono">{selected.address}</h3>
      {selected.label ? <section><h4>Local label</h4><p>{selected.label.name} · {selected.label.category}</p><p>Source: {selected.label.source} · Date: {selected.label.date}</p></section> : <p>No local label.</p>}
      <h4>Transfers ({transfers.length})</h4>
      <ul>{transfers.map((edge, index) => <li key={`${edge.tx_hash}-${index}`}><span>{edge.sender === selected.address ? 'Outgoing' : 'Incoming'} · {edge.tx_hash}</span><span>{edge.asset} {edge.amount} · {new Date(edge.block_time * 1000).toLocaleString()}</span></li>)}</ul>
      <h4>Findings ({nodeFindings.length})</h4>
      <ul>{nodeFindings.map((finding) => <li key={finding.finding_id}>{finding.title}</li>)}</ul>
    </aside>}
  </div>;
}
