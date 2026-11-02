import type { ChainGraph } from '../types';

export function ChainTraceGraph({ graph }: { graph: ChainGraph }) {
  const nodes = graph.nodes.slice(0, 500); const width = 900; const height = Math.max(160, nodes.length * 32);
  return <div><svg role="img" aria-label="Wallet transfer graph" viewBox={`0 0 ${width} ${height}`} className="chain-graph">
    {graph.edges.slice(0, 5000).map((edge, i) => { const a = nodes.findIndex((n) => n.address === edge.sender); const b = nodes.findIndex((n) => n.address === edge.receiver); if (a < 0 || b < 0) return null; return <line key={`${edge.tx_hash}-${i}`} x1="160" y1={24 + a * 32} x2="740" y2={24 + b * 32} stroke="#678" strokeWidth={Math.min(5, 1 + Math.log10(Number(edge.amount) + 1))}/>; })}
    {nodes.map((node, i) => <g key={node.address}><circle cx="160" cy={24 + i * 32} r="8" fill="#51a58b"/><text x="180" y={28 + i * 32}>{node.address.slice(0, 8)}…{node.address.slice(-4)}</text></g>)}
  </svg>{graph.nodes.length > 500 && <p role="status">Showing 500 of {graph.nodes.length} nodes.</p>}{!graph.nodes.length && <p>No graph nodes were recorded.</p>}</div>;
}
