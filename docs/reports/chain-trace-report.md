# Chain trace hardening report

## Scope

The on-chain tracing implementation supports offline explorer imports, local provenance-bearing
labels, graph exports, investigative heuristic findings, and optional Etherscan-family lookup.
Heuristic findings are leads, never proof of ownership or attribution.

## Network policy

- Network access is disabled by default. CLI lookup requires `--allow-network-chain`; web lookup
  requires both request opt-in and the server's `chain_network_enabled` setting.
- Built-in EVM chains use the `api.etherscan.io` host allowlist. Custom registry endpoints require
  HTTPS, public DNS results, no user information, and port 443 unless configured otherwise.
- Redirects are limited to two HTTPS hops on the original host. The transport disables environment
  proxies, resolves and checks addresses again before connecting, and pins the validated address.
- The Etherscan API key is read from its configured environment variable and attached to the query
  only inside the transport adapter. It is not stored in records or returned by APIs or diagnostics.
- Trace limits default to a 120-second deadline, 100 provider requests, 500 addresses, depth 6, and
  2 MB per response. Bound hits produce coverage gaps and a partial scan.
- Doctor and web diagnostics report network enabled state and key configuration as booleans. A
  missing key while network lookup is enabled is a warning; disabled network lookup preserves the
  offline-ready check.

## Checkout artifacts

Inspected names and sizes without reading generated file contents:

| Path | Inventory |
| --- | --- |
| `ct/` | Pytest basetemp tree; 1,684 files, 2,332 directories, 9,471,218 bytes. Contains per-test directories, SQLite fixtures, and synthetic sample files. |
| `ct-chaintrace-final/` | Pytest basetemp tree; 1,684 files, 2,331 directories, 9,472,812 bytes. Contains per-test directories, SQLite fixtures, and synthetic sample files. |
| `export.csv` | 693 bytes; generated transfer export. |
| `g.graphml` | 113 bytes; generated graph export. |

These paths are now narrowly ignored. No artifact has been deleted. Proposed deletion after operator
approval: `ct/`, `ct-chaintrace-final/`, `export.csv`, and `g.graphml`.

Pytest now rejects `--basetemp` paths that resolve inside the repository. The guard was verified
with an OS-temp basetemp (chain tests passed) and a checkout-local basetemp (pytest exited at
configuration with the documented usage error).

## Malware timer regression

The separate `fix/malware-bound-timer` branch injects a monotonic clock into project malware
scanning; the production default remains `time.monotonic`. The per-file bound test advances a fake
clock without sleeps or a tiny real timeout. The malware project test file passed 50 consecutive
runs. Full backend acceptance passed 423 tests with 5 deselected and 81.53% total coverage; Ruff
check/format and strict mypy passed. PR #18 is open against `main`, ready for review, and all
reported CI checks passed.
