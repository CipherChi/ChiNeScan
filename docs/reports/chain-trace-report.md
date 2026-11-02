# Chain trace hardening report

## Scope

The on-chain tracing implementation supports offline explorer imports, local provenance-bearing
labels, graph exports, investigative heuristic findings, and optional Etherscan-family lookup.
Heuristic findings are leads, never proof of ownership or attribution.

## Finding detail and report quality

Repeated coverage gaps are grouped by code with an occurrence count and a representative chain-trace
example. Heuristic descriptions report their trigger counts, time windows or thresholds, and up to ten
supporting transaction hashes. Share summaries truncate wallet addresses and omit transaction
references.

Default lead severity is LOW for `fan_out`, `fan_in`, `first_funder`, `peel_chain`, and
`rapid_pass_through`; MEDIUM for `address_poisoning`, `cash_out`, `mixer_exposure`, and
`drainer_pattern`; and HIGH for `sanctioned_exposure`. Exchange, bridge, or router counterparty
labels lower medium findings to LOW and confidence to POSSIBLE, with the label context stated in the
description. A label only documents its local source and date; it does not establish identity or
attribution. Heuristic false positives include exchanges, custodians, and CoinJoin activity.

Example local label JSON (schema illustration only; it asserts no real attribution):

```json
{
  "labels": [
    {
      "address": "<wallet-address>",
      "chain": "ethereum",
      "category": "exchange",
      "name": "Example service",
      "source": "operator sample",
      "date": "2026-01-01"
    }
  ]
}
```

`source` and `date` are required for every label. Supported categories include `exchange`, `bridge`,
`router`, `mixer`, `sanctioned`, `scam`, and `other`.

## Network policy

- Network access is disabled by default. CLI lookup requires `--allow-network-chain`; web lookup
  requires both request opt-in and the server's `chain_network_enabled` setting.
- Built-in EVM chains use the `api.etherscan.io` host allowlist. Custom registry endpoints require
  HTTPS, public DNS results, no user information, and port 443 unless configured otherwise.
- Redirects are limited to two HTTPS hops on the original host. The transport disables environment
  proxies, resolves and checks addresses again before connecting, pins the validated address, and
  uses a bounded daemon resolver pool with a two-second timeout.
- Built-in Etherscan-family EVM chains use API V2 (`https://api.etherscan.io/v2/api`) with the
  registry's numeric `chain_id` parameter. Other EVM chains can be added through registry TOML.
- The Etherscan API key is read from its configured environment variable and sent in the POST body
  only inside the transport adapter. It is not stored in records or returned by APIs or diagnostics.
- Provider error payloads map to `rate_limited`, `invalid_api_key`, or `provider_error` with a short
  redacted reason. “No transactions found” is an empty result with no coverage gap.
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
