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
- All redirects are refused to prevent the API-key POST body from being forwarded to another path
  or host. The transport disables environment proxies, checks every resolved address, pins the
  validated address, preserves TLS hostname verification, and uses at most four bounded daemon DNS
  workers with a two-second resolver timeout.
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

## Verification status

- Review date: 2026-11-02.
- No live provider request was made during this review. A previous Ethereum-only Etherscan V2 smoke
  test is mentioned in task history, but no checked-in artifact independently supports that claim.
- Other configured EVM chains are configured in the registry but have not been tested live.
- Non-EVM chains are supported through offline import only; live provider lookups are not
  configured for them.
- Network lookups are off by default and require explicit operator authorization.
- Findings are investigative leads, not proof of ownership or attribution.
- Tested offline: endpoint authority and address validation (including mixed DNS and IPv4/IPv6
  special ranges), redirect refusal for 301/302/303/307/308, API-key containment and error mapping,
  response size/content type/JSON handling, retry bounds, report redaction with 25 identifiers, and
  the CLI label-file path with synthetic fixture addresses and provenance. Diagnostics are covered
  by a separate test that checks only enabled/configured booleans are exposed.
- Untested live: every EVM chain and every non-EVM network provider. The non-EVM network provider is
  not implemented; those chains use offline import only.
- Local verification: Ruff passed, strict mypy passed, backend pytest reported 506 passed and 5
  deselected, frontend typecheck passed, and frontend Vitest reported 50 passed. The five deselected
  backend tests are opt-in real-scanner integration tests; no chain-trace security test was skipped.
