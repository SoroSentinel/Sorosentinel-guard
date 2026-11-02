# Changelog

All notable changes to this repository. Versions follow [Semantic Versioning](https://semver.org/); until 1.0, minor versions may add findings and patch versions fix bugs.

## [Unreleased]

- Code of conduct and changelog.
- README and CONTRIBUTING: removed dead community links.

## [0.1.0] - 2026-11-01

First release. Not yet published to npm.

- `analyze()` decodes exactly the bytes being signed, including fee-bump envelopes, per-operation sources and muxed accounts.
- Worst-case balance and account effects per affected account (`delta_min`, `delta_max`, `assurance`), in integer stroops.
- `analyzeAsync()` adds Soroban simulation through the caller's RPC endpoint, with a timeout.
- Client-side verification of Intel's signed snapshot, a stale-data state, and an opt-in Intel API fallback.
- Findings: `G-ACCOUNT-CONTROL`, `G-SIGNER-ADDED`, `G-NO-EXPIRY`, `G-NETWORK-UNKNOWN`, `G-MEMO-REQUIRED`, `G-DEST-FLAGGED`, `G-TRUST-FLAGGED`, `G-CONTRACT-FLAGGED`.
- SEP-43 signature replies checked against the analyzed entry.
- Untrusted strings sanitized before display. Statuses are `findings_present`, `no_issues_found`, `partial` or `unanalyzable`, never "safe".
- Latency benchmark (`make bench`) and the E2 replay harness over 12,000+ testnet transactions.

[Unreleased]: https://github.com/SoroSentinel/Sorosentinel-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SoroSentinel/Sorosentinel-guard/releases/tag/v0.1.0
