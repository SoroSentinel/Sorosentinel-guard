# Security Policy

## Status

SoroSentinel Guard is pre-release and **has not been audited**. Do not rely on it to protect funds.

## Reporting a vulnerability

Please do not open a public issue, PR or discussion for a vulnerability.

Report privately through GitHub: **Security** tab → **Report a vulnerability** (private vulnerability reporting), or email TODO-security-contact.

Include:

- A description of the issue and its impact
- Steps or an input that reproduces it (a minimal XDR, WASM or request)
- The commit or version you tested

We aim to acknowledge reports within TODO business days and to agree on a disclosure date with you. Please give us reasonable time to fix the issue before disclosing it.

## Scope

In scope:

- Anything that makes SoroSentinel report a clean result for input it did not fully analyze
- Crashes, hangs or resource exhaustion from hostile input (XDR, WASM, `stellar.toml`, API requests)
- The XDR decoder and anything that could make Guard report fewer findings than a transaction warrants.
- Leaks of private data or keys, or bypasses of the public-wording controls

Out of scope:

- Findings in third-party dependencies with no demonstrated impact on this project (report those upstream)
- Social engineering, physical attacks, and denial of service by volume against hosted infrastructure
- Disagreements with a signal about a specific asset or account: use the review process instead

## Safe harbor

Good-faith research that follows this policy, avoids privacy violations and service disruption, and does not touch other users' funds will not be pursued.
