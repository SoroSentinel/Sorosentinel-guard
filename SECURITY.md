# Security Policy

## Status

SoroSentinel Guard is pre-release and **has not been audited**. Do not rely on it to protect funds.

## Reporting a vulnerability

Please do not open a public issue, PR or discussion for a vulnerability.

Report it privately through GitHub's private vulnerability reporting:
<https://github.com/SoroSentinel/Sorosentinel-guard/security/advisories/new>
(the **Security** tab → **Report a vulnerability**). If you cannot use GitHub, email TODO-security-contact.

Include:

- A description of the issue and its impact
- Steps or an input that reproduces it (a minimal XDR, WASM or request)
- The commit or version you tested

## Disclosure process

1. **Acknowledge:** we confirm receipt within 5 business days.
2. **Assess:** we reproduce the issue, agree its severity with you, and keep you updated at least every 14 days.
3. **Fix:** we prepare the fix in a private security advisory and, where possible, invite you to review it.
4. **Disclose:** we publish the advisory, request a CVE where appropriate, and credit you unless you ask us not to.

We aim to release a fix and disclose within 90 days of the report, earlier if a fix ships sooner. If the issue is being exploited, or the 90 days pass without a fix, we will agree on an earlier or later date with you. Please do not disclose before the agreed date.

Only the latest commit on `main` is supported while the project is pre-release.

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
