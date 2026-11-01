<!-- GENERATED: edit sorosentinel-intel/docs/adr/0008-docs-site-github-pages.md, then run scripts/sync-docs.sh. -->

# ADR 0008: the documentation site is GitHub Pages, built from `docs/site/` by a workflow

Status: proposed — the merge and the Pages source selection are the owner's ·
Date: 2026-11-01 · Decided by: open

## Context

The playbook and issue #57 both ask for a documentation site with a URL. The
content is already written and merged: `docs/site/` holds an index, a status
page, a snapshot-verification page and three reference pages (Guard's finding
codes, Intel's public signal names, Scan's indicators), configured with
`_config.yml` for Jekyll and `jekyll-theme-minimal`.

Nothing serves it, and the obvious route is blocked by a path detail. GitHub
Pages' "deploy from branch" mode can only publish the repository root or the
top-level `/docs` folder. This site is `docs/site/`, deliberately, because the
PRD, `ARCHITECTURE.md`, the nine runbooks and the ADRs already live under
`docs/` and every cross-repo link points at them. Moving the site to `/docs`
would either publish those working documents as a public site or break the
links; moving it to the root would collide with the repo's own README.

So the remaining step is a build pipeline, not writing.

## Decision (proposed)

1. Publish with a workflow, `.github/workflows/docs-pages.yml`, using only
   actions from the `actions` organization, each pinned to a full commit SHA
   the way `ci.yml` and `scorecard.yml` already pin theirs:
   `checkout` v7.0.1, `configure-pages` v6.0.0, `jekyll-build-pages` v1.0.13
   (`source: ./docs/site`, `destination: ./_site`), `upload-pages-artifact`
   v5.0.0, `deploy-pages` v5.0.1.
2. **No Gemfile and no new product dependency.** The build runs the
   `github-pages` gem, and `jekyll-theme-minimal` is one of its runtime
   dependencies (checked against rubygems for github-pages 232 on 2026-11-01),
   so `_config.yml` resolves without extra packages.
3. Triggers: push to `main` touching `docs/site/**` or the workflow itself,
   plus `workflow_dispatch`. Permissions are the minimum Pages needs —
   `contents: read`, `pages: write`, `id-token: write` — with `pull-request`
   deliberately absent, so no fork can run the deploy path and no workflow
   reads a secret or a signing key.
4. The owner sets Settings → Pages → Source to **GitHub Actions** once, and
   fills the repo homepage field with the URL Pages assigns.

## Consequences

- Until step 4 happens, the deploy job fails with "Pages is not enabled" while
  the build job stays green. That is the intended signal. Do not "fix" it by
  dropping the deploy job or by moving the site.
- When it is live, the two `docker-compose.yml` placeholders that default to
  `github.com/blob` URLs — `INTEL_METHODOLOGY_URL` and `INTEL_REVIEW_URL` — get
  real page URLs, which is what makes every published statement's methodology
  and review links readable by a wallet user rather than pointing into source
  control.
- Issue #57 closes, and the submission text can carry a docs link. The URL is
  assigned by Pages; nothing in this repo or these docs should quote one before
  it resolves.
- The site is public prose about a security product, so it is subject to the
  same rules as the API: AGENTS.md §5's blocklist lint and template discipline
  apply to it, and `docs/site/status.md` carries a measurement date because a
  status page that ages silently becomes an overstatement.
