# workflows

Reusable GitHub Actions workflows for solhann.net apps.

- **`deploy.yml`** — the deploy pipeline every app repo calls. App repos carry
  only a thin caller (`uses: sol-apps/workflows/.github/workflows/deploy.yml@main`,
  `secrets: inherit`); the actual pipeline lives here, once.
- **`greenlight/pr-verifier/`** — the immutable, permissionless pull-request
  verifier used by public app repositories. Callers pin a full commit SHA.
- **`greenlight/app-template/`** — the canonical template snapshot consumed by
  that same pinned verifier commit. It contains no credentials or production data.

This repo must stay **public**: reusable workflows in a public repo are the only
kind callable from the (public) app repos on the free org plan. Keep anything
sensitive in org secrets/variables, never in this repo. The verifier bundle is
published here for the same reason; a public workflow cannot resolve an action or
download a template snapshot from the private platform repository.
