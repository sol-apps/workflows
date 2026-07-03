# workflows

Reusable GitHub Actions workflows for solhann.net apps.

- **`deploy.yml`** — the deploy pipeline every app repo calls. App repos carry
  only a thin caller (`uses: sol-apps/workflows/.github/workflows/deploy.yml@main`,
  `secrets: inherit`); the actual pipeline lives here, once.

This repo must stay **public**: reusable workflows in a public repo are the only
kind callable from the (public) app repos on the free org plan. Keep anything
sensitive in org secrets/variables, never in this repo.
