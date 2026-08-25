
# GitHub release branches (DO NOT DELETE)

`main` is the **development monorepo** (`@better-auth/root`). It is **not** an installable package tip for npm/git consumers.

These branches are **packaging artifacts** produced by `.github/workflows/release-branch.yml` (`publish-release-branch.mjs`). Each tip is a standalone package root with `dist/` + `package.json`:

| Consumer dependency | Install tip (keep forever) |
| --- | --- |
| `better-auth` | `github:2keyapp/better-auth#release` |
| `@better-auth/flutter` | `github:2keyapp/better-auth#release-flutter` |
| `@better-auth/scim` | `github:2keyapp/better-auth#release-scim` |

**Never delete** `release`, `release-flutter`, or `release-scim`. Deleting them breaks every consumer that pins those refs (including `2key-billing`). Pinning `#main` also breaks installs because the monorepo root has no published `dist/` layout.

To refresh tips: push to `main` (workflow auto-runs) or `workflow_dispatch` **Publish release branch**. Do not recreate these as feature branches or merge them into `main`.
