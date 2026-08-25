# Upstream sync (2key fork)

This fork tracks [better-auth/better-auth](https://github.com/better-auth/better-auth).

## Remotes

```bash
git remote -v
# origin    → 2keyapp/better-auth
# upstream  → better-auth/better-auth
```

If `upstream` is missing:

```bash
git remote add upstream https://github.com/better-auth/better-auth.git
```

## Manual sync

```bash
git fetch upstream
git checkout main
git merge upstream/main
# resolve conflicts — prefer isolating 2key code under packages/native, packages/clients, packages/scim
pnpm install
pnpm typecheck
pnpm --filter @2key/auth-native test
cd packages/clients/dart && dart test
```

Open a PR titled `chore: sync upstream better-auth` with notes on conflicts.

## Automated workflow

`.github/workflows/upstream-sync.yml` (scheduled + manual) fetches upstream,
opens a PR when `main` is behind, and runs package filters for native + core.

## Patch discipline

1. Prefer **new packages** (`packages/native`, `packages/clients/*`, `packages/scim`) over editing upstream files.
2. If core must change: minimal patch + document in the PR.
3. Never implement billing usage / mTLS product logic in this fork.

## Release tips after sync

```bash
pnpm run release:branch   # refreshes release, release-scim, release-native
```

Consumers pin `#release*` tips — never floating `#main` for npm git deps.
