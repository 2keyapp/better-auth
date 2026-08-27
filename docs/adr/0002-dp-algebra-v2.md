# ADR-0002: DP algebra v2 — path_prefix, semver, explicit deny

**Status:** Accepted  
**Date:** 2026-08-27  
**Applies to:** `@2key/dp-authorize`, `dp_rust::authorize`, Better Auth inlined `capability/*`, conformance fixtures

## Context

OS20 and other tenants need path-tree resource matching, version-range scope, and mandatory deny policy. The v1 algebras (`exact`, `dns_prefix`, `set`) and allow-only capabilities are insufficient without forking AuthZ outside the shared PEP.

## Decisions

### 1. `path_prefix` scope algebra

- Rightward path trees (segment-bounded): child ⊆ parent iff `child === parent` or `child.startsWith(parent + "/")`.
- Parent `""` covers all.
- Do **not** overload `dns_prefix` (leftward FQHN labels for IDR).

### 2. `semver` scope algebra

- Closed v1 grammar: exact, `N.x` / `N.M.x`, `^`, `~`, `>=A <B`.
- Authorize: exact version satisfies grant range(s).
- Attenuate: child range ⊆ parent range (interval inclusion).
- Prereleases fail closed unless the range is an exact prerelease match.

### 3. Explicit deny via `Capability.effect`

```text
Capability = { action, scope, delegable, effect? }
effect ∈ { allow, deny }  // omitted ⇒ allow
```

**Authorize precedence:** matching deny → `EXPLICIT_DENY`; else matching allow → ok; else `NOT_AUTHORIZED`.

**Attenuation:**

- Child allow must be ⊆ some delegable parent allow and must not overlap any parent deny (`DENY_OVERRIDE_VIOLATION`).
- Child deny must be ⊆ some delegable parent allow or deny (deny only inside held authority).

### 4. Sync rule unchanged

Edit `@2key/dp-authorize` first, then fixtures, Rust, and BA inlined copy together. Fixtures `version` field is `2`.

## Consequences

- New error codes: `EXPLICIT_DENY`, `DENY_OVERRIDE_VIOLATION`.
- Catalogs may declare `path_prefix` / `semver` dimensions; IDR/demo remain on v1 algebras until they opt in.
- Credential wire: optional `effect` on permissions; missing means allow.

## References

- Implementation: `2key-browser-sdk/packages/dp-authorize/`
- Fixtures: `conformance/dp-authz/fixtures.json`
- Prior: `docs/adr/0001-delegate-permissions.md`
