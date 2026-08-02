# ADR-0001: Delegate Permissions (AuthZ + catalog + PKI path)

**Status:** Accepted (P0)\
**Date:** 2026-08-02\
**Applies to:** Better Auth fork (`delegate-permissions` plugin), multi-tenant Auth+Billing apps (one Postgres DB per app deployment)

## Context

Apps share one Auth+Billing codebase and Better Auth for AuthN, but each deployment has its own database and brings its own actions/scopes. We need a **generic AuthZ engine** based on **delegated permissions** (capability attenuation), with a later PKI path (Option B: CapabilitySet on certificates). Stock Better Auth `createAccessControl` is code-defined RBAC and is **not** the source of truth for this model.

## Decisions

### AuthN vs AuthZ

| Concern                             | Owner                                                           |
| ----------------------------------- | --------------------------------------------------------------- |
| Human AuthN (user/session/org/SCIM) | Better Auth                                                     |
| Device AuthN (cert chain)           | Later phases (`delegate-permissions` + CosignProvider)          |
| AuthZ                               | `delegate-permissions` capability engine                        |
| Billing entitlement                 | Billing module; compose as `capability AND entitlement` at PEPs |

### Catalog

* Actions and scope dimensions are **DB-configured per app** (`serviceId`).
* The **catalog schema/algebra** is code; each credential/grant carries only a **CapabilitySet instance** (subset of the catalog), never the full catalog.
* Catalog is versioned via `catalogGeneration`.

### Capability model

```text
Capability = { action, scope, delegable }
CapabilitySet = Capability[]
Scope = map of dimension → value (string | string[])
```

* Root / profile expansion yields the entity permission universe for that app package.
* **Attenuation:** every child grant must satisfy `child ⊆ parent` (action coverage + scope subset + `delegable` rules).
* A holder may set `delegable: false` even when the parent had `delegable: true`.

### Scope algebras (v1)

| Algebra      | Subset rule                                                              |
| ------------ | ------------------------------------------------------------------------ |
| `exact`      | child value === parent value                                             |
| `dns_prefix` | child === parent OR child ends with `.` + parent; parent `""` covers all |
| `set`        | every child member ∈ parent set                                          |

Missing dimension on a grant means **unrestricted** for that dimension (parent ALL). Child may narrow.

### Action coverage (v1)

* Exact match, or
* Grant action `foo.*` covers `foo.bar` (single trailing wildcard segment style: prefix before `.*`)

### PKI (v1 direction, not in P0/P1)

* **Option B:** zone/permissions live on the certificate; API stores occupancy, revocation, seats.
* Name is **ZA or Machine, never both**; no `.admin--` host-name markers.
* Host optional for ZA/interim admin; Machine fully-qualified host name required.
* Platform authority co-signs Entity Root + Machine leaf; Machine binds permanent billing seat (later).

### Plugin identity

* Plugin id: `delegate-permissions`
* Distinct from OAuth `device-authorization` plugin

### Multi-tenancy

* One app deployment = one DB (merchant/app isolation).
* Same plugin code; different catalog seeds/rows per DB.

## Error codes (stable)

| Code                      | Meaning                             |
| ------------------------- | ----------------------------------- |
| `CATALOG_NOT_SEEDED`      | No catalog rows for service         |
| `UNKNOWN_ACTION`          | Action not in catalog               |
| `UNKNOWN_SCOPE_DIMENSION` | Dimension not in catalog            |
| `SUBSET_VIOLATION`        | Child grants not ⊆ parent           |
| `NOT_AUTHORIZED`          | authorize() denied                  |
| `NO_PRINCIPAL_GRANT`      | User has no principal CapabilitySet |
| `NO_SESSION_GRANT`        | Session has no issued capabilities  |
| `GRANT_EXPIRED`           | Grant past expiresAt                |
| `INVALID_CAPABILITY_SET`  | Malformed permissions payload       |
| `SEED_DISABLED`           | Seeding not configured/allowed      |

## Consequences

* P1 implements catalog + algebra + session grants + plugin endpoints.
* P2–P4 add kickstart (Entity Root + Root Admin), zone/interim issue with name occupancy, machine issue + platform cosign + billing `machine_seats` binder.
* Org RBAC (`organization` plugin) may remain for coarse UI; it must not replace CapabilitySets.
* Tenant PEPs and client SDKs (`dp-sdk`) consume the same pure algebra / credential verify exports. Product catalogs (actions/profiles) are tenant-supplied, not hard-coded in the plugin.

## References

* Implementation: `packages/better-auth/src/plugins/delegate-permissions/`
* Billing: merchant-per-DB model; machine seats deferred to P4 (`billing/DECISIONS.md`)
