# Platform tenants (Auth view)

Better Auth `delegate-permissions` is **product-neutral**. Tenant action/profile seeds live in `2keyapp/2key-browser-sdk/catalogs/<slug>` and are passed as `seed: CatalogSeed` at deploy time — not as built-in plugin string shortcuts (except `"demo"` for tests).

Canonical registry: [`2keyapp/2key-browser-sdk` docs/TENANTS.md](https://github.com/2keyapp/2key-browser-sdk/blob/main/docs/TENANTS.md).

| Slug         | Display         | Catalog package            | Notes                                                            |
| ------------ | --------------- | -------------------------- | ---------------------------------------------------------------- |
| `demo`       | Demo            | `@2key/catalog-demo`       | Built-in plugin alias `"demo"` for tests                         |
| `scomm`      | Scomm Workflows | `@2key/catalog-scomm`      | Populated — channels + FSM documents; `authorize` then FSM PEP   |
| `idr`        | IDR             | `@2key/catalog-idr`        | Populated — Presence PEP; see catalog README                     |
| `os20`       | OS20            | `@2key/catalog-os20`       | Populated — API/registry PEP + Workbench advisory; DP algebra v2 |
| `stemsketch` | StemSketch      | `@2key/catalog-stemsketch` | Auth + Billing model **TBD**                                     |
| `mnms`       | MnMs            | `@2key/catalog-mnms`       | Populated — App-owner → Admin DevOps; multi-owner grant union    |

```ts
import { CATALOG_SEED, SERVICE_ID } from "@2key/catalog-scomm";

// Production: Platform CA is required (HAProxy ca-file).
delegatePermissions({
  serviceId: SERVICE_ID,
  seed: CATALOG_SEED,
  platformCa: {
    privateJwk: platformPrivateJwk,
    rootPem: platformRootPem,
  },
});

// Local tests only — `seed: "demo"` wires a built-in demo Platform CA.
delegatePermissions({ serviceId: "demo", seed: "demo" });
```
