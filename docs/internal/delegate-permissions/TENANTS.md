# Platform tenants (Auth view)

Better Auth `delegate-permissions` is **product-neutral**. Tenant action/profile seeds live in `2keyapp/2key-core-sdk/catalogs/<slug>` and are passed as `seed: CatalogSeed` at deploy time — not as built-in plugin string shortcuts (except `"demo"` for tests).

Canonical registry: [`2keyapp/2key-core-sdk` TENANTS.md](https://github.com/2keyapp/2key-core-sdk/blob/main/TENANTS.md).

| Slug         | Display    | Catalog package            | Notes                                    |
| ------------ | ---------- | -------------------------- | ---------------------------------------- |
| `demo`       | Demo       | `@2key/catalog-demo`       | Built-in plugin alias `"demo"` for tests |
| `scomm`      | Scomm      | `@2key/catalog-scomm`      | Auth + Billing model **TBD**             |
| `idr`        | IDR        | `@2key/catalog-idr`        | Auth + Billing model **TBD**             |
| `os20`       | OS20       | `@2key/catalog-os20`       | Auth + Billing model **TBD**             |
| `stemsketch` | StemSketch | `@2key/catalog-stemsketch` | Auth + Billing model **TBD**             |
| `mnms`       | MnMs       | `@2key/catalog-mnms`       | Auth + Billing model **TBD**             |

```ts
import { CATALOG_SEED, SERVICE_ID } from "@2key/catalog-idr";

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
