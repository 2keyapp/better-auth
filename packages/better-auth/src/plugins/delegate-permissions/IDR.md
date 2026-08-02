# Delegate Permissions — IDR tenant notes

Catalog: `@2key/catalog-idr` (`2keyapp/dp-sdk`). Commercial packages: Billing `IDR_BILLING_PACKAGES.md`.

## Entity packages

| DP `package` | Billing SKU | Source AuthN | Notes |
|--------------|-------------|--------------|-------|
| `personal` | `idr_personal_bundle` | mTLS required | Same-entity AuthZ; single-label hosts; ≤5 Target seats |
| `enterprise` | `idr_enterprise_bundle` | mTLS required | Hierarchy, multi-admin, ZA, SCIM; separate paying vs using |
| *(Target seat flag)* | `idr_sp_target` | Anonymous Sources **allowed** | Service Provider is a **Target commercial package**, not a third EntityPackage |

Wire `delegatePermissions({ serviceId: "idr", seed: CATALOG_SEED, seatBinder })` for machine credential issue → Billing `machine_seats`.

## seatBinder

On machine credential issue, call Billing allocate/bind so Presence can deny `device_unbound` when no active seat exists for the host/SKI.
