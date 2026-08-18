# Delegate Permissions — IDR tenant notes

Catalog: `@2key/catalog-idr` (`2keyapp/dp-sdk`). Commercial packages: Billing `IDR_BILLING_PACKAGES.md`.

## Entity packages

| DP `package` | Billing SKU | Source AuthN | Notes |
|--------------|-------------|--------------|-------|
| `personal` | `idr_personal_bundle` | mTLS required | Same-entity AuthZ; `host--email`; ≤5 **devices** (Source + Target) |
| `enterprise` | `idr_enterprise_bundle` | mTLS required | Hierarchy, multi-admin, ZA, SCIM; ≤5 devices (Source + Target) |
| *(Target seat flag)* | `idr_sp_target` | Anonymous Sources **only** | No Source enroll; per-Target seat |

FQHN / locator store form: `{host}--{entity}` (DEF RFC v2 structural `--`). Host path unique **per entity**.

## CSR enrollment inbox (generic)

Kinds on `enroll-create` / `enroll-instant` (`kind` or legacy `role`):

| Kind | Host | Zone | Seat | Packages |
|------|------|------|------|----------|
| `machine_target` (`target`) | required `host--entity` | — | yes | all |
| `machine_source` (`source`) | required | — | yes | personal, enterprise (**not** SP) |
| `zone_authority` | — | required | no | enterprise |
| `interim_admin` | — | — | no | enterprise |

Flow:

1. Device/sub-admin: keygen + PKCS#10 CSR (private key never leaves device).
2. `POST /delegate-permissions/enroll-create` → server stores `csrPem` (`pending`).
3. Admin: `enroll-list` → sign leaf + CapabilityCredential → `enroll-approve`.
4. Platform CA **X.509-signs** an endorsement leaf (`cosignLeafCert` → `platformCertPem`); machines also `cosignMachine` + `seatBinder`.
5. Device: `enroll-pull` → DeviceIdentity (`certPem` + `chainPem` + `platformCertPem` + `platformRootPem` + credential).
6. **Localhost**: `enroll-instant` when admin CA keys are on the same host.

Wire `delegatePermissions({ serviceId: "idr", seed: CATALOG_SEED, seatBinder, cosign, onEntityKickstart })`.

## seatBinder

On machine enroll-approve / issue-machine, Billing allocates a **device seat** for `role: target | source` (combined quota). Presence denies unbound Targets via agent-token mint.
