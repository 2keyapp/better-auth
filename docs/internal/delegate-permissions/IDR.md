{/* cspell:ignore FQHN SPKI */}

# Delegate Permissions — IDR tenant notes

Catalog: `@2key/catalog-idr` (`2keyapp/2key-core-sdk`). Commercial packages: Billing `IDR_BILLING_PACKAGES.md`.

## Entity packages

| DP `package`         | Billing SKU             | Source AuthN               | Notes                                                              |
| -------------------- | ----------------------- | -------------------------- | ------------------------------------------------------------------ |
| `personal`           | `idr_personal_bundle`   | mTLS required              | Same-entity AuthZ; `host--email`; ≤5 **devices** (Source + Target) |
| `enterprise`         | `idr_enterprise_bundle` | mTLS required              | Hierarchy, multi-admin, ZA, SCIM; ≤5 devices (Source + Target)     |
| *(Target seat flag)* | `idr_sp_target`         | Anonymous Sources **only** | No Source enroll; per-Target seat                                  |

FQHN / locator store form: `{host}--{entity}` (DEF RFC v2 structural `--`). Host path unique **per entity**.

## CSR enrollment inbox (generic)

Kinds on `enroll-create` / `enroll-instant` (`kind` or legacy `role`):

| Kind                        | Host                    | Zone     | Seat | Packages                          |
| --------------------------- | ----------------------- | -------- | ---- | --------------------------------- |
| `machine_target` (`target`) | required `host--entity` | —        | yes  | all                               |
| `machine_source` (`source`) | required                | —        | yes  | personal, enterprise (**not** SP) |
| `zone_authority`            | —                       | required | no   | enterprise                        |
| `interim_admin`             | —                       | —        | no   | enterprise                        |

Flow:

1. Device/sub-admin: keygen + PKCS#10 CSR (private key never leaves device).
2. `POST /delegate-permissions/enroll-create` → server **parses/verifies** CSR, stores `csrPem` (`pending`).
3. Admin: `enroll-list` → sign leaf with Entity CA (SPKI must match CSR) + CapabilityCredential → `enroll-approve`.
4. Platform CA **X.509-signs** an endorsement leaf (`cosignLeafCert` → `platformCertPem`); machines also `cosignMachine` + `seatBinder`.
5. Device: `enroll-pull` → DeviceIdentity (`certPem` + `chainPem` + `platformCertPem` + `platformRootPem` + credential).
6. **Localhost**: `enroll-instant` when admin CA keys are on the same host.

**HAProxy litmus:** `GET /delegate-permissions/platform-root` is the single `ca-file`. The device presents `platformCertPem` (Platform-endorsed leaf). Production: `delegatePermissions({ serviceId: "idr", seed: CATALOG_SEED, platformCa, seatBinder, cosign, onEntityKickstart })` — `platformCa` must be a **stable** tenant key. `seed: "demo"` already wires a demo Platform CA so local enroll works without extra config.

## seatBinder

On machine enroll-approve / issue-machine, Billing allocates a **device seat** for `role: target | source` (combined quota). Presence denies unbound Targets via agent-token mint.
