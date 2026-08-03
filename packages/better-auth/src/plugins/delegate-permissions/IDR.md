# Delegate Permissions — IDR tenant notes

Catalog: `@2key/catalog-idr` (`2keyapp/dp-sdk`). Commercial packages: Billing `IDR_BILLING_PACKAGES.md`.

## Entity packages

| DP `package` | Billing SKU | Source AuthN | Notes |
|--------------|-------------|--------------|-------|
| `personal` | `idr_personal_bundle` | mTLS required | Same-entity AuthZ; single-label hosts; ≤5 Target seats |
| `enterprise` | `idr_enterprise_bundle` | mTLS required | Hierarchy, multi-admin, ZA, SCIM; separate paying vs using |
| *(Target seat flag)* | `idr_sp_target` | Anonymous Sources **allowed** | Service Provider is a **Target commercial package**, not a third EntityPackage |

## Machine enrollment (CSR)

1. Device CLI: `identity init` → on-device Ed25519 key + PKCS#10 CSR (private key never leaves device).
2. `identity enroll` → `POST /delegate-permissions/enroll-create` (pending queue).
3. PKI admin (within `cert.issue` / `machine.bind` space): sign leaf with Entity CA + CapabilityCredential → `enroll-approve`.
4. Platform **co-signs** Entity CA root (kickstart) and every machine leaf (`cosignCaCert` / `cosignLeafCert`).
5. Device: `identity pull` → DeviceIdentity with `certPem` + `chainPem` + credential.
6. **Localhost**: when admin CA keys are on the same host as the machine, `identity enroll --local` calls `enroll-instant` (generate + sign + accept in one step).

Wire `delegatePermissions({ serviceId: "idr", seed: CATALOG_SEED, seatBinder, cosign, onEntityKickstart })` so kickstart publishes Entity CA PEM to Presence `target_ca_roots`.

## seatBinder

On machine credential issue / enroll-approve, call Billing allocate/bind so Presence can deny `device_unbound` when no active seat exists for the host/SKI.
