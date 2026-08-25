import { CapabilitySet } from "./capability/types.mjs";
import { CosignProvider, SeatBinder } from "./pki/types.mjs";
import { CatalogSeed } from "./seeds/types.mjs";

//#region src/plugins/delegate-permissions/types.d.ts
type DelegatePermissionsOptions = {
  /**
   * Service id for this app DB catalog.
   * @default "default"
   */
  serviceId?: string | undefined;
  /**
   * Seed catalog when empty. Pass `"demo"` for the built-in example seed
   * (includes a **demo** Platform CA so `GET /platform-root` works locally).
   * Production tenants pass a CatalogSeed and their own `platformCa`.
   */
  seed?: "demo" | CatalogSeed | undefined;
  /**
   * Allow `/delegate-permissions/seed-catalog` from clients.
   * @default false
   */
  allowClientSeed?: boolean | undefined;
  /**
   * Session grant lifetime in seconds.
   * @default 3600
   */
  sessionGrantExpiresIn?: number | undefined;
  /**
   * Default enroll-invite lifetime in seconds when the request omits `expiresIn`.
   * Capped by `inviteMaxExpiresIn`.
   * @default 604800 (7 days)
   */
  inviteExpiresIn?: number | undefined;
  /**
   * Maximum enroll-invite `expiresIn` in seconds.
   * @default 2592000 (30 days)
   */
  inviteMaxExpiresIn?: number | undefined;
  /**
   * Default enroll-invite redeem cap when the request omits `maxUses`.
   * `0` = unlimited until expiry.
   * @default 1
   */
  inviteMaxUses?: number | undefined;
  /**
   * Capability-credential lifetime in seconds when the plugin mints
   * credentials (kickstart, issue-delegate, issue-machine, enroll-approve).
   * @default 31536000 (365 days)
   */
  credentialExpiresIn?: number | undefined;
  /**
   * Self-signed Entity / Platform CA certificate lifetime in seconds.
   * Also used as the default Platform endorsement lifetime for Entity CAs.
   * @default 315360000 (3650 days)
   */
  caCertExpiresIn?: number | undefined;
  /**
   * Platform-endorsed machine leaf certificate lifetime in seconds.
   * @default 31536000 (365 days)
   */
  leafCertExpiresIn?: number | undefined;
  /**
   * Allow the server to generate Entity Root / subject keypairs during kickstart
   * (returns private JWKs once). Prefer client-held keys in production.
   * Also permits an ephemeral Platform CA when `platformCa` / `cosign` are omitted.
   * @default false
   */
  allowServerKeygen?: boolean | undefined;
  /**
   * Stable Platform CA material. HAProxy `ca-file` is `rootPem` (or the PEM
   * from `GET /delegate-permissions/platform-root`). Required in production.
   * `seed: "demo"` falls back to the built-in demo Platform CA when this is omitted.
   */
  platformCa?: {
    privateJwk: Record<string, unknown>; /** Persist this PEM so HAProxy's trust file is byte-stable. */
    rootPem?: string;
    commonName?: string;
  } | undefined;
  /**
   * Mint a throwaway Platform CA when `platformCa` and `cosign` are omitted.
   * Defaults to `allowServerKeygen`. Must be false in production.
   */
  allowEphemeralPlatformCa?: boolean | undefined;
  /**
   * Optional platform co-sign provider (root + machine). When omitted, the
   * plugin uses `platformCa` (or an ephemeral CA if allowed).
   */
  cosign?: CosignProvider | undefined;
  /**
   * Optional permanent machine seat binder (billing integration).
   */
  seatBinder?: SeatBinder | undefined;
  /**
   * Called after successful entity kickstart when an Entity CA cert is registered.
   */
  onEntityKickstart?: ((info: {
    entityId: string;
    package: "personal" | "enterprise";
    rootSki: string;
    caCertPem?: string;
    platformCaCertCosign?: {
      platformCertPem: string;
      platformRootPem: string;
    };
  }) => void | Promise<void>) | undefined;
};
type DpActionRow = {
  id: string;
  serviceId: string;
  action: string;
  description: string | null;
  catalogGeneration: number;
  createdAt: Date;
};
type DpScopeDimensionRow = {
  id: string;
  serviceId: string;
  dimension: string;
  algebra: string;
  catalogGeneration: number;
  createdAt: Date;
};
type DpProfileRow = {
  id: string;
  serviceId: string;
  profile: string;
  permissions: CapabilitySet;
  catalogGeneration: number;
  createdAt: Date;
};
type DpCatalogMetaRow = {
  id: string;
  serviceId: string;
  generation: number;
  updatedAt: Date;
};
type DpPrincipalGrantRow = {
  id: string;
  userId: string;
  entityId: string | null;
  permissions: CapabilitySet;
  profile: string | null;
  expiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};
type DpSessionGrantRow = {
  id: string;
  sessionId: string;
  userId: string;
  permissions: CapabilitySet;
  expiresAt: Date;
  createdAt: Date;
};
type DpEntityRow = {
  id: string;
  entityId: string;
  package: string;
  rootSki: string;
  caCertPem: string | null;
  platformCaCertCosign: Record<string, unknown> | null;
  ownerUserId: string;
  createdAt: Date;
  updatedAt: Date;
};
type DpCredentialRow = {
  id: string;
  ski: string;
  entityId: string;
  kind: string;
  publicJwk: Record<string, unknown>;
  credential: Record<string, unknown>;
  zone: string | null;
  host: string | null;
  seatId: string | null;
  status: string;
  revokedAt: Date | null;
  revokedReason: string | null;
  renewedBySki: string | null;
  createdAt: Date;
};
type DpNameOccupancyRow = {
  id: string;
  entityId: string;
  nameKey: string;
  kind: string;
  credentialSki: string;
  createdAt: Date;
};
type DpUserCredentialBindRow = {
  id: string;
  userId: string;
  credentialSki: string;
  entityId: string;
  isPrimary: boolean;
  createdAt: Date;
};
type DpRevocationReason = "decommissioned" | "key_compromise" | "machine_lost" | "replaced" | "organization_policy" | "renewed" | "other";
/** CSR inbox kinds — machines + zone/interim admin (server-stored pending CSR). */
type DpEnrollKind = "machine_target" | "machine_source" | "zone_authority" | "interim_admin" /** @deprecated use machine_target */ | "target" /** @deprecated use machine_source */ | "source";
/** Push-invite: admin authorizes a device to submit a CSR for this entity. */
type DpEnrollInviteRow = {
  id: string;
  entityId: string; /** Unused; machine name is chosen at enroll-create. */
  host: string;
  zone: string | null;
  role: string;
  inviteToken: string;
  expiresAt: Date; /** `0` = unlimited until expiresAt. Default 1. */
  maxUses: number;
  usedCount: number;
  consumedAt: Date | null;
  createdByUserId: string | null;
  createdAt: Date;
};
type DpEnrollRequestRow = {
  id: string;
  entityId: string; /** Full locator `host--entity` for machines; empty string for admin kinds. */
  host: string; /** Zone path for zone_authority; null otherwise. */
  zone: string | null; /** Enroll kind (role column; stores DpEnrollKind). */
  role: string;
  csrPem: string;
  subjectSki: string;
  publicJwk: Record<string, unknown>;
  status: string;
  pullToken: string;
  createdByUserId: string | null;
  leafPem: string | null;
  chainPem: string | null;
  credential: Record<string, unknown> | null;
  platformCertCosign: Record<string, unknown> | null;
  seatId: string | null;
  createdAt: Date;
  updatedAt: Date;
};
//#endregion
export { DelegatePermissionsOptions, DpActionRow, DpCatalogMetaRow, DpCredentialRow, DpEnrollInviteRow, DpEnrollKind, DpEnrollRequestRow, DpEntityRow, DpNameOccupancyRow, DpPrincipalGrantRow, DpProfileRow, DpRevocationReason, DpScopeDimensionRow, DpSessionGrantRow, DpUserCredentialBindRow };