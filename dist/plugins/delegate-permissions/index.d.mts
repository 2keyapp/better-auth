import { actionCovers } from "./capability/action.mjs";
import { ActionDef, AuthorizeResult, Capability, CapabilitySet, Catalog, ProfileDef, Resource, ScopeAlgebra, ScopeDimensionDef, ScopeMap, SubsetResult } from "./capability/types.mjs";
import { authorize } from "./capability/authorize.mjs";
import { expandProfile } from "./capability/expand.mjs";
import { dnsPrefixSubset, resourceSatisfiesScope, scopeMapSubset, scopeValueSubset } from "./capability/scope.mjs";
import { assertSubset } from "./capability/subset.mjs";
import { PlatformCertCosign, attachPlatformCertCosign, verifyPlatformCertCosign } from "./pki/cert-cosign.mjs";
import { PlatformCaMaterial, PlatformCertIssue, createPlatformRootPem, createSelfSignedCaPem, generateEphemeralPlatformCa, issuePlatformEndorsementCert, loadPlatformCaMaterial, verifyAgainstTrustAnchor } from "./pki/platform-ca.mjs";
import { CapabilityCredential, CosignProvider, EntityPackage, SeatBinder } from "./pki/types.mjs";
import { attachPlatformCosign, issueCredential, verifyCredentialSignature } from "./pki/credential.mjs";
import { bindCsrToPublicJwk, createDeviceCsr, leafMatchesCsr, signCsrWithCa } from "./pki/csr.mjs";
import { generateEd25519KeyPair } from "./pki/keys.mjs";
import { CatalogSeed } from "./seeds/types.mjs";
import { DEMO_CATALOG_SEED, DEMO_SERVICE_ID } from "./seeds/demo.mjs";
import { DEMO_PLATFORM_CA } from "./seeds/demo-platform-ca.mjs";
import { DelegatePermissionsOptions, DpActionRow, DpCatalogMetaRow, DpCredentialRow, DpEnrollKind, DpEnrollRequestRow, DpEntityRow, DpNameOccupancyRow, DpPrincipalGrantRow, DpProfileRow, DpRevocationReason, DpScopeDimensionRow, DpSessionGrantRow, DpUserCredentialBindRow } from "./types.mjs";
import { DELEGATE_PERMISSIONS_ERROR_CODES } from "./error-codes.mjs";
import { schema } from "./schema.mjs";
import * as _better_auth_core_db0 from "@better-auth/core/db";
import * as better_call0 from "better-call";
import * as z from "zod";

//#region src/plugins/delegate-permissions/index.d.ts
declare module "@better-auth/core" {
  interface BetterAuthPluginRegistry<AuthOptions, Options> {
    "delegate-permissions": {
      creator: typeof delegatePermissions;
    };
  }
}
/**
 * Delegate Permissions plugin.
 *
 * Production mTLS: set `platformCa` (stable key). The TLS terminator `ca-file`
 * is the Platform Root from `GET /delegate-permissions/platform-root`. Machine
 * leaves are Platform-endorsed (`platformCertPem` on enroll-pull).
 * `seed: "demo"` includes a demo Platform CA — do not use that key in production.
 */
declare const delegatePermissions: (options?: DelegatePermissionsOptions) => {
  id: "delegate-permissions";
  version: string;
  options: DelegatePermissionsOptions | undefined;
  schema: {
    dpCatalogMeta: {
      fields: {
        serviceId: {
          type: "string";
          required: true;
          unique: true;
        };
        generation: {
          type: "number";
          required: true;
          defaultValue: number;
        };
        updatedAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpAction: {
      fields: {
        serviceId: {
          type: "string";
          required: true;
          index: true;
        };
        action: {
          type: "string";
          required: true;
        };
        description: {
          type: "string";
          required: false;
        };
        catalogGeneration: {
          type: "number";
          required: true;
        };
        createdAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpScopeDimension: {
      fields: {
        serviceId: {
          type: "string";
          required: true;
          index: true;
        };
        dimension: {
          type: "string";
          required: true;
        };
        algebra: {
          type: "string";
          required: true;
        };
        catalogGeneration: {
          type: "number";
          required: true;
        };
        createdAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpProfile: {
      fields: {
        serviceId: {
          type: "string";
          required: true;
          index: true;
        };
        profile: {
          type: "string";
          required: true;
        };
        permissions: {
          type: "json";
          required: true;
          transform: {
            input(value: _better_auth_core_db0.DBPrimitive): string | number | boolean | Date | Record<string, unknown> | null | undefined;
            output(value: _better_auth_core_db0.DBPrimitive): _better_auth_core_db0.DBPrimitive;
          };
        };
        catalogGeneration: {
          type: "number";
          required: true;
        };
        createdAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpPrincipalGrant: {
      fields: {
        userId: {
          type: "string";
          required: true;
          index: true;
          references: {
            model: string;
            field: string;
          };
        };
        entityId: {
          type: "string";
          required: false;
        };
        permissions: {
          type: "json";
          required: true;
          transform: {
            input(value: _better_auth_core_db0.DBPrimitive): string | number | boolean | Date | Record<string, unknown> | null | undefined;
            output(value: _better_auth_core_db0.DBPrimitive): _better_auth_core_db0.DBPrimitive;
          };
        };
        profile: {
          type: "string";
          required: false;
        };
        expiresAt: {
          type: "date";
          required: false;
        };
        createdAt: {
          type: "date";
          required: true;
        };
        updatedAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpSessionGrant: {
      fields: {
        sessionId: {
          type: "string";
          required: true;
          unique: true;
          index: true;
          references: {
            model: string;
            field: string;
          };
        };
        userId: {
          type: "string";
          required: true;
          index: true;
          references: {
            model: string;
            field: string;
          };
        };
        permissions: {
          type: "json";
          required: true;
          transform: {
            input(value: _better_auth_core_db0.DBPrimitive): string | number | boolean | Date | Record<string, unknown> | null | undefined;
            output(value: _better_auth_core_db0.DBPrimitive): _better_auth_core_db0.DBPrimitive;
          };
        };
        expiresAt: {
          type: "date";
          required: true;
        };
        createdAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpEntity: {
      fields: {
        entityId: {
          type: "string";
          required: true;
          unique: true;
        };
        package: {
          type: "string";
          required: true;
        };
        rootSki: {
          type: "string";
          required: true;
        };
        caCertPem: {
          type: "string";
          required: false;
        };
        platformCaCertCosign: {
          type: "json";
          required: false;
        };
        ownerUserId: {
          type: "string";
          required: true;
          index: true;
          references: {
            model: string;
            field: string;
          };
        };
        createdAt: {
          type: "date";
          required: true;
        };
        updatedAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpCredential: {
      fields: {
        ski: {
          type: "string";
          required: true;
          unique: true;
        };
        entityId: {
          type: "string";
          required: true;
          index: true;
        };
        kind: {
          type: "string";
          required: true;
        };
        publicJwk: {
          type: "json";
          required: true;
        };
        credential: {
          type: "json";
          required: true;
        };
        zone: {
          type: "string";
          required: false;
        };
        host: {
          type: "string";
          required: false;
        };
        seatId: {
          type: "string";
          required: false;
        };
        status: {
          type: "string";
          required: true;
          defaultValue: string;
        };
        revokedAt: {
          type: "date";
          required: false;
        };
        revokedReason: {
          type: "string";
          required: false;
        };
        renewedBySki: {
          type: "string";
          required: false;
        };
        createdAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpUserCredentialBind: {
      fields: {
        userId: {
          type: "string";
          required: true;
          index: true;
          references: {
            model: string;
            field: string;
          };
        };
        credentialSki: {
          type: "string";
          required: true;
          index: true;
        };
        entityId: {
          type: "string";
          required: true;
          index: true;
        };
        isPrimary: {
          type: "boolean";
          required: true;
          defaultValue: true;
        };
        createdAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpNameOccupancy: {
      fields: {
        entityId: {
          type: "string";
          required: true;
          index: true;
        };
        nameKey: {
          type: "string";
          required: true;
        };
        kind: {
          type: "string";
          required: true;
        };
        credentialSki: {
          type: "string";
          required: true;
        };
        createdAt: {
          type: "date";
          required: true;
        };
      };
    };
    dpEnrollRequest: {
      fields: {
        entityId: {
          type: "string";
          required: true;
          index: true;
        };
        host: {
          type: "string";
          required: false;
        };
        zone: {
          type: "string";
          required: false;
        };
        role: {
          type: "string";
          required: true;
        };
        csrPem: {
          type: "string";
          required: true;
        };
        subjectSki: {
          type: "string";
          required: true;
          index: true;
        };
        publicJwk: {
          type: "json";
          required: true;
        };
        status: {
          type: "string";
          required: true;
          defaultValue: string;
        };
        pullToken: {
          type: "string";
          required: true;
          unique: true;
        };
        createdByUserId: {
          type: "string";
          required: false;
        };
        leafPem: {
          type: "string";
          required: false;
        };
        chainPem: {
          type: "string";
          required: false;
        };
        credential: {
          type: "json";
          required: false;
        };
        platformCertCosign: {
          type: "json";
          required: false;
        };
        seatId: {
          type: "string";
          required: false;
        };
        createdAt: {
          type: "date";
          required: true;
        };
        updatedAt: {
          type: "date";
          required: true;
        };
      };
    };
  };
  endpoints: {
    dpPlatformRoot: better_call0.StrictEndpoint<"/delegate-permissions/platform-root", {
      method: "GET";
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      platformRootPem: string;
      ski: string;
    }>;
    dpSeedCatalog: better_call0.StrictEndpoint<"/delegate-permissions/seed-catalog", {
      method: "POST";
      body: z.ZodOptional<z.ZodObject<{
        force: z.ZodOptional<z.ZodBoolean>;
      }, z.core.$strip>>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      seeded: boolean;
      catalog: Catalog;
    }>;
    dpGetCatalog: better_call0.StrictEndpoint<"/delegate-permissions/catalog", {
      method: "GET";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      catalog: Catalog;
      profiles: readonly ProfileDef[];
    }>;
    dpSetPrincipalGrant: better_call0.StrictEndpoint<"/delegate-permissions/principal-grant", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        permissions: z.ZodOptional<z.ZodArray<z.ZodObject<{
          action: z.ZodString;
          scope: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<readonly [z.ZodString, z.ZodArray<z.ZodString>]>>>;
          delegable: z.ZodBoolean;
        }, z.core.$strip>>>;
        profile: z.ZodOptional<z.ZodString>;
        entityId: z.ZodOptional<z.ZodString>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      grant: {
        id: string;
        userId: string;
        entityId: string | null;
        permissions: CapabilitySet;
        profile: string | null;
        expiresAt: Date | null;
      };
    }>;
    dpIssueSessionCapabilities: better_call0.StrictEndpoint<"/delegate-permissions/issue-session-capabilities", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodOptional<z.ZodObject<{
        permissions: z.ZodOptional<z.ZodArray<z.ZodObject<{
          action: z.ZodString;
          scope: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<readonly [z.ZodString, z.ZodArray<z.ZodString>]>>>;
          delegable: z.ZodBoolean;
        }, z.core.$strip>>>;
      }, z.core.$strip>>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      permissions: CapabilitySet;
      expiresAt: Date;
      catalogGeneration: number;
    }>;
    dpAuthorize: better_call0.StrictEndpoint<"/delegate-permissions/authorize", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        action: z.ZodString;
        resource: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<readonly [z.ZodString, z.ZodArray<z.ZodString>]>>>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      allowed: false;
      code: string;
      message: string;
    } | {
      allowed: true;
      code?: undefined;
      message?: undefined;
    }>;
    dpAssertSubset: better_call0.StrictEndpoint<"/delegate-permissions/assert-subset", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        parent: z.ZodArray<z.ZodObject<{
          action: z.ZodString;
          scope: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<readonly [z.ZodString, z.ZodArray<z.ZodString>]>>>;
          delegable: z.ZodBoolean;
        }, z.core.$strip>>;
        child: z.ZodArray<z.ZodObject<{
          action: z.ZodString;
          scope: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<readonly [z.ZodString, z.ZodArray<z.ZodString>]>>>;
          delegable: z.ZodBoolean;
        }, z.core.$strip>>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      ok: false;
      code: string;
      message: string;
    } | {
      ok: true;
      code?: undefined;
      message?: undefined;
    }>;
    dpCredentialRevoke: better_call0.StrictEndpoint<"/delegate-permissions/credential-revoke", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        ski: z.ZodString;
        reason: z.ZodDefault<z.ZodEnum<{
          decommissioned: "decommissioned";
          key_compromise: "key_compromise";
          machine_lost: "machine_lost";
          replaced: "replaced";
          organization_policy: "organization_policy";
          renewed: "renewed";
          other: "other";
        }>>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      ski: string;
      status: "revoked";
      reason: "decommissioned" | "key_compromise" | "machine_lost" | "replaced" | "organization_policy" | "renewed" | "other";
      revokedAt: string;
    }>;
    dpCredentialStatus: better_call0.StrictEndpoint<"/delegate-permissions/credential-status", {
      method: "GET";
      query: z.ZodObject<{
        ski: z.ZodString;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      ski: string;
      entityId: string;
      kind: string;
      status: string;
      host: string | null;
      zone: string | null;
      revokedAt: string | null;
      revokedReason: string | null;
      renewedBySki: string | null;
      createdAt: string;
    }>;
    dpCredentialList: better_call0.StrictEndpoint<"/delegate-permissions/credential-list", {
      method: "GET";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      query: z.ZodObject<{
        entityId: z.ZodString;
        status: z.ZodOptional<z.ZodString>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      credentials: {
        ski: string;
        entityId: string;
        kind: string;
        status: string;
        host: string | null;
        zone: string | null;
        seatId: string | null;
        revokedAt: string | null;
        revokedReason: string | null;
        renewedBySki: string | null;
        createdAt: string;
      }[];
    }>;
    dpMachineDecommission: better_call0.StrictEndpoint<"/delegate-permissions/machine-decommission", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        ski: z.ZodString;
        reason: z.ZodDefault<z.ZodEnum<{
          decommissioned: "decommissioned";
          key_compromise: "key_compromise";
          machine_lost: "machine_lost";
          replaced: "replaced";
          organization_policy: "organization_policy";
          renewed: "renewed";
          other: "other";
        }>>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      ski: string;
      entityId: string;
      status: "decommissioned";
      reason: "decommissioned" | "key_compromise" | "machine_lost" | "replaced" | "organization_policy" | "renewed" | "other";
      revokedAt: string;
    }>;
    dpMachineRenew: better_call0.StrictEndpoint<"/delegate-permissions/machine-renew", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        ski: z.ZodString;
        csrPem: z.ZodString;
        publicJwk: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        leafPem: z.ZodString;
        chainPem: z.ZodString;
        credential: z.ZodRecord<z.ZodString, z.ZodUnknown>;
        issuerSki: z.ZodString;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      oldSki: string;
      newSki: string;
      status: "renewed";
      entityId: string;
      host: string | null;
      platformCertPem: string;
      platformRootPem: string;
    }>;
    dpEnrollCreate: better_call0.StrictEndpoint<"/delegate-permissions/enroll-create", {
      method: "POST";
      body: z.ZodObject<{
        entityId: z.ZodString;
        host: z.ZodOptional<z.ZodString>;
        zone: z.ZodOptional<z.ZodString>;
        kind: z.ZodOptional<z.ZodEnum<{
          source: "source";
          target: "target";
          interim_admin: "interim_admin";
          zone_authority: "zone_authority";
          machine_target: "machine_target";
          machine_source: "machine_source";
        }>>;
        role: z.ZodDefault<z.ZodEnum<{
          source: "source";
          target: "target";
          interim_admin: "interim_admin";
          zone_authority: "zone_authority";
          machine_target: "machine_target";
          machine_source: "machine_source";
        }>>;
        csrPem: z.ZodString;
        publicJwk: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        subjectSki: z.ZodOptional<z.ZodString>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      enrollId: string;
      pullToken: string;
      subjectSki: string;
      kind: "interim_admin" | "zone_authority" | "machine_target" | "machine_source";
      status: "pending";
    }>;
    dpEnrollList: better_call0.StrictEndpoint<"/delegate-permissions/enroll-list", {
      method: "GET";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      query: z.ZodObject<{
        entityId: z.ZodString;
        status: z.ZodOptional<z.ZodString>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      enrollments: {
        enrollId: string;
        host: string | null;
        zone: string | null;
        kind: string;
        role: string;
        subjectSki: string;
        status: string;
        createdAt: Date;
        csrPem: string;
        publicJwk: Record<string, unknown>;
        entityId: string;
      }[];
    }>;
    dpEnrollApprove: better_call0.StrictEndpoint<"/delegate-permissions/enroll-approve", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        enrollId: z.ZodString;
        leafPem: z.ZodString;
        chainPem: z.ZodString;
        credential: z.ZodRecord<z.ZodString, z.ZodUnknown>;
        issuerSki: z.ZodString;
        issuerPrivateJwk: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        payingPartyId: z.ZodOptional<z.ZodString>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      enrollId: string;
      status: "approved";
      pullToken: string;
      kind: "interim_admin" | "zone_authority" | "machine_target" | "machine_source";
      seatId: string | undefined;
      platformCertPem: string;
      platformRootPem: string;
      platformCertCosign: PlatformCertIssue;
    }>;
    dpEnrollReject: better_call0.StrictEndpoint<"/delegate-permissions/enroll-reject", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        enrollId: z.ZodString;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      enrollId: string;
      status: "rejected";
    }>;
    dpEnrollPull: better_call0.StrictEndpoint<"/delegate-permissions/enroll-pull", {
      method: "POST";
      body: z.ZodObject<{
        pullToken: z.ZodString;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      status: "pending";
      enrollId: string;
      host?: undefined;
      zone?: undefined;
      kind?: undefined;
      role?: undefined;
      ski?: undefined;
      publicJwk?: undefined;
      certPem?: undefined;
      chainPem?: undefined;
      credential?: undefined;
      platformCertPem?: undefined;
      platformRootPem?: undefined;
      platformCertCosign?: undefined;
      seatId?: undefined;
    } | {
      status: "rejected";
      enrollId: string;
      host?: undefined;
      zone?: undefined;
      kind?: undefined;
      role?: undefined;
      ski?: undefined;
      publicJwk?: undefined;
      certPem?: undefined;
      chainPem?: undefined;
      credential?: undefined;
      platformCertPem?: undefined;
      platformRootPem?: undefined;
      platformCertCosign?: undefined;
      seatId?: undefined;
    } | {
      status: "approved";
      enrollId: string;
      host: string | null;
      zone: string | null;
      kind: string;
      role: string;
      ski: string;
      publicJwk: Record<string, unknown>;
      certPem: string;
      chainPem: string;
      credential: Record<string, unknown>;
      platformCertPem: string | null;
      platformRootPem: string | null;
      platformCertCosign: Record<string, unknown> | null;
      seatId: string | null;
    }>;
    dpEnrollInstant: better_call0.StrictEndpoint<"/delegate-permissions/enroll-instant", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        entityId: z.ZodString;
        host: z.ZodOptional<z.ZodString>;
        zone: z.ZodOptional<z.ZodString>;
        kind: z.ZodOptional<z.ZodEnum<{
          source: "source";
          target: "target";
          interim_admin: "interim_admin";
          zone_authority: "zone_authority";
          machine_target: "machine_target";
          machine_source: "machine_source";
        }>>;
        role: z.ZodDefault<z.ZodEnum<{
          source: "source";
          target: "target";
          interim_admin: "interim_admin";
          zone_authority: "zone_authority";
          machine_target: "machine_target";
          machine_source: "machine_source";
        }>>;
        csrPem: z.ZodString;
        publicJwk: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        subjectSki: z.ZodOptional<z.ZodString>;
        leafPem: z.ZodString;
        chainPem: z.ZodString;
        credential: z.ZodRecord<z.ZodString, z.ZodUnknown>;
        issuerSki: z.ZodString;
        payingPartyId: z.ZodOptional<z.ZodString>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      enrollId: string;
      status: "approved";
      ski: string;
      host: string | null;
      zone: string | null;
      kind: "interim_admin" | "zone_authority" | "machine_target" | "machine_source";
      certPem: string;
      chainPem: string;
      credential: CapabilityCredential;
      platformCertPem: string;
      platformRootPem: string;
      platformCertCosign: PlatformCertIssue;
      seatId: string | undefined;
    }>;
    dpEnrollMachinePermissions: better_call0.StrictEndpoint<"/delegate-permissions/enroll-machine-permissions", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        entityId: z.ZodString;
        host: z.ZodOptional<z.ZodString>;
        zone: z.ZodOptional<z.ZodString>;
        kind: z.ZodOptional<z.ZodEnum<{
          source: "source";
          target: "target";
          interim_admin: "interim_admin";
          zone_authority: "zone_authority";
          machine_target: "machine_target";
          machine_source: "machine_source";
        }>>;
        role: z.ZodDefault<z.ZodEnum<{
          source: "source";
          target: "target";
          interim_admin: "interim_admin";
          zone_authority: "zone_authority";
          machine_target: "machine_target";
          machine_source: "machine_source";
        }>>;
        permissions: z.ZodOptional<z.ZodArray<z.ZodObject<{
          action: z.ZodString;
          scope: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<readonly [z.ZodString, z.ZodArray<z.ZodString>]>>>;
          delegable: z.ZodBoolean;
        }, z.core.$strip>>>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      permissions: CapabilitySet;
      nameKey: string;
      entityId: string;
      kind: "interim_admin" | "zone_authority" | "machine_target" | "machine_source";
    }>;
    dpKickstartEntity: better_call0.StrictEndpoint<"/delegate-permissions/kickstart-entity", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        entityId: z.ZodString;
        package: z.ZodEnum<{
          personal: "personal";
          enterprise: "enterprise";
        }>;
        rootPublicJwk: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        adminPublicJwk: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        rootCredential: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        adminCredential: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        caCertPem: z.ZodOptional<z.ZodString>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      entityId: string;
      package: EntityPackage;
      root: {
        credential: CapabilityCredential;
        privateJwk?: undefined;
      };
      rootAdmin: {
        credential: CapabilityCredential;
        privateJwk?: undefined;
      };
      caCertPem: string | undefined;
      platformCaCertPem: string;
      platformRootPem: string;
      platformCaCertCosign: PlatformCertIssue;
    } | {
      entityId: string;
      package: EntityPackage;
      root: {
        credential: CapabilityCredential;
        privateJwk: Record<string, unknown>;
      };
      rootAdmin: {
        credential: CapabilityCredential;
        privateJwk: Record<string, unknown>;
      };
      caCertPem: string;
      platformCaCertPem: string;
      platformRootPem: string;
      platformCaCertCosign: PlatformCertIssue;
    }>;
    dpGetEntity: better_call0.StrictEndpoint<"/delegate-permissions/entity", {
      method: "GET";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      query: z.ZodObject<{
        entityId: z.ZodString;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      entityId: string;
      exists: boolean;
      package: string | null;
    }>;
    dpIssueDelegate: better_call0.StrictEndpoint<"/delegate-permissions/issue-delegate", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        entityId: z.ZodString;
        kind: z.ZodEnum<{
          interim_admin: "interim_admin";
          zone_authority: "zone_authority";
        }>;
        zone: z.ZodOptional<z.ZodString>;
        permissions: z.ZodOptional<z.ZodArray<z.ZodObject<{
          action: z.ZodString;
          scope: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<readonly [z.ZodString, z.ZodArray<z.ZodString>]>>>;
          delegable: z.ZodBoolean;
        }, z.core.$strip>>>;
        issuerPrivateJwk: z.ZodRecord<z.ZodString, z.ZodUnknown>;
        issuerSki: z.ZodString;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      credential: CapabilityCredential;
      privateJwk: Record<string, unknown>;
    }>;
    dpIssueMachine: better_call0.StrictEndpoint<"/delegate-permissions/issue-machine", {
      method: "POST";
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        session: {
          session: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            userId: string;
            expiresAt: Date;
            token: string;
            ipAddress?: string | null | undefined;
            userAgent?: string | null | undefined;
          };
          user: Record<string, any> & {
            id: string;
            createdAt: Date;
            updatedAt: Date;
            email: string;
            emailVerified: boolean;
            name: string;
            image?: string | null | undefined;
          };
        };
      }>)[];
      body: z.ZodObject<{
        entityId: z.ZodString;
        host: z.ZodString;
        permissions: z.ZodOptional<z.ZodArray<z.ZodObject<{
          action: z.ZodString;
          scope: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<readonly [z.ZodString, z.ZodArray<z.ZodString>]>>>;
          delegable: z.ZodBoolean;
        }, z.core.$strip>>>;
        issuerPrivateJwk: z.ZodRecord<z.ZodString, z.ZodUnknown>;
        issuerSki: z.ZodString;
        payingPartyId: z.ZodOptional<z.ZodString>;
      }, z.core.$strip>;
      metadata: {
        openapi: {
          description: string;
        };
      };
    }, {
      credential: CapabilityCredential;
      privateJwk: Record<string, unknown>;
      seatId: string;
    }>;
  };
};
type DelegatePermissionsPlugin = ReturnType<typeof delegatePermissions>;
//#endregion
export { ActionDef, AuthorizeResult, Capability, type CapabilityCredential, CapabilitySet, Catalog, type CatalogSeed, type CosignProvider, DELEGATE_PERMISSIONS_ERROR_CODES, DEMO_CATALOG_SEED, DEMO_PLATFORM_CA, DEMO_SERVICE_ID, DelegatePermissionsOptions, DelegatePermissionsPlugin, DpActionRow, DpCatalogMetaRow, DpCredentialRow, DpEnrollKind, DpEnrollRequestRow, DpEntityRow, DpNameOccupancyRow, DpPrincipalGrantRow, DpProfileRow, DpRevocationReason, DpScopeDimensionRow, DpSessionGrantRow, DpUserCredentialBindRow, type PlatformCaMaterial, type PlatformCertCosign, type PlatformCertIssue, ProfileDef, Resource, ScopeAlgebra, ScopeDimensionDef, ScopeMap, type SeatBinder, SubsetResult, actionCovers, assertSubset, attachPlatformCertCosign, attachPlatformCosign, authorize, bindCsrToPublicJwk, createDeviceCsr, createPlatformRootPem, createSelfSignedCaPem, delegatePermissions, dnsPrefixSubset, expandProfile, generateEd25519KeyPair, generateEphemeralPlatformCa, issueCredential, issuePlatformEndorsementCert, leafMatchesCsr, loadPlatformCaMaterial, resourceSatisfiesScope, schema, scopeMapSubset, scopeValueSubset, signCsrWithCa, verifyAgainstTrustAnchor, verifyCredentialSignature, verifyPlatformCertCosign };