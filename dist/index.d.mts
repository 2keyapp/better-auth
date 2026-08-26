import * as _$better_auth0 from "better-auth";
import { APIError, BetterAuthError, DBAdapter, DBTransactionAdapter } from "better-auth";
import * as _$better_call0 from "better-call";
import { statusCodes } from "better-call";
import * as _$zod from "zod";
import * as _$zod_v4_core0 from "zod/v4/core";

//#region src/configuration.d.ts
/** An operation scope carried by an authenticated SCIM principal. */
type SCIMScope = "scim.users.read" | "scim.users.write" | "scim.groups.read" | "scim.groups.write";
/** One static bearer credential accepted by a SCIM connection. */
interface SCIMBearerCredentialOptions {
  type: "bearer";
  /** Stable identifier included in the authenticated SCIM principal. */
  id: string;
  /** Opaque secret presented in the HTTP Authorization header. */
  token: string;
  /** Operation scopes granted to this credential. Defaults to every scope. */
  scopes?: readonly SCIMScope[];
  /** Optional hard expiry used for staged credential rotation. */
  expiresAt?: Date;
}
/** A code-defined SCIM provisioning connection. */
interface SCIMConnectionOptions {
  /** Immutable identifier used to scope every provisioned resource. */
  id: string;
  /** Active and retiring credentials accepted for this connection. */
  credentials: readonly SCIMBearerCredentialOptions[];
  /**
   * Application-owned boundary that receives provisioned resources.
   * Defaults to the connection id.
   */
  provisioningDomainId?: string;
}
/** The connection resolved from an authenticated SCIM request. */
interface SCIMConnection {
  id: string;
  provisioningDomainId: string;
}
interface SCIMPrincipalFields {
  connectionId: string;
  provisioningDomainId: string;
  credentialId: string;
  scopes: readonly SCIMScope[];
  expiresAt?: Date;
}
/** A principal authenticated from a code-defined static bearer credential. */
interface SCIMStaticBearerPrincipal extends SCIMPrincipalFields {
  type: "static-bearer";
}
/** A principal authenticated by an application-owned OAuth verifier. */
interface SCIMOAuthBearerPrincipal extends SCIMPrincipalFields {
  type: "oauth-bearer";
}
/** A principal authenticated by the framework-managed connection catalog. */
interface SCIMManagedBearerPrincipal extends SCIMPrincipalFields {
  type: "managed-bearer";
}
/** The authenticated identity attached to a SCIM request. */
type SCIMPrincipal = SCIMStaticBearerPrincipal | SCIMManagedBearerPrincipal | SCIMOAuthBearerPrincipal;
/** Bearer request data passed to an application-owned token verifier. */
interface SCIMBearerTokenVerificationInput {
  token: string;
  method: string;
  path: string;
  headers: Headers;
}
/** Verified bearer claims resolved before a SCIM request is authorized. */
interface SCIMDeclaredConnectionVerificationResult {
  /** Identifier of a connection declared in `SCIMOptions.connections`. */
  connectionId: string;
  /** A configured-connection result cannot also resolve a connection. */
  connection?: never;
  credentialId: string;
  scopes: readonly SCIMScope[];
  expiresAt?: Date;
}
/**
 * Verified bearer claims and their application-resolved provisioning
 * connection.
 */
interface SCIMResolvedConnectionVerificationResult {
  /**
   * Application-owned connection resolved in the same operation that verifies
   * the bearer credential.
   */
  connection: SCIMConnection;
  /** A resolved-connection result cannot also reference a configured ID. */
  connectionId?: never;
  credentialId: string;
  scopes: readonly SCIMScope[];
  expiresAt?: Date;
}
/** A configured or application-resolved bearer token verification. */
type SCIMBearerTokenVerification = SCIMDeclaredConnectionVerificationResult | SCIMResolvedConnectionVerificationResult;
/** Database access available to an application-owned bearer token verifier. */
interface SCIMBearerTokenVerificationContext {
  database: Pick<DBAdapter, "findOne" | "update">;
}
/** Application-owned verification boundary for bearer access tokens. */
interface SCIMAuthenticationOptions {
  verifyBearerToken(input: SCIMBearerTokenVerificationInput, context: SCIMBearerTokenVerificationContext): SCIMBearerTokenVerification | null | Promise<SCIMBearerTokenVerification | null>;
}
/** Configuration for the optional SCIM-owned connection catalog. */
interface SCIMManagedConnectionOptions {
  /**
   * Independent HMAC secret used to digest managed bearer credentials.
   * Must contain at least 32 characters.
   */
  credentialHashSecret: string;
  /**
   * Maximum number of unexpired, non-revoked credentials per connection.
   * Must be an integer from `1` through `100`. Defaults to `5`.
   */
  maxActiveCredentials?: number;
  /**
   * Minimum interval between persisted last-used updates for a credential.
   * Must be a nonnegative integer. Defaults to `300` seconds.
   */
  lastUsedWriteIntervalSeconds?: number;
}
/** Durable lifecycle state for one persisted SCIM connection binding. */
type SCIMConnectionDecommissionStatus = "active" | "reconciling" | "complete";
/** Components of a SCIM User's name. */
interface SCIMName {
  formatted?: string;
  givenName?: string;
  familyName?: string;
  middleName?: string;
  honorificPrefix?: string;
  honorificSuffix?: string;
}
/** One email address supplied on a SCIM User resource. */
interface SCIMEmail {
  value: string;
  primary?: boolean;
  type?: string;
}
/** A normalized name supplied to application-owned SCIM integrations. */
interface SCIMCanonicalName {
  formatted: string;
  givenName?: string;
  familyName?: string;
  middleName?: string;
  honorificPrefix?: string;
  honorificSuffix?: string;
}
/** A normalized email supplied to application-owned SCIM integrations. */
interface SCIMCanonicalEmail {
  value: string;
  primary: boolean;
  type?: string;
}
/** A normalized phone number supplied on a SCIM User resource. */
interface SCIMCanonicalPhoneNumber {
  value: string;
  type?: string;
  primary?: boolean;
}
/** A normalized postal address supplied on a SCIM User resource. */
interface SCIMCanonicalAddress {
  formatted?: string;
  streetAddress?: string;
  locality?: string;
  region?: string;
  postalCode?: string;
  country?: string;
  type?: string;
  primary?: boolean;
}
/** A normalized role supplied on a SCIM User resource. */
interface SCIMCanonicalRole {
  value: string;
  display?: string;
  type?: string;
  primary?: boolean;
}
/** A normalized entitlement supplied on a SCIM User resource. */
interface SCIMCanonicalEntitlement {
  value: string;
  display?: string;
  type?: string;
  primary?: boolean;
}
/** A manager reference containing an identifier, resource URI, or both. */
type SCIMCanonicalManager = {
  value: string;
  $ref?: string;
} | {
  value?: string;
  $ref: string;
};
/** Supported attributes from the standard Enterprise User extension. */
interface SCIMEnterpriseUser {
  employeeNumber?: string;
  costCenter?: string;
  organization?: string;
  division?: string;
  department?: string;
  manager?: SCIMCanonicalManager;
}
/** The normalized SCIM User supplied to application-owned integrations. */
interface SCIMCanonicalUser {
  schemas: readonly string[];
  externalId?: string;
  userName: string;
  primaryEmail: string;
  displayName: string;
  name: SCIMCanonicalName;
  emails: readonly SCIMCanonicalEmail[];
  title?: string;
  userType?: string;
  preferredLanguage?: string;
  locale?: string;
  timezone?: string;
  phoneNumbers?: readonly SCIMCanonicalPhoneNumber[];
  addresses?: readonly SCIMCanonicalAddress[];
  roles?: readonly SCIMCanonicalRole[];
  entitlements?: readonly SCIMCanonicalEntitlement[];
  enterprise?: SCIMEnterpriseUser;
  active: boolean;
}
/** One connection-owned identity source participating in aggregate lifecycle. */
interface SCIMIdentitySource {
  readonly id: string;
  readonly connectionId: string;
  readonly provisioningDomainId: string;
  readonly active: boolean;
}
/** Explicit create-or-link decision for an incoming SCIM User. */
type SCIMIdentityResolution = {
  action: "create";
} | {
  action: "link";
  userId: string;
  profile: "manage" | "preserve";
};
/** Canonical incoming identity passed to application-owned resolution. */
interface SCIMIdentityResolutionInput {
  connectionId: string;
  provisioningDomainId: string;
  resource: SCIMCanonicalUser;
}
/** Read context for resolving an incoming SCIM User before its transaction. */
interface SCIMIdentityResolutionContext {
  database: Pick<DBAdapter, "count" | "findMany" | "findOne">;
}
/** Complete global lifecycle state for one linked Better Auth user. */
interface SCIMIdentityState {
  readonly userId: string;
  readonly active: boolean;
  readonly profileSourceId?: string;
  readonly sources: readonly SCIMIdentitySource[];
}
/** Transaction-bound context shared by identity and access reconciliation. */
interface SCIMTransactionContext {
  database: DBTransactionAdapter;
}
/** Explicit identity linking and application lifecycle reconciliation. */
interface SCIMIdentity {
  /**
   * Resolves a stable application-owned mapping. Returning `link` must not be
   * based on an unverified email match.
   */
  resolveUser?(input: SCIMIdentityResolutionInput, context: SCIMIdentityResolutionContext): SCIMIdentityResolution | Promise<SCIMIdentityResolution>;
  /** Reconciles global enabled or disabled state inside the SCIM transaction. */
  reconcileUser?(input: SCIMIdentityState, context: SCIMTransactionContext): void | Promise<void>;
}
/** A SCIM Group used as an application authorization source. */
interface SCIMGroupAuthorizationSource {
  type: "group";
  /** Stable source identity; currently the SCIM Group resource id. */
  id: string;
  externalId?: string;
  displayName: string;
}
/** A canonical SCIM fact that may be mapped to application authorization. */
type SCIMAuthorizationSource = SCIMGroupAuthorizationSource;
/** One validated, source-aware role grant passed to a projection. */
interface SCIMProjectedRoleGrant {
  source: SCIMAuthorizationSource;
  role: string;
}
/** The complete desired projection state for one Better Auth user. */
interface SCIMProjectedUserState {
  provisioningDomainId: string;
  userId: string;
  active: boolean;
  sources: readonly SCIMIdentitySource[];
  grants: readonly SCIMProjectedRoleGrant[];
}
/** Input passed to an application's SCIM role mapper. */
interface SCIMRoleMappingInput {
  connectionId: string;
  provisioningDomainId: string;
  scimUserId: string;
  userId: string;
  source: SCIMAuthorizationSource;
}
/** Input passed to an application's SCIM role existence check. */
interface SCIMRoleExistenceInput {
  connectionId: string;
  provisioningDomainId: string;
  role: string;
}
/** Maps canonical SCIM authorization sources to application roles. */
interface SCIMRoleProjection {
  /** Maps one source fact to opaque application role slugs. */
  map(input: SCIMRoleMappingInput, context: SCIMTransactionContext): readonly string[] | undefined | Promise<readonly string[] | undefined>;
  /** Confirms that a mapped role exists in the target domain. */
  exists(input: SCIMRoleExistenceInput, context: SCIMTransactionContext): boolean | Promise<boolean>;
}
/** Maps canonical SCIM facts to an application's access model. */
interface SCIMProjection {
  roles?: SCIMRoleProjection;
  /**
   * Reconciles the complete effective state. Implementations must be
   * idempotent and must use the supplied transaction for database writes.
   */
  reconcileUser(input: SCIMProjectedUserState, context: SCIMTransactionContext): void | Promise<void>;
}
/** Microsoft Entra provisioning client compatibility. */
interface SCIMMicrosoftEntraCompatibilityOptions {
  /**
   * Accept Microsoft's classic, attribute-less Group schema marker on
   * `POST /Groups`. The marker is never advertised, persisted, or returned.
   * Defaults to `false`.
   */
  acceptLegacyGroupSchema?: boolean;
}
/** Narrow ingress compatibility for documented provider request shapes. */
interface SCIMCompatibilityOptions {
  microsoftEntra?: SCIMMicrosoftEntraCompatibilityOptions;
}
/** Configuration for the SCIM plugin. */
interface SCIMOptions {
  /**
   * Code-defined provisioning connections accepted by the SCIM endpoint.
   * May be empty when an application verifier or the managed connection
   * catalog resolves connections.
   */
  connections: readonly SCIMConnectionOptions[];
  /** Optional verification boundary for bearer access tokens. */
  authentication?: SCIMAuthenticationOptions;
  /** Optional SCIM-owned persisted connection and credential catalog. */
  managedConnections?: SCIMManagedConnectionOptions;
  /** Optional explicit linking and global lifecycle integration. */
  identity?: SCIMIdentity;
  /** Optional application or tenancy projection. No projection grants access. */
  projection?: SCIMProjection;
  /** Narrow ingress compatibility for documented provider request shapes. */
  compatibility?: SCIMCompatibilityOptions;
}
//#endregion
//#region src/user-schemas.d.ts
interface SCIMDiscoveryAttribute {
  name: string;
  subAttributes?: readonly SCIMDiscoveryAttribute[];
  [key: string]: unknown;
}
//#endregion
//#region src/resource-attribute-projection.d.ts
/** Minimum shape required for SCIM response attribute projection. */
interface SCIMProjectableResource {
  schemas: readonly string[];
  id: string;
}
type SCIMProjectedAttributeValue<Value> = Value extends Date ? Value : Value extends (infer Item)[] ? SCIMProjectedAttributeValue<Item>[] : Value extends readonly (infer Item)[] ? readonly SCIMProjectedAttributeValue<Item>[] : Value extends object ? { [Key in keyof Value]?: SCIMProjectedAttributeValue<Value[Key]> } : Value;
/** A projected resource always retains the mandatory SCIM identity fields. */
type SCIMProjectedResource<Resource extends SCIMProjectableResource> = Pick<Resource, "schemas" | "id"> & { [Key in keyof Omit<Resource, "schemas" | "id">]?: SCIMProjectedAttributeValue<Resource[Key]> };
//#endregion
//#region src/identity.d.ts
/** Exact external directory reference for one connection-owned SCIM User. */
interface SCIMUserExternalIdReference {
  connectionId: string;
  externalId: string;
}
/** Exact Better Auth User link acquired from an active SCIM source. */
interface SCIMActiveUserLink {
  scimUserId: string;
  userId: string;
}
/** Transaction-bound database capabilities required to acquire an active link. */
interface SCIMActiveUserLinkContext {
  database: Pick<DBTransactionAdapter, "findOne" | "incrementOne">;
}
/**
 * Acquires an active provisioned User link inside the caller's transaction.
 *
 * The lookup is scoped to the exact SCIM connection and externalId. It never
 * falls back to userName, email, or deleted identity tombstones. Pass the
 * active transaction adapter supplied by the authentication resolver. A
 * concurrent lifecycle mutation throws a SCIM conflict. A direct caller can
 * choose to retry its entire transaction after starting from fresh state.
 */
declare function acquireActiveSCIMUserLink(reference: SCIMUserExternalIdReference, context: SCIMActiveUserLinkContext): Promise<SCIMActiveUserLink | null>;
//#endregion
//#region src/managed-connections.d.ts
/** Error code returned when a managed connection creation request ID is reused. */
declare const SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT = "SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT";
/** Lifecycle state for a framework-managed SCIM connection. */
type SCIMManagedConnectionStatus = "active" | "decommissioning" | "decommissioned";
/** Lifecycle state for a framework-managed SCIM credential. */
type SCIMManagedCredentialStatus = "active" | "expired" | "revoked" | "decommissioned";
type SCIMManagedConnectionEventType = "connection.created" | "credential.issued" | "credential.rotated" | "credential.revoked" | "connection.decommissioning" | "connection.decommissioned";
/** Public state for one framework-managed SCIM connection. */
interface SCIMManagedConnection {
  /**
   * Immutable application-supplied correlation for the logical creation
   * operation. It identifies ownership during recovery; it does not replay a
   * credential or make creation idempotent.
   */
  creationRequestId: string;
  connectionId: string;
  provisioningDomainId: string;
  status: SCIMManagedConnectionStatus;
  createdAt: Date;
  createdBy: string;
  decommissionStartedAt: Date | null;
  decommissionStartedBy: string | null;
  decommissionedAt: Date | null;
  decommissionedBy: string | null;
}
/** Public state for one framework-managed SCIM credential. */
interface SCIMManagedCredential {
  credentialId: string;
  status: SCIMManagedCredentialStatus;
  scopes: readonly SCIMScope[];
  expiresAt: Date;
  createdAt: Date;
  createdBy: string;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
  revokedBy: string | null;
}
/** One bounded audit event emitted by the managed SCIM catalog. */
interface SCIMManagedConnectionEvent {
  sequence: number;
  type: SCIMManagedConnectionEventType;
  actorId: string;
  credentialId: string | null;
  createdAt: Date;
}
//#endregion
//#region src/index.d.ts
declare module "@better-auth/core" {
  interface BetterAuthPluginRegistry<AuthOptions, Options> {
    scim: {
      creator: typeof scim;
    };
  }
}
/**
 * Adds an inbound SCIM 2.0 service provider to Better Auth.
 *
 * Every configured connection owns an isolated set of SCIM resources. The
 * plugin does not require the organization plugin and never represents a
 * provisioned identity as an authentication account.
 */
declare function createSCIMPlugin(options: SCIMOptions): {
  id: "scim";
  version: string;
  init(ctx: _$better_auth0.AuthContext): void;
  onRequest(request: Request): Promise<{
    request: Request;
    response?: undefined;
  } | {
    response: Response;
    request?: undefined;
  } | undefined>;
  endpoints: {
    decommissionSCIMConnection: _$better_call0.StrictEndpoint<string, {
      method: "POST";
      body: _$zod.ZodObject<{
        connectionId: _$zod.ZodString;
        provisioningDomainId: _$zod.ZodOptional<_$zod.ZodString>;
      }, _$zod_v4_core0.$strip>;
    }, {
      connectionId: string;
      provisioningDomainId: string;
      status: "complete" | "reconciling";
      decommissionedAt: Date | null;
      completedAt: Date | null;
      retryAfter: Date | null;
      reconciledUsers: number;
      batches: number;
    }>;
    reconcileSCIMProjection: _$better_call0.StrictEndpoint<string, {
      method: "POST";
      body: _$zod.ZodObject<{
        provisioningDomainId: _$zod.ZodString;
      }, _$zod_v4_core0.$strip>;
    }, {
      provisioningDomainId: string;
      reconciledUsers: number;
      batches: number;
    }>;
    createSCIMGroup: _$better_call0.StrictEndpoint<"/scim/v2/Groups", {
      method: "POST";
      body: _$zod.ZodObject<{
        schemas: _$zod.ZodArray<_$zod.ZodLiteral<"urn:ietf:params:scim:schemas:core:2.0:Group">>;
        externalId: _$zod.ZodOptional<_$zod.ZodString>;
        displayName: _$zod.ZodString;
        members: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodString;
          type: _$zod.ZodOptional<_$zod.ZodString>;
        }, _$zod_v4_core0.$strip>>>;
      }, _$zod_v4_core0.$strip>;
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, SCIMProjectedResource<{
      members: {
        value: string;
        $ref: string;
        display: string;
        type: "User";
      }[];
      displayName: string;
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      externalId?: string | undefined;
      schemas: string[];
      id: string;
    }>>;
    deleteSCIMGroup: _$better_call0.StrictEndpoint<"/scim/v2/Groups/:groupId", {
      method: "DELETE";
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, void>;
    getSCIMGroup: _$better_call0.StrictEndpoint<"/scim/v2/Groups/:groupId", {
      method: "GET";
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, SCIMProjectedResource<{
      members: {
        value: string;
        $ref: string;
        display: string;
        type: "User";
      }[];
      displayName: string;
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      externalId?: string | undefined;
      schemas: string[];
      id: string;
    }>>;
    listSCIMGroups: _$better_call0.StrictEndpoint<"/scim/v2/Groups", {
      method: "GET";
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        filter: _$zod.ZodOptional<_$zod.ZodString>;
        startIndex: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodNumber]>>;
        count: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodNumber]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, {
      schemas: string[];
      totalResults: number;
      startIndex: number;
      itemsPerPage: number;
      Resources: SCIMProjectedResource<{
        members: {
          value: string;
          $ref: string;
          display: string;
          type: "User";
        }[];
        displayName: string;
        meta: {
          resourceType: string;
          created: Date;
          lastModified: Date;
          location: string;
        };
        externalId?: string | undefined;
        schemas: string[];
        id: string;
      }>[];
    }>;
    patchSCIMGroup: _$better_call0.StrictEndpoint<"/scim/v2/Groups/:groupId", {
      method: "PATCH";
      body: _$zod.ZodObject<{
        schemas: _$zod.ZodArray<_$zod.ZodLiteral<"urn:ietf:params:scim:api:messages:2.0:PatchOp">>;
        Operations: _$zod.ZodArray<_$zod.ZodObject<{
          op: _$zod.ZodPipe<_$zod.ZodDefault<_$zod.ZodString>, _$zod.ZodEnum<{
            replace: "replace";
            add: "add";
            remove: "remove";
          }>>;
          path: _$zod.ZodOptional<_$zod.ZodString>;
          value: _$zod.ZodOptional<_$zod.ZodUnknown>;
        }, _$zod_v4_core0.$strip>>;
      }, _$zod_v4_core0.$strip>;
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, SCIMProjectedResource<{
      members: {
        value: string;
        $ref: string;
        display: string;
        type: "User";
      }[];
      displayName: string;
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      externalId?: string | undefined;
      schemas: string[];
      id: string;
    }>>;
    replaceSCIMGroup: _$better_call0.StrictEndpoint<"/scim/v2/Groups/:groupId", {
      method: "PUT";
      body: _$zod.ZodObject<{
        schemas: _$zod.ZodArray<_$zod.ZodLiteral<"urn:ietf:params:scim:schemas:core:2.0:Group">>;
        externalId: _$zod.ZodOptional<_$zod.ZodString>;
        displayName: _$zod.ZodString;
        members: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodString;
          type: _$zod.ZodOptional<_$zod.ZodString>;
        }, _$zod_v4_core0.$strip>>>;
      }, _$zod_v4_core0.$strip>;
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, SCIMProjectedResource<{
      members: {
        value: string;
        $ref: string;
        display: string;
        type: "User";
      }[];
      displayName: string;
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      externalId?: string | undefined;
      schemas: string[];
      id: string;
    }>>;
    createSCIMUser: _$better_call0.StrictEndpoint<"/scim/v2/Users", {
      method: "POST";
      body: _$zod.ZodObject<{
        schemas: _$zod.ZodPipe<_$zod.ZodArray<_$zod.ZodString>, _$zod.ZodTransform<("urn:ietf:params:scim:schemas:core:2.0:User" | "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")[], string[]>>;
        userName: _$zod.ZodString;
        externalId: _$zod.ZodOptional<_$zod.ZodString>;
        displayName: _$zod.ZodOptional<_$zod.ZodString>;
        name: _$zod.ZodOptional<_$zod.ZodObject<{
          formatted: _$zod.ZodOptional<_$zod.ZodString>;
          givenName: _$zod.ZodOptional<_$zod.ZodString>;
          familyName: _$zod.ZodOptional<_$zod.ZodString>;
          middleName: _$zod.ZodOptional<_$zod.ZodString>;
          honorificPrefix: _$zod.ZodOptional<_$zod.ZodString>;
          honorificSuffix: _$zod.ZodOptional<_$zod.ZodString>;
        }, _$zod_v4_core0.$strip>>;
        emails: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodEmail;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
        }, _$zod_v4_core0.$strip>>>;
        title: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        userType: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        preferredLanguage: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        locale: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        timezone: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        phoneNumbers: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodString;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
        }, _$zod_v4_core0.$strip>>>;
        addresses: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          formatted: _$zod.ZodOptional<_$zod.ZodString>;
          streetAddress: _$zod.ZodOptional<_$zod.ZodString>;
          locality: _$zod.ZodOptional<_$zod.ZodString>;
          region: _$zod.ZodOptional<_$zod.ZodString>;
          postalCode: _$zod.ZodOptional<_$zod.ZodString>;
          country: _$zod.ZodOptional<_$zod.ZodString>;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
        }, _$zod_v4_core0.$strip>>>;
        roles: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodString;
          display: _$zod.ZodOptional<_$zod.ZodString>;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
        }, _$zod_v4_core0.$strip>>>;
        entitlements: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodString;
          display: _$zod.ZodOptional<_$zod.ZodString>;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
        }, _$zod_v4_core0.$strip>>>;
        active: _$zod.ZodOptional<_$zod.ZodBoolean>;
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodObject<{
          manager: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodObject<{
            value: _$zod.ZodOptional<_$zod.ZodString>;
            $ref: _$zod.ZodOptional<_$zod.ZodString>;
            displayName: _$zod.ZodOptional<_$zod.ZodString>;
          }, _$zod_v4_core0.$strip>, _$zod.ZodArray<_$zod.ZodObject<{
            value: _$zod.ZodOptional<_$zod.ZodString>;
            $ref: _$zod.ZodOptional<_$zod.ZodString>;
            displayName: _$zod.ZodOptional<_$zod.ZodString>;
          }, _$zod_v4_core0.$strip>>]>, _$zod.ZodTransform<{
            $ref?: string | undefined;
            value: string;
          } | {
            $ref: string;
          } | undefined, string | {
            value?: string | undefined;
            $ref?: string | undefined;
            displayName?: string | undefined;
          } | {
            value?: string | undefined;
            $ref?: string | undefined;
            displayName?: string | undefined;
          }[]>>>;
          employeeNumber: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
          costCenter: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
          organization: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
          division: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
          department: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        }, _$zod_v4_core0.$strip>, _$zod.ZodTransform<{
          manager?: {
            $ref?: string | undefined;
            value: string;
          } | {
            $ref: string;
          } | undefined;
          employeeNumber?: string | undefined;
          costCenter?: string | undefined;
          organization?: string | undefined;
          division?: string | undefined;
          department?: string | undefined;
        }, {
          manager?: {
            $ref?: string | undefined;
            value: string;
          } | {
            $ref: string;
          } | undefined;
          employeeNumber?: string | undefined;
          costCenter?: string | undefined;
          organization?: string | undefined;
          division?: string | undefined;
          department?: string | undefined;
        }>>>;
      }, _$zod_v4_core0.$strip>;
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, SCIMProjectedResource<{
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"?: {
        manager?: {
          $ref?: string | undefined;
          value: string;
        } | {
          $ref: string;
        } | undefined;
        employeeNumber?: string | undefined;
        costCenter?: string | undefined;
        organization?: string | undefined;
        division?: string | undefined;
        department?: string | undefined;
      } | undefined;
      userName: string;
      displayName: string;
      active: boolean;
      externalId?: string | undefined;
      id: string;
      schemas: ("urn:ietf:params:scim:schemas:core:2.0:User" | "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")[];
      name: {
        formatted: string;
        givenName?: string | undefined;
        familyName?: string | undefined;
        middleName?: string | undefined;
        honorificPrefix?: string | undefined;
        honorificSuffix?: string | undefined;
      };
      emails: {
        value: string;
        primary: boolean;
        type?: string | undefined;
      }[];
      title?: string | undefined;
      userType?: string | undefined;
      preferredLanguage?: string | undefined;
      locale?: string | undefined;
      timezone?: string | undefined;
      phoneNumbers?: {
        value: string;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      addresses?: {
        formatted?: string | undefined;
        streetAddress?: string | undefined;
        locality?: string | undefined;
        region?: string | undefined;
        postalCode?: string | undefined;
        country?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      roles?: {
        value: string;
        display?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      entitlements?: {
        value: string;
        display?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
    }>>;
    deleteSCIMUser: _$better_call0.StrictEndpoint<"/scim/v2/Users/:userId", {
      method: "DELETE";
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, void>;
    getSCIMUser: _$better_call0.StrictEndpoint<"/scim/v2/Users/:userId", {
      method: "GET";
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, SCIMProjectedResource<{
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"?: {
        manager?: {
          $ref?: string | undefined;
          value: string;
        } | {
          $ref: string;
        } | undefined;
        employeeNumber?: string | undefined;
        costCenter?: string | undefined;
        organization?: string | undefined;
        division?: string | undefined;
        department?: string | undefined;
      } | undefined;
      userName: string;
      displayName: string;
      active: boolean;
      externalId?: string | undefined;
      id: string;
      schemas: ("urn:ietf:params:scim:schemas:core:2.0:User" | "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")[];
      name: {
        formatted: string;
        givenName?: string | undefined;
        familyName?: string | undefined;
        middleName?: string | undefined;
        honorificPrefix?: string | undefined;
        honorificSuffix?: string | undefined;
      };
      emails: {
        value: string;
        primary: boolean;
        type?: string | undefined;
      }[];
      title?: string | undefined;
      userType?: string | undefined;
      preferredLanguage?: string | undefined;
      locale?: string | undefined;
      timezone?: string | undefined;
      phoneNumbers?: {
        value: string;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      addresses?: {
        formatted?: string | undefined;
        streetAddress?: string | undefined;
        locality?: string | undefined;
        region?: string | undefined;
        postalCode?: string | undefined;
        country?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      roles?: {
        value: string;
        display?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      entitlements?: {
        value: string;
        display?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
    }>>;
    listSCIMUsers: _$better_call0.StrictEndpoint<"/scim/v2/Users", {
      method: "GET";
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        filter: _$zod.ZodOptional<_$zod.ZodString>;
        startIndex: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodNumber]>>;
        count: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodNumber]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, {
      schemas: string[];
      totalResults: number;
      startIndex: number;
      itemsPerPage: number;
      Resources: SCIMProjectedResource<{
        meta: {
          resourceType: string;
          created: Date;
          lastModified: Date;
          location: string;
        };
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"?: {
          manager?: {
            $ref?: string | undefined;
            value: string;
          } | {
            $ref: string;
          } | undefined;
          employeeNumber?: string | undefined;
          costCenter?: string | undefined;
          organization?: string | undefined;
          division?: string | undefined;
          department?: string | undefined;
        } | undefined;
        userName: string;
        displayName: string;
        active: boolean;
        externalId?: string | undefined;
        id: string;
        schemas: ("urn:ietf:params:scim:schemas:core:2.0:User" | "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")[];
        name: {
          formatted: string;
          givenName?: string | undefined;
          familyName?: string | undefined;
          middleName?: string | undefined;
          honorificPrefix?: string | undefined;
          honorificSuffix?: string | undefined;
        };
        emails: {
          value: string;
          primary: boolean;
          type?: string | undefined;
        }[];
        title?: string | undefined;
        userType?: string | undefined;
        preferredLanguage?: string | undefined;
        locale?: string | undefined;
        timezone?: string | undefined;
        phoneNumbers?: {
          value: string;
          type?: string | undefined;
          primary?: boolean | undefined;
        }[] | undefined;
        addresses?: {
          formatted?: string | undefined;
          streetAddress?: string | undefined;
          locality?: string | undefined;
          region?: string | undefined;
          postalCode?: string | undefined;
          country?: string | undefined;
          type?: string | undefined;
          primary?: boolean | undefined;
        }[] | undefined;
        roles?: {
          value: string;
          display?: string | undefined;
          type?: string | undefined;
          primary?: boolean | undefined;
        }[] | undefined;
        entitlements?: {
          value: string;
          display?: string | undefined;
          type?: string | undefined;
          primary?: boolean | undefined;
        }[] | undefined;
      }>[];
    }>;
    patchSCIMUser: _$better_call0.StrictEndpoint<"/scim/v2/Users/:userId", {
      method: "PATCH";
      body: _$zod.ZodObject<{
        schemas: _$zod.ZodArray<_$zod.ZodLiteral<"urn:ietf:params:scim:api:messages:2.0:PatchOp">>;
        Operations: _$zod.ZodArray<_$zod.ZodObject<{
          op: _$zod.ZodPipe<_$zod.ZodDefault<_$zod.ZodString>, _$zod.ZodEnum<{
            replace: "replace";
            add: "add";
            remove: "remove";
          }>>;
          path: _$zod.ZodOptional<_$zod.ZodString>;
          value: _$zod.ZodOptional<_$zod.ZodUnknown>;
        }, _$zod_v4_core0.$strip>>;
      }, _$zod_v4_core0.$strip>;
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, SCIMProjectedResource<{
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"?: {
        manager?: {
          $ref?: string | undefined;
          value: string;
        } | {
          $ref: string;
        } | undefined;
        employeeNumber?: string | undefined;
        costCenter?: string | undefined;
        organization?: string | undefined;
        division?: string | undefined;
        department?: string | undefined;
      } | undefined;
      userName: string;
      displayName: string;
      active: boolean;
      externalId?: string | undefined;
      id: string;
      schemas: ("urn:ietf:params:scim:schemas:core:2.0:User" | "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")[];
      name: {
        formatted: string;
        givenName?: string | undefined;
        familyName?: string | undefined;
        middleName?: string | undefined;
        honorificPrefix?: string | undefined;
        honorificSuffix?: string | undefined;
      };
      emails: {
        value: string;
        primary: boolean;
        type?: string | undefined;
      }[];
      title?: string | undefined;
      userType?: string | undefined;
      preferredLanguage?: string | undefined;
      locale?: string | undefined;
      timezone?: string | undefined;
      phoneNumbers?: {
        value: string;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      addresses?: {
        formatted?: string | undefined;
        streetAddress?: string | undefined;
        locality?: string | undefined;
        region?: string | undefined;
        postalCode?: string | undefined;
        country?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      roles?: {
        value: string;
        display?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      entitlements?: {
        value: string;
        display?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
    }>>;
    replaceSCIMUser: _$better_call0.StrictEndpoint<"/scim/v2/Users/:userId", {
      method: "PUT";
      body: _$zod.ZodObject<{
        schemas: _$zod.ZodPipe<_$zod.ZodArray<_$zod.ZodString>, _$zod.ZodTransform<("urn:ietf:params:scim:schemas:core:2.0:User" | "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")[], string[]>>;
        userName: _$zod.ZodString;
        externalId: _$zod.ZodOptional<_$zod.ZodString>;
        displayName: _$zod.ZodOptional<_$zod.ZodString>;
        name: _$zod.ZodOptional<_$zod.ZodObject<{
          formatted: _$zod.ZodOptional<_$zod.ZodString>;
          givenName: _$zod.ZodOptional<_$zod.ZodString>;
          familyName: _$zod.ZodOptional<_$zod.ZodString>;
          middleName: _$zod.ZodOptional<_$zod.ZodString>;
          honorificPrefix: _$zod.ZodOptional<_$zod.ZodString>;
          honorificSuffix: _$zod.ZodOptional<_$zod.ZodString>;
        }, _$zod_v4_core0.$strip>>;
        emails: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodEmail;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
        }, _$zod_v4_core0.$strip>>>;
        title: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        userType: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        preferredLanguage: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        locale: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        timezone: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        phoneNumbers: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodString;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
        }, _$zod_v4_core0.$strip>>>;
        addresses: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          formatted: _$zod.ZodOptional<_$zod.ZodString>;
          streetAddress: _$zod.ZodOptional<_$zod.ZodString>;
          locality: _$zod.ZodOptional<_$zod.ZodString>;
          region: _$zod.ZodOptional<_$zod.ZodString>;
          postalCode: _$zod.ZodOptional<_$zod.ZodString>;
          country: _$zod.ZodOptional<_$zod.ZodString>;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
        }, _$zod_v4_core0.$strip>>>;
        roles: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodString;
          display: _$zod.ZodOptional<_$zod.ZodString>;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
        }, _$zod_v4_core0.$strip>>>;
        entitlements: _$zod.ZodOptional<_$zod.ZodArray<_$zod.ZodObject<{
          value: _$zod.ZodString;
          display: _$zod.ZodOptional<_$zod.ZodString>;
          type: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodString, _$zod.ZodTransform<string, string>>>;
          primary: _$zod.ZodOptional<_$zod.ZodBoolean>;
        }, _$zod_v4_core0.$strip>>>;
        active: _$zod.ZodOptional<_$zod.ZodBoolean>;
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodObject<{
          manager: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodObject<{
            value: _$zod.ZodOptional<_$zod.ZodString>;
            $ref: _$zod.ZodOptional<_$zod.ZodString>;
            displayName: _$zod.ZodOptional<_$zod.ZodString>;
          }, _$zod_v4_core0.$strip>, _$zod.ZodArray<_$zod.ZodObject<{
            value: _$zod.ZodOptional<_$zod.ZodString>;
            $ref: _$zod.ZodOptional<_$zod.ZodString>;
            displayName: _$zod.ZodOptional<_$zod.ZodString>;
          }, _$zod_v4_core0.$strip>>]>, _$zod.ZodTransform<{
            $ref?: string | undefined;
            value: string;
          } | {
            $ref: string;
          } | undefined, string | {
            value?: string | undefined;
            $ref?: string | undefined;
            displayName?: string | undefined;
          } | {
            value?: string | undefined;
            $ref?: string | undefined;
            displayName?: string | undefined;
          }[]>>>;
          employeeNumber: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
          costCenter: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
          organization: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
          division: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
          department: _$zod.ZodOptional<_$zod.ZodPipe<_$zod.ZodTransform<any, unknown>, _$zod.ZodString>>;
        }, _$zod_v4_core0.$strip>, _$zod.ZodTransform<{
          manager?: {
            $ref?: string | undefined;
            value: string;
          } | {
            $ref: string;
          } | undefined;
          employeeNumber?: string | undefined;
          costCenter?: string | undefined;
          organization?: string | undefined;
          division?: string | undefined;
          department?: string | undefined;
        }, {
          manager?: {
            $ref?: string | undefined;
            value: string;
          } | {
            $ref: string;
          } | undefined;
          employeeNumber?: string | undefined;
          costCenter?: string | undefined;
          organization?: string | undefined;
          division?: string | undefined;
          department?: string | undefined;
        }>>>;
      }, _$zod_v4_core0.$strip>;
      query: _$zod.ZodOptional<_$zod.ZodObject<{
        attributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
        excludedAttributes: _$zod.ZodOptional<_$zod.ZodUnion<readonly [_$zod.ZodString, _$zod.ZodArray<_$zod.ZodString>]>>;
      }, _$zod_v4_core0.$strip>>;
      metadata: Record<string, unknown>;
      use: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<{
        scimConnection: SCIMConnection;
        scimPrincipal: SCIMPrincipal;
      }>>[];
    }, SCIMProjectedResource<{
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"?: {
        manager?: {
          $ref?: string | undefined;
          value: string;
        } | {
          $ref: string;
        } | undefined;
        employeeNumber?: string | undefined;
        costCenter?: string | undefined;
        organization?: string | undefined;
        division?: string | undefined;
        department?: string | undefined;
      } | undefined;
      userName: string;
      displayName: string;
      active: boolean;
      externalId?: string | undefined;
      id: string;
      schemas: ("urn:ietf:params:scim:schemas:core:2.0:User" | "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")[];
      name: {
        formatted: string;
        givenName?: string | undefined;
        familyName?: string | undefined;
        middleName?: string | undefined;
        honorificPrefix?: string | undefined;
        honorificSuffix?: string | undefined;
      };
      emails: {
        value: string;
        primary: boolean;
        type?: string | undefined;
      }[];
      title?: string | undefined;
      userType?: string | undefined;
      preferredLanguage?: string | undefined;
      locale?: string | undefined;
      timezone?: string | undefined;
      phoneNumbers?: {
        value: string;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      addresses?: {
        formatted?: string | undefined;
        streetAddress?: string | undefined;
        locality?: string | undefined;
        region?: string | undefined;
        postalCode?: string | undefined;
        country?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      roles?: {
        value: string;
        display?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
      entitlements?: {
        value: string;
        display?: string | undefined;
        type?: string | undefined;
        primary?: boolean | undefined;
      }[] | undefined;
    }>>;
    getSCIMServiceProviderConfig: _$better_call0.StrictEndpoint<"/scim/v2/ServiceProviderConfig", {
      method: "GET";
      metadata: Record<string, unknown>;
    }, {
      schemas: string[];
      patch: {
        supported: boolean;
      };
      bulk: {
        supported: boolean;
        maxOperations: number;
        maxPayloadSize: number;
      };
      filter: {
        supported: boolean;
        maxResults: number;
      };
      changePassword: {
        supported: boolean;
      };
      sort: {
        supported: boolean;
      };
      etag: {
        supported: boolean;
      };
      authenticationSchemes: {
        name: string;
        description: string;
        specUri: string;
        type: string;
        primary: boolean;
      }[];
      meta: {
        resourceType: string;
        location: string;
      };
    }>;
    getSCIMSchemas: _$better_call0.StrictEndpoint<"/scim/v2/Schemas", {
      method: "GET";
      metadata: Record<string, unknown>;
    }, {
      schemas: string[];
      totalResults: number;
      startIndex: number;
      itemsPerPage: number;
      Resources: ({
        meta: {
          location: string;
          resourceType: string;
        } | {
          location: string;
          resourceType: string;
        } | {
          location: string;
          resourceType: string;
        };
        id: string;
        schemas: string[];
        name: string;
        description: string;
        attributes: ({
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          caseExact: boolean;
          mutability: string;
          returned: string;
          uniqueness: string;
          subAttributes?: undefined;
        } | {
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          mutability: string;
          returned: string;
          uniqueness: string;
          subAttributes: ({
            name: string;
            type: string;
            multiValued: boolean;
            description: string;
            required: boolean;
            caseExact: boolean;
            mutability: string;
            returned: string;
            uniqueness: string;
            referenceTypes?: undefined;
            canonicalValues?: undefined;
          } | {
            name: string;
            type: string;
            referenceTypes: string[];
            multiValued: boolean;
            description: string;
            required: boolean;
            caseExact: boolean;
            mutability: string;
            returned: string;
            uniqueness: string;
            canonicalValues?: undefined;
          } | {
            name: string;
            type: string;
            multiValued: boolean;
            description: string;
            required: boolean;
            caseExact: boolean;
            canonicalValues: string[];
            mutability: string;
            returned: string;
            uniqueness: string;
            referenceTypes?: undefined;
          })[];
          caseExact?: undefined;
        })[];
      } | {
        meta: {
          location: string;
          resourceType: string;
        } | {
          location: string;
          resourceType: string;
        } | {
          location: string;
          resourceType: string;
        };
        id: string;
        schemas: string[];
        name: string;
        description: string;
        attributes: ({
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          caseExact: boolean;
          mutability: "readWrite" | "readOnly";
          returned: string;
          uniqueness: "server" | "none";
        } | {
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          subAttributes: readonly SCIMDiscoveryAttribute[];
          mutability: string;
          returned: string;
          uniqueness: string;
        } | {
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          mutability: string;
          returned: string;
          subAttributes?: undefined;
          uniqueness?: undefined;
        } | {
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          subAttributes: {
            name: string;
            type: string;
            multiValued: boolean;
            description: string;
            required: boolean;
            caseExact: boolean;
            mutability: "readWrite" | "readOnly";
            returned: string;
            uniqueness: "server" | "none";
          }[];
          mutability: string;
          returned: string;
          uniqueness: string;
        })[];
      } | {
        meta: {
          location: string;
          resourceType: string;
        } | {
          location: string;
          resourceType: string;
        } | {
          location: string;
          resourceType: string;
        };
        id: string;
        schemas: string[];
        name: string;
        description: string;
        attributes: ({
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          caseExact: boolean;
          mutability: "readWrite" | "readOnly";
          returned: string;
          uniqueness: "server" | "none";
        } | {
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          subAttributes: ({
            name: string;
            type: string;
            multiValued: boolean;
            description: string;
            required: boolean;
            caseExact: boolean;
            mutability: "readWrite" | "readOnly";
            returned: string;
            uniqueness: "server" | "none";
          } | {
            name: string;
            type: string;
            referenceTypes: string[];
            multiValued: boolean;
            description: string;
            required: boolean;
            caseExact: boolean;
            mutability: string;
            returned: string;
            uniqueness: string;
          })[];
          mutability: string;
          returned: string;
          uniqueness: string;
        })[];
      })[];
    }>;
    getSCIMSchema: _$better_call0.StrictEndpoint<"/scim/v2/Schemas/:schemaId", {
      method: "GET";
      metadata: Record<string, unknown>;
    }, {
      meta: {
        location: string;
        resourceType: string;
      } | {
        location: string;
        resourceType: string;
      } | {
        location: string;
        resourceType: string;
      };
      id: string;
      schemas: string[];
      name: string;
      description: string;
      attributes: ({
        name: string;
        type: string;
        multiValued: boolean;
        description: string;
        required: boolean;
        caseExact: boolean;
        mutability: string;
        returned: string;
        uniqueness: string;
        subAttributes?: undefined;
      } | {
        name: string;
        type: string;
        multiValued: boolean;
        description: string;
        required: boolean;
        mutability: string;
        returned: string;
        uniqueness: string;
        subAttributes: ({
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          caseExact: boolean;
          mutability: string;
          returned: string;
          uniqueness: string;
          referenceTypes?: undefined;
          canonicalValues?: undefined;
        } | {
          name: string;
          type: string;
          referenceTypes: string[];
          multiValued: boolean;
          description: string;
          required: boolean;
          caseExact: boolean;
          mutability: string;
          returned: string;
          uniqueness: string;
          canonicalValues?: undefined;
        } | {
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          caseExact: boolean;
          canonicalValues: string[];
          mutability: string;
          returned: string;
          uniqueness: string;
          referenceTypes?: undefined;
        })[];
        caseExact?: undefined;
      })[];
    } | {
      meta: {
        location: string;
        resourceType: string;
      } | {
        location: string;
        resourceType: string;
      } | {
        location: string;
        resourceType: string;
      };
      id: string;
      schemas: string[];
      name: string;
      description: string;
      attributes: ({
        name: string;
        type: string;
        multiValued: boolean;
        description: string;
        required: boolean;
        caseExact: boolean;
        mutability: "readWrite" | "readOnly";
        returned: string;
        uniqueness: "server" | "none";
      } | {
        name: string;
        type: string;
        multiValued: boolean;
        description: string;
        required: boolean;
        subAttributes: readonly SCIMDiscoveryAttribute[];
        mutability: string;
        returned: string;
        uniqueness: string;
      } | {
        name: string;
        type: string;
        multiValued: boolean;
        description: string;
        required: boolean;
        mutability: string;
        returned: string;
        subAttributes?: undefined;
        uniqueness?: undefined;
      } | {
        name: string;
        type: string;
        multiValued: boolean;
        description: string;
        required: boolean;
        subAttributes: {
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          caseExact: boolean;
          mutability: "readWrite" | "readOnly";
          returned: string;
          uniqueness: "server" | "none";
        }[];
        mutability: string;
        returned: string;
        uniqueness: string;
      })[];
    } | {
      meta: {
        location: string;
        resourceType: string;
      } | {
        location: string;
        resourceType: string;
      } | {
        location: string;
        resourceType: string;
      };
      id: string;
      schemas: string[];
      name: string;
      description: string;
      attributes: ({
        name: string;
        type: string;
        multiValued: boolean;
        description: string;
        required: boolean;
        caseExact: boolean;
        mutability: "readWrite" | "readOnly";
        returned: string;
        uniqueness: "server" | "none";
      } | {
        name: string;
        type: string;
        multiValued: boolean;
        description: string;
        required: boolean;
        subAttributes: ({
          name: string;
          type: string;
          multiValued: boolean;
          description: string;
          required: boolean;
          caseExact: boolean;
          mutability: "readWrite" | "readOnly";
          returned: string;
          uniqueness: "server" | "none";
        } | {
          name: string;
          type: string;
          referenceTypes: string[];
          multiValued: boolean;
          description: string;
          required: boolean;
          caseExact: boolean;
          mutability: string;
          returned: string;
          uniqueness: string;
        })[];
        mutability: string;
        returned: string;
        uniqueness: string;
      })[];
    }>;
    getSCIMResourceTypes: _$better_call0.StrictEndpoint<"/scim/v2/ResourceTypes", {
      method: "GET";
      metadata: Record<string, unknown>;
    }, {
      schemas: string[];
      totalResults: number;
      startIndex: number;
      itemsPerPage: number;
      Resources: ({
        meta: {
          location: string;
          resourceType: string;
        } | {
          location: string;
          resourceType: string;
        };
        schemas: string[];
        id: string;
        name: string;
        endpoint: string;
        description: string;
        schema: string;
      } | {
        meta: {
          location: string;
          resourceType: string;
        } | {
          location: string;
          resourceType: string;
        };
        schemas: string[];
        id: string;
        name: string;
        endpoint: string;
        description: string;
        schema: "urn:ietf:params:scim:schemas:core:2.0:User";
        schemaExtensions: {
          schema: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
          required: false;
        }[];
      })[];
    }>;
    getSCIMResourceType: _$better_call0.StrictEndpoint<"/scim/v2/ResourceTypes/:resourceTypeId", {
      method: "GET";
      metadata: Record<string, unknown>;
    }, {
      meta: {
        location: string;
        resourceType: string;
      } | {
        location: string;
        resourceType: string;
      };
      schemas: string[];
      id: string;
      name: string;
      endpoint: string;
      description: string;
      schema: string;
    } | {
      meta: {
        location: string;
        resourceType: string;
      } | {
        location: string;
        resourceType: string;
      };
      schemas: string[];
      id: string;
      name: string;
      endpoint: string;
      description: string;
      schema: "urn:ietf:params:scim:schemas:core:2.0:User";
      schemaExtensions: {
        schema: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        required: false;
      }[];
    }>;
    createSCIMManagedConnection: _$better_call0.StrictEndpoint<string, {
      method: "POST";
      body: _$zod.ZodObject<{
        scopes: _$zod.ZodReadonly<_$zod.ZodArray<_$zod.ZodEnum<{
          "scim.users.read": "scim.users.read";
          "scim.users.write": "scim.users.write";
          "scim.groups.read": "scim.groups.read";
          "scim.groups.write": "scim.groups.write";
        }>>>;
        expiresAt: _$zod.ZodDate;
        creationRequestId: _$zod.ZodString;
        provisioningDomainId: _$zod.ZodString;
        actorId: _$zod.ZodString;
      }, _$zod_v4_core0.$strip>;
      metadata: {
        noStore: boolean;
      };
    }, {
      connection: SCIMManagedConnection;
      credential: SCIMManagedCredential;
      token: string;
    }>;
    listSCIMManagedConnections: _$better_call0.StrictEndpoint<string, {
      method: "POST";
      body: _$zod.ZodObject<{
        provisioningDomainId: _$zod.ZodString;
      }, _$zod_v4_core0.$strip>;
    }, {
      connections: SCIMManagedConnection[];
    }>;
    getSCIMManagedConnection: _$better_call0.StrictEndpoint<string, {
      method: "POST";
      body: _$zod.ZodObject<{
        connectionId: _$zod.ZodString;
        provisioningDomainId: _$zod.ZodString;
      }, _$zod_v4_core0.$strip>;
    }, {
      connection: SCIMManagedConnection;
      credentials: SCIMManagedCredential[];
    }>;
    rotateSCIMManagedCredential: _$better_call0.StrictEndpoint<string, {
      method: "POST";
      body: _$zod.ZodObject<{
        scopes: _$zod.ZodReadonly<_$zod.ZodArray<_$zod.ZodEnum<{
          "scim.users.read": "scim.users.read";
          "scim.users.write": "scim.users.write";
          "scim.groups.read": "scim.groups.read";
          "scim.groups.write": "scim.groups.write";
        }>>>;
        expiresAt: _$zod.ZodDate;
        connectionId: _$zod.ZodString;
        provisioningDomainId: _$zod.ZodString;
        actorId: _$zod.ZodString;
      }, _$zod_v4_core0.$strip>;
      metadata: {
        noStore: boolean;
      };
    }, {
      connection: SCIMManagedConnection;
      credential: SCIMManagedCredential;
      token: string;
    }>;
    revokeSCIMManagedCredential: _$better_call0.StrictEndpoint<string, {
      method: "POST";
      body: _$zod.ZodObject<{
        connectionId: _$zod.ZodString;
        provisioningDomainId: _$zod.ZodString;
        credentialId: _$zod.ZodString;
        actorId: _$zod.ZodString;
      }, _$zod_v4_core0.$strip>;
    }, {
      connection: SCIMManagedConnection;
      credentials: SCIMManagedCredential[];
    }>;
    listSCIMManagedConnectionEvents: _$better_call0.StrictEndpoint<string, {
      method: "POST";
      body: _$zod.ZodObject<{
        connectionId: _$zod.ZodString;
        provisioningDomainId: _$zod.ZodString;
      }, _$zod_v4_core0.$strip>;
    }, {
      events: SCIMManagedConnectionEvent[];
    }>;
    decommissionSCIMManagedConnection: _$better_call0.StrictEndpoint<string, {
      method: "POST";
      body: _$zod.ZodObject<{
        connectionId: _$zod.ZodString;
        provisioningDomainId: _$zod.ZodString;
        actorId: _$zod.ZodString;
      }, _$zod_v4_core0.$strip>;
    }, {
      decommission: {
        status: "complete";
        retryAfter: null;
      };
      connection: SCIMManagedConnection;
      credentials: SCIMManagedCredential[];
    } | {
      decommission: {
        connectionId: string;
        provisioningDomainId: string;
        status: "complete" | "reconciling";
        decommissionedAt: Date | null;
        completedAt: Date | null;
        retryAfter: Date | null;
        reconciledUsers: number;
        batches: number;
      };
      connection: SCIMManagedConnection;
      credentials: SCIMManagedCredential[];
    }>;
  };
  onResponse(response: Response): Promise<{
    response: Response;
  } | undefined>;
  hooks: {
    after: {
      matcher: (context: _$better_auth0.HookEndpointContext) => boolean;
      handler: _$better_call0.Middleware<_$better_call0.MiddlewareOptions, (inputContext: _$better_call0.MiddlewareInputContext<_$better_call0.MiddlewareOptions>) => Promise<void>>;
    }[];
  };
  schema: {
    scimConnectionBinding: {
      fields: {
        connectionId: {
          type: "string";
          required: true;
          index: true;
        };
        connectionKey: {
          type: "string";
          required: true;
          unique: true;
          returned: false;
        };
        provisioningDomainId: {
          type: "string";
          required: true;
        };
        createdAt: {
          type: "date";
          required: true;
        };
        decommissionedAt: {
          type: "date";
          required: false;
        };
        decommissionStatus: {
          type: "string";
          required: true;
          defaultValue: string;
        };
        decommissionCursorUserId: {
          type: "string";
          required: false;
          returned: false;
        };
        decommissionReconciledUserCount: {
          type: "number";
          required: true;
          defaultValue: number;
        };
        decommissionBatchCount: {
          type: "number";
          required: true;
          defaultValue: number;
        };
        decommissionRevision: {
          type: "number";
          required: true;
          defaultValue: number;
          returned: false;
        };
        decommissionCompletedAt: {
          type: "date";
          required: false;
        };
        decommissionLeaseId: {
          type: "string";
          required: false;
          returned: false;
        };
        decommissionLeaseExpiresAt: {
          type: "date";
          required: false;
          returned: false;
        };
      };
    };
    scimIdentityTombstone: {
      fields: {
        connectionId: {
          type: "string";
          required: true;
          index: true;
        };
        provisioningDomainId: {
          type: "string";
          required: true;
          index: true;
        };
        externalId: {
          type: "string";
          required: true;
        };
        externalIdKey: {
          type: "string";
          required: true;
          unique: true;
          returned: false;
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
        profile: {
          type: "string";
          required: true;
        };
        deletedAt: {
          type: "date";
          required: true;
        };
      };
    };
    scimSubject: {
      fields: {
        userId: {
          type: "string";
          required: true;
          unique: true;
          references: {
            model: string;
            field: string;
          };
        };
        profileSourceId: {
          type: "string";
          required: false;
          index: true;
        };
        revision: {
          type: "number";
          required: true;
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
    scimUser: {
      fields: {
        connectionId: {
          type: "string";
          required: true;
          index: true;
        };
        provisioningDomainId: {
          type: "string";
          required: true;
          index: true;
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
        connectionUserKey: {
          type: "string";
          required: true;
          unique: true;
          returned: false;
        };
        userName: {
          type: "string";
          required: true;
        };
        userNameKey: {
          type: "string";
          required: true;
          unique: true;
          returned: false;
        };
        primaryEmail: {
          type: "string";
          required: true;
        };
        workEmailValueIndex: {
          type: "string";
          required: true;
          returned: false;
        };
        emailValueIndex: {
          type: "string";
          required: true;
          returned: false;
        };
        displayName: {
          type: "string";
          required: true;
        };
        formattedName: {
          type: "string";
          required: true;
        };
        givenName: {
          type: "string";
          required: false;
        };
        familyName: {
          type: "string";
          required: false;
        };
        serializedEmails: {
          type: "string";
          required: true;
          returned: false;
        };
        serializedAttributes: {
          type: "string";
          required: false;
          returned: false;
        };
        externalId: {
          type: "string";
          required: false;
        };
        externalIdKey: {
          type: "string";
          required: false;
          unique: true;
          returned: false;
        };
        active: {
          type: "boolean";
          required: true;
        };
        orderKey: {
          type: "string";
          required: true;
          unique: true;
          returned: false;
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
    scimProjectionGrant: {
      fields: {
        connectionId: {
          type: "string";
          required: true;
          index: true;
        };
        provisioningDomainId: {
          type: "string";
          required: true;
          index: true;
        };
        scimUserId: {
          type: "string";
          required: true;
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
        sourceKind: {
          type: "string";
          required: true;
        };
        sourceId: {
          type: "string";
          required: true;
        };
        sourceValue: {
          type: "string";
          required: false;
        };
        role: {
          type: "string";
          required: true;
        };
        grantKey: {
          type: "string";
          required: true;
          unique: true;
          returned: false;
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
    scimGroup: {
      fields: {
        connectionId: {
          type: "string";
          required: true;
          index: true;
        };
        provisioningDomainId: {
          type: "string";
          required: true;
          index: true;
        };
        revision: {
          type: "number";
          required: true;
          defaultValue: number;
          returned: false;
        };
        displayName: {
          type: "string";
          required: true;
        };
        displayNameKey: {
          type: "string";
          required: true;
          unique: true;
          returned: false;
        };
        externalId: {
          type: "string";
          required: false;
        };
        externalIdKey: {
          type: "string";
          required: false;
          unique: true;
          returned: false;
        };
        orderKey: {
          type: "string";
          required: true;
          unique: true;
          returned: false;
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
    scimGroupMember: {
      fields: {
        connectionId: {
          type: "string";
          required: true;
          index: true;
        };
        groupId: {
          type: "string";
          required: true;
          index: true;
          references: {
            model: string;
            field: string;
          };
        };
        scimUserId: {
          type: "string";
          required: true;
          index: true;
          references: {
            model: string;
            field: string;
          };
        };
        membershipKey: {
          type: "string";
          required: true;
          unique: true;
          returned: false;
        };
        createdAt: {
          type: "date";
          required: true;
        };
      };
    };
    scimManagedConnection?: {
      readonly fields: {
        readonly creationRequestId: {
          readonly type: "string";
          readonly required: true;
          readonly unique: true;
        };
        readonly connectionId: {
          readonly type: "string";
          readonly required: true;
          readonly unique: true;
        };
        readonly provisioningDomainId: {
          readonly type: "string";
          readonly required: true;
          readonly index: true;
        };
        readonly status: {
          readonly type: "string";
          readonly required: true;
        };
        readonly revision: {
          readonly type: "number";
          readonly required: true;
          readonly returned: false;
        };
        readonly createdAt: {
          readonly type: "date";
          readonly required: true;
        };
        readonly createdBy: {
          readonly type: "string";
          readonly required: true;
        };
        readonly decommissionStartedAt: {
          readonly type: "date";
          readonly required: false;
        };
        readonly decommissionStartedBy: {
          readonly type: "string";
          readonly required: false;
        };
        readonly decommissionedAt: {
          readonly type: "date";
          readonly required: false;
        };
        readonly decommissionedBy: {
          readonly type: "string";
          readonly required: false;
        };
      };
    } | undefined;
    scimManagedCredential?: {
      readonly fields: {
        readonly connectionRecordId: {
          readonly type: "string";
          readonly required: true;
          readonly index: true;
          readonly references: {
            readonly model: "scimManagedConnection";
            readonly field: "id";
            readonly onDelete: "cascade";
          };
        };
        readonly credentialId: {
          readonly type: "string";
          readonly required: true;
          readonly unique: true;
        };
        readonly tokenDigest: {
          readonly type: "string";
          readonly required: true;
          readonly returned: false;
        };
        readonly hashVersion: {
          readonly type: "string";
          readonly required: true;
          readonly returned: false;
        };
        readonly activeSlotKey: {
          readonly type: "string";
          readonly required: true;
          readonly unique: true;
          readonly returned: false;
        };
        readonly status: {
          readonly type: "string";
          readonly required: true;
        };
        readonly serializedScopes: {
          readonly type: "string";
          readonly required: true;
          readonly returned: false;
        };
        readonly expiresAt: {
          readonly type: "date";
          readonly required: true;
        };
        readonly createdAt: {
          readonly type: "date";
          readonly required: true;
        };
        readonly createdBy: {
          readonly type: "string";
          readonly required: true;
        };
        readonly lastUsedAt: {
          readonly type: "date";
          readonly required: false;
        };
        readonly revokedAt: {
          readonly type: "date";
          readonly required: false;
        };
        readonly revokedBy: {
          readonly type: "string";
          readonly required: false;
        };
        readonly decommissionedAt: {
          readonly type: "date";
          readonly required: false;
        };
      };
    } | undefined;
    scimManagedConnectionEvent?: {
      readonly fields: {
        readonly connectionRecordId: {
          readonly type: "string";
          readonly required: true;
          readonly index: true;
          readonly references: {
            readonly model: "scimManagedConnection";
            readonly field: "id";
            readonly onDelete: "cascade";
          };
        };
        readonly eventKey: {
          readonly type: "string";
          readonly required: true;
          readonly unique: true;
          readonly returned: false;
        };
        readonly sequence: {
          readonly type: "number";
          readonly required: true;
        };
        readonly type: {
          readonly type: "string";
          readonly required: true;
        };
        readonly actorId: {
          readonly type: "string";
          readonly required: true;
        };
        readonly credentialId: {
          readonly type: "string";
          readonly required: false;
        };
        readonly createdAt: {
          readonly type: "date";
          readonly required: true;
        };
      };
    } | undefined;
  };
  options: SCIMOptions;
};
/** The Better Auth plugin returned by {@link scim}. */
type SCIMPlugin = ReturnType<typeof createSCIMPlugin>;
/** The server endpoints installed by the SCIM plugin. */
type SCIMEndpoints = SCIMPlugin["endpoints"];
/**
 * Adds an inbound SCIM 2.0 service provider to Better Auth.
 *
 * Every configured connection owns an isolated set of SCIM resources. The
 * plugin does not require the organization plugin and never represents a
 * provisioned identity as an authentication account.
 */
declare function scim(options: SCIMOptions): SCIMPlugin;
//#endregion
export { type SCIMActiveUserLink, type SCIMActiveUserLinkContext, type SCIMAuthenticationOptions, type SCIMAuthorizationSource, type SCIMBearerCredentialOptions, type SCIMBearerTokenVerification, type SCIMBearerTokenVerificationContext, type SCIMBearerTokenVerificationInput, type SCIMCanonicalAddress, type SCIMCanonicalEmail, type SCIMCanonicalEntitlement, type SCIMCanonicalManager, type SCIMCanonicalName, type SCIMCanonicalPhoneNumber, type SCIMCanonicalRole, type SCIMCanonicalUser, type SCIMCompatibilityOptions, type SCIMConnection, type SCIMConnectionDecommissionStatus, type SCIMConnectionOptions, type SCIMDeclaredConnectionVerificationResult, type SCIMEmail, SCIMEndpoints, type SCIMEnterpriseUser, type SCIMGroupAuthorizationSource, type SCIMIdentity, type SCIMIdentityResolution, type SCIMIdentityResolutionContext, type SCIMIdentityResolutionInput, type SCIMIdentitySource, type SCIMIdentityState, type SCIMManagedBearerPrincipal, type SCIMManagedConnection, type SCIMManagedConnectionEvent, type SCIMManagedConnectionEventType, type SCIMManagedConnectionOptions, type SCIMManagedConnectionStatus, type SCIMManagedCredential, type SCIMManagedCredentialStatus, type SCIMMicrosoftEntraCompatibilityOptions, type SCIMName, type SCIMOAuthBearerPrincipal, type SCIMOptions, SCIMPlugin, type SCIMPrincipal, type SCIMProjectedRoleGrant, type SCIMProjectedUserState, type SCIMProjection, type SCIMResolvedConnectionVerificationResult, type SCIMRoleExistenceInput, type SCIMRoleMappingInput, type SCIMRoleProjection, type SCIMScope, type SCIMStaticBearerPrincipal, type SCIMTransactionContext, type SCIMUserExternalIdReference, SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT, acquireActiveSCIMUserLink, scim };