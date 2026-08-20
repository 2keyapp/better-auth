import { User } from "better-auth";
import * as better_call0 from "better-call";
import { Member } from "better-auth/plugins";
import * as zod from "zod";
import * as zod_v4_core0 from "zod/v4/core";

//#region src/types.d.ts
interface SCIMProvider {
  id: string;
  providerId: string;
  scimToken: string;
  organizationId?: string;
  userId?: string;
}
type SCIMName = {
  formatted?: string;
  givenName?: string;
  familyName?: string;
};
type SCIMEmail = {
  value?: string;
  primary?: boolean;
};
type SCIMOptions = {
  /**
   * SCIM provider ownership configuration. When enabled, each provider
   * connection is linked to the user who generated its token.
   */
  providerOwnership?: {
    enabled: boolean;
  };
  /**
   * Minimum organization role(s) required for SCIM management operations
   * (generate-token, list/get/delete provider connections).
   *
   * Defaults to `["admin", organization.creatorRole ?? "owner"]`.
   */
  requiredRole?: string[];
  /**
   * Default list of SCIM providers for testing.
   * These will take precedence over the database when present.
   */
  defaultSCIM?: Omit<SCIMProvider, "id">[];
  /**
   * Controls whether SCIM provisioning may link to a *pre-existing* Better
   * Auth user whose email matches the incoming SCIM resource.
   *
   * Disabled by default: when a user with the same email already exists,
   * `createSCIMUser` returns `409` (uniqueness) instead of silently creating a
   * SCIM account link for that user. Linking by email alone would give a SCIM
   * token access to an account it never provisioned.
   *
   * - `true` restores the legacy behavior of linking any existing user that
   *   matches by email. Only use this with a fully trusted token-issuance flow.
   * - An object enables linking only when *every* provided constraint passes.
   */
  linkExistingUsers?: boolean | {
    /**
     * Only link when the email's domain is in this allow-list
     * (case-insensitive). An empty/absent list is not a match.
     */
    trustedDomains?: string[];
    /**
     * For organization-scoped tokens, only link a user who is already
     * a member of the token's organization (never auto-add them). Has
     * no effect for non-org (personal) tokens, which then never match
     * on this constraint.
     */
    requireExistingOrgMembership?: boolean;
    /**
     * Full control: return `true` to allow linking the matched user.
     */
    shouldLinkUser?: (payload: {
      user: User;
      email: string;
      provider: {
        providerId: string;
        organizationId?: string;
      };
    }) => boolean | Promise<boolean>;
  };
  /**
   * A callback that runs before a new SCIM token is generated.
   * Runs after the built-in role check, so it can add additional
   * restrictions but cannot bypass the role requirement.
   */
  beforeSCIMTokenGenerated?: (payload: {
    user: User;
    member: Member | null;
    scimToken: string;
  }) => Promise<void>;
  /**
   * A callback that runs after a new SCIM token is generated.
   */
  afterSCIMTokenGenerated?: (payload: {
    user: User;
    member: Member | null;
    scimToken: string;
    scimProvider: SCIMProvider;
  }) => Promise<void>; /** Runs after a SCIM user is provisioned (create). */
  afterSCIMUserProvisioned?: (payload: {
    user: User;
    scimProvider: Omit<SCIMProvider, "id">;
    externalId?: string;
  }) => Promise<void>; /** Runs after org-scoped SCIM deprovision (delete) or active=false deactivation. */
  afterSCIMUserDeprovisioned?: (payload: {
    user: User;
    scimProvider: Omit<SCIMProvider, "id">;
  }) => Promise<void>;
  /**
   * Authorize who may generate a SCIM token. Runs after the built-in checks
   * (org-scoped tokens still require org membership + the required role), so it
   * can add restrictions but cannot loosen them.
   *
   * Use this to lock down *personal* (non-org-scoped) token creation, which is
   * otherwise available to any authenticated user. SCIM tokens can provision
   * and manage users, so return `false` to deny. `member` is `null` for
   * personal tokens.
   */
  canGenerateToken?: (payload: {
    user: User;
    providerId: string;
    organizationId?: string;
    member: Member | null;
  }) => boolean | Promise<boolean>;
  /**
   * How to store the SCIM token in the database.
   *
   * @default "plain"
   */
  storeSCIMToken?: ("hashed" | "plain" | "encrypted" | {
    hash: (scimToken: string) => Promise<string>;
  } | {
    encrypt: (scimToken: string) => Promise<string>;
    decrypt: (scimToken: string) => Promise<string>;
  }) | undefined;
};
//#endregion
//#region src/index.d.ts
declare module "@better-auth/core" {
  interface BetterAuthPluginRegistry<AuthOptions, Options> {
    scim: {
      creator: typeof scim;
    };
  }
}
declare const scim: (options?: SCIMOptions) => {
  id: "scim";
  version: string;
  endpoints: {
    generateSCIMToken: better_call0.StrictEndpoint<"/scim/generate-token", {
      method: "POST";
      body: zod.ZodObject<{
        providerId: zod.ZodString;
        organizationId: zod.ZodOptional<zod.ZodString>;
      }, zod_v4_core0.$strip>;
      metadata: {
        openapi: {
          summary: string;
          description: string;
          responses: {
            "201": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    type: "object";
                    properties: {
                      scimToken: {
                        description: string;
                        type: string;
                      };
                    };
                  };
                };
              };
            };
          };
        };
      };
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
    }, {
      scimToken: string;
    }>;
    listSCIMProviderConnections: better_call0.StrictEndpoint<"/scim/list-provider-connections", {
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
          operationId: string;
          summary: string;
          description: string;
          responses: {
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    type: "object";
                    properties: {
                      providers: {
                        type: string;
                        items: {
                          type: string;
                          properties: {
                            id: {
                              type: string;
                            };
                            providerId: {
                              type: string;
                            };
                            organizationId: {
                              type: string;
                              nullable: boolean;
                            };
                          };
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
      };
    }, {
      providers: {
        id: string;
        providerId: string;
        organizationId: string | null;
      }[];
    }>;
    getSCIMProviderConnection: better_call0.StrictEndpoint<"/scim/get-provider-connection", {
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
      query: zod.ZodObject<{
        providerId: zod.ZodString;
      }, zod_v4_core0.$strip>;
      metadata: {
        openapi: {
          operationId: string;
          summary: string;
          description: string;
          responses: {
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    type: "object";
                    properties: {
                      id: {
                        type: string;
                      };
                      providerId: {
                        type: string;
                      };
                      organizationId: {
                        type: string;
                        nullable: boolean;
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
            };
            "403": {
              description: string;
            };
          };
        };
      };
    }, {
      id: string;
      providerId: string;
      organizationId: string | null;
    }>;
    deleteSCIMProviderConnection: better_call0.StrictEndpoint<"/scim/delete-provider-connection", {
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
      body: zod.ZodObject<{
        providerId: zod.ZodString;
      }, zod_v4_core0.$strip>;
      metadata: {
        openapi: {
          operationId: string;
          summary: string;
          description: string;
          responses: {
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    type: "object";
                    properties: {
                      success: {
                        type: string;
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
            };
            "403": {
              description: string;
            };
          };
        };
      };
    }, {
      success: boolean;
    }>;
    getSCIMUser: better_call0.StrictEndpoint<"/scim/v2/Users/:userId", {
      method: "GET";
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly id: {
                        readonly type: "string";
                      };
                      readonly meta: {
                        readonly type: "object";
                        readonly properties: {
                          readonly resourceType: {
                            readonly type: "string";
                          };
                          readonly created: {
                            readonly type: "string";
                            readonly format: "date-time";
                          };
                          readonly lastModified: {
                            readonly type: "string";
                            readonly format: "date-time";
                          };
                          readonly location: {
                            readonly type: "string";
                          };
                        };
                      };
                      readonly userName: {
                        readonly type: "string";
                      };
                      readonly name: {
                        readonly type: "object";
                        readonly properties: {
                          readonly formatted: {
                            readonly type: "string";
                          };
                          readonly givenName: {
                            readonly type: "string";
                          };
                          readonly familyName: {
                            readonly type: "string";
                          };
                        };
                      };
                      readonly displayName: {
                        readonly type: "string";
                      };
                      readonly active: {
                        readonly type: "boolean";
                      };
                      readonly emails: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "object";
                          readonly properties: {
                            readonly value: {
                              readonly type: "string";
                            };
                            readonly primary: {
                              readonly type: "boolean";
                            };
                          };
                        };
                      };
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
        scope: "server";
      };
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        authSCIMToken: string;
        scimProvider: Omit<SCIMProvider, "id">;
      }>)[];
    }, {
      id: string;
      externalId: string | undefined;
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      userName: string;
      name: {
        formatted: string;
      };
      displayName: string;
      active: boolean;
      emails: {
        primary: boolean;
        value: string;
      }[];
      schemas: string[];
    }>;
    createSCIMUser: better_call0.StrictEndpoint<"/scim/v2/Users", {
      method: "POST";
      body: zod.ZodObject<{
        userName: zod.ZodString;
        externalId: zod.ZodOptional<zod.ZodString>;
        name: zod.ZodOptional<zod.ZodObject<{
          formatted: zod.ZodOptional<zod.ZodString>;
          givenName: zod.ZodOptional<zod.ZodString>;
          familyName: zod.ZodOptional<zod.ZodString>;
        }, zod_v4_core0.$strip>>;
        emails: zod.ZodOptional<zod.ZodArray<zod.ZodObject<{
          value: zod.ZodEmail;
          primary: zod.ZodOptional<zod.ZodBoolean>;
        }, zod_v4_core0.$strip>>>;
        active: zod.ZodOptional<zod.ZodBoolean>;
      }, zod_v4_core0.$strip>;
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "201": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly id: {
                        readonly type: "string";
                      };
                      readonly meta: {
                        readonly type: "object";
                        readonly properties: {
                          readonly resourceType: {
                            readonly type: "string";
                          };
                          readonly created: {
                            readonly type: "string";
                            readonly format: "date-time";
                          };
                          readonly lastModified: {
                            readonly type: "string";
                            readonly format: "date-time";
                          };
                          readonly location: {
                            readonly type: "string";
                          };
                        };
                      };
                      readonly userName: {
                        readonly type: "string";
                      };
                      readonly name: {
                        readonly type: "object";
                        readonly properties: {
                          readonly formatted: {
                            readonly type: "string";
                          };
                          readonly givenName: {
                            readonly type: "string";
                          };
                          readonly familyName: {
                            readonly type: "string";
                          };
                        };
                      };
                      readonly displayName: {
                        readonly type: "string";
                      };
                      readonly active: {
                        readonly type: "boolean";
                      };
                      readonly emails: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "object";
                          readonly properties: {
                            readonly value: {
                              readonly type: "string";
                            };
                            readonly primary: {
                              readonly type: "boolean";
                            };
                          };
                        };
                      };
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
        scope: "server";
      };
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        authSCIMToken: string;
        scimProvider: Omit<SCIMProvider, "id">;
      }>)[];
    }, {
      id: string;
      externalId: string | undefined;
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      userName: string;
      name: {
        formatted: string;
      };
      displayName: string;
      active: boolean;
      emails: {
        primary: boolean;
        value: string;
      }[];
      schemas: string[];
    }>;
    patchSCIMUser: better_call0.StrictEndpoint<"/scim/v2/Users/:userId", {
      method: "PATCH";
      body: zod.ZodObject<{
        schemas: zod.ZodArray<zod.ZodString>;
        Operations: zod.ZodArray<zod.ZodObject<{
          op: zod.ZodPipe<zod.ZodDefault<zod.ZodString>, zod.ZodEnum<{
            replace: "replace";
            add: "add";
            remove: "remove";
          }>>;
          path: zod.ZodOptional<zod.ZodString>;
          value: zod.ZodAny;
        }, zod_v4_core0.$strip>>;
      }, zod_v4_core0.$strip>;
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "204": {
              description: string;
            };
          };
        };
        scope: "server";
      };
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        authSCIMToken: string;
        scimProvider: Omit<SCIMProvider, "id">;
      }>)[];
    }, void>;
    deleteSCIMUser: better_call0.StrictEndpoint<"/scim/v2/Users/:userId", {
      method: "DELETE";
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "204": {
              description: string;
            };
          };
        };
        scope: "server";
      };
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        authSCIMToken: string;
        scimProvider: Omit<SCIMProvider, "id">;
      }>)[];
    }, void>;
    updateSCIMUser: better_call0.StrictEndpoint<"/scim/v2/Users/:userId", {
      method: "PUT";
      body: zod.ZodObject<{
        userName: zod.ZodString;
        externalId: zod.ZodOptional<zod.ZodString>;
        name: zod.ZodOptional<zod.ZodObject<{
          formatted: zod.ZodOptional<zod.ZodString>;
          givenName: zod.ZodOptional<zod.ZodString>;
          familyName: zod.ZodOptional<zod.ZodString>;
        }, zod_v4_core0.$strip>>;
        emails: zod.ZodOptional<zod.ZodArray<zod.ZodObject<{
          value: zod.ZodEmail;
          primary: zod.ZodOptional<zod.ZodBoolean>;
        }, zod_v4_core0.$strip>>>;
        active: zod.ZodOptional<zod.ZodBoolean>;
      }, zod_v4_core0.$strip>;
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly id: {
                        readonly type: "string";
                      };
                      readonly meta: {
                        readonly type: "object";
                        readonly properties: {
                          readonly resourceType: {
                            readonly type: "string";
                          };
                          readonly created: {
                            readonly type: "string";
                            readonly format: "date-time";
                          };
                          readonly lastModified: {
                            readonly type: "string";
                            readonly format: "date-time";
                          };
                          readonly location: {
                            readonly type: "string";
                          };
                        };
                      };
                      readonly userName: {
                        readonly type: "string";
                      };
                      readonly name: {
                        readonly type: "object";
                        readonly properties: {
                          readonly formatted: {
                            readonly type: "string";
                          };
                          readonly givenName: {
                            readonly type: "string";
                          };
                          readonly familyName: {
                            readonly type: "string";
                          };
                        };
                      };
                      readonly displayName: {
                        readonly type: "string";
                      };
                      readonly active: {
                        readonly type: "boolean";
                      };
                      readonly emails: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "object";
                          readonly properties: {
                            readonly value: {
                              readonly type: "string";
                            };
                            readonly primary: {
                              readonly type: "boolean";
                            };
                          };
                        };
                      };
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
        scope: "server";
      };
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        authSCIMToken: string;
        scimProvider: Omit<SCIMProvider, "id">;
      }>)[];
    }, {
      id: string;
      externalId: string | undefined;
      meta: {
        resourceType: string;
        created: Date;
        lastModified: Date;
        location: string;
      };
      userName: string;
      name: {
        formatted: string;
      };
      displayName: string;
      active: boolean;
      emails: {
        primary: boolean;
        value: string;
      }[];
      schemas: string[];
    }>;
    listSCIMUsers: better_call0.StrictEndpoint<"/scim/v2/Users", {
      method: "GET";
      query: zod.ZodOptional<zod.ZodObject<{
        filter: zod.ZodOptional<zod.ZodString>;
      }, zod_v4_core0.$strip>>;
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    type: "object";
                    properties: {
                      totalResults: {
                        type: string;
                      };
                      itemsPerPage: {
                        type: string;
                      };
                      startIndex: {
                        type: string;
                      };
                      Resources: {
                        type: string;
                        items: {
                          readonly type: "object";
                          readonly properties: {
                            readonly id: {
                              readonly type: "string";
                            };
                            readonly meta: {
                              readonly type: "object";
                              readonly properties: {
                                readonly resourceType: {
                                  readonly type: "string";
                                };
                                readonly created: {
                                  readonly type: "string";
                                  readonly format: "date-time";
                                };
                                readonly lastModified: {
                                  readonly type: "string";
                                  readonly format: "date-time";
                                };
                                readonly location: {
                                  readonly type: "string";
                                };
                              };
                            };
                            readonly userName: {
                              readonly type: "string";
                            };
                            readonly name: {
                              readonly type: "object";
                              readonly properties: {
                                readonly formatted: {
                                  readonly type: "string";
                                };
                                readonly givenName: {
                                  readonly type: "string";
                                };
                                readonly familyName: {
                                  readonly type: "string";
                                };
                              };
                            };
                            readonly displayName: {
                              readonly type: "string";
                            };
                            readonly active: {
                              readonly type: "boolean";
                            };
                            readonly emails: {
                              readonly type: "array";
                              readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                  readonly value: {
                                    readonly type: "string";
                                  };
                                  readonly primary: {
                                    readonly type: "boolean";
                                  };
                                };
                              };
                            };
                            readonly schemas: {
                              readonly type: "array";
                              readonly items: {
                                readonly type: "string";
                              };
                            };
                          };
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
        scope: "server";
      };
      use: ((inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<{
        authSCIMToken: string;
        scimProvider: Omit<SCIMProvider, "id">;
      }>)[];
    }, {
      readonly schemas: readonly ["urn:ietf:params:scim:api:messages:2.0:ListResponse"];
      readonly totalResults: 0;
      readonly startIndex: 1;
      readonly itemsPerPage: 0;
      readonly Resources: readonly [];
    } | {
      schemas: string[];
      totalResults: number;
      startIndex: number;
      itemsPerPage: number;
      Resources: {
        id: string;
        externalId: string | undefined;
        meta: {
          resourceType: string;
          created: Date;
          lastModified: Date;
          location: string;
        };
        userName: string;
        name: {
          formatted: string;
        };
        displayName: string;
        active: boolean;
        emails: {
          primary: boolean;
          value: string;
        }[];
        schemas: string[];
      }[];
    }>;
    getSCIMServiceProviderConfig: better_call0.StrictEndpoint<"/scim/v2/ServiceProviderConfig", {
      method: "GET";
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly patch: {
                        type: string;
                        properties: {
                          supported: {
                            type: string;
                          };
                        };
                      };
                      readonly bulk: {
                        type: string;
                        properties: {
                          supported: {
                            type: string;
                          };
                        };
                      };
                      readonly filter: {
                        type: string;
                        properties: {
                          supported: {
                            type: string;
                          };
                        };
                      };
                      readonly changePassword: {
                        type: string;
                        properties: {
                          supported: {
                            type: string;
                          };
                        };
                      };
                      readonly sort: {
                        type: string;
                        properties: {
                          supported: {
                            type: string;
                          };
                        };
                      };
                      readonly etag: {
                        type: string;
                        properties: {
                          supported: {
                            type: string;
                          };
                        };
                      };
                      readonly authenticationSchemes: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "object";
                          readonly properties: {
                            readonly name: {
                              readonly type: "string";
                            };
                            readonly description: {
                              readonly type: "string";
                            };
                            readonly specUri: {
                              readonly type: "string";
                            };
                            readonly type: {
                              readonly type: "string";
                            };
                            readonly primary: {
                              readonly type: "boolean";
                            };
                          };
                        };
                      };
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly meta: {
                        readonly type: "object";
                        readonly properties: {
                          readonly resourceType: {
                            readonly type: "string";
                          };
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
        scope: "server";
      };
    }, {
      patch: {
        supported: boolean;
      };
      bulk: {
        supported: boolean;
      };
      filter: {
        supported: boolean;
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
      schemas: string[];
      meta: {
        resourceType: string;
      };
    }>;
    getSCIMSchemas: better_call0.StrictEndpoint<"/scim/v2/Schemas", {
      method: "GET";
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    type: "array";
                    items: {
                      readonly type: "object";
                      readonly properties: {
                        readonly id: {
                          readonly type: "string";
                        };
                        readonly schemas: {
                          readonly type: "array";
                          readonly items: {
                            readonly type: "string";
                          };
                        };
                        readonly name: {
                          readonly type: "string";
                        };
                        readonly description: {
                          readonly type: "string";
                        };
                        readonly attributes: {
                          readonly type: "array";
                          readonly items: {
                            readonly properties: {
                              readonly subAttributes: {
                                readonly type: "array";
                                readonly items: {
                                  readonly type: "object";
                                  readonly properties: {
                                    readonly name: {
                                      readonly type: "string";
                                    };
                                    readonly type: {
                                      readonly type: "string";
                                    };
                                    readonly multiValued: {
                                      readonly type: "boolean";
                                    };
                                    readonly description: {
                                      readonly type: "string";
                                    };
                                    readonly required: {
                                      readonly type: "boolean";
                                    };
                                    readonly caseExact: {
                                      readonly type: "boolean";
                                    };
                                    readonly mutability: {
                                      readonly type: "string";
                                    };
                                    readonly returned: {
                                      readonly type: "string";
                                    };
                                    readonly uniqueness: {
                                      readonly type: "string";
                                    };
                                  };
                                };
                              };
                              readonly name: {
                                readonly type: "string";
                              };
                              readonly type: {
                                readonly type: "string";
                              };
                              readonly multiValued: {
                                readonly type: "boolean";
                              };
                              readonly description: {
                                readonly type: "string";
                              };
                              readonly required: {
                                readonly type: "boolean";
                              };
                              readonly caseExact: {
                                readonly type: "boolean";
                              };
                              readonly mutability: {
                                readonly type: "string";
                              };
                              readonly returned: {
                                readonly type: "string";
                              };
                              readonly uniqueness: {
                                readonly type: "string";
                              };
                            };
                            readonly type: "object";
                          };
                        };
                        readonly meta: {
                          readonly type: "object";
                          readonly properties: {
                            readonly resourceType: {
                              readonly type: "string";
                            };
                            readonly location: {
                              readonly type: "string";
                            };
                          };
                          readonly required: readonly ["resourceType", "location"];
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
        scope: "server";
      };
    }, {
      totalResults: number;
      itemsPerPage: number;
      startIndex: number;
      schemas: string[];
      Resources: {
        meta: {
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
          caseExact?: undefined;
          uniqueness?: undefined;
          subAttributes?: undefined;
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
            mutability: string;
            returned: string;
            uniqueness: string;
          }[];
          caseExact?: undefined;
          mutability?: undefined;
          returned?: undefined;
          uniqueness?: undefined;
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
            caseExact?: undefined;
            uniqueness?: undefined;
          })[];
          mutability: string;
          returned: string;
          uniqueness: string;
          caseExact?: undefined;
        })[];
      }[];
    }>;
    getSCIMSchema: better_call0.StrictEndpoint<"/scim/v2/Schemas/:schemaId", {
      method: "GET";
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly id: {
                        readonly type: "string";
                      };
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly name: {
                        readonly type: "string";
                      };
                      readonly description: {
                        readonly type: "string";
                      };
                      readonly attributes: {
                        readonly type: "array";
                        readonly items: {
                          readonly properties: {
                            readonly subAttributes: {
                              readonly type: "array";
                              readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                  readonly name: {
                                    readonly type: "string";
                                  };
                                  readonly type: {
                                    readonly type: "string";
                                  };
                                  readonly multiValued: {
                                    readonly type: "boolean";
                                  };
                                  readonly description: {
                                    readonly type: "string";
                                  };
                                  readonly required: {
                                    readonly type: "boolean";
                                  };
                                  readonly caseExact: {
                                    readonly type: "boolean";
                                  };
                                  readonly mutability: {
                                    readonly type: "string";
                                  };
                                  readonly returned: {
                                    readonly type: "string";
                                  };
                                  readonly uniqueness: {
                                    readonly type: "string";
                                  };
                                };
                              };
                            };
                            readonly name: {
                              readonly type: "string";
                            };
                            readonly type: {
                              readonly type: "string";
                            };
                            readonly multiValued: {
                              readonly type: "boolean";
                            };
                            readonly description: {
                              readonly type: "string";
                            };
                            readonly required: {
                              readonly type: "boolean";
                            };
                            readonly caseExact: {
                              readonly type: "boolean";
                            };
                            readonly mutability: {
                              readonly type: "string";
                            };
                            readonly returned: {
                              readonly type: "string";
                            };
                            readonly uniqueness: {
                              readonly type: "string";
                            };
                          };
                          readonly type: "object";
                        };
                      };
                      readonly meta: {
                        readonly type: "object";
                        readonly properties: {
                          readonly resourceType: {
                            readonly type: "string";
                          };
                          readonly location: {
                            readonly type: "string";
                          };
                        };
                        readonly required: readonly ["resourceType", "location"];
                      };
                    };
                  };
                };
              };
            };
          };
        };
        scope: "server";
      };
    }, {
      meta: {
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
        caseExact?: undefined;
        uniqueness?: undefined;
        subAttributes?: undefined;
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
          mutability: string;
          returned: string;
          uniqueness: string;
        }[];
        caseExact?: undefined;
        mutability?: undefined;
        returned?: undefined;
        uniqueness?: undefined;
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
          caseExact?: undefined;
          uniqueness?: undefined;
        })[];
        mutability: string;
        returned: string;
        uniqueness: string;
        caseExact?: undefined;
      })[];
    }>;
    getSCIMResourceTypes: better_call0.StrictEndpoint<"/scim/v2/ResourceTypes", {
      method: "GET";
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    type: "object";
                    properties: {
                      totalResults: {
                        type: string;
                      };
                      itemsPerPage: {
                        type: string;
                      };
                      startIndex: {
                        type: string;
                      };
                      Resources: {
                        type: string;
                        items: {
                          readonly type: "object";
                          readonly properties: {
                            readonly schemas: {
                              readonly type: "array";
                              readonly items: {
                                readonly type: "string";
                              };
                            };
                            readonly id: {
                              readonly type: "string";
                            };
                            readonly name: {
                              readonly type: "string";
                            };
                            readonly endpoint: {
                              readonly type: "string";
                            };
                            readonly description: {
                              readonly type: "string";
                            };
                            readonly schema: {
                              readonly type: "string";
                            };
                            readonly meta: {
                              readonly type: "object";
                              readonly properties: {
                                readonly resourceType: {
                                  readonly type: "string";
                                };
                                readonly location: {
                                  readonly type: "string";
                                };
                              };
                            };
                          };
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
        scope: "server";
      };
    }, {
      totalResults: number;
      itemsPerPage: number;
      startIndex: number;
      schemas: string[];
      Resources: {
        meta: {
          location: string;
          resourceType: string;
        };
        schemas: string[];
        id: string;
        name: string;
        endpoint: string;
        description: string;
        schema: string;
      }[];
    }>;
    getSCIMResourceType: better_call0.StrictEndpoint<"/scim/v2/ResourceTypes/:resourceTypeId", {
      method: "GET";
      metadata: {
        allowedMediaTypes: string[];
        openapi: {
          summary: string;
          description: string;
          responses: {
            "400": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "401": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "403": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "404": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "429": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "500": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly status: {
                        readonly type: "string";
                      };
                      readonly detail: {
                        readonly type: "string";
                      };
                      readonly scimType: {
                        readonly type: "string";
                      };
                    };
                  };
                };
              };
            };
            "200": {
              description: string;
              content: {
                "application/json": {
                  schema: {
                    readonly type: "object";
                    readonly properties: {
                      readonly schemas: {
                        readonly type: "array";
                        readonly items: {
                          readonly type: "string";
                        };
                      };
                      readonly id: {
                        readonly type: "string";
                      };
                      readonly name: {
                        readonly type: "string";
                      };
                      readonly endpoint: {
                        readonly type: "string";
                      };
                      readonly description: {
                        readonly type: "string";
                      };
                      readonly schema: {
                        readonly type: "string";
                      };
                      readonly meta: {
                        readonly type: "object";
                        readonly properties: {
                          readonly resourceType: {
                            readonly type: "string";
                          };
                          readonly location: {
                            readonly type: "string";
                          };
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
        scope: "server";
      };
    }, {
      meta: {
        location: string;
        resourceType: string;
      };
      schemas: string[];
      id: string;
      name: string;
      endpoint: string;
      description: string;
      schema: string;
    }>;
  };
  schema: {
    scimProvider: {
      fields: {
        userId?: {
          type: "string";
          required: false;
        } | undefined;
        providerId: {
          type: "string";
          required: true;
          unique: true;
        };
        scimToken: {
          type: "string";
          required: true;
          unique: true;
        };
        organizationId: {
          type: "string";
          required: false;
        };
      };
    };
  };
  options: SCIMOptions | undefined;
};
//#endregion
export { SCIMEmail, SCIMName, SCIMOptions, SCIMProvider, scim };