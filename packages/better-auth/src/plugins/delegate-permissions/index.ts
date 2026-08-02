import type { BetterAuthPlugin } from "@better-auth/core";
import { createAuthEndpoint } from "@better-auth/core/api";
import * as z from "zod";
import { APIError, sessionMiddleware } from "../../api";
import { mergeSchema } from "../../db/schema";
import { PACKAGE_VERSION } from "../../version";
import { getDelegatePermissionsAdapter } from "./adapter";
import { authorize } from "./capability/authorize";
import { expandProfile } from "./capability/expand";
import { assertSubset } from "./capability/subset";
import type { CapabilitySet, Resource } from "./capability/types";
import { DELEGATE_PERMISSIONS_ERROR_CODES } from "./error-codes";
import { capabilitySetSchema, parseCapabilitySet } from "./parse";
import { schema } from "./schema";
import type { CatalogSeed } from "./seeds/idr";
import { IDR_CATALOG_SEED } from "./seeds/idr";
import type { DelegatePermissionsOptions } from "./types";

export type * from "./capability";
export {
	actionCovers,
	assertSubset,
	authorize,
	dnsPrefixSubset,
	expandProfile,
	resourceSatisfiesScope,
	scopeMapSubset,
	scopeValueSubset,
} from "./capability";
export { DELEGATE_PERMISSIONS_ERROR_CODES } from "./error-codes";
export { schema } from "./schema";
export { IDR_CATALOG_SEED, IDR_SERVICE_ID } from "./seeds/idr";
export type * from "./types";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		"delegate-permissions": {
			creator: typeof delegatePermissions;
		};
	}
}

function resolveSeed(
	seed: DelegatePermissionsOptions["seed"],
	serviceId: string,
): CatalogSeed | null {
	if (!seed) {
		return null;
	}
	if (seed === "idr") {
		return { ...IDR_CATALOG_SEED, serviceId };
	}
	return { ...seed, serviceId: seed.serviceId || serviceId };
}

const resourceSchema = z.record(
	z.string(),
	z.union([z.string(), z.array(z.string())]),
);

export const delegatePermissions = (options?: DelegatePermissionsOptions) => {
	const serviceId = options?.serviceId ?? "default";
	const sessionGrantExpiresIn = options?.sessionGrantExpiresIn ?? 3600;
	const allowClientSeed = options?.allowClientSeed ?? false;
	const configuredSeed = resolveSeed(options?.seed, serviceId);

	return {
		id: "delegate-permissions",
		version: PACKAGE_VERSION,
		options: options as DelegatePermissionsOptions | undefined,
		schema: mergeSchema(schema, {}),
		endpoints: {
			dpSeedCatalog: createAuthEndpoint(
				"/delegate-permissions/seed-catalog",
				{
					method: "POST",
					body: z
						.object({
							force: z.boolean().optional(),
						})
						.optional(),
					metadata: {
						openapi: {
							description:
								"Seed the delegate-permissions catalog for this service",
						},
					},
				},
				async (ctx) => {
					if (!allowClientSeed && ctx.request) {
						throw APIError.from(
							"FORBIDDEN",
							DELEGATE_PERMISSIONS_ERROR_CODES.SEED_DISABLED,
						);
					}
					if (!configuredSeed) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.SEED_DISABLED,
						);
					}
					const dp = getDelegatePermissionsAdapter(
						ctx.context.adapter,
						serviceId,
					);
					const existing = await dp.loadCatalog(ctx);
					if (existing && !ctx.body?.force) {
						return {
							seeded: false,
							catalog: existing,
						};
					}
					const catalog = await dp.seedCatalog(configuredSeed, ctx);
					return { seeded: true, catalog };
				},
			),

			dpGetCatalog: createAuthEndpoint(
				"/delegate-permissions/catalog",
				{
					method: "GET",
					use: [sessionMiddleware],
					metadata: {
						openapi: {
							description: "Get the delegate-permissions catalog",
						},
					},
				},
				async (ctx) => {
					const dp = getDelegatePermissionsAdapter(
						ctx.context.adapter,
						serviceId,
					);
					let catalog = await dp.loadCatalog(ctx);
					if (!catalog && configuredSeed) {
						catalog = await dp.seedCatalog(configuredSeed, ctx);
					}
					if (!catalog) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED,
						);
					}
					const profiles = await dp.loadProfiles(ctx);
					return { catalog, profiles };
				},
			),

			dpSetPrincipalGrant: createAuthEndpoint(
				"/delegate-permissions/principal-grant",
				{
					method: "POST",
					use: [sessionMiddleware],
					body: z.object({
						permissions: capabilitySetSchema.optional(),
						profile: z.string().optional(),
						entityId: z.string().optional(),
					}),
					metadata: {
						openapi: {
							description:
								"Set the caller's principal capability grant from a profile or explicit permissions",
						},
					},
				},
				async (ctx) => {
					const dp = getDelegatePermissionsAdapter(
						ctx.context.adapter,
						serviceId,
					);
					let catalog = await dp.loadCatalog(ctx);
					if (!catalog && configuredSeed) {
						catalog = await dp.seedCatalog(configuredSeed, ctx);
					}
					if (!catalog) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED,
						);
					}

					let permissions: CapabilitySet;
					if (ctx.body.profile) {
						const profiles = await dp.loadProfiles(ctx);
						try {
							permissions = expandProfile(ctx.body.profile, profiles, catalog);
						} catch {
							throw APIError.from("BAD_REQUEST", {
								message: `Unknown profile: ${ctx.body.profile}`,
								code: "UNKNOWN_PROFILE",
							});
						}
					} else if (ctx.body.permissions) {
						try {
							permissions = parseCapabilitySet(ctx.body.permissions);
						} catch {
							throw APIError.from(
								"BAD_REQUEST",
								DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CAPABILITY_SET,
							);
						}
					} else {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CAPABILITY_SET,
						);
					}

					const grant = await dp.upsertPrincipalGrant({
						userId: ctx.context.session.user.id,
						entityId: ctx.body.entityId ?? null,
						permissions,
						profile: ctx.body.profile ?? null,
					});
					return {
						grant: {
							id: grant.id,
							userId: grant.userId,
							entityId: grant.entityId,
							permissions: grant.permissions,
							profile: grant.profile,
							expiresAt: grant.expiresAt,
						},
					};
				},
			),

			dpIssueSessionCapabilities: createAuthEndpoint(
				"/delegate-permissions/issue-session-capabilities",
				{
					method: "POST",
					use: [sessionMiddleware],
					body: z
						.object({
							permissions: capabilitySetSchema.optional(),
						})
						.optional(),
					metadata: {
						openapi: {
							description:
								"Issue a session CapabilitySet attenuated from the principal grant",
						},
					},
				},
				async (ctx) => {
					const dp = getDelegatePermissionsAdapter(
						ctx.context.adapter,
						serviceId,
					);
					let catalog = await dp.loadCatalog(ctx);
					if (!catalog && configuredSeed) {
						catalog = await dp.seedCatalog(configuredSeed, ctx);
					}
					if (!catalog) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED,
						);
					}

					const principal = await dp.getPrincipalGrant(
						ctx.context.session.user.id,
						ctx,
					);
					if (!principal) {
						throw APIError.from(
							"FORBIDDEN",
							DELEGATE_PERMISSIONS_ERROR_CODES.NO_PRINCIPAL_GRANT,
						);
					}
					if (
						principal.expiresAt &&
						principal.expiresAt.getTime() < Date.now()
					) {
						throw APIError.from(
							"FORBIDDEN",
							DELEGATE_PERMISSIONS_ERROR_CODES.GRANT_EXPIRED,
						);
					}

					let sessionPermissions: CapabilitySet = principal.permissions;
					if (ctx.body?.permissions) {
						let child: CapabilitySet;
						try {
							child = parseCapabilitySet(ctx.body.permissions);
						} catch {
							throw APIError.from(
								"BAD_REQUEST",
								DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CAPABILITY_SET,
							);
						}
						const subset = assertSubset(child, principal.permissions, catalog);
						if (!subset.ok) {
							throw APIError.from("FORBIDDEN", {
								message: subset.message,
								code: subset.code,
							});
						}
						sessionPermissions = child;
					}

					const expiresAt = new Date(Date.now() + sessionGrantExpiresIn * 1000);
					const grant = await dp.upsertSessionGrant({
						sessionId: ctx.context.session.session.id,
						userId: ctx.context.session.user.id,
						permissions: sessionPermissions,
						expiresAt,
					});

					return {
						permissions: grant.permissions,
						expiresAt: grant.expiresAt,
						catalogGeneration: catalog.generation,
					};
				},
			),

			dpAuthorize: createAuthEndpoint(
				"/delegate-permissions/authorize",
				{
					method: "POST",
					use: [sessionMiddleware],
					body: z.object({
						action: z.string().min(1),
						resource: resourceSchema.default({}),
					}),
					metadata: {
						openapi: {
							description:
								"Authorize an action against the session (or principal) CapabilitySet",
						},
					},
				},
				async (ctx) => {
					const dp = getDelegatePermissionsAdapter(
						ctx.context.adapter,
						serviceId,
					);
					let catalog = await dp.loadCatalog(ctx);
					if (!catalog && configuredSeed) {
						catalog = await dp.seedCatalog(configuredSeed, ctx);
					}
					if (!catalog) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED,
						);
					}

					const sessionGrant = await dp.getSessionGrant(
						ctx.context.session.session.id,
						ctx,
					);
					let grants: CapabilitySet | null = null;
					if (sessionGrant) {
						if (sessionGrant.expiresAt.getTime() < Date.now()) {
							throw APIError.from(
								"FORBIDDEN",
								DELEGATE_PERMISSIONS_ERROR_CODES.GRANT_EXPIRED,
							);
						}
						grants = sessionGrant.permissions;
					} else {
						const principal = await dp.getPrincipalGrant(
							ctx.context.session.user.id,
							ctx,
						);
						if (!principal) {
							throw APIError.from(
								"FORBIDDEN",
								DELEGATE_PERMISSIONS_ERROR_CODES.NO_SESSION_GRANT,
							);
						}
						if (
							principal.expiresAt &&
							principal.expiresAt.getTime() < Date.now()
						) {
							throw APIError.from(
								"FORBIDDEN",
								DELEGATE_PERMISSIONS_ERROR_CODES.GRANT_EXPIRED,
							);
						}
						grants = principal.permissions;
					}

					const result = authorize(
						grants,
						ctx.body.action,
						ctx.body.resource as Resource,
						catalog,
					);
					if (!result.ok) {
						return {
							allowed: false as const,
							code: result.code,
							message: result.message,
						};
					}
					return { allowed: true as const };
				},
			),

			dpAssertSubset: createAuthEndpoint(
				"/delegate-permissions/assert-subset",
				{
					method: "POST",
					use: [sessionMiddleware],
					body: z.object({
						parent: capabilitySetSchema,
						child: capabilitySetSchema,
					}),
					metadata: {
						openapi: {
							description:
								"Check whether child CapabilitySet ⊆ parent under the catalog algebra",
						},
					},
				},
				async (ctx) => {
					const dp = getDelegatePermissionsAdapter(
						ctx.context.adapter,
						serviceId,
					);
					let catalog = await dp.loadCatalog(ctx);
					if (!catalog && configuredSeed) {
						catalog = await dp.seedCatalog(configuredSeed, ctx);
					}
					if (!catalog) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED,
						);
					}
					let parent: CapabilitySet;
					let child: CapabilitySet;
					try {
						parent = parseCapabilitySet(ctx.body.parent);
						child = parseCapabilitySet(ctx.body.child);
					} catch {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CAPABILITY_SET,
						);
					}
					const result = assertSubset(child, parent, catalog);
					if (!result.ok) {
						return {
							ok: false as const,
							code: result.code,
							message: result.message,
						};
					}
					return { ok: true as const };
				},
			),
		},
	} satisfies BetterAuthPlugin;
};

export type DelegatePermissionsPlugin = ReturnType<typeof delegatePermissions>;
