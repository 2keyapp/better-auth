import { mergeSchema } from "../../db/schema.mjs";
import { sessionMiddleware } from "../../api/routes/session.mjs";
import { APIError } from "../../api/index.mjs";
import { PACKAGE_VERSION } from "../../version.mjs";
import { getDelegatePermissionsAdapter } from "./adapter.mjs";
import { actionCovers } from "./capability/action.mjs";
import { dnsPrefixSubset, resourceSatisfiesScope, scopeMapSubset, scopeValueSubset } from "./capability/scope.mjs";
import { authorize } from "./capability/authorize.mjs";
import { expandProfile } from "./capability/expand.mjs";
import { assertSubset } from "./capability/subset.mjs";
import { secondsToDays } from "./defaults.mjs";
import { DELEGATE_PERMISSIONS_ERROR_CODES } from "./error-codes.mjs";
import { capabilitySetSchema, parseCapabilitySet } from "./parse.mjs";
import { attachPlatformCertCosign, verifyPlatformCertCosign } from "./pki/cert-cosign.mjs";
import { attachPlatformCosign, issueCredential, verifyCredentialSignature } from "./pki/credential.mjs";
import { generateEd25519KeyPair } from "./pki/keys.mjs";
import { bindCsrToPublicJwk, createDeviceCsr, leafMatchesCsr, signCsrWithCa } from "./pki/csr.mjs";
import { createPlatformRootPem, createSelfSignedCaPem, generateEphemeralPlatformCa, issuePlatformEndorsementCert, loadPlatformCaMaterial, verifyAgainstTrustAnchor } from "./pki/platform-ca.mjs";
import { createCredentialEndpoints } from "./credentials.mjs";
import { createEnrollEndpoints } from "./enroll.mjs";
import { createLifecycleEndpoints } from "./lifecycle.mjs";
import { schema } from "./schema.mjs";
import { DEMO_CATALOG_SEED, DEMO_SERVICE_ID } from "./seeds/demo.mjs";
import { DEMO_PLATFORM_CA } from "./seeds/demo-platform-ca.mjs";
import { createAuthEndpoint } from "@better-auth/core/api";
import * as z from "zod";
//#region src/plugins/delegate-permissions/index.ts
function resolveSeed(seed, serviceId) {
	if (!seed) return null;
	if (seed === "demo") return {
		...DEMO_CATALOG_SEED,
		serviceId
	};
	return {
		...seed,
		serviceId: seed.serviceId || serviceId
	};
}
function defaultTestCosign(platform, certExpires) {
	return {
		async cosignRoot(credential) {
			return attachPlatformCosign(credential, platform.key.privateJwk, platform.key.ski);
		},
		async cosignMachine(credential, _seatId) {
			return attachPlatformCosign(credential, platform.key.privateJwk, platform.key.ski);
		},
		async cosignCaCert(caCertPem) {
			return issuePlatformEndorsementCert({
				platform,
				entityCertPem: caCertPem,
				kind: "ca",
				notAfterDays: secondsToDays(certExpires.caCertExpiresIn)
			});
		},
		async cosignLeafCert(leafCertPem, opts) {
			return issuePlatformEndorsementCert({
				platform,
				entityCertPem: leafCertPem,
				kind: "leaf",
				chainPem: opts?.chainPem,
				subjectCn: opts?.subjectSki,
				host: opts?.host,
				notAfterDays: secondsToDays(certExpires.leafCertExpiresIn)
			});
		}
	};
}
const resourceSchema = z.record(z.string(), z.union([z.string(), z.array(z.string())]));
/**
* Delegate Permissions plugin.
*
* Production mTLS: set `platformCa` (stable key). The TLS terminator `ca-file`
* is the Platform Root from `GET /delegate-permissions/platform-root`. Machine
* leaves are Platform-endorsed (`platformCertPem` on enroll-pull).
* `seed: "demo"` includes a demo Platform CA — do not use that key in production.
*/
const delegatePermissions = (options) => {
	const serviceId = options?.serviceId ?? "default";
	const sessionGrantExpiresIn = options?.sessionGrantExpiresIn ?? 3600;
	const inviteExpiresIn = options?.inviteExpiresIn ?? 604800;
	const inviteMaxExpiresIn = options?.inviteMaxExpiresIn ?? 2592e3;
	const inviteMaxUses = options?.inviteMaxUses ?? 1;
	const credentialExpiresIn = options?.credentialExpiresIn ?? 31536e3;
	const caCertExpiresIn = options?.caCertExpiresIn ?? 31536e4;
	const leafCertExpiresIn = options?.leafCertExpiresIn ?? 31536e3;
	const allowClientSeed = options?.allowClientSeed ?? false;
	const allowServerKeygen = options?.allowServerKeygen ?? false;
	const allowEphemeralPlatformCa = options?.allowEphemeralPlatformCa ?? allowServerKeygen;
	const configuredSeed = resolveSeed(options?.seed, serviceId);
	const demoPlatformCa = options?.seed === "demo" && !options?.platformCa && !options?.cosign ? {
		privateJwk: { ...DEMO_PLATFORM_CA.privateJwk },
		commonName: DEMO_PLATFORM_CA.commonName
	} : void 0;
	let resolvedPlatformCa;
	const resolvePlatformCa = async () => {
		if (resolvedPlatformCa) return resolvedPlatformCa;
		if (options?.platformCa) {
			resolvedPlatformCa = await loadPlatformCaMaterial({
				...options.platformCa,
				notAfterDays: secondsToDays(caCertExpiresIn)
			});
			return resolvedPlatformCa;
		}
		if (demoPlatformCa) {
			resolvedPlatformCa = await loadPlatformCaMaterial({
				...demoPlatformCa,
				notAfterDays: secondsToDays(caCertExpiresIn)
			});
			return resolvedPlatformCa;
		}
		if (allowEphemeralPlatformCa) {
			resolvedPlatformCa = await generateEphemeralPlatformCa(void 0, secondsToDays(caCertExpiresIn));
			return resolvedPlatformCa;
		}
		throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.COSIGN_REQUIRED);
	};
	const resolveCosign = async () => {
		if (options?.cosign) return options.cosign;
		return defaultTestCosign(await resolvePlatformCa(), {
			caCertExpiresIn,
			leafCertExpiresIn
		});
	};
	const credentialEndpoints = createCredentialEndpoints({
		serviceId,
		configuredSeed,
		allowServerKeygen,
		cosign: options?.cosign,
		seatBinder: options?.seatBinder,
		getFallbackCosignKey: async () => (await resolvePlatformCa()).key,
		resolveCosign,
		onEntityKickstart: options?.onEntityKickstart,
		credentialExpiresIn,
		caCertExpiresIn
	});
	const enrollEndpoints = createEnrollEndpoints({
		serviceId,
		configuredSeed,
		cosign: options?.cosign,
		seatBinder: options?.seatBinder,
		resolveCosign,
		inviteExpiresIn,
		inviteMaxExpiresIn,
		inviteMaxUses,
		credentialExpiresIn
	});
	const lifecycleEndpoints = createLifecycleEndpoints({
		serviceId,
		configuredSeed,
		resolveCosign,
		seatBinder: options?.seatBinder
	});
	return {
		id: "delegate-permissions",
		version: PACKAGE_VERSION,
		options,
		schema: mergeSchema(schema, {}),
		endpoints: {
			...credentialEndpoints,
			...enrollEndpoints,
			...lifecycleEndpoints,
			dpPlatformRoot: createAuthEndpoint("/delegate-permissions/platform-root", {
				method: "GET",
				metadata: { openapi: { description: "Platform Root PEM for HAProxy ca-file (public key of the co-signing CA)" } }
			}, async () => {
				if (options?.platformCa || demoPlatformCa || allowEphemeralPlatformCa) {
					const platform = await resolvePlatformCa();
					return {
						platformRootPem: platform.rootPem.endsWith("\n") ? platform.rootPem : `${platform.rootPem}\n`,
						ski: platform.key.ski
					};
				}
				throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.COSIGN_REQUIRED);
			}),
			dpSeedCatalog: createAuthEndpoint("/delegate-permissions/seed-catalog", {
				method: "POST",
				body: z.object({ force: z.boolean().optional() }).optional(),
				metadata: { openapi: { description: "Seed the delegate-permissions catalog for this service" } }
			}, async (ctx) => {
				if (!allowClientSeed && ctx.request) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.SEED_DISABLED);
				if (!configuredSeed) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.SEED_DISABLED);
				const dp = getDelegatePermissionsAdapter(ctx.context.adapter, serviceId);
				const existing = await dp.loadCatalog(ctx);
				if (existing && !ctx.body?.force) return {
					seeded: false,
					catalog: existing
				};
				return {
					seeded: true,
					catalog: await dp.seedCatalog(configuredSeed, ctx)
				};
			}),
			dpGetCatalog: createAuthEndpoint("/delegate-permissions/catalog", {
				method: "GET",
				use: [sessionMiddleware],
				metadata: { openapi: { description: "Get the delegate-permissions catalog" } }
			}, async (ctx) => {
				const dp = getDelegatePermissionsAdapter(ctx.context.adapter, serviceId);
				let catalog = await dp.loadCatalog(ctx);
				if (!catalog && configuredSeed) catalog = await dp.seedCatalog(configuredSeed, ctx);
				if (!catalog) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED);
				const profiles = await dp.loadProfiles(ctx);
				return {
					catalog,
					profiles
				};
			}),
			dpSetPrincipalGrant: createAuthEndpoint("/delegate-permissions/principal-grant", {
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({
					permissions: capabilitySetSchema.optional(),
					profile: z.string().optional(),
					entityId: z.string().optional()
				}),
				metadata: { openapi: { description: "Set the caller's principal capability grant from a profile or explicit permissions" } }
			}, async (ctx) => {
				const dp = getDelegatePermissionsAdapter(ctx.context.adapter, serviceId);
				let catalog = await dp.loadCatalog(ctx);
				if (!catalog && configuredSeed) catalog = await dp.seedCatalog(configuredSeed, ctx);
				if (!catalog) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED);
				let permissions;
				if (ctx.body.profile) {
					const profiles = await dp.loadProfiles(ctx);
					try {
						permissions = expandProfile(ctx.body.profile, profiles, catalog);
					} catch {
						throw APIError.from("BAD_REQUEST", {
							message: `Unknown profile: ${ctx.body.profile}`,
							code: "UNKNOWN_PROFILE"
						});
					}
				} else if (ctx.body.permissions) try {
					permissions = parseCapabilitySet(ctx.body.permissions);
				} catch {
					throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CAPABILITY_SET);
				}
				else throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CAPABILITY_SET);
				const grant = await dp.upsertPrincipalGrant({
					userId: ctx.context.session.user.id,
					entityId: ctx.body.entityId ?? null,
					permissions,
					profile: ctx.body.profile ?? null
				});
				return { grant: {
					id: grant.id,
					userId: grant.userId,
					entityId: grant.entityId,
					permissions: grant.permissions,
					profile: grant.profile,
					expiresAt: grant.expiresAt
				} };
			}),
			dpIssueSessionCapabilities: createAuthEndpoint("/delegate-permissions/issue-session-capabilities", {
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({ permissions: capabilitySetSchema.optional() }).optional(),
				metadata: { openapi: { description: "Issue a session CapabilitySet attenuated from the principal grant" } }
			}, async (ctx) => {
				const dp = getDelegatePermissionsAdapter(ctx.context.adapter, serviceId);
				let catalog = await dp.loadCatalog(ctx);
				if (!catalog && configuredSeed) catalog = await dp.seedCatalog(configuredSeed, ctx);
				if (!catalog) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED);
				const principal = await dp.getPrincipalGrant(ctx.context.session.user.id, ctx);
				if (!principal) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.NO_PRINCIPAL_GRANT);
				if (principal.expiresAt && principal.expiresAt.getTime() < Date.now()) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.GRANT_EXPIRED);
				let sessionPermissions = principal.permissions;
				if (ctx.body?.permissions) {
					let child;
					try {
						child = parseCapabilitySet(ctx.body.permissions);
					} catch {
						throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CAPABILITY_SET);
					}
					const subset = assertSubset(child, principal.permissions, catalog);
					if (!subset.ok) throw APIError.from("FORBIDDEN", {
						message: subset.message,
						code: subset.code
					});
					sessionPermissions = child;
				}
				const expiresAt = new Date(Date.now() + sessionGrantExpiresIn * 1e3);
				const grant = await dp.upsertSessionGrant({
					sessionId: ctx.context.session.session.id,
					userId: ctx.context.session.user.id,
					permissions: sessionPermissions,
					expiresAt
				});
				return {
					permissions: grant.permissions,
					expiresAt: grant.expiresAt,
					catalogGeneration: catalog.generation
				};
			}),
			dpAuthorize: createAuthEndpoint("/delegate-permissions/authorize", {
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({
					action: z.string().min(1),
					resource: resourceSchema.default({})
				}),
				metadata: { openapi: { description: "Authorize an action against the session (or principal) CapabilitySet" } }
			}, async (ctx) => {
				const dp = getDelegatePermissionsAdapter(ctx.context.adapter, serviceId);
				let catalog = await dp.loadCatalog(ctx);
				if (!catalog && configuredSeed) catalog = await dp.seedCatalog(configuredSeed, ctx);
				if (!catalog) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED);
				const sessionGrant = await dp.getSessionGrant(ctx.context.session.session.id, ctx);
				let grants = null;
				if (sessionGrant) {
					if (sessionGrant.expiresAt.getTime() < Date.now()) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.GRANT_EXPIRED);
					grants = sessionGrant.permissions;
				} else {
					const principal = await dp.getPrincipalGrant(ctx.context.session.user.id, ctx);
					if (!principal) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.NO_SESSION_GRANT);
					if (principal.expiresAt && principal.expiresAt.getTime() < Date.now()) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.GRANT_EXPIRED);
					grants = principal.permissions;
				}
				const result = authorize(grants, ctx.body.action, ctx.body.resource, catalog);
				if (!result.ok) return {
					allowed: false,
					code: result.code,
					message: result.message
				};
				return { allowed: true };
			}),
			dpAssertSubset: createAuthEndpoint("/delegate-permissions/assert-subset", {
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({
					parent: capabilitySetSchema,
					child: capabilitySetSchema
				}),
				metadata: { openapi: { description: "Check whether child CapabilitySet ⊆ parent under the catalog algebra" } }
			}, async (ctx) => {
				const dp = getDelegatePermissionsAdapter(ctx.context.adapter, serviceId);
				let catalog = await dp.loadCatalog(ctx);
				if (!catalog && configuredSeed) catalog = await dp.seedCatalog(configuredSeed, ctx);
				if (!catalog) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED);
				let parent;
				let child;
				try {
					parent = parseCapabilitySet(ctx.body.parent);
					child = parseCapabilitySet(ctx.body.child);
				} catch {
					throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CAPABILITY_SET);
				}
				const result = assertSubset(child, parent, catalog);
				if (!result.ok) return {
					ok: false,
					code: result.code,
					message: result.message
				};
				return { ok: true };
			})
		}
	};
};
//#endregion
export { DELEGATE_PERMISSIONS_ERROR_CODES, DEMO_CATALOG_SEED, DEMO_PLATFORM_CA, DEMO_SERVICE_ID, actionCovers, assertSubset, attachPlatformCertCosign, attachPlatformCosign, authorize, bindCsrToPublicJwk, createDeviceCsr, createPlatformRootPem, createSelfSignedCaPem, delegatePermissions, dnsPrefixSubset, expandProfile, generateEd25519KeyPair, generateEphemeralPlatformCa, issueCredential, issuePlatformEndorsementCert, leafMatchesCsr, loadPlatformCaMaterial, resourceSatisfiesScope, schema, scopeMapSubset, scopeValueSubset, signCsrWithCa, verifyAgainstTrustAnchor, verifyCredentialSignature, verifyPlatformCertCosign };
