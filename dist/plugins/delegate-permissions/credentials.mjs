import { sessionMiddleware } from "../../api/routes/session.mjs";
import { APIError } from "../../api/index.mjs";
import { getDelegatePermissionsAdapter } from "./adapter.mjs";
import { expandProfile } from "./capability/expand.mjs";
import { assertSubset } from "./capability/subset.mjs";
import { secondsToDays } from "./defaults.mjs";
import { DELEGATE_PERMISSIONS_ERROR_CODES } from "./error-codes.mjs";
import { machineNameKey, parseMachineHost, zoneNameKey, zoneUnderParent } from "./names.mjs";
import { capabilitySetSchema, parseCapabilitySet } from "./parse.mjs";
import { issueCredential } from "./pki/credential.mjs";
import { generateEd25519KeyPair } from "./pki/keys.mjs";
import { createSelfSignedCaPem } from "./pki/platform-ca.mjs";
import { createAuthEndpoint } from "@better-auth/core/api";
import * as z from "zod";
//#region src/plugins/delegate-permissions/credentials.ts
function withEntityScope(permissions, entityId) {
	return permissions.map((p) => ({
		...p,
		scope: {
			...p.scope,
			entity: entityId
		}
	}));
}
function withNameScope(permissions, name) {
	return permissions.map((p) => ({
		...p,
		scope: {
			...p.scope,
			name
		}
	}));
}
async function ensureCatalog(dp, configuredSeed) {
	let catalog = await dp.loadCatalog();
	if (!catalog && configuredSeed) catalog = await dp.seedCatalog(configuredSeed);
	if (!catalog) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED);
	return catalog;
}
function createCredentialEndpoints(opts) {
	const credentialExpiresIn = opts.credentialExpiresIn ?? 31536e3;
	const caCertExpiresIn = opts.caCertExpiresIn ?? 31536e4;
	const dpOf = (adapter) => getDelegatePermissionsAdapter(adapter, opts.serviceId);
	return {
		dpKickstartEntity: createAuthEndpoint("/delegate-permissions/kickstart-entity", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({
				entityId: z.string().min(1),
				package: z.enum(["personal", "enterprise"]),
				rootPublicJwk: z.record(z.string(), z.unknown()).optional(),
				adminPublicJwk: z.record(z.string(), z.unknown()).optional(),
				rootCredential: z.record(z.string(), z.unknown()).optional(),
				adminCredential: z.record(z.string(), z.unknown()).optional(),
				caCertPem: z.string().optional()
			}),
			metadata: { openapi: { description: "Create Entity Root + Root Admin credentials and bind to the session user" } }
		}, async (ctx) => {
			const clientKeyed = !!ctx.body.rootPublicJwk && !!ctx.body.adminPublicJwk && !!ctx.body.rootCredential && !!ctx.body.adminCredential && !!ctx.body.caCertPem;
			if (!opts.allowServerKeygen && !clientKeyed) throw APIError.from("BAD_REQUEST", {
				message: "Server keygen disabled; provide client-generated root/admin JWKs, signed credentials, and caCertPem",
				code: "SERVER_KEYGEN_DISABLED"
			});
			const dp = dpOf(ctx.context.adapter);
			const catalog = await ensureCatalog(dp, opts.configuredSeed);
			const entityId = ctx.body.entityId.toLowerCase();
			if (await dp.getEntity(entityId)) throw APIError.from("CONFLICT", DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_EXISTS);
			const entityPackage = ctx.body.package;
			const profileName = entityPackage === "personal" ? "personal_root" : "root_admin";
			const basePermissions = withEntityScope(expandProfile(profileName, await dp.loadProfiles(), catalog), entityId);
			const cosign = await opts.resolveCosign();
			if (clientKeyed) {
				let rootCredential = ctx.body.rootCredential;
				const adminCredential = ctx.body.adminCredential;
				rootCredential = await cosign.cosignRoot(rootCredential);
				const platformCaCertCosign = await cosign.cosignCaCert(ctx.body.caCertPem);
				await dp.createEntity({
					entityId,
					package: entityPackage,
					rootSki: rootCredential.ski,
					ownerUserId: ctx.context.session.user.id,
					caCertPem: ctx.body.caCertPem,
					platformCaCertCosign
				});
				await dp.createCredential({ credential: rootCredential });
				await dp.createCredential({ credential: adminCredential });
				await dp.bindUserCredential({
					userId: ctx.context.session.user.id,
					credentialSki: adminCredential.ski,
					entityId,
					isPrimary: true
				});
				await dp.upsertPrincipalGrant({
					userId: ctx.context.session.user.id,
					entityId,
					permissions: basePermissions,
					profile: profileName
				});
				await opts.onEntityKickstart?.({
					entityId,
					package: entityPackage,
					rootSki: rootCredential.ski,
					caCertPem: ctx.body.caCertPem,
					platformCaCertCosign
				});
				return {
					entityId,
					package: entityPackage,
					root: { credential: rootCredential },
					rootAdmin: { credential: adminCredential },
					caCertPem: ctx.body.caCertPem,
					platformCaCertPem: platformCaCertCosign.platformCertPem,
					platformRootPem: platformCaCertCosign.platformRootPem,
					platformCaCertCosign
				};
			}
			const rootKeys = await generateEd25519KeyPair();
			const adminKeys = await generateEd25519KeyPair();
			let rootCredential = await issueCredential({
				kind: "entity_root",
				entityId,
				subject: rootKeys,
				permissions: basePermissions,
				issuerSki: rootKeys.ski,
				issuerPrivateJwk: rootKeys.privateJwk,
				package: entityPackage,
				ttlSeconds: credentialExpiresIn
			});
			rootCredential = await cosign.cosignRoot(rootCredential);
			const entityCa = await createSelfSignedCaPem(rootKeys.privateJwk, `Entity CA ${entityId}`, secondsToDays(caCertExpiresIn));
			const platformCaCertCosign = await cosign.cosignCaCert(entityCa.rootPem);
			const adminCredential = await issueCredential({
				kind: "root_admin",
				entityId,
				subject: adminKeys,
				permissions: basePermissions,
				issuerSki: rootKeys.ski,
				issuerPrivateJwk: rootKeys.privateJwk,
				package: entityPackage,
				zone: "",
				ttlSeconds: credentialExpiresIn
			});
			await dp.createEntity({
				entityId,
				package: entityPackage,
				rootSki: rootKeys.ski,
				ownerUserId: ctx.context.session.user.id,
				caCertPem: entityCa.rootPem,
				platformCaCertCosign
			});
			await dp.createCredential({ credential: rootCredential });
			await dp.createCredential({ credential: adminCredential });
			await dp.bindUserCredential({
				userId: ctx.context.session.user.id,
				credentialSki: adminKeys.ski,
				entityId,
				isPrimary: true
			});
			await dp.upsertPrincipalGrant({
				userId: ctx.context.session.user.id,
				entityId,
				permissions: basePermissions,
				profile: profileName
			});
			await opts.onEntityKickstart?.({
				entityId,
				package: entityPackage,
				rootSki: rootKeys.ski,
				caCertPem: entityCa.rootPem,
				platformCaCertCosign
			});
			return {
				entityId,
				package: entityPackage,
				root: {
					credential: rootCredential,
					privateJwk: rootKeys.privateJwk
				},
				rootAdmin: {
					credential: adminCredential,
					privateJwk: adminKeys.privateJwk
				},
				caCertPem: entityCa.rootPem,
				platformCaCertPem: platformCaCertCosign.platformCertPem,
				platformRootPem: platformCaCertCosign.platformRootPem,
				platformCaCertCosign
			};
		}),
		dpGetEntity: createAuthEndpoint("/delegate-permissions/entity", {
			method: "GET",
			use: [sessionMiddleware],
			query: z.object({ entityId: z.string().min(1) }),
			metadata: { openapi: { description: "Lookup whether a DP entity exists (Entity CA / Admin kickstart). Billing email rows are not Admin." } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const entityId = ctx.query.entityId.toLowerCase();
			const entity = await dp.getEntity(entityId);
			return {
				entityId,
				exists: entity != null,
				package: entity?.package ?? null
			};
		}),
		dpIssueDelegate: createAuthEndpoint("/delegate-permissions/issue-delegate", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({
				entityId: z.string().min(1),
				kind: z.enum(["interim_admin", "zone_authority"]),
				zone: z.string().optional(),
				permissions: capabilitySetSchema.optional(),
				issuerPrivateJwk: z.record(z.string(), z.unknown()),
				issuerSki: z.string().min(1)
			}),
			metadata: { openapi: { description: "Issue an interim admin or zone-authority credential (Option B)" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const catalog = await ensureCatalog(dp, opts.configuredSeed);
			const entityId = ctx.body.entityId.toLowerCase();
			const entity = await dp.getEntity(entityId);
			if (!entity) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND);
			if (entity.package === "personal" && ctx.body.kind === "zone_authority") throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.PACKAGE_FORBIDDEN);
			if (entity.package === "personal" && ctx.body.kind === "interim_admin") throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.PACKAGE_FORBIDDEN);
			const issuerRow = await dp.getCredential(ctx.body.issuerSki);
			if (!issuerRow || issuerRow.entityId !== entityId) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.ISSUER_UNAUTHORIZED);
			const issuerCred = issuerRow.credential;
			const parentPermissions = issuerCred.permissions;
			const profiles = await dp.loadProfiles();
			let childPermissions;
			if (ctx.body.permissions) childPermissions = parseCapabilitySet(ctx.body.permissions);
			else if (ctx.body.kind === "interim_admin") childPermissions = withEntityScope(expandProfile("interim_admin", profiles, catalog), entityId);
			else {
				const zone = zoneNameKey(ctx.body.zone ?? "");
				if (zone === "") throw APIError.from("BAD_REQUEST", {
					message: "zone is required for zone_authority",
					code: "ZONE_REQUIRED"
				});
				if (!zoneUnderParent(zone, issuerCred.zone ?? "")) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.SUBSET_VIOLATION);
				childPermissions = withNameScope(withEntityScope(expandProfile("zone_delegate", profiles, catalog), entityId), zone);
			}
			const subset = assertSubset(childPermissions, parentPermissions, catalog);
			if (!subset.ok) throw APIError.from("FORBIDDEN", {
				message: subset.message,
				code: subset.code
			});
			if (ctx.body.kind === "zone_authority") {
				const zone = zoneNameKey(ctx.body.zone ?? "");
				if (await dp.getNameOccupancy(entityId, zone)) throw APIError.from("CONFLICT", DELEGATE_PERMISSIONS_ERROR_CODES.NAME_OCCUPIED);
			}
			const subject = await generateEd25519KeyPair();
			const zone = ctx.body.kind === "zone_authority" ? zoneNameKey(ctx.body.zone ?? "") : void 0;
			const credential = await issueCredential({
				kind: ctx.body.kind,
				entityId,
				subject,
				permissions: childPermissions,
				issuerSki: ctx.body.issuerSki,
				issuerPrivateJwk: ctx.body.issuerPrivateJwk,
				zone,
				package: entity.package,
				ttlSeconds: credentialExpiresIn
			});
			await dp.createCredential({ credential });
			if (ctx.body.kind === "zone_authority" && zone !== void 0) await dp.claimName({
				entityId,
				nameKey: zone,
				kind: "za",
				credentialSki: subject.ski
			});
			return {
				credential,
				privateJwk: subject.privateJwk
			};
		}),
		dpIssueMachine: createAuthEndpoint("/delegate-permissions/issue-machine", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({
				entityId: z.string().min(1),
				host: z.string().min(1),
				permissions: capabilitySetSchema.optional(),
				issuerPrivateJwk: z.record(z.string(), z.unknown()),
				issuerSki: z.string().min(1),
				payingPartyId: z.string().optional()
			}),
			metadata: { openapi: { description: "Issue a Machine credential, claim host name, platform co-sign, bind permanent seat" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const catalog = await ensureCatalog(dp, opts.configuredSeed);
			const entityId = ctx.body.entityId.toLowerCase();
			const entity = await dp.getEntity(entityId);
			if (!entity) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND);
			const parsed = parseMachineHost(ctx.body.host, entityId);
			if (!parsed) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST);
			const nameKey = machineNameKey(parsed.path);
			const occupied = await dp.getNameOccupancy(entityId, nameKey);
			if (occupied) throw APIError.from("CONFLICT", occupied.kind === "za" ? DELEGATE_PERMISSIONS_ERROR_CODES.NAME_CONFLICT : DELEGATE_PERMISSIONS_ERROR_CODES.NAME_OCCUPIED);
			const issuerRow = await dp.getCredential(ctx.body.issuerSki);
			if (!issuerRow || issuerRow.entityId !== entityId) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.ISSUER_UNAUTHORIZED);
			const issuerCred = issuerRow.credential;
			const profiles = await dp.loadProfiles();
			let childPermissions;
			if (ctx.body.permissions) childPermissions = parseCapabilitySet(ctx.body.permissions);
			else childPermissions = withNameScope(withEntityScope(expandProfile("machine", profiles, catalog), entityId), nameKey);
			const subset = assertSubset(childPermissions, issuerCred.permissions, catalog);
			if (!subset.ok) throw APIError.from("FORBIDDEN", {
				message: subset.message,
				code: subset.code
			});
			const issuerZone = issuerCred.zone ?? "";
			if (issuerZone !== "" && !nameKey.endsWith(`.${issuerZone}`) && nameKey !== issuerZone) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.SUBSET_VIOLATION);
			const subject = await generateEd25519KeyPair();
			const host = ctx.body.host.toLowerCase();
			let credential = await issueCredential({
				kind: "machine",
				entityId,
				subject,
				permissions: childPermissions,
				issuerSki: ctx.body.issuerSki,
				issuerPrivateJwk: ctx.body.issuerPrivateJwk,
				host,
				package: entity.package,
				ttlSeconds: credentialExpiresIn
			});
			let seatId;
			if (opts.seatBinder) try {
				seatId = (await opts.seatBinder.allocateAndBind({
					entityId,
					host,
					machineSki: subject.ski,
					payingPartyId: ctx.body.payingPartyId
				})).seatId;
			} catch {
				throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.SEAT_BIND_FAILED);
			}
			else seatId = `dev-seat-${subject.ski.slice(0, 12)}`;
			credential = await (await opts.resolveCosign()).cosignMachine(credential, seatId);
			await dp.claimName({
				entityId,
				nameKey,
				kind: "machine",
				credentialSki: subject.ski
			});
			await dp.createCredential({
				credential,
				seatId
			});
			return {
				credential,
				privateJwk: subject.privateJwk,
				seatId
			};
		})
	};
}
//#endregion
export { createCredentialEndpoints };
