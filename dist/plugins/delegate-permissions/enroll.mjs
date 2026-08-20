import { sessionMiddleware } from "../../api/routes/session.mjs";
import { APIError } from "../../api/index.mjs";
import { getDelegatePermissionsAdapter } from "./adapter.mjs";
import { expandProfile } from "./capability/expand.mjs";
import { assertSubset } from "./capability/subset.mjs";
import { DELEGATE_PERMISSIONS_ERROR_CODES } from "./error-codes.mjs";
import { machineNameKey, parseMachineHost, zoneNameKey } from "./names.mjs";
import { capabilitySetSchema, parseCapabilitySet } from "./parse.mjs";
import { issueCredential } from "./pki/credential.mjs";
import { bindCsrToPublicJwk, leafMatchesCsr } from "./pki/csr.mjs";
import { createAuthEndpoint } from "@better-auth/core/api";
import * as z from "zod";
//#region src/plugins/delegate-permissions/enroll.ts
const enrollKindSchema = z.enum([
	"machine_target",
	"machine_source",
	"zone_authority",
	"interim_admin",
	"target",
	"source"
]);
function normalizeEnrollKind(kind) {
	if (kind === "target") return "machine_target";
	if (kind === "source") return "machine_source";
	return kind;
}
function isMachineKind(kind) {
	return kind === "machine_target" || kind === "machine_source";
}
function deviceSeatRole(kind) {
	return kind === "machine_source" ? "source" : "target";
}
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
function randomPullToken() {
	const bytes = new Uint8Array(24);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
async function bindEnrollCsr(csrPem, publicJwk, subjectSki) {
	let bound;
	try {
		bound = await bindCsrToPublicJwk(csrPem, publicJwk);
	} catch {
		throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CSR);
	}
	if (subjectSki && subjectSki !== bound.ski) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CSR);
	return bound;
}
function assertKindAllowedForPackage(pkg, kind) {
	if (pkg === "personal" && !isMachineKind(kind)) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.PACKAGE_FORBIDDEN);
	if ((pkg === "service_provider" || pkg === "sp") && kind === "machine_source") throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.PACKAGE_FORBIDDEN);
}
async function finalizeApprovedEnroll(opts) {
	const issuerRow = await opts.dp.getCredential(opts.issuerSki);
	if (!issuerRow || issuerRow.entityId !== opts.entityId) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.ISSUER_UNAUTHORIZED);
	const issuerCred = issuerRow.credential;
	const subset = assertSubset(opts.credential.permissions, issuerCred.permissions, opts.catalog);
	if (!subset.ok) throw APIError.from("FORBIDDEN", {
		message: subset.message,
		code: subset.code
	});
	if (opts.credential.ski !== opts.subjectSki) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CERT_MISMATCH);
	if (isMachineKind(opts.kind)) {
		if (opts.credential.host && opts.credential.host !== opts.host) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CERT_MISMATCH);
		const parsed = parseMachineHost(opts.host, opts.entityId);
		if (!parsed) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST);
		const nameKey = machineNameKey(parsed.path);
		const occupied = await opts.dp.getNameOccupancy(opts.entityId, nameKey);
		if (occupied) throw APIError.from("CONFLICT", occupied.kind === "za" ? DELEGATE_PERMISSIONS_ERROR_CODES.NAME_CONFLICT : DELEGATE_PERMISSIONS_ERROR_CODES.NAME_OCCUPIED);
		const seatRole = deviceSeatRole(opts.kind);
		let seatId;
		if (opts.seatBinder) try {
			seatId = (await opts.seatBinder.allocateAndBind({
				entityId: opts.entityId,
				host: opts.host,
				machineSki: opts.subjectSki,
				payingPartyId: opts.payingPartyId,
				role: seatRole
			})).seatId;
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			console.error("[delegate-permissions] seatBinder failed:", message);
			throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.SEAT_BIND_FAILED);
		}
		else seatId = `dev-seat-${opts.subjectSki.slice(0, 12)}`;
		const credential = await opts.cosign.cosignMachine(opts.credential, seatId);
		const platformCertCosign = await opts.cosign.cosignLeafCert(opts.leafPem, {
			chainPem: opts.chainPem,
			subjectSki: opts.subjectSki,
			host: opts.host
		});
		await opts.dp.claimName({
			entityId: opts.entityId,
			nameKey,
			kind: "machine",
			credentialSki: opts.subjectSki
		});
		await opts.dp.createCredential({
			credential,
			seatId
		});
		return {
			credential,
			leafPem: opts.leafPem,
			chainPem: opts.chainPem,
			platformCertCosign,
			seatId
		};
	}
	if (opts.kind === "zone_authority") {
		const zone = zoneNameKey(opts.zone ?? opts.credential.zone ?? "");
		if (!zone) throw APIError.from("BAD_REQUEST", {
			message: "zone is required for zone_authority enroll",
			code: "ZONE_REQUIRED"
		});
		if (await opts.dp.getNameOccupancy(opts.entityId, zone)) throw APIError.from("CONFLICT", DELEGATE_PERMISSIONS_ERROR_CODES.NAME_OCCUPIED);
		const platformCertCosign = await opts.cosign.cosignLeafCert(opts.leafPem, {
			chainPem: opts.chainPem,
			subjectSki: opts.subjectSki
		});
		await opts.dp.createCredential({ credential: opts.credential });
		await opts.dp.claimName({
			entityId: opts.entityId,
			nameKey: zone,
			kind: "za",
			credentialSki: opts.subjectSki
		});
		return {
			credential: opts.credential,
			leafPem: opts.leafPem,
			chainPem: opts.chainPem,
			platformCertCosign
		};
	}
	const platformCertCosign = await opts.cosign.cosignLeafCert(opts.leafPem, {
		chainPem: opts.chainPem,
		subjectSki: opts.subjectSki
	});
	await opts.dp.createCredential({ credential: opts.credential });
	return {
		credential: opts.credential,
		leafPem: opts.leafPem,
		chainPem: opts.chainPem,
		platformCertCosign
	};
}
function createEnrollEndpoints(opts) {
	const dpOf = (adapter) => getDelegatePermissionsAdapter(adapter, opts.serviceId);
	return {
		dpEnrollCreate: createAuthEndpoint("/delegate-permissions/enroll-create", {
			method: "POST",
			body: z.object({
				entityId: z.string().min(1),
				host: z.string().optional(),
				zone: z.string().optional(),
				kind: enrollKindSchema.optional(),
				role: enrollKindSchema.default("machine_target"),
				csrPem: z.string().min(1),
				publicJwk: z.record(z.string(), z.unknown()).optional(),
				subjectSki: z.string().min(1).optional()
			}),
			metadata: { openapi: { description: "Create a pending enrollment CSR (machine, zone authority, or interim admin)" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			await ensureCatalog(dp, opts.configuredSeed);
			const entityId = ctx.body.entityId.toLowerCase();
			const entity = await dp.getEntity(entityId);
			if (!entity) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND);
			const kind = normalizeEnrollKind(ctx.body.kind ?? ctx.body.role);
			assertKindAllowedForPackage(entity.package, kind);
			let host = "";
			let zone = null;
			if (isMachineKind(kind)) {
				if (!ctx.body.host) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST);
				host = ctx.body.host.toLowerCase();
				if (!parseMachineHost(host, entityId)) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST);
			} else if (kind === "zone_authority") {
				zone = zoneNameKey(ctx.body.zone ?? "");
				if (!zone) throw APIError.from("BAD_REQUEST", {
					message: "zone is required for zone_authority",
					code: "ZONE_REQUIRED"
				});
			}
			const bound = await bindEnrollCsr(ctx.body.csrPem, ctx.body.publicJwk, ctx.body.subjectSki);
			const subjectSki = bound.ski;
			const pullToken = randomPullToken();
			const row = await dp.createEnrollRequest({
				entityId,
				host,
				zone,
				role: kind,
				csrPem: ctx.body.csrPem,
				subjectSki,
				publicJwk: bound.publicJwk,
				pullToken,
				createdByUserId: ctx.context.session?.user?.id ?? null
			});
			return {
				enrollId: row.id,
				pullToken: row.pullToken,
				subjectSki,
				kind,
				status: "pending"
			};
		}),
		dpEnrollList: createAuthEndpoint("/delegate-permissions/enroll-list", {
			method: "GET",
			use: [sessionMiddleware],
			query: z.object({
				entityId: z.string().min(1),
				status: z.string().optional()
			}),
			metadata: { openapi: { description: "List enrollment requests for an entity" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const entityId = ctx.query.entityId.toLowerCase();
			return { enrollments: (await dp.listEnrollRequests(entityId, ctx.query.status ?? "pending")).map((r) => ({
				enrollId: r.id,
				host: r.host || null,
				zone: r.zone,
				kind: r.role,
				role: r.role,
				subjectSki: r.subjectSki,
				status: r.status,
				createdAt: r.createdAt,
				csrPem: r.csrPem,
				publicJwk: r.publicJwk,
				entityId: r.entityId
			})) };
		}),
		dpEnrollApprove: createAuthEndpoint("/delegate-permissions/enroll-approve", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({
				enrollId: z.string().min(1),
				leafPem: z.string().min(1),
				chainPem: z.string().min(1),
				credential: z.record(z.string(), z.unknown()),
				issuerSki: z.string().min(1),
				issuerPrivateJwk: z.record(z.string(), z.unknown()).optional(),
				payingPartyId: z.string().optional()
			}),
			metadata: { openapi: { description: "Approve pending enroll with admin-signed leaf + CapabilityCredential; platform co-signs leaf" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const catalog = await ensureCatalog(dp, opts.configuredSeed);
			const row = await dp.getEnrollRequest(ctx.body.enrollId);
			if (!row) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_FOUND);
			if (row.status !== "pending") throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_PENDING);
			if (!await leafMatchesCsr(ctx.body.leafPem, row.csrPem)) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CERT_MISMATCH);
			const kind = normalizeEnrollKind(row.role);
			const entity = await dp.getEntity(row.entityId);
			if (!entity) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND);
			let credential = ctx.body.credential;
			if (ctx.body.issuerPrivateJwk && (!credential.signature || typeof credential.signature !== "string")) {
				const profiles = await dp.loadProfiles();
				const nameKey = isMachineKind(kind) ? machineNameKey(parseMachineHost(row.host, row.entityId)?.path ?? "") : "";
				const permissions = credential.permissions ?? (isMachineKind(kind) ? withNameScope(withEntityScope(expandProfile("machine", profiles, catalog), row.entityId), nameKey) : withEntityScope(expandProfile("interim_admin", profiles, catalog), row.entityId));
				credential = await issueCredential({
					kind: isMachineKind(kind) ? "machine" : "interim_admin",
					entityId: row.entityId,
					subject: {
						ski: row.subjectSki,
						publicJwk: row.publicJwk,
						privateJwk: {}
					},
					permissions,
					issuerSki: ctx.body.issuerSki,
					issuerPrivateJwk: ctx.body.issuerPrivateJwk,
					host: row.host || void 0,
					zone: row.zone || void 0,
					package: entity.package
				});
			}
			const cosign = await opts.resolveCosign();
			const finalized = await finalizeApprovedEnroll({
				dp,
				catalog,
				entityId: row.entityId,
				kind,
				host: row.host,
				zone: row.zone,
				subjectSki: row.subjectSki,
				publicJwk: row.publicJwk,
				leafPem: ctx.body.leafPem,
				chainPem: ctx.body.chainPem,
				credential,
				issuerSki: ctx.body.issuerSki,
				payingPartyId: ctx.body.payingPartyId,
				cosign,
				seatBinder: opts.seatBinder
			});
			await dp.updateEnrollRequest(row.id, {
				status: "approved",
				leafPem: finalized.leafPem,
				chainPem: finalized.chainPem,
				credential: finalized.credential,
				platformCertCosign: finalized.platformCertCosign,
				seatId: finalized.seatId ?? null
			});
			return {
				enrollId: row.id,
				status: "approved",
				pullToken: row.pullToken,
				kind,
				seatId: finalized.seatId,
				platformCertPem: finalized.platformCertCosign.platformCertPem,
				platformRootPem: finalized.platformCertCosign.platformRootPem,
				platformCertCosign: finalized.platformCertCosign
			};
		}),
		dpEnrollReject: createAuthEndpoint("/delegate-permissions/enroll-reject", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({ enrollId: z.string().min(1) }),
			metadata: { openapi: { description: "Reject a pending enrollment" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const row = await dp.getEnrollRequest(ctx.body.enrollId);
			if (!row) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_FOUND);
			if (row.status !== "pending") throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_PENDING);
			await dp.updateEnrollRequest(row.id, { status: "rejected" });
			return {
				enrollId: row.id,
				status: "rejected"
			};
		}),
		dpEnrollPull: createAuthEndpoint("/delegate-permissions/enroll-pull", {
			method: "POST",
			body: z.object({ pullToken: z.string().min(1) }),
			metadata: { openapi: { description: "Device pulls approved enrollment (leaf + chain + credential + platform cert cosign)" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const row = await dp.getEnrollByPullToken(ctx.body.pullToken);
			if (!row) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_FOUND);
			if (row.status === "pending") return {
				status: "pending",
				enrollId: row.id
			};
			if (row.status === "rejected") return {
				status: "rejected",
				enrollId: row.id
			};
			if (row.status === "consumed" || row.status === "approved") {
				if (!row.leafPem || !row.chainPem || !row.credential) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_READY);
				if (row.status === "approved") await dp.updateEnrollRequest(row.id, { status: "consumed" });
				return {
					status: "approved",
					enrollId: row.id,
					host: row.host || null,
					zone: row.zone,
					kind: row.role,
					role: row.role,
					ski: row.subjectSki,
					publicJwk: row.publicJwk,
					certPem: row.leafPem,
					chainPem: row.chainPem,
					credential: row.credential,
					platformCertPem: row.platformCertCosign?.platformCertPem ?? null,
					platformRootPem: row.platformCertCosign?.platformRootPem ?? null,
					platformCertCosign: row.platformCertCosign,
					seatId: row.seatId
				};
			}
			throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_READY);
		}),
		dpEnrollInstant: createAuthEndpoint("/delegate-permissions/enroll-instant", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({
				entityId: z.string().min(1),
				host: z.string().optional(),
				zone: z.string().optional(),
				kind: enrollKindSchema.optional(),
				role: enrollKindSchema.default("machine_target"),
				csrPem: z.string().min(1),
				publicJwk: z.record(z.string(), z.unknown()).optional(),
				subjectSki: z.string().min(1).optional(),
				leafPem: z.string().min(1),
				chainPem: z.string().min(1),
				credential: z.record(z.string(), z.unknown()),
				issuerSki: z.string().min(1),
				payingPartyId: z.string().optional()
			}),
			metadata: { openapi: { description: "Instant enroll when admin CA keys are on the same host (sign + accept in one call)" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const catalog = await ensureCatalog(dp, opts.configuredSeed);
			const entityId = ctx.body.entityId.toLowerCase();
			const entity = await dp.getEntity(entityId);
			if (!entity) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND);
			const kind = normalizeEnrollKind(ctx.body.kind ?? ctx.body.role);
			assertKindAllowedForPackage(entity.package, kind);
			const host = (ctx.body.host ?? "").toLowerCase();
			const zone = ctx.body.zone ? zoneNameKey(ctx.body.zone) : null;
			if (isMachineKind(kind) && !host) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST);
			const bound = await bindEnrollCsr(ctx.body.csrPem, ctx.body.publicJwk, ctx.body.subjectSki);
			const subjectSki = bound.ski;
			if (!await leafMatchesCsr(ctx.body.leafPem, ctx.body.csrPem)) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CERT_MISMATCH);
			const cosign = await opts.resolveCosign();
			const finalized = await finalizeApprovedEnroll({
				dp,
				catalog,
				entityId,
				kind,
				host,
				zone,
				subjectSki,
				publicJwk: bound.publicJwk,
				leafPem: ctx.body.leafPem,
				chainPem: ctx.body.chainPem,
				credential: ctx.body.credential,
				issuerSki: ctx.body.issuerSki,
				payingPartyId: ctx.body.payingPartyId,
				cosign,
				seatBinder: opts.seatBinder
			});
			const pullToken = randomPullToken();
			return {
				enrollId: (await dp.createEnrollRequest({
					entityId,
					host,
					zone,
					role: kind,
					csrPem: ctx.body.csrPem,
					subjectSki,
					publicJwk: bound.publicJwk,
					pullToken,
					createdByUserId: ctx.context.session.user.id,
					status: "consumed",
					leafPem: finalized.leafPem,
					chainPem: finalized.chainPem,
					credential: finalized.credential,
					platformCertCosign: finalized.platformCertCosign,
					seatId: finalized.seatId ?? null
				})).id,
				status: "approved",
				ski: subjectSki,
				host: host || null,
				zone,
				kind,
				certPem: finalized.leafPem,
				chainPem: finalized.chainPem,
				credential: finalized.credential,
				platformCertPem: finalized.platformCertCosign.platformCertPem,
				platformRootPem: finalized.platformCertCosign.platformRootPem,
				platformCertCosign: finalized.platformCertCosign,
				seatId: finalized.seatId
			};
		}),
		dpEnrollMachinePermissions: createAuthEndpoint("/delegate-permissions/enroll-machine-permissions", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({
				entityId: z.string().min(1),
				host: z.string().optional(),
				zone: z.string().optional(),
				kind: enrollKindSchema.optional(),
				role: enrollKindSchema.default("machine_target"),
				permissions: capabilitySetSchema.optional()
			}),
			metadata: { openapi: { description: "Expand catalog profile for machine / zone / interim enroll (offline credential signing)" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const catalog = await ensureCatalog(dp, opts.configuredSeed);
			const entityId = ctx.body.entityId.toLowerCase();
			const kind = normalizeEnrollKind(ctx.body.kind ?? ctx.body.role);
			const profiles = await dp.loadProfiles();
			let permissions;
			let nameKey = "";
			if (ctx.body.permissions) permissions = parseCapabilitySet(ctx.body.permissions);
			else if (kind === "interim_admin") permissions = withEntityScope(expandProfile("interim_admin", profiles, catalog), entityId);
			else if (kind === "zone_authority") {
				nameKey = zoneNameKey(ctx.body.zone ?? "");
				if (!nameKey) throw APIError.from("BAD_REQUEST", {
					message: "zone is required for zone_authority",
					code: "ZONE_REQUIRED"
				});
				permissions = withNameScope(withEntityScope(expandProfile("zone_delegate", profiles, catalog), entityId), nameKey);
			} else {
				if (!ctx.body.host) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST);
				const parsed = parseMachineHost(ctx.body.host.toLowerCase(), entityId);
				if (!parsed) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST);
				nameKey = machineNameKey(parsed.path);
				const profileName = kind === "machine_source" ? "machine_source" : "machine";
				try {
					permissions = withNameScope(withEntityScope(expandProfile(profileName, profiles, catalog), entityId), nameKey);
				} catch {
					permissions = withNameScope(withEntityScope(expandProfile("machine", profiles, catalog), entityId), nameKey);
				}
			}
			return {
				permissions,
				nameKey,
				entityId,
				kind
			};
		})
	};
}
//#endregion
export { createEnrollEndpoints };
