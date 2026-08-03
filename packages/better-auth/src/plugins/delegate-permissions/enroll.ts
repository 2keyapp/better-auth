import { createAuthEndpoint } from "@better-auth/core/api";
import { calculateJwkThumbprint } from "jose";
import * as z from "zod";
import { APIError, sessionMiddleware } from "../../api";
import { getDelegatePermissionsAdapter } from "./adapter";
import { expandProfile } from "./capability/expand";
import { assertSubset } from "./capability/subset";
import type { CapabilitySet, Catalog } from "./capability/types";
import { DELEGATE_PERMISSIONS_ERROR_CODES } from "./error-codes";
import { machineNameKey, parseMachineHost } from "./names";
import { capabilitySetSchema, parseCapabilitySet } from "./parse";
import type {
	CapabilityCredential,
	CosignProvider,
	KeyPairMaterial,
	PublicJwk,
	SeatBinder,
} from "./pki/types";
import type { CatalogSeed } from "./seeds";

type DpAdapter = ReturnType<typeof getDelegatePermissionsAdapter>;

function withEntityScope(
	permissions: CapabilitySet,
	entityId: string,
): CapabilitySet {
	return permissions.map((p) => ({
		...p,
		scope: { ...p.scope, entity: entityId },
	}));
}

function withNameScope(
	permissions: CapabilitySet,
	name: string,
): CapabilitySet {
	return permissions.map((p) => ({
		...p,
		scope: { ...p.scope, name },
	}));
}

async function ensureCatalog(
	dp: DpAdapter,
	configuredSeed: CatalogSeed | null,
): Promise<Catalog> {
	let catalog = await dp.loadCatalog();
	if (!catalog && configuredSeed) {
		catalog = await dp.seedCatalog(configuredSeed);
	}
	if (!catalog) {
		throw APIError.from(
			"BAD_REQUEST",
			DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED,
		);
	}
	return catalog;
}

function randomPullToken(): string {
	const bytes = new Uint8Array(24);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function skiFromPublicJwk(
	publicJwk: Record<string, unknown>,
): Promise<string> {
	return calculateJwkThumbprint(publicJwk as PublicJwk, "sha256");
}

async function finalizeApprovedEnroll(opts: {
	dp: DpAdapter;
	catalog: Catalog;
	entityId: string;
	host: string;
	role: "target" | "source";
	subjectSki: string;
	publicJwk: Record<string, unknown>;
	leafPem: string;
	chainPem: string;
	credential: CapabilityCredential;
	issuerSki: string;
	payingPartyId?: string;
	cosign: CosignProvider;
	seatBinder?: SeatBinder;
}): Promise<{
	credential: CapabilityCredential;
	leafPem: string;
	chainPem: string;
	platformCertCosign: Awaited<ReturnType<CosignProvider["cosignLeafCert"]>>;
	seatId?: string;
}> {
	const issuerRow = await opts.dp.getCredential(opts.issuerSki);
	if (!issuerRow || issuerRow.entityId !== opts.entityId) {
		throw APIError.from(
			"FORBIDDEN",
			DELEGATE_PERMISSIONS_ERROR_CODES.ISSUER_UNAUTHORIZED,
		);
	}
	const issuerCred = issuerRow.credential as unknown as CapabilityCredential;
	const subset = assertSubset(
		opts.credential.permissions,
		issuerCred.permissions,
		opts.catalog,
	);
	if (!subset.ok) {
		throw APIError.from("FORBIDDEN", {
			message: subset.message,
			code: subset.code,
		});
	}

	if (opts.credential.ski !== opts.subjectSki) {
		throw APIError.from(
			"BAD_REQUEST",
			DELEGATE_PERMISSIONS_ERROR_CODES.CERT_MISMATCH,
		);
	}
	if (opts.credential.host && opts.credential.host !== opts.host) {
		throw APIError.from(
			"BAD_REQUEST",
			DELEGATE_PERMISSIONS_ERROR_CODES.CERT_MISMATCH,
		);
	}

	const parsed = parseMachineHost(opts.host, opts.entityId);
	if (!parsed) {
		throw APIError.from(
			"BAD_REQUEST",
			DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST,
		);
	}
	const nameKey = machineNameKey(parsed.path);
	const occupied = await opts.dp.getNameOccupancy(opts.entityId, nameKey);
	if (occupied) {
		throw APIError.from(
			"CONFLICT",
			occupied.kind === "za"
				? DELEGATE_PERMISSIONS_ERROR_CODES.NAME_CONFLICT
				: DELEGATE_PERMISSIONS_ERROR_CODES.NAME_OCCUPIED,
		);
	}

	let seatId: string | undefined;
	if (opts.role === "target") {
		if (opts.seatBinder) {
			try {
				const seat = await opts.seatBinder.allocateAndBind({
					entityId: opts.entityId,
					host: opts.host,
					machineSki: opts.subjectSki,
					payingPartyId: opts.payingPartyId,
				});
				seatId = seat.seatId;
			} catch {
				throw APIError.from(
					"BAD_REQUEST",
					DELEGATE_PERMISSIONS_ERROR_CODES.SEAT_BIND_FAILED,
				);
			}
		} else {
			seatId = `dev-seat-${opts.subjectSki.slice(0, 12)}`;
		}
	}

	const credential = await opts.cosign.cosignMachine(
		opts.credential,
		seatId ?? `source-${opts.subjectSki.slice(0, 12)}`,
	);
	const platformCertCosign = await opts.cosign.cosignLeafCert(opts.leafPem);

	await opts.dp.claimName({
		entityId: opts.entityId,
		nameKey,
		kind: "machine",
		credentialSki: opts.subjectSki,
	});
	await opts.dp.createCredential({ credential, seatId });

	return {
		credential,
		leafPem: opts.leafPem,
		chainPem: opts.chainPem,
		platformCertCosign,
		seatId,
	};
}

export function createEnrollEndpoints(opts: {
	serviceId: string;
	configuredSeed: CatalogSeed | null;
	cosign?: CosignProvider;
	seatBinder?: SeatBinder;
	getFallbackCosignKey?: () => Promise<KeyPairMaterial>;
	resolveCosign: () => Promise<CosignProvider>;
}) {
	const dpOf = (adapter: Parameters<typeof getDelegatePermissionsAdapter>[0]) =>
		getDelegatePermissionsAdapter(adapter, opts.serviceId);

	return {
		dpEnrollCreate: createAuthEndpoint(
			"/delegate-permissions/enroll-create",
			{
				method: "POST",
				body: z.object({
					entityId: z.string().min(1),
					host: z.string().min(1),
					role: z.enum(["target", "source"]).default("target"),
					csrPem: z.string().min(1),
					publicJwk: z.record(z.string(), z.unknown()),
					subjectSki: z.string().min(1).optional(),
				}),
				metadata: {
					openapi: {
						description:
							"Create a pending machine enrollment from an on-device PKCS#10 CSR",
					},
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				await ensureCatalog(dp, opts.configuredSeed);
				const entityId = ctx.body.entityId.toLowerCase();
				const entity = await dp.getEntity(entityId);
				if (!entity) {
					throw APIError.from(
						"NOT_FOUND",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND,
					);
				}
				const host = ctx.body.host.toLowerCase();
				const parsed = parseMachineHost(host, entityId);
				if (!parsed) {
					throw APIError.from(
						"BAD_REQUEST",
						DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST,
					);
				}
				const subjectSki =
					ctx.body.subjectSki ?? (await skiFromPublicJwk(ctx.body.publicJwk));
				const pullToken = randomPullToken();
				const row = await dp.createEnrollRequest({
					entityId,
					host,
					role: ctx.body.role,
					csrPem: ctx.body.csrPem,
					subjectSki,
					publicJwk: ctx.body.publicJwk,
					pullToken,
					createdByUserId: ctx.context.session?.user?.id ?? null,
				});
				return {
					enrollId: row.id,
					pullToken: row.pullToken,
					subjectSki,
					status: "pending" as const,
				};
			},
		),

		dpEnrollList: createAuthEndpoint(
			"/delegate-permissions/enroll-list",
			{
				method: "GET",
				use: [sessionMiddleware],
				query: z.object({
					entityId: z.string().min(1),
					status: z.string().optional(),
				}),
				metadata: {
					openapi: {
						description: "List enrollment requests for an entity",
					},
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				const entityId = ctx.query.entityId.toLowerCase();
				const rows = await dp.listEnrollRequests(
					entityId,
					ctx.query.status ?? "pending",
				);
				return {
					enrollments: rows.map((r) => ({
						enrollId: r.id,
						host: r.host,
						role: r.role,
						subjectSki: r.subjectSki,
						status: r.status,
						createdAt: r.createdAt,
					})),
				};
			},
		),

		dpEnrollApprove: createAuthEndpoint(
			"/delegate-permissions/enroll-approve",
			{
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({
					enrollId: z.string().min(1),
					leafPem: z.string().min(1),
					chainPem: z.string().min(1),
					credential: z.record(z.string(), z.unknown()),
					issuerSki: z.string().min(1),
					payingPartyId: z.string().optional(),
				}),
				metadata: {
					openapi: {
						description:
							"Approve pending enroll with admin-signed leaf + CapabilityCredential; platform co-signs leaf",
					},
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				const catalog = await ensureCatalog(dp, opts.configuredSeed);
				const row = await dp.getEnrollRequest(ctx.body.enrollId);
				if (!row) {
					throw APIError.from(
						"NOT_FOUND",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_FOUND,
					);
				}
				if (row.status !== "pending") {
					throw APIError.from(
						"BAD_REQUEST",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_PENDING,
					);
				}
				const cosign = await opts.resolveCosign();
				const finalized = await finalizeApprovedEnroll({
					dp,
					catalog,
					entityId: row.entityId,
					host: row.host,
					role: row.role as "target" | "source",
					subjectSki: row.subjectSki,
					publicJwk: row.publicJwk,
					leafPem: ctx.body.leafPem,
					chainPem: ctx.body.chainPem,
					credential: ctx.body.credential as unknown as CapabilityCredential,
					issuerSki: ctx.body.issuerSki,
					payingPartyId: ctx.body.payingPartyId,
					cosign,
					seatBinder: opts.seatBinder,
				});
				await dp.updateEnrollRequest(row.id, {
					status: "approved",
					leafPem: finalized.leafPem,
					chainPem: finalized.chainPem,
					credential: finalized.credential as unknown as Record<
						string,
						unknown
					>,
					platformCertCosign: finalized.platformCertCosign as unknown as Record<
						string,
						unknown
					>,
					seatId: finalized.seatId ?? null,
				});
				return {
					enrollId: row.id,
					status: "approved" as const,
					pullToken: row.pullToken,
					seatId: finalized.seatId,
					platformCertCosign: finalized.platformCertCosign,
				};
			},
		),

		dpEnrollReject: createAuthEndpoint(
			"/delegate-permissions/enroll-reject",
			{
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({
					enrollId: z.string().min(1),
				}),
				metadata: {
					openapi: { description: "Reject a pending enrollment" },
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				const row = await dp.getEnrollRequest(ctx.body.enrollId);
				if (!row) {
					throw APIError.from(
						"NOT_FOUND",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_FOUND,
					);
				}
				if (row.status !== "pending") {
					throw APIError.from(
						"BAD_REQUEST",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_PENDING,
					);
				}
				await dp.updateEnrollRequest(row.id, { status: "rejected" });
				return { enrollId: row.id, status: "rejected" as const };
			},
		),

		dpEnrollPull: createAuthEndpoint(
			"/delegate-permissions/enroll-pull",
			{
				method: "POST",
				body: z.object({
					pullToken: z.string().min(1),
				}),
				metadata: {
					openapi: {
						description:
							"Device pulls approved enrollment (leaf + chain + credential + platform cert cosign)",
					},
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				const row = await dp.getEnrollByPullToken(ctx.body.pullToken);
				if (!row) {
					throw APIError.from(
						"NOT_FOUND",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_FOUND,
					);
				}
				if (row.status === "pending") {
					return { status: "pending" as const, enrollId: row.id };
				}
				if (row.status === "rejected") {
					return { status: "rejected" as const, enrollId: row.id };
				}
				if (row.status === "consumed") {
					throw APIError.from(
						"BAD_REQUEST",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_READY,
					);
				}
				if (!row.leafPem || !row.chainPem || !row.credential) {
					throw APIError.from(
						"BAD_REQUEST",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_READY,
					);
				}
				await dp.updateEnrollRequest(row.id, { status: "consumed" });
				return {
					status: "approved" as const,
					enrollId: row.id,
					host: row.host,
					role: row.role,
					ski: row.subjectSki,
					publicJwk: row.publicJwk,
					certPem: row.leafPem,
					chainPem: row.chainPem,
					credential: row.credential,
					platformCertCosign: row.platformCertCosign,
					seatId: row.seatId,
				};
			},
		),

		/**
		 * Localhost / same-admin ceremony: CSR already signed locally;
		 * create + approve + return result immediately (no queue wait).
		 */
		dpEnrollInstant: createAuthEndpoint(
			"/delegate-permissions/enroll-instant",
			{
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({
					entityId: z.string().min(1),
					host: z.string().min(1),
					role: z.enum(["target", "source"]).default("target"),
					csrPem: z.string().min(1),
					publicJwk: z.record(z.string(), z.unknown()),
					subjectSki: z.string().min(1).optional(),
					leafPem: z.string().min(1),
					chainPem: z.string().min(1),
					credential: z.record(z.string(), z.unknown()),
					issuerSki: z.string().min(1),
					payingPartyId: z.string().optional(),
				}),
				metadata: {
					openapi: {
						description:
							"Instant enroll when admin CA keys are on the same host as the machine (sign + accept in one call)",
					},
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				const catalog = await ensureCatalog(dp, opts.configuredSeed);
				const entityId = ctx.body.entityId.toLowerCase();
				const entity = await dp.getEntity(entityId);
				if (!entity) {
					throw APIError.from(
						"NOT_FOUND",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND,
					);
				}
				const host = ctx.body.host.toLowerCase();
				const subjectSki =
					ctx.body.subjectSki ?? (await skiFromPublicJwk(ctx.body.publicJwk));
				const cosign = await opts.resolveCosign();
				const finalized = await finalizeApprovedEnroll({
					dp,
					catalog,
					entityId,
					host,
					role: ctx.body.role,
					subjectSki,
					publicJwk: ctx.body.publicJwk,
					leafPem: ctx.body.leafPem,
					chainPem: ctx.body.chainPem,
					credential: ctx.body.credential as unknown as CapabilityCredential,
					issuerSki: ctx.body.issuerSki,
					payingPartyId: ctx.body.payingPartyId,
					cosign,
					seatBinder: opts.seatBinder,
				});
				const pullToken = randomPullToken();
				const row = await dp.createEnrollRequest({
					entityId,
					host,
					role: ctx.body.role,
					csrPem: ctx.body.csrPem,
					subjectSki,
					publicJwk: ctx.body.publicJwk,
					pullToken,
					createdByUserId: ctx.context.session.user.id,
					status: "consumed",
					leafPem: finalized.leafPem,
					chainPem: finalized.chainPem,
					credential: finalized.credential as unknown as Record<
						string,
						unknown
					>,
					platformCertCosign: finalized.platformCertCosign as unknown as Record<
						string,
						unknown
					>,
					seatId: finalized.seatId ?? null,
				});
				return {
					enrollId: row.id,
					status: "approved" as const,
					ski: subjectSki,
					host,
					certPem: finalized.leafPem,
					chainPem: finalized.chainPem,
					credential: finalized.credential,
					platformCertCosign: finalized.platformCertCosign,
					seatId: finalized.seatId,
				};
			},
		),

		/** Build default machine permissions for a host (admin CLI helper). */
		dpEnrollMachinePermissions: createAuthEndpoint(
			"/delegate-permissions/enroll-machine-permissions",
			{
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({
					entityId: z.string().min(1),
					host: z.string().min(1),
					role: z.enum(["target", "source"]).default("target"),
					permissions: capabilitySetSchema.optional(),
				}),
				metadata: {
					openapi: {
						description:
							"Expand catalog machine / machine_source profile for a host (for offline credential signing)",
					},
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				const catalog = await ensureCatalog(dp, opts.configuredSeed);
				const entityId = ctx.body.entityId.toLowerCase();
				const parsed = parseMachineHost(ctx.body.host.toLowerCase(), entityId);
				if (!parsed) {
					throw APIError.from(
						"BAD_REQUEST",
						DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST,
					);
				}
				const nameKey = machineNameKey(parsed.path);
				const profiles = await dp.loadProfiles();
				const profileName =
					ctx.body.role === "source" ? "machine_source" : "machine";
				let permissions: CapabilitySet;
				if (ctx.body.permissions) {
					permissions = parseCapabilitySet(ctx.body.permissions);
				} else {
					try {
						permissions = withNameScope(
							withEntityScope(
								expandProfile(profileName, profiles, catalog),
								entityId,
							),
							nameKey,
						);
					} catch {
						permissions = withNameScope(
							withEntityScope(
								expandProfile("machine", profiles, catalog),
								entityId,
							),
							nameKey,
						);
					}
				}
				return { permissions, nameKey, entityId };
			},
		),
	};
}
