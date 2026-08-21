import { createAuthEndpoint } from "@better-auth/core/api";
import * as z from "zod";
import { APIError, sessionMiddleware } from "../../api";
import { getDelegatePermissionsAdapter } from "./adapter";
import { expandProfile } from "./capability/expand";
import { assertSubset } from "./capability/subset";
import type { CapabilitySet, Catalog } from "./capability/types";
import {
	DEFAULT_CREDENTIAL_EXPIRES_IN,
	DEFAULT_INVITE_EXPIRES_IN,
	DEFAULT_INVITE_MAX_EXPIRES_IN,
	DEFAULT_INVITE_MAX_USES,
} from "./defaults";
import { DELEGATE_PERMISSIONS_ERROR_CODES } from "./error-codes";
import { machineNameKey, parseMachineHost, zoneNameKey } from "./names";
import { capabilitySetSchema, parseCapabilitySet } from "./parse";
import { issueCredential } from "./pki/credential";
import { bindCsrToPublicJwk, leafMatchesCsr } from "./pki/csr";
import type {
	CapabilityCredential,
	CosignProvider,
	EntityPackage,
	KeyPairMaterial,
	PublicJwk,
	SeatBinder,
} from "./pki/types";
import type { CatalogSeed } from "./seeds";
import type { DpEnrollKind } from "./types";

type DpAdapter = ReturnType<typeof getDelegatePermissionsAdapter>;

const enrollKindSchema = z.enum([
	"machine_target",
	"machine_source",
	"zone_authority",
	"interim_admin",
	"target",
	"source",
]);

function normalizeEnrollKind(
	kind: z.infer<typeof enrollKindSchema>,
): Exclude<DpEnrollKind, "target" | "source"> {
	if (kind === "target") return "machine_target";
	if (kind === "source") return "machine_source";
	return kind;
}

function isMachineKind(
	kind: ReturnType<typeof normalizeEnrollKind>,
): kind is "machine_target" | "machine_source" {
	return kind === "machine_target" || kind === "machine_source";
}

function deviceSeatRole(
	kind: "machine_target" | "machine_source",
): "target" | "source" {
	return kind === "machine_source" ? "source" : "target";
}

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

function asDate(value: Date | string): Date {
	return value instanceof Date ? value : new Date(value);
}

function inviteTtlSeconds(
	expiresIn: number | undefined,
	defaultTtl: number,
	maxTtl: number,
): number {
	const sec = expiresIn ?? defaultTtl;
	if (!Number.isFinite(sec) || sec <= 0 || sec > maxTtl) {
		throw APIError.from("BAD_REQUEST", {
			message: `expiresIn must be between 1 and ${maxTtl} seconds`,
			code: "INVALID_EXPIRES_IN",
		});
	}
	return sec;
}

function asCount(value: unknown, fallback: number): number {
	const n = typeof value === "number" ? value : Number(value);
	return Number.isFinite(n) && n >= 0 ? n : fallback;
}

/** `maxUses === 0` means unlimited until `expiresAt`. */
function inviteIsExhausted(maxUses: number, usedCount: number): boolean {
	return maxUses > 0 && usedCount >= maxUses;
}

async function requireOpenInvite(
	dp: DpAdapter,
	inviteToken: string,
): Promise<{
	id: string;
	entityId: string;
	role: string;
	expiresAt: Date;
	maxUses: number;
}> {
	const row = await dp.getEnrollInviteByToken(inviteToken);
	if (!row) {
		throw APIError.from(
			"NOT_FOUND",
			DELEGATE_PERMISSIONS_ERROR_CODES.INVITE_NOT_FOUND,
		);
	}
	const expiresAt = asDate(row.expiresAt);
	if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
		throw APIError.from(
			"BAD_REQUEST",
			DELEGATE_PERMISSIONS_ERROR_CODES.INVITE_EXPIRED,
		);
	}
	const maxUses = asCount(row.maxUses, 1);
	const usedCount = asCount(row.usedCount, 0);
	if (row.consumedAt || inviteIsExhausted(maxUses, usedCount)) {
		throw APIError.from(
			"BAD_REQUEST",
			DELEGATE_PERMISSIONS_ERROR_CODES.INVITE_USED,
		);
	}
	return {
		id: row.id,
		entityId: row.entityId,
		role: row.role,
		expiresAt,
		maxUses,
	};
}

async function bindEnrollCsr(
	csrPem: string,
	publicJwk?: Record<string, unknown>,
	subjectSki?: string,
): Promise<{ ski: string; publicJwk: PublicJwk }> {
	let bound: { ski: string; publicJwk: PublicJwk };
	try {
		bound = await bindCsrToPublicJwk(csrPem, publicJwk);
	} catch {
		throw APIError.from(
			"BAD_REQUEST",
			DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CSR,
		);
	}
	if (subjectSki && subjectSki !== bound.ski) {
		throw APIError.from(
			"BAD_REQUEST",
			DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CSR,
		);
	}
	return bound;
}

function assertKindAllowedForPackage(
	pkg: string | null | undefined,
	kind: ReturnType<typeof normalizeEnrollKind>,
): void {
	if (pkg === "personal" && !isMachineKind(kind)) {
		throw APIError.from(
			"FORBIDDEN",
			DELEGATE_PERMISSIONS_ERROR_CODES.PACKAGE_FORBIDDEN,
		);
	}
	// Service-provider Targets: anonymous Sources only — no source enroll.
	if (
		(pkg === "service_provider" || pkg === "sp") &&
		kind === "machine_source"
	) {
		throw APIError.from(
			"FORBIDDEN",
			DELEGATE_PERMISSIONS_ERROR_CODES.PACKAGE_FORBIDDEN,
		);
	}
}

async function finalizeApprovedEnroll(opts: {
	dp: DpAdapter;
	catalog: Catalog;
	entityId: string;
	kind: ReturnType<typeof normalizeEnrollKind>;
	host: string;
	zone: string | null;
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

	if (isMachineKind(opts.kind)) {
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

		const seatRole = deviceSeatRole(opts.kind);
		let seatId: string | undefined;
		if (opts.seatBinder) {
			try {
				const seat = await opts.seatBinder.allocateAndBind({
					entityId: opts.entityId,
					host: opts.host,
					machineSki: opts.subjectSki,
					payingPartyId: opts.payingPartyId,
					role: seatRole,
				});
				seatId = seat.seatId;
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				console.error("[delegate-permissions] seatBinder failed:", message);
				throw APIError.from(
					"BAD_REQUEST",
					DELEGATE_PERMISSIONS_ERROR_CODES.SEAT_BIND_FAILED,
				);
			}
		} else {
			seatId = `dev-seat-${opts.subjectSki.slice(0, 12)}`;
		}

		const credential = await opts.cosign.cosignMachine(opts.credential, seatId);
		const platformCertCosign = await opts.cosign.cosignLeafCert(opts.leafPem, {
			chainPem: opts.chainPem,
			subjectSki: opts.subjectSki,
			host: opts.host,
		});

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

	// Zone authority / interim admin — no device seat.
	if (opts.kind === "zone_authority") {
		const zone = zoneNameKey(opts.zone ?? opts.credential.zone ?? "");
		if (!zone) {
			throw APIError.from("BAD_REQUEST", {
				message: "zone is required for zone_authority enroll",
				code: "ZONE_REQUIRED",
			});
		}
		const occupied = await opts.dp.getNameOccupancy(opts.entityId, zone);
		if (occupied) {
			throw APIError.from(
				"CONFLICT",
				DELEGATE_PERMISSIONS_ERROR_CODES.NAME_OCCUPIED,
			);
		}
		const platformCertCosign = await opts.cosign.cosignLeafCert(opts.leafPem, {
			chainPem: opts.chainPem,
			subjectSki: opts.subjectSki,
		});
		await opts.dp.createCredential({ credential: opts.credential });
		await opts.dp.claimName({
			entityId: opts.entityId,
			nameKey: zone,
			kind: "za",
			credentialSki: opts.subjectSki,
		});
		return {
			credential: opts.credential,
			leafPem: opts.leafPem,
			chainPem: opts.chainPem,
			platformCertCosign,
		};
	}

	// interim_admin
	const platformCertCosign = await opts.cosign.cosignLeafCert(opts.leafPem, {
		chainPem: opts.chainPem,
		subjectSki: opts.subjectSki,
	});
	await opts.dp.createCredential({ credential: opts.credential });
	return {
		credential: opts.credential,
		leafPem: opts.leafPem,
		chainPem: opts.chainPem,
		platformCertCosign,
	};
}

export function createEnrollEndpoints(opts: {
	serviceId: string;
	configuredSeed: CatalogSeed | null;
	cosign?: CosignProvider;
	seatBinder?: SeatBinder;
	getFallbackCosignKey?: () => Promise<KeyPairMaterial>;
	resolveCosign: () => Promise<CosignProvider>;
	inviteExpiresIn?: number;
	inviteMaxExpiresIn?: number;
	inviteMaxUses?: number;
	credentialExpiresIn?: number;
}) {
	const inviteMaxExpiresIn =
		opts.inviteMaxExpiresIn ?? DEFAULT_INVITE_MAX_EXPIRES_IN;
	const inviteExpiresIn = Math.min(
		opts.inviteExpiresIn ?? DEFAULT_INVITE_EXPIRES_IN,
		inviteMaxExpiresIn,
	);
	const inviteMaxUses = opts.inviteMaxUses ?? DEFAULT_INVITE_MAX_USES;
	const credentialExpiresIn =
		opts.credentialExpiresIn ?? DEFAULT_CREDENTIAL_EXPIRES_IN;
	const dpOf = (adapter: Parameters<typeof getDelegatePermissionsAdapter>[0]) =>
		getDelegatePermissionsAdapter(adapter, opts.serviceId);

	return {
		dpEnrollCreate: createAuthEndpoint(
			"/delegate-permissions/enroll-create",
			{
				method: "POST",
				body: z.object({
					entityId: z.string().min(1).optional(),
					host: z.string().optional(),
					zone: z.string().optional(),
					kind: enrollKindSchema.optional(),
					role: enrollKindSchema.default("machine_target"),
					csrPem: z.string().min(1),
					publicJwk: z.record(z.string(), z.unknown()).optional(),
					subjectSki: z.string().min(1).optional(),
					inviteToken: z.string().min(1).optional(),
				}),
				metadata: {
					openapi: {
						description:
							"Create a pending enrollment CSR (machine, zone authority, or interim admin). Optional inviteToken binds the CSR to an invited entity.",
					},
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				await ensureCatalog(dp, opts.configuredSeed);
				const invite = ctx.body.inviteToken
					? await requireOpenInvite(dp, ctx.body.inviteToken)
					: null;

				let entityId = (
					ctx.body.entityId ??
					invite?.entityId ??
					""
				).toLowerCase();
				if (invite) {
					if (entityId && entityId !== invite.entityId) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.INVITE_MISMATCH,
						);
					}
					entityId = invite.entityId;
				}
				if (!entityId) {
					throw APIError.from(
						"NOT_FOUND",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND,
					);
				}
				const entity = await dp.getEntity(entityId);
				if (!entity) {
					throw APIError.from(
						"NOT_FOUND",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND,
					);
				}

				const kind = normalizeEnrollKind(ctx.body.kind ?? ctx.body.role);
				assertKindAllowedForPackage(entity.package, kind);

				let host = "";
				let zone: string | null = null;
				if (isMachineKind(kind)) {
					if (!ctx.body.host) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST,
						);
					}
					host = ctx.body.host.toLowerCase();
					const parsed = parseMachineHost(host, entityId);
					if (!parsed) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST,
						);
					}
				} else if (kind === "zone_authority") {
					zone = zoneNameKey(ctx.body.zone ?? "");
					if (!zone) {
						throw APIError.from("BAD_REQUEST", {
							message: "zone is required for zone_authority",
							code: "ZONE_REQUIRED",
						});
					}
				}

				const bound = await bindEnrollCsr(
					ctx.body.csrPem,
					ctx.body.publicJwk,
					ctx.body.subjectSki,
				);
				if (invite) {
					const redeemed = await dp.redeemEnrollInvite(invite.id);
					if (!redeemed) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.INVITE_USED,
						);
					}
				}
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
					createdByUserId: ctx.context.session?.user?.id ?? null,
				});
				return {
					enrollId: row.id,
					pullToken: row.pullToken,
					subjectSki,
					kind,
					status: "pending" as const,
				};
			},
		),

		dpEnrollInviteCreate: createAuthEndpoint(
			"/delegate-permissions/enroll-invite",
			{
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({
					entityId: z.string().min(1),
					kind: enrollKindSchema.optional(),
					role: enrollKindSchema.optional(),
					expiresIn: z.number().int().positive().optional(),
					/** Redeem cap. Default from plugin `inviteMaxUses` (`1`). `0` = unlimited until expiresAt. */
					maxUses: z.number().int().min(0).optional(),
				}),
				metadata: {
					openapi: {
						description:
							"Create a push-invite token that authorizes a device to submit a CSR for an entity",
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
				const kind = normalizeEnrollKind(
					ctx.body.kind ?? ctx.body.role ?? "machine_target",
				);
				if (!isMachineKind(kind)) {
					throw APIError.from("BAD_REQUEST", {
						message:
							"enroll invites are for machine_target or machine_source only",
						code: "INVITE_KIND_UNSUPPORTED",
					});
				}
				assertKindAllowedForPackage(entity.package, kind);
				const maxUses = ctx.body.maxUses ?? inviteMaxUses;
				const expiresAt = new Date(
					Date.now() +
						inviteTtlSeconds(
							ctx.body.expiresIn,
							inviteExpiresIn,
							inviteMaxExpiresIn,
						) *
							1000,
				);
				const row = await dp.createEnrollInvite({
					entityId,
					role: kind,
					inviteToken: randomPullToken(),
					expiresAt,
					maxUses,
					createdByUserId: ctx.context.session.user.id,
				});
				return {
					inviteId: row.id,
					inviteToken: row.inviteToken,
					entityId: row.entityId,
					kind,
					expiresAt: asDate(row.expiresAt).toISOString(),
					maxUses,
				};
			},
		),

		dpEnrollInviteGet: createAuthEndpoint(
			"/delegate-permissions/enroll-invite",
			{
				method: "GET",
				query: z.object({
					inviteToken: z.string().min(1),
				}),
				metadata: {
					openapi: {
						description: "Look up an enrollment invite without consuming it",
					},
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				const invite = await requireOpenInvite(dp, ctx.query.inviteToken);
				return {
					inviteId: invite.id,
					entityId: invite.entityId,
					kind: invite.role,
					expiresAt: invite.expiresAt.toISOString(),
					maxUses: invite.maxUses,
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
						host: r.host || null,
						zone: r.zone,
						kind: r.role,
						role: r.role,
						subjectSki: r.subjectSki,
						status: r.status,
						createdAt: r.createdAt,
						csrPem: r.csrPem,
						publicJwk: r.publicJwk,
						entityId: r.entityId,
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
					/** When set, server issues a signed machine credential from the enroll row. */
					issuerPrivateJwk: z.record(z.string(), z.unknown()).optional(),
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
				if (!(await leafMatchesCsr(ctx.body.leafPem, row.csrPem))) {
					throw APIError.from(
						"BAD_REQUEST",
						DELEGATE_PERMISSIONS_ERROR_CODES.CERT_MISMATCH,
					);
				}
				const kind = normalizeEnrollKind(
					row.role as z.infer<typeof enrollKindSchema>,
				);
				const entity = await dp.getEntity(row.entityId);
				if (!entity) {
					throw APIError.from(
						"NOT_FOUND",
						DELEGATE_PERMISSIONS_ERROR_CODES.ENTITY_NOT_FOUND,
					);
				}
				let credential = ctx.body.credential as unknown as CapabilityCredential;
				if (
					ctx.body.issuerPrivateJwk &&
					(!credential.signature || typeof credential.signature !== "string")
				) {
					const profiles = await dp.loadProfiles();
					const nameKey = isMachineKind(kind)
						? machineNameKey(
								parseMachineHost(row.host, row.entityId)?.path ?? "",
							)
						: "";
					const permissions =
						(credential.permissions as CapabilitySet | undefined) ??
						(isMachineKind(kind)
							? withNameScope(
									withEntityScope(
										expandProfile("machine", profiles, catalog),
										row.entityId,
									),
									nameKey,
								)
							: withEntityScope(
									expandProfile("interim_admin", profiles, catalog),
									row.entityId,
								));
					credential = await issueCredential({
						kind: isMachineKind(kind) ? "machine" : "interim_admin",
						entityId: row.entityId,
						subject: {
							ski: row.subjectSki,
							publicJwk: row.publicJwk as PublicJwk,
							privateJwk: {},
						},
						permissions,
						issuerSki: ctx.body.issuerSki,
						issuerPrivateJwk: ctx.body.issuerPrivateJwk,
						host: row.host || undefined,
						zone: row.zone || undefined,
						package: entity.package as EntityPackage,
						ttlSeconds: credentialExpiresIn,
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
					kind,
					seatId: finalized.seatId,
					platformCertPem: finalized.platformCertCosign.platformCertPem,
					platformRootPem: finalized.platformCertCosign.platformRootPem,
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
				// Idempotent: already-pulled enrolls still return materials (app restart / refresh).
				if (row.status === "consumed" || row.status === "approved") {
					if (!row.leafPem || !row.chainPem || !row.credential) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_READY,
						);
					}
					if (row.status === "approved") {
						await dp.updateEnrollRequest(row.id, { status: "consumed" });
					}
					return {
						status: "approved" as const,
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
						platformCertPem:
							(row.platformCertCosign as { platformCertPem?: string } | null)
								?.platformCertPem ?? null,
						platformRootPem:
							(row.platformCertCosign as { platformRootPem?: string } | null)
								?.platformRootPem ?? null,
						platformCertCosign: row.platformCertCosign,
						seatId: row.seatId,
					};
				}
				throw APIError.from(
					"BAD_REQUEST",
					DELEGATE_PERMISSIONS_ERROR_CODES.ENROLL_NOT_READY,
				);
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
					payingPartyId: z.string().optional(),
				}),
				metadata: {
					openapi: {
						description:
							"Instant enroll when admin CA keys are on the same host (sign + accept in one call)",
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
				const kind = normalizeEnrollKind(ctx.body.kind ?? ctx.body.role);
				assertKindAllowedForPackage(entity.package, kind);
				const host = (ctx.body.host ?? "").toLowerCase();
				const zone = ctx.body.zone ? zoneNameKey(ctx.body.zone) : null;
				if (isMachineKind(kind) && !host) {
					throw APIError.from(
						"BAD_REQUEST",
						DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST,
					);
				}
				const bound = await bindEnrollCsr(
					ctx.body.csrPem,
					ctx.body.publicJwk,
					ctx.body.subjectSki,
				);
				const subjectSki = bound.ski;
				if (!(await leafMatchesCsr(ctx.body.leafPem, ctx.body.csrPem))) {
					throw APIError.from(
						"BAD_REQUEST",
						DELEGATE_PERMISSIONS_ERROR_CODES.CERT_MISMATCH,
					);
				}
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
					host: host || null,
					zone,
					kind,
					certPem: finalized.leafPem,
					chainPem: finalized.chainPem,
					credential: finalized.credential,
					platformCertPem: finalized.platformCertCosign.platformCertPem,
					platformRootPem: finalized.platformCertCosign.platformRootPem,
					platformCertCosign: finalized.platformCertCosign,
					seatId: finalized.seatId,
				};
			},
		),

		/** Build default permissions for enroll kind (admin CLI helper). */
		dpEnrollMachinePermissions: createAuthEndpoint(
			"/delegate-permissions/enroll-machine-permissions",
			{
				method: "POST",
				use: [sessionMiddleware],
				body: z.object({
					entityId: z.string().min(1),
					host: z.string().optional(),
					zone: z.string().optional(),
					kind: enrollKindSchema.optional(),
					role: enrollKindSchema.default("machine_target"),
					permissions: capabilitySetSchema.optional(),
				}),
				metadata: {
					openapi: {
						description:
							"Expand catalog profile for machine / zone / interim enroll (offline credential signing)",
					},
				},
			},
			async (ctx) => {
				const dp = dpOf(ctx.context.adapter);
				const catalog = await ensureCatalog(dp, opts.configuredSeed);
				const entityId = ctx.body.entityId.toLowerCase();
				const kind = normalizeEnrollKind(ctx.body.kind ?? ctx.body.role);
				const profiles = await dp.loadProfiles();
				let permissions: CapabilitySet;
				let nameKey = "";

				if (ctx.body.permissions) {
					permissions = parseCapabilitySet(ctx.body.permissions);
				} else if (kind === "interim_admin") {
					permissions = withEntityScope(
						expandProfile("interim_admin", profiles, catalog),
						entityId,
					);
				} else if (kind === "zone_authority") {
					nameKey = zoneNameKey(ctx.body.zone ?? "");
					if (!nameKey) {
						throw APIError.from("BAD_REQUEST", {
							message: "zone is required for zone_authority",
							code: "ZONE_REQUIRED",
						});
					}
					permissions = withNameScope(
						withEntityScope(
							expandProfile("zone_delegate", profiles, catalog),
							entityId,
						),
						nameKey,
					);
				} else {
					if (!ctx.body.host) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST,
						);
					}
					const parsed = parseMachineHost(
						ctx.body.host.toLowerCase(),
						entityId,
					);
					if (!parsed) {
						throw APIError.from(
							"BAD_REQUEST",
							DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_HOST,
						);
					}
					nameKey = machineNameKey(parsed.path);
					const profileName =
						kind === "machine_source" ? "machine_source" : "machine";
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
				return { permissions, nameKey, entityId, kind };
			},
		),
	};
}
