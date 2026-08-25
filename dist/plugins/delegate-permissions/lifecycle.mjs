import { sessionMiddleware } from "../../api/routes/session.mjs";
import { APIError } from "../../api/index.mjs";
import { getDelegatePermissionsAdapter } from "./adapter.mjs";
import { assertSubset } from "./capability/subset.mjs";
import { DELEGATE_PERMISSIONS_ERROR_CODES } from "./error-codes.mjs";
import { machineNameKey, parseMachineHost } from "./names.mjs";
import { bindCsrToPublicJwk, leafMatchesCsr } from "./pki/csr.mjs";
import { createAuthEndpoint } from "@better-auth/core/api";
import * as z from "zod";
//#region src/plugins/delegate-permissions/lifecycle.ts
const revocationReasonSchema = z.enum([
	"decommissioned",
	"key_compromise",
	"machine_lost",
	"replaced",
	"organization_policy",
	"renewed",
	"other"
]);
function createLifecycleEndpoints(opts) {
	const dpOf = (adapter) => getDelegatePermissionsAdapter(adapter, opts.serviceId);
	async function ensureCatalog(dp) {
		let catalog = await dp.loadCatalog();
		if (!catalog && opts.configuredSeed) catalog = await dp.seedCatalog(opts.configuredSeed);
		if (!catalog) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CATALOG_NOT_SEEDED);
		return catalog;
	}
	return {
		dpCredentialRevoke: createAuthEndpoint("/delegate-permissions/credential-revoke", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({
				ski: z.string().min(1),
				reason: revocationReasonSchema.default("other")
			}),
			metadata: { openapi: { description: "Revoke a credential by SKI. The certificate remains cryptographically valid but the server marks it revoked." } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const cred = await dp.getCredential(ctx.body.ski);
			if (!cred) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.CREDENTIAL_NOT_FOUND);
			if (cred.status === "revoked") throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CREDENTIAL_ALREADY_REVOKED);
			const now = /* @__PURE__ */ new Date();
			await dp.updateCredentialStatus(ctx.body.ski, {
				status: "revoked",
				revokedAt: now,
				revokedReason: ctx.body.reason
			});
			return {
				ski: ctx.body.ski,
				status: "revoked",
				reason: ctx.body.reason,
				revokedAt: now.toISOString()
			};
		}),
		dpCredentialStatus: createAuthEndpoint("/delegate-permissions/credential-status", {
			method: "GET",
			query: z.object({ ski: z.string().min(1) }),
			metadata: { openapi: { description: "Check credential status by SKI" } }
		}, async (ctx) => {
			const cred = await dpOf(ctx.context.adapter).getCredential(ctx.query.ski);
			if (!cred) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.CREDENTIAL_NOT_FOUND);
			return {
				ski: cred.ski,
				entityId: cred.entityId,
				kind: cred.kind,
				status: cred.status,
				host: cred.host,
				zone: cred.zone,
				revokedAt: cred.revokedAt?.toISOString() ?? null,
				revokedReason: cred.revokedReason ?? null,
				renewedBySki: cred.renewedBySki ?? null,
				createdAt: cred.createdAt.toISOString()
			};
		}),
		dpCredentialList: createAuthEndpoint("/delegate-permissions/credential-list", {
			method: "GET",
			use: [sessionMiddleware],
			query: z.object({
				entityId: z.string().min(1),
				status: z.string().optional()
			}),
			metadata: { openapi: { description: "List credentials for an entity, optionally filtered by status" } }
		}, async (ctx) => {
			return { credentials: (await dpOf(ctx.context.adapter).listCredentials(ctx.query.entityId.toLowerCase(), ctx.query.status)).map((c) => ({
				ski: c.ski,
				entityId: c.entityId,
				kind: c.kind,
				status: c.status,
				host: c.host,
				zone: c.zone,
				seatId: c.seatId,
				revokedAt: c.revokedAt?.toISOString() ?? null,
				revokedReason: c.revokedReason ?? null,
				renewedBySki: c.renewedBySki ?? null,
				createdAt: c.createdAt.toISOString()
			})) };
		}),
		dpMachineDecommission: createAuthEndpoint("/delegate-permissions/machine-decommission", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({
				ski: z.string().min(1),
				reason: revocationReasonSchema.default("decommissioned")
			}),
			metadata: { openapi: { description: "Decommission a machine: revoke credential, release name occupancy, optionally release seat" } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const cred = await dp.getCredential(ctx.body.ski);
			if (!cred) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.CREDENTIAL_NOT_FOUND);
			if (cred.status === "revoked" || cred.status === "decommissioned") throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CREDENTIAL_ALREADY_REVOKED);
			const now = /* @__PURE__ */ new Date();
			await dp.updateCredentialStatus(ctx.body.ski, {
				status: "decommissioned",
				revokedAt: now,
				revokedReason: ctx.body.reason
			});
			await dp.releaseNameBySki(cred.entityId, ctx.body.ski);
			if (cred.seatId && opts.seatBinder?.release) try {
				await opts.seatBinder.release(cred.seatId);
			} catch {}
			return {
				ski: ctx.body.ski,
				entityId: cred.entityId,
				status: "decommissioned",
				reason: ctx.body.reason,
				revokedAt: now.toISOString()
			};
		}),
		dpMachineRenew: createAuthEndpoint("/delegate-permissions/machine-renew", {
			method: "POST",
			use: [sessionMiddleware],
			body: z.object({
				ski: z.string().min(1),
				csrPem: z.string().min(1),
				publicJwk: z.record(z.string(), z.unknown()).optional(),
				leafPem: z.string().min(1),
				chainPem: z.string().min(1),
				credential: z.record(z.string(), z.unknown()),
				issuerSki: z.string().min(1)
			}),
			metadata: { openapi: { description: "Renew a machine certificate: new key/CSR/cert, same identity. Old credential is marked renewed." } }
		}, async (ctx) => {
			const dp = dpOf(ctx.context.adapter);
			const catalog = await ensureCatalog(dp);
			const oldCred = await dp.getCredential(ctx.body.ski);
			if (!oldCred) throw APIError.from("NOT_FOUND", DELEGATE_PERMISSIONS_ERROR_CODES.CREDENTIAL_NOT_FOUND);
			if (oldCred.status !== "active") throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CREDENTIAL_NOT_ACTIVE);
			let bound;
			try {
				bound = await bindCsrToPublicJwk(ctx.body.csrPem, ctx.body.publicJwk);
			} catch {
				throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.INVALID_CSR);
			}
			if (!await leafMatchesCsr(ctx.body.leafPem, ctx.body.csrPem)) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.CERT_MISMATCH);
			const newCredential = ctx.body.credential;
			if (newCredential.entityId !== oldCred.entityId) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.RENEWAL_IDENTITY_MISMATCH);
			if (newCredential.host && oldCred.host && newCredential.host !== oldCred.host) throw APIError.from("BAD_REQUEST", DELEGATE_PERMISSIONS_ERROR_CODES.RENEWAL_IDENTITY_MISMATCH);
			const issuerRow = await dp.getCredential(ctx.body.issuerSki);
			if (!issuerRow || issuerRow.entityId !== oldCred.entityId) throw APIError.from("FORBIDDEN", DELEGATE_PERMISSIONS_ERROR_CODES.ISSUER_UNAUTHORIZED);
			const issuerCred = issuerRow.credential;
			const subset = assertSubset(newCredential.permissions, issuerCred.permissions, catalog);
			if (!subset.ok) throw APIError.from("FORBIDDEN", {
				message: subset.message,
				code: subset.code
			});
			const cosign = await opts.resolveCosign();
			const platformCertCosign = await cosign.cosignLeafCert(ctx.body.leafPem, {
				chainPem: ctx.body.chainPem,
				subjectSki: bound.ski,
				host: oldCred.host ?? void 0
			});
			const cosignedCredential = await cosign.cosignMachine(newCredential, oldCred.seatId ?? `dev-seat-${bound.ski.slice(0, 12)}`);
			await dp.createCredential({
				credential: cosignedCredential,
				seatId: oldCred.seatId
			});
			const now = /* @__PURE__ */ new Date();
			await dp.updateCredentialStatus(ctx.body.ski, {
				status: "renewed",
				revokedAt: now,
				revokedReason: "renewed",
				renewedBySki: bound.ski
			});
			if (oldCred.host) {
				await dp.releaseNameBySki(oldCred.entityId, ctx.body.ski);
				const parsed = parseMachineHost(oldCred.host, oldCred.entityId);
				if (parsed) await dp.claimName({
					entityId: oldCred.entityId,
					nameKey: machineNameKey(parsed.path),
					kind: "machine",
					credentialSki: bound.ski
				});
			}
			return {
				oldSki: ctx.body.ski,
				newSki: bound.ski,
				status: "renewed",
				entityId: oldCred.entityId,
				host: oldCred.host,
				platformCertPem: platformCertCosign.platformCertPem,
				platformRootPem: platformCertCosign.platformRootPem
			};
		})
	};
}
//#endregion
export { createLifecycleEndpoints };
