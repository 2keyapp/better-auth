import { CompactSign, compactVerify, importJWK } from "jose";
//#region src/plugins/delegate-permissions/pki/credential.ts
function canonicalPayload(credential) {
	const ordered = {
		version: credential.version,
		kind: credential.kind,
		entityId: credential.entityId,
		ski: credential.ski,
		publicJwk: credential.publicJwk,
		permissions: credential.permissions,
		zone: credential.zone ?? null,
		host: credential.host ?? null,
		issuerSki: credential.issuerSki,
		notBefore: credential.notBefore,
		notAfter: credential.notAfter,
		package: credential.package ?? null
	};
	return new TextEncoder().encode(JSON.stringify(ordered));
}
async function signCredential(unsigned, issuerPrivateJwk) {
	const key = await importJWK(issuerPrivateJwk, "EdDSA");
	const signature = await new CompactSign(canonicalPayload(unsigned)).setProtectedHeader({ alg: "EdDSA" }).sign(key);
	return {
		...unsigned,
		signature
	};
}
async function verifyCredentialSignature(credential, issuerPublicJwk) {
	try {
		const key = await importJWK(issuerPublicJwk, "EdDSA");
		const { payload } = await compactVerify(credential.signature, key);
		const expected = canonicalPayload(credential);
		if (payload.byteLength !== expected.byteLength) return false;
		for (let i = 0; i < expected.byteLength; i++) if (payload[i] !== expected[i]) return false;
		return true;
	} catch {
		return false;
	}
}
async function issueCredential(input) {
	const now = Date.now();
	const ttl = (input.ttlSeconds ?? 365 * 24 * 60 * 60) * 1e3;
	return signCredential({
		version: 1,
		kind: input.kind,
		entityId: input.entityId,
		ski: input.subject.ski,
		publicJwk: input.subject.publicJwk,
		permissions: input.permissions,
		zone: input.zone,
		host: input.host,
		issuerSki: input.issuerSki,
		notBefore: new Date(now).toISOString(),
		notAfter: new Date(now + ttl).toISOString(),
		package: input.package
	}, input.issuerPrivateJwk);
}
/** Test/dev cosign: attach platformCosign with the platform authority key. */
async function attachPlatformCosign(credential, platformPrivateJwk, platformKid) {
	const signedAt = (/* @__PURE__ */ new Date()).toISOString();
	const key = await importJWK(platformPrivateJwk, "EdDSA");
	const signature = await new CompactSign(new TextEncoder().encode(JSON.stringify({
		ski: credential.ski,
		kind: credential.kind,
		entityId: credential.entityId,
		host: credential.host ?? null,
		signedAt
	}))).setProtectedHeader({
		alg: "EdDSA",
		kid: platformKid
	}).sign(key);
	return {
		...credential,
		platformCosign: {
			kid: platformKid,
			signedAt,
			signature
		}
	};
}
//#endregion
export { attachPlatformCosign, issueCredential, verifyCredentialSignature };
