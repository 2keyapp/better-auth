import { CompactSign, compactVerify, importJWK } from "jose";
//#region src/plugins/delegate-permissions/pki/cert-cosign.ts
/**
* Platform co-sign over an X.509 PEM (DER committed as base64).
* Used for Entity CA roots and machine leaf certificates.
*/
async function attachPlatformCertCosign(certPem, platformPrivateJwk, platformKid) {
	const signedAt = (/* @__PURE__ */ new Date()).toISOString();
	const key = await importJWK(platformPrivateJwk, "EdDSA");
	const derB64 = pemToDerB64(certPem);
	return {
		kid: platformKid,
		signedAt,
		signature: await new CompactSign(new TextEncoder().encode(JSON.stringify({
			certDerB64: derB64,
			signedAt
		}))).setProtectedHeader({
			alg: "EdDSA",
			kid: platformKid
		}).sign(key)
	};
}
async function verifyPlatformCertCosign(certPem, cosign, platformPublicJwk) {
	try {
		const key = await importJWK(platformPublicJwk, "EdDSA");
		const { payload } = await compactVerify(cosign.signature, key);
		const expected = JSON.stringify({
			certDerB64: pemToDerB64(certPem),
			signedAt: cosign.signedAt
		});
		return new TextDecoder().decode(payload) === expected;
	} catch {
		return false;
	}
}
function pemToDerB64(pem) {
	return pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
}
//#endregion
export { attachPlatformCertCosign, verifyPlatformCertCosign };
