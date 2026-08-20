import { CompactSign, compactVerify, importJWK } from "jose";

export type PlatformCertCosign = {
	readonly kid: string;
	readonly signedAt: string;
	readonly signature: string;
};

/**
 * Platform co-sign over an X.509 PEM (DER committed as base64).
 * Used for Entity CA roots and machine leaf certificates.
 */
export async function attachPlatformCertCosign(
	certPem: string,
	platformPrivateJwk: Record<string, unknown>,
	platformKid: string,
): Promise<PlatformCertCosign> {
	const signedAt = new Date().toISOString();
	const key = await importJWK(platformPrivateJwk, "EdDSA");
	const derB64 = pemToDerB64(certPem);
	const body = new TextEncoder().encode(
		JSON.stringify({ certDerB64: derB64, signedAt }),
	);
	const signature = await new CompactSign(body)
		.setProtectedHeader({ alg: "EdDSA", kid: platformKid })
		.sign(key);
	return { kid: platformKid, signedAt, signature };
}

export async function verifyPlatformCertCosign(
	certPem: string,
	cosign: PlatformCertCosign,
	platformPublicJwk: Record<string, unknown>,
): Promise<boolean> {
	try {
		const key = await importJWK(platformPublicJwk, "EdDSA");
		const { payload } = await compactVerify(cosign.signature, key);
		const expected = JSON.stringify({
			certDerB64: pemToDerB64(certPem),
			signedAt: cosign.signedAt,
		});
		return new TextDecoder().decode(payload) === expected;
	} catch {
		return false;
	}
}

function pemToDerB64(pem: string): string {
	const b64 = pem
		.replace(/-----BEGIN [^-]+-----/g, "")
		.replace(/-----END [^-]+-----/g, "")
		.replace(/\s+/g, "");
	return b64;
}
