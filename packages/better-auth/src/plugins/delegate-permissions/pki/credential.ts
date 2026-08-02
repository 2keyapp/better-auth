import { CompactSign, compactVerify, importJWK } from "jose";
import type { CapabilitySet } from "../capability/types";
import type {
	CapabilityCredential,
	CredentialKind,
	EntityPackage,
	KeyPairMaterial,
	PublicJwk,
} from "./types";

type UnsignedCredential = Omit<CapabilityCredential, "signature">;

function canonicalPayload(credential: UnsignedCredential): Uint8Array {
	// idrCosign is attested separately and must not break the issuer signature.
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
		package: credential.package ?? null,
	};
	return new TextEncoder().encode(JSON.stringify(ordered));
}

async function signCredential(
	unsigned: UnsignedCredential,
	issuerPrivateJwk: Record<string, unknown>,
): Promise<CapabilityCredential> {
	const key = await importJWK(issuerPrivateJwk, "EdDSA");
	const signature = await new CompactSign(canonicalPayload(unsigned))
		.setProtectedHeader({ alg: "EdDSA" })
		.sign(key);
	// CompactSign returns header.payload.signature — store full compact JWS
	return { ...unsigned, signature };
}

export async function verifyCredentialSignature(
	credential: CapabilityCredential,
	issuerPublicJwk: PublicJwk,
): Promise<boolean> {
	try {
		const key = await importJWK(issuerPublicJwk, "EdDSA");
		const { payload } = await compactVerify(credential.signature, key);
		const expected = canonicalPayload(credential);
		if (payload.byteLength !== expected.byteLength) {
			return false;
		}
		for (let i = 0; i < expected.byteLength; i++) {
			if (payload[i] !== expected[i]) {
				return false;
			}
		}
		return true;
	} catch {
		return false;
	}
}

export async function issueCredential(input: {
	kind: CredentialKind;
	entityId: string;
	subject: KeyPairMaterial;
	permissions: CapabilitySet;
	issuerSki: string;
	issuerPrivateJwk: Record<string, unknown>;
	zone?: string;
	host?: string;
	package?: EntityPackage;
	ttlSeconds?: number;
}): Promise<CapabilityCredential> {
	const now = Date.now();
	const ttl = (input.ttlSeconds ?? 365 * 24 * 60 * 60) * 1000;
	const unsigned: UnsignedCredential = {
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
		package: input.package,
	};
	return signCredential(unsigned, input.issuerPrivateJwk);
}

/** Test/dev cosign: re-sign idrCosign block with provided IDR key. */
export async function attachIdrCosign(
	credential: CapabilityCredential,
	idrPrivateJwk: Record<string, unknown>,
	idrKid: string,
): Promise<CapabilityCredential> {
	const signedAt = new Date().toISOString();
	const key = await importJWK(idrPrivateJwk, "EdDSA");
	const body = new TextEncoder().encode(
		JSON.stringify({
			ski: credential.ski,
			kind: credential.kind,
			entityId: credential.entityId,
			host: credential.host ?? null,
			signedAt,
		}),
	);
	const signature = await new CompactSign(body)
		.setProtectedHeader({ alg: "EdDSA", kid: idrKid })
		.sign(key);
	return {
		...credential,
		idrCosign: { kid: idrKid, signedAt, signature },
	};
}
