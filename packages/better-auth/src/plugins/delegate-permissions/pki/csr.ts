/**
 * PKCS#10 CSR bind + Entity-CA leaf issue for machine enrollment.
 *
 * The device keeps the private key. Better Auth stores the CSR, checks the
 * admin-signed leaf matches that CSR, then Platform co-signs the same SPKI.
 */
import * as x509 from "@peculiar/x509";
import { calculateJwkThumbprint, exportJWK, importJWK } from "jose";
import { constantTimeEqual } from "../../../crypto/buffer";
import { generateEd25519KeyPair } from "./keys";
import type { KeyPairMaterial, PublicJwk } from "./types";

const ED25519 = { name: "Ed25519" } as const;
const DAY_MS = 24 * 60 * 60 * 1000;

function setX509Crypto(): void {
	x509.cryptoProvider.set(globalThis.crypto);
}

function toPublicJwk(jwk: Record<string, unknown>): PublicJwk {
	const { d: _d, ...rest } = jwk;
	return rest as PublicJwk;
}

function jwkCoordsEqual(a: PublicJwk, b: PublicJwk): boolean {
	return a.kty === b.kty && a.crv === b.crv && a.x === b.x;
}

async function publicJwkFromCsr(
	csr: x509.Pkcs10CertificateRequest,
): Promise<PublicJwk> {
	const cryptoKey = await csr.publicKey.export();
	return toPublicJwk((await exportJWK(cryptoKey)) as Record<string, unknown>);
}

/**
 * Parse a PKCS#10 PEM, verify the CSR signature, and bind it to `publicJwk`
 * when that is supplied. Returns the canonical public JWK + SKI from the CSR.
 */
export async function bindCsrToPublicJwk(
	csrPem: string,
	publicJwk?: Record<string, unknown>,
): Promise<{ ski: string; publicJwk: PublicJwk }> {
	setX509Crypto();
	let csr: x509.Pkcs10CertificateRequest;
	try {
		csr = new x509.Pkcs10CertificateRequest(csrPem);
	} catch {
		throw new Error("INVALID_CSR");
	}
	const signatureOk = await csr.verify();
	if (!signatureOk) {
		throw new Error("INVALID_CSR");
	}
	const csrJwk = await publicJwkFromCsr(csr);
	if (publicJwk) {
		if (publicJwk.d != null) {
			throw new Error("INVALID_CSR");
		}
		if (!jwkCoordsEqual(csrJwk, toPublicJwk(publicJwk))) {
			throw new Error("INVALID_CSR");
		}
	}
	const ski = await calculateJwkThumbprint(csrJwk, "sha256");
	return {
		ski,
		publicJwk: { ...csrJwk, kid: ski, alg: "EdDSA" },
	};
}

/** True when the leaf SPKI is the same public key as the enrollment CSR. */
export async function leafMatchesCsr(
	leafPem: string,
	csrPem: string,
): Promise<boolean> {
	setX509Crypto();
	try {
		const csr = new x509.Pkcs10CertificateRequest(csrPem);
		const leaf = new x509.X509Certificate(leafPem);
		return constantTimeEqual(
			new Uint8Array(csr.publicKey.rawData),
			new Uint8Array(leaf.publicKey.rawData),
		);
	} catch {
		return false;
	}
}

/**
 * Device `identity init`: Ed25519 keypair + PKCS#10 CSR.
 * Private key is returned once for the caller to store locally.
 */
export async function createDeviceCsr(input?: {
	commonName?: string;
}): Promise<{
	key: KeyPairMaterial;
	csrPem: string;
}> {
	setX509Crypto();
	const key = await generateEd25519KeyPair();
	const privateKey = (await importJWK(
		{ ...key.privateJwk, alg: "EdDSA" },
		"EdDSA",
	)) as CryptoKey;
	const publicKey = (await importJWK(
		{ ...key.publicJwk, alg: "EdDSA" },
		"EdDSA",
	)) as CryptoKey;
	const csr = await x509.Pkcs10CertificateRequestGenerator.create({
		name: `CN=${input?.commonName ?? key.ski}`,
		keys: { privateKey, publicKey },
		signingAlgorithm: ED25519,
	});
	return { key, csrPem: csr.toString("pem") };
}

/**
 * Admin signs a pending CSR with the Entity CA (same host as `enroll-instant`).
 * `chainPem` is leaf + Entity CA so Platform can verify before endorsement.
 */
export async function signCsrWithCa(input: {
	csrPem: string;
	caCertPem: string;
	caPrivateJwk: Record<string, unknown>;
	host?: string;
	subjectCn?: string;
	notAfterDays?: number;
}): Promise<{ leafPem: string; chainPem: string }> {
	setX509Crypto();
	const bound = await bindCsrToPublicJwk(input.csrPem);
	const csr = new x509.Pkcs10CertificateRequest(input.csrPem);
	const caCert = new x509.X509Certificate(input.caCertPem);
	const caPrivateKey = (await importJWK(
		{ ...input.caPrivateJwk, alg: "EdDSA" },
		"EdDSA",
	)) as CryptoKey;

	const notBefore = new Date();
	const notAfter = new Date(
		notBefore.getTime() + (input.notAfterDays ?? 365) * DAY_MS,
	);
	const subjectCn = input.subjectCn ?? bound.ski;
	const leaf = await x509.X509CertificateGenerator.create({
		serialNumber: Array.from(
			globalThis.crypto.getRandomValues(new Uint8Array(16)),
		)
			.map((b) => b.toString(16).padStart(2, "0"))
			.join(""),
		subject: `CN=${subjectCn}`,
		issuer: caCert.subjectName,
		notBefore,
		notAfter,
		publicKey: csr.publicKey,
		signingKey: caPrivateKey,
		signingAlgorithm: ED25519,
		extensions: [
			new x509.KeyUsagesExtension(
				x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement,
				true,
			),
			new x509.ExtendedKeyUsageExtension(
				[x509.ExtendedKeyUsage.clientAuth],
				false,
			),
			...(input.host
				? [
						new x509.SubjectAlternativeNameExtension(
							[{ type: "dns" as const, value: input.host }],
							false,
						),
					]
				: []),
		],
	});
	const leafPem = leaf.toString("pem");
	const caPem = input.caCertPem.endsWith("\n")
		? input.caCertPem
		: `${input.caCertPem}\n`;
	return {
		leafPem,
		chainPem: `${leafPem}\n${caPem}`,
	};
}
