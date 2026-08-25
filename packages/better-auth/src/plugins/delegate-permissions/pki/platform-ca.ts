/**
 * Platform self-signed X.509 CA helpers.
 *
 * After an Entity admin signs a leaf (or Entity CA is registered), the Platform
 * CA issues a Platform-signed endorsement certificate for the same public key.
 */
import * as x509 from "@peculiar/x509";
import { calculateJwkThumbprint, exportJWK, importJWK } from "jose";
import type { KeyPairMaterial, PublicJwk } from "./types";

const DAY_MS = 24 * 60 * 60 * 1000;
const ED25519 = { name: "Ed25519" } as const;
const DEFAULT_PLATFORM_CN = "Platform CA";

export type PlatformCertIssue = {
	readonly platformCertPem: string;
	readonly platformRootPem: string;
};

export type PlatformCaMaterial = {
	readonly key: KeyPairMaterial;
	readonly rootPem: string;
	readonly privateKey: CryptoKey;
	readonly publicKey: CryptoKey;
};

function randomSerialHex(bytes = 16): string {
	const buf = new Uint8Array(bytes);
	globalThis.crypto.getRandomValues(buf);
	return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function setX509Crypto(): void {
	x509.cryptoProvider.set(globalThis.crypto);
}

/** All PEM certificate blocks from a PEM or PEM chain. */
function pemCerts(pemOrChain: string): string[] {
	const matches = pemOrChain.match(
		/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
	);
	if (!matches?.length) {
		throw new Error("No CERTIFICATE PEM block found in chain");
	}
	return matches;
}

/**
 * Issuer CA PEM from a chain. Device `chainPem` is typically leaf+EntityCA
 * (leaf first); use the last cert. A bare Entity CA PEM is a single block.
 */
function issuerPemFromChain(pemOrChain: string): string {
	const certs = pemCerts(pemOrChain);
	return certs[certs.length - 1]!;
}

async function skiFromPublicJwk(
	publicJwk: Record<string, unknown>,
): Promise<string> {
	const { d: _d, ...pub } = publicJwk;
	return calculateJwkThumbprint(pub as PublicJwk, "sha256");
}

async function importEd25519Private(
	privateJwk: Record<string, unknown>,
): Promise<CryptoKey> {
	return (await importJWK(
		{ ...privateJwk, alg: "EdDSA" },
		"EdDSA",
	)) as CryptoKey;
}

async function importEd25519Public(
	publicJwk: Record<string, unknown>,
): Promise<CryptoKey> {
	const { d: _d, ...pub } = publicJwk;
	return (await importJWK({ ...pub, alg: "EdDSA" }, "EdDSA")) as CryptoKey;
}

/** Build a self-signed CA PEM from an Ed25519 private JWK (Platform Root or Entity CA). */
export async function createSelfSignedCaPem(
	privateJwk: Record<string, unknown>,
	commonName: string,
	notAfterDays?: number,
): Promise<{
	rootPem: string;
	ski: string;
	publicJwk: Record<string, unknown>;
}> {
	setX509Crypto();

	const { d: _d, ...publicJwkRest } = privateJwk;
	const ski =
		(typeof privateJwk.kid === "string" && privateJwk.kid) ||
		(await skiFromPublicJwk(publicJwkRest));
	const publicJwk = { ...publicJwkRest, kid: ski, alg: "EdDSA" };
	const privateKey = await importEd25519Private({
		...privateJwk,
		kid: ski,
		alg: "EdDSA",
	});
	const publicKey = await importEd25519Public(publicJwk);

	const notBefore = new Date();
	const notAfter = new Date(
		notBefore.getTime() + (notAfterDays ?? 3650) * DAY_MS,
	);
	const cert = await x509.X509CertificateGenerator.createSelfSigned({
		serialNumber: randomSerialHex(),
		name: `CN=${commonName}`,
		notBefore,
		notAfter,
		keys: { privateKey, publicKey },
		signingAlgorithm: ED25519,
		extensions: [
			new x509.BasicConstraintsExtension(true, undefined, true),
			new x509.KeyUsagesExtension(
				x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
				true,
			),
			await x509.SubjectKeyIdentifierExtension.create(publicKey),
		],
	});

	return { rootPem: cert.toString("pem"), ski, publicJwk };
}

/** Build (or rebuild) a self-signed Platform Root CA PEM from an Ed25519 private JWK. */
export async function createPlatformRootPem(
	privateJwk: Record<string, unknown>,
	commonName = DEFAULT_PLATFORM_CN,
	notAfterDays?: number,
): Promise<{
	rootPem: string;
	ski: string;
	publicJwk: Record<string, unknown>;
}> {
	return createSelfSignedCaPem(privateJwk, commonName, notAfterDays);
}

/** Load Platform CA from private JWK + optional stored root PEM. */
export async function loadPlatformCaMaterial(input: {
	privateJwk: Record<string, unknown>;
	rootPem?: string;
	commonName?: string;
	notAfterDays?: number;
}): Promise<PlatformCaMaterial> {
	setX509Crypto();

	const built = await createPlatformRootPem(
		input.privateJwk,
		input.commonName ?? DEFAULT_PLATFORM_CN,
		input.notAfterDays,
	);
	const rootPem = input.rootPem?.trim() ? input.rootPem : built.rootPem;
	const privateKey = await importEd25519Private({
		...input.privateJwk,
		kid: built.ski,
		alg: "EdDSA",
	});
	const publicKey = await importEd25519Public(built.publicJwk);

	return {
		key: {
			ski: built.ski,
			publicJwk: built.publicJwk as KeyPairMaterial["publicJwk"],
			privateJwk: {
				...input.privateJwk,
				kid: built.ski,
				alg: "EdDSA",
			},
		},
		rootPem,
		privateKey,
		publicKey,
	};
}

/** Generate an ephemeral Platform CA (dev/test). */
export async function generateEphemeralPlatformCa(
	commonName?: string,
	notAfterDays?: number,
): Promise<PlatformCaMaterial> {
	setX509Crypto();
	const { privateKey, publicKey } = (await globalThis.crypto.subtle.generateKey(
		ED25519,
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const privateJwk = (await exportJWK(privateKey)) as Record<string, unknown>;
	const publicJwk = (await exportJWK(publicKey)) as Record<string, unknown>;
	const ski = await skiFromPublicJwk(publicJwk);
	return loadPlatformCaMaterial({
		privateJwk: { ...privateJwk, kid: ski, alg: "EdDSA" },
		commonName: commonName ?? `${DEFAULT_PLATFORM_CN} (dev)`,
		notAfterDays,
	});
}

type IssueKind = "ca" | "leaf";

/**
 * Issue a Platform-signed endorsement certificate for the same SPKI as
 * `entityCertPem` (Entity CA or Entity-signed leaf).
 *
 * For `kind: "ca"`, the Entity CA must verify as self-signed.
 * For `kind: "leaf"`, pass `chainPem` (Entity CA, or leaf+EntityCA) to verify.
 */
export async function issuePlatformEndorsementCert(input: {
	platform: PlatformCaMaterial;
	entityCertPem: string;
	kind: IssueKind;
	/** Entity CA PEM, or leaf+CA chain (issuer = last cert). */
	chainPem?: string;
	subjectCn?: string;
	host?: string;
	notAfterDays?: number;
}): Promise<PlatformCertIssue> {
	setX509Crypto();

	const entityCert = new x509.X509Certificate(input.entityCertPem);
	if (input.kind === "ca") {
		const entityOk = await entityCert.verify();
		if (!entityOk) {
			throw new Error("Entity CA certificate signature verification failed");
		}
	} else {
		if (!input.chainPem?.trim()) {
			throw new Error(
				"Entity CA chain is required to endorse a leaf certificate",
			);
		}
		const issuerPem = issuerPemFromChain(input.chainPem);
		const issuer = new x509.X509Certificate(issuerPem);
		const leafOk = await entityCert.verify({ publicKey: issuer.publicKey });
		if (!leafOk) {
			throw new Error(
				"Entity leaf certificate is not signed by the provided Entity CA",
			);
		}
	}

	const platformRoot = new x509.X509Certificate(input.platform.rootPem);
	const notBefore = new Date();
	const notAfter = new Date(
		notBefore.getTime() +
			(input.notAfterDays ?? (input.kind === "ca" ? 3650 : 365)) * DAY_MS,
	);

	const subjectCn =
		input.subjectCn ||
		entityCert.subjectName.toString().replace(/^CN=/i, "") ||
		input.platform.key.ski;

	const extensions: x509.Extension[] =
		input.kind === "ca"
			? [
					new x509.BasicConstraintsExtension(true, undefined, true),
					new x509.KeyUsagesExtension(
						x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
						true,
					),
					await x509.SubjectKeyIdentifierExtension.create(entityCert.publicKey),
					await x509.AuthorityKeyIdentifierExtension.create(
						platformRoot.publicKey,
					),
				]
			: [
					new x509.KeyUsagesExtension(
						x509.KeyUsageFlags.digitalSignature |
							x509.KeyUsageFlags.keyAgreement,
						true,
					),
					new x509.ExtendedKeyUsageExtension(
						[x509.ExtendedKeyUsage.clientAuth],
						false,
					),
					new x509.SubjectAlternativeNameExtension(
						[
							{
								type: "url" as const,
								value: `ski:sha256:${subjectCn}`,
							},
							...(input.host
								? [{ type: "dns" as const, value: input.host }]
								: []),
						],
						false,
					),
					await x509.AuthorityKeyIdentifierExtension.create(
						platformRoot.publicKey,
					),
				];

	const endorsed = await x509.X509CertificateGenerator.create({
		serialNumber: randomSerialHex(),
		subject: `CN=${subjectCn}`,
		issuer: platformRoot.subjectName,
		notBefore,
		notAfter,
		publicKey: entityCert.publicKey,
		signingKey: input.platform.privateKey,
		signingAlgorithm: ED25519,
		extensions,
	});

	const platformCertPem = endorsed.toString("pem");
	const platformRootPem = input.platform.rootPem.endsWith("\n")
		? input.platform.rootPem
		: `${input.platform.rootPem}\n`;

	return { platformCertPem, platformRootPem };
}

/**
 * HAProxy litmus: `platformCertPem` verifies against the single Platform Root
 * (`ca-file` / `ca-sign-file`).
 */
export async function verifyAgainstTrustAnchor(
	certPem: string,
	rootPem: string,
): Promise<boolean> {
	setX509Crypto();
	try {
		const cert = new x509.X509Certificate(certPem);
		const root = new x509.X509Certificate(rootPem);
		return await cert.verify({ publicKey: root.publicKey });
	} catch {
		return false;
	}
}
