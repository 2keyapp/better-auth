import { calculateJwkThumbprint, exportJWK, importJWK } from "jose";
import * as x509 from "@peculiar/x509";
//#region src/plugins/delegate-permissions/pki/platform-ca.ts
/**
* Platform self-signed X.509 CA helpers.
*
* After an Entity admin signs a leaf (or Entity CA is registered), the Platform
* CA issues a Platform-signed endorsement certificate for the same public key.
*/
const DAY_MS = 1440 * 60 * 1e3;
const ED25519 = { name: "Ed25519" };
const DEFAULT_PLATFORM_CN = "Platform CA";
function randomSerialHex(bytes = 16) {
	const buf = new Uint8Array(bytes);
	globalThis.crypto.getRandomValues(buf);
	return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}
function setX509Crypto() {
	x509.cryptoProvider.set(globalThis.crypto);
}
/** All PEM certificate blocks from a PEM or PEM chain. */
function pemCerts(pemOrChain) {
	const matches = pemOrChain.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
	if (!matches?.length) throw new Error("No CERTIFICATE PEM block found in chain");
	return matches;
}
/**
* Issuer CA PEM from a chain. Device `chainPem` is typically leaf+EntityCA
* (leaf first); use the last cert. A bare Entity CA PEM is a single block.
*/
function issuerPemFromChain(pemOrChain) {
	const certs = pemCerts(pemOrChain);
	return certs[certs.length - 1];
}
async function skiFromPublicJwk(publicJwk) {
	const { d: _d, ...pub } = publicJwk;
	return calculateJwkThumbprint(pub, "sha256");
}
async function importEd25519Private(privateJwk) {
	return await importJWK({
		...privateJwk,
		alg: "EdDSA"
	}, "EdDSA");
}
async function importEd25519Public(publicJwk) {
	const { d: _d, ...pub } = publicJwk;
	return await importJWK({
		...pub,
		alg: "EdDSA"
	}, "EdDSA");
}
/** Build a self-signed CA PEM from an Ed25519 private JWK (Platform Root or Entity CA). */
async function createSelfSignedCaPem(privateJwk, commonName) {
	setX509Crypto();
	const { d: _d, ...publicJwkRest } = privateJwk;
	const ski = typeof privateJwk.kid === "string" && privateJwk.kid || await skiFromPublicJwk(publicJwkRest);
	const publicJwk = {
		...publicJwkRest,
		kid: ski,
		alg: "EdDSA"
	};
	const privateKey = await importEd25519Private({
		...privateJwk,
		kid: ski,
		alg: "EdDSA"
	});
	const publicKey = await importEd25519Public(publicJwk);
	const notBefore = /* @__PURE__ */ new Date();
	const notAfter = new Date(notBefore.getTime() + 3650 * DAY_MS);
	return {
		rootPem: (await x509.X509CertificateGenerator.createSelfSigned({
			serialNumber: randomSerialHex(),
			name: `CN=${commonName}`,
			notBefore,
			notAfter,
			keys: {
				privateKey,
				publicKey
			},
			signingAlgorithm: ED25519,
			extensions: [
				new x509.BasicConstraintsExtension(true, void 0, true),
				new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
				await x509.SubjectKeyIdentifierExtension.create(publicKey)
			]
		})).toString("pem"),
		ski,
		publicJwk
	};
}
/** Build (or rebuild) a self-signed Platform Root CA PEM from an Ed25519 private JWK. */
async function createPlatformRootPem(privateJwk, commonName = DEFAULT_PLATFORM_CN) {
	return createSelfSignedCaPem(privateJwk, commonName);
}
/** Load Platform CA from private JWK + optional stored root PEM. */
async function loadPlatformCaMaterial(input) {
	setX509Crypto();
	const built = await createPlatformRootPem(input.privateJwk, input.commonName ?? DEFAULT_PLATFORM_CN);
	const rootPem = input.rootPem?.trim() ? input.rootPem : built.rootPem;
	const privateKey = await importEd25519Private({
		...input.privateJwk,
		kid: built.ski,
		alg: "EdDSA"
	});
	const publicKey = await importEd25519Public(built.publicJwk);
	return {
		key: {
			ski: built.ski,
			publicJwk: built.publicJwk,
			privateJwk: {
				...input.privateJwk,
				kid: built.ski,
				alg: "EdDSA"
			}
		},
		rootPem,
		privateKey,
		publicKey
	};
}
/** Generate an ephemeral Platform CA (dev/test). */
async function generateEphemeralPlatformCa(commonName = `${DEFAULT_PLATFORM_CN} (dev)`) {
	setX509Crypto();
	const { privateKey, publicKey } = await globalThis.crypto.subtle.generateKey(ED25519, true, ["sign", "verify"]);
	const privateJwk = await exportJWK(privateKey);
	const ski = await skiFromPublicJwk(await exportJWK(publicKey));
	return loadPlatformCaMaterial({
		privateJwk: {
			...privateJwk,
			kid: ski,
			alg: "EdDSA"
		},
		commonName
	});
}
/**
* Issue a Platform-signed endorsement certificate for the same SPKI as
* `entityCertPem` (Entity CA or Entity-signed leaf).
*
* For `kind: "ca"`, the Entity CA must verify as self-signed.
* For `kind: "leaf"`, pass `chainPem` (Entity CA, or leaf+EntityCA) to verify.
*/
async function issuePlatformEndorsementCert(input) {
	setX509Crypto();
	const entityCert = new x509.X509Certificate(input.entityCertPem);
	if (input.kind === "ca") {
		if (!await entityCert.verify()) throw new Error("Entity CA certificate signature verification failed");
	} else {
		if (!input.chainPem?.trim()) throw new Error("Entity CA chain is required to endorse a leaf certificate");
		const issuerPem = issuerPemFromChain(input.chainPem);
		const issuer = new x509.X509Certificate(issuerPem);
		if (!await entityCert.verify({ publicKey: issuer.publicKey })) throw new Error("Entity leaf certificate is not signed by the provided Entity CA");
	}
	const platformRoot = new x509.X509Certificate(input.platform.rootPem);
	const notBefore = /* @__PURE__ */ new Date();
	const notAfter = new Date(notBefore.getTime() + (input.notAfterDays ?? (input.kind === "ca" ? 3650 : 365)) * DAY_MS);
	const subjectCn = input.subjectCn || entityCert.subjectName.toString().replace(/^CN=/i, "") || input.platform.key.ski;
	const extensions = input.kind === "ca" ? [
		new x509.BasicConstraintsExtension(true, void 0, true),
		new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
		await x509.SubjectKeyIdentifierExtension.create(entityCert.publicKey),
		await x509.AuthorityKeyIdentifierExtension.create(platformRoot.publicKey)
	] : [
		new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement, true),
		new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth], false),
		new x509.SubjectAlternativeNameExtension([{
			type: "url",
			value: `ski:sha256:${subjectCn}`
		}, ...input.host ? [{
			type: "dns",
			value: input.host
		}] : []], false),
		await x509.AuthorityKeyIdentifierExtension.create(platformRoot.publicKey)
	];
	return {
		platformCertPem: (await x509.X509CertificateGenerator.create({
			serialNumber: randomSerialHex(),
			subject: `CN=${subjectCn}`,
			issuer: platformRoot.subjectName,
			notBefore,
			notAfter,
			publicKey: entityCert.publicKey,
			signingKey: input.platform.privateKey,
			signingAlgorithm: ED25519,
			extensions
		})).toString("pem"),
		platformRootPem: input.platform.rootPem.endsWith("\n") ? input.platform.rootPem : `${input.platform.rootPem}\n`
	};
}
/**
* HAProxy litmus: `platformCertPem` verifies against the single Platform Root
* (`ca-file` / `ca-sign-file`).
*/
async function verifyAgainstTrustAnchor(certPem, rootPem) {
	setX509Crypto();
	try {
		const cert = new x509.X509Certificate(certPem);
		const root = new x509.X509Certificate(rootPem);
		return await cert.verify({ publicKey: root.publicKey });
	} catch {
		return false;
	}
}
//#endregion
export { createPlatformRootPem, createSelfSignedCaPem, generateEphemeralPlatformCa, issuePlatformEndorsementCert, loadPlatformCaMaterial, verifyAgainstTrustAnchor };
