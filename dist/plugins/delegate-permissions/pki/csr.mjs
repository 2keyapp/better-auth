import { constantTimeEqual } from "../../../crypto/buffer.mjs";
import { generateEd25519KeyPair } from "./keys.mjs";
import { calculateJwkThumbprint, exportJWK, importJWK } from "jose";
import * as x509 from "@peculiar/x509";
//#region src/plugins/delegate-permissions/pki/csr.ts
/**
* PKCS#10 CSR bind + Entity-CA leaf issue for machine enrollment.
*
* The device keeps the private key. Better Auth stores the CSR, checks the
* admin-signed leaf matches that CSR, then Platform co-signs the same SPKI.
*/
const ED25519 = { name: "Ed25519" };
const DAY_MS = 1440 * 60 * 1e3;
function setX509Crypto() {
	x509.cryptoProvider.set(globalThis.crypto);
}
function toPublicJwk(jwk) {
	const { d: _d, ...rest } = jwk;
	return rest;
}
function jwkCoordsEqual(a, b) {
	return a.kty === b.kty && a.crv === b.crv && a.x === b.x;
}
async function publicJwkFromCsr(csr) {
	return toPublicJwk(await exportJWK(await csr.publicKey.export()));
}
/**
* Parse a PKCS#10 PEM, verify the CSR signature, and bind it to `publicJwk`
* when that is supplied. Returns the canonical public JWK + SKI from the CSR.
*/
async function bindCsrToPublicJwk(csrPem, publicJwk) {
	setX509Crypto();
	let csr;
	try {
		csr = new x509.Pkcs10CertificateRequest(csrPem);
	} catch {
		throw new Error("INVALID_CSR");
	}
	if (!await csr.verify()) throw new Error("INVALID_CSR");
	const csrJwk = await publicJwkFromCsr(csr);
	if (publicJwk) {
		if (publicJwk.d != null) throw new Error("INVALID_CSR");
		if (!jwkCoordsEqual(csrJwk, toPublicJwk(publicJwk))) throw new Error("INVALID_CSR");
	}
	const ski = await calculateJwkThumbprint(csrJwk, "sha256");
	return {
		ski,
		publicJwk: {
			...csrJwk,
			kid: ski,
			alg: "EdDSA"
		}
	};
}
/** True when the leaf SPKI is the same public key as the enrollment CSR. */
async function leafMatchesCsr(leafPem, csrPem) {
	setX509Crypto();
	try {
		const csr = new x509.Pkcs10CertificateRequest(csrPem);
		const leaf = new x509.X509Certificate(leafPem);
		return constantTimeEqual(new Uint8Array(csr.publicKey.rawData), new Uint8Array(leaf.publicKey.rawData));
	} catch {
		return false;
	}
}
/**
* Device `identity init`: Ed25519 keypair + PKCS#10 CSR.
* Private key is returned once for the caller to store locally.
*/
async function createDeviceCsr(input) {
	setX509Crypto();
	const key = await generateEd25519KeyPair();
	const privateKey = await importJWK({
		...key.privateJwk,
		alg: "EdDSA"
	}, "EdDSA");
	const publicKey = await importJWK({
		...key.publicJwk,
		alg: "EdDSA"
	}, "EdDSA");
	return {
		key,
		csrPem: (await x509.Pkcs10CertificateRequestGenerator.create({
			name: `CN=${input?.commonName ?? key.ski}`,
			keys: {
				privateKey,
				publicKey
			},
			signingAlgorithm: ED25519
		})).toString("pem")
	};
}
/**
* Admin signs a pending CSR with the Entity CA (same host as `enroll-instant`).
* `chainPem` is leaf + Entity CA so Platform can verify before endorsement.
*/
async function signCsrWithCa(input) {
	setX509Crypto();
	const bound = await bindCsrToPublicJwk(input.csrPem);
	const csr = new x509.Pkcs10CertificateRequest(input.csrPem);
	const caCert = new x509.X509Certificate(input.caCertPem);
	const caPrivateKey = await importJWK({
		...input.caPrivateJwk,
		alg: "EdDSA"
	}, "EdDSA");
	const notBefore = /* @__PURE__ */ new Date();
	const notAfter = new Date(notBefore.getTime() + (input.notAfterDays ?? 365) * DAY_MS);
	const subjectCn = input.subjectCn ?? bound.ski;
	const leafPem = (await x509.X509CertificateGenerator.create({
		serialNumber: Array.from(globalThis.crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join(""),
		subject: `CN=${subjectCn}`,
		issuer: caCert.subjectName,
		notBefore,
		notAfter,
		publicKey: csr.publicKey,
		signingKey: caPrivateKey,
		signingAlgorithm: ED25519,
		extensions: [
			new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement, true),
			new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth], false),
			...input.host ? [new x509.SubjectAlternativeNameExtension([{
				type: "dns",
				value: input.host
			}], false)] : []
		]
	})).toString("pem");
	return {
		leafPem,
		chainPem: `${leafPem}\n${input.caCertPem.endsWith("\n") ? input.caCertPem : `${input.caCertPem}\n`}`
	};
}
//#endregion
export { bindCsrToPublicJwk, createDeviceCsr, leafMatchesCsr, signCsrWithCa };
