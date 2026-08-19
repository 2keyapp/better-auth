import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	generateEphemeralPlatformCa,
	issuePlatformEndorsementCert,
} from "./platform-ca";

const ED25519 = { name: "Ed25519" } as const;
const DAY_MS = 24 * 60 * 60 * 1000;

async function createSelfSignedEntityCaAndLeaf(): Promise<{
	caPem: string;
	leafPem: string;
}> {
	x509.cryptoProvider.set(webcrypto as Crypto);
	const caKeys = (await webcrypto.subtle.generateKey(ED25519, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const deviceKeys = (await webcrypto.subtle.generateKey(ED25519, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;

	const notBefore = new Date();
	const notAfter = new Date(notBefore.getTime() + 365 * DAY_MS);
	const ca = await x509.X509CertificateGenerator.createSelfSigned({
		serialNumber: "01",
		name: "CN=Entity CA",
		notBefore,
		notAfter,
		keys: caKeys,
		signingAlgorithm: ED25519,
		extensions: [
			new x509.BasicConstraintsExtension(true, undefined, true),
			new x509.KeyUsagesExtension(
				x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
				true,
			),
		],
	});
	const leaf = await x509.X509CertificateGenerator.create({
		serialNumber: "02",
		subject: "CN=device",
		issuer: ca.subjectName,
		notBefore,
		notAfter,
		publicKey: deviceKeys.publicKey,
		signingKey: caKeys.privateKey,
		signingAlgorithm: ED25519,
		extensions: [
			new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
		],
	});
	return { caPem: ca.toString("pem"), leafPem: leaf.toString("pem") };
}

describe("platform CA X.509 endorsement", () => {
	it("issues Platform-signed leaf when chainPem is leaf+EntityCA", async () => {
		const platform = await generateEphemeralPlatformCa();
		const { caPem, leafPem } = await createSelfSignedEntityCaAndLeaf();

		const issued = await issuePlatformEndorsementCert({
			platform,
			entityCertPem: leafPem,
			kind: "leaf",
			chainPem: `${leafPem}\n${caPem}`,
			subjectCn: "device-ski",
			host: "host--entity.idr.to",
		});

		expect(issued.platformCertPem).toContain("BEGIN CERTIFICATE");
		expect(issued.platformRootPem.trim()).toBe(platform.rootPem.trim());
	});

	it("issues Platform-signed leaf after Entity CA signs", async () => {
		const platform = await generateEphemeralPlatformCa();
		const { caPem, leafPem } = await createSelfSignedEntityCaAndLeaf();

		const issued = await issuePlatformEndorsementCert({
			platform,
			entityCertPem: leafPem,
			kind: "leaf",
			chainPem: caPem,
			subjectCn: "device-ski",
			host: "host--entity.idr.to",
		});

		expect(issued.platformCertPem).toContain("BEGIN CERTIFICATE");
		expect(issued.platformRootPem).toContain("BEGIN CERTIFICATE");
		expect(issued.platformRootPem.trim()).toBe(platform.rootPem.trim());
	});

	it("issues Platform-signed Entity CA endorsement", async () => {
		const platform = await generateEphemeralPlatformCa();
		const { caPem } = await createSelfSignedEntityCaAndLeaf();
		const issued = await issuePlatformEndorsementCert({
			platform,
			entityCertPem: caPem,
			kind: "ca",
		});
		expect(issued.platformCertPem).toContain("BEGIN CERTIFICATE");
	});

	it("rejects leaf not signed by provided Entity CA", async () => {
		const platform = await generateEphemeralPlatformCa();
		const a = await createSelfSignedEntityCaAndLeaf();
		const b = await createSelfSignedEntityCaAndLeaf();
		await expect(
			issuePlatformEndorsementCert({
				platform,
				entityCertPem: a.leafPem,
				kind: "leaf",
				chainPem: b.caPem,
			}),
		).rejects.toThrow(/not signed by the provided Entity CA/);
	});
});
