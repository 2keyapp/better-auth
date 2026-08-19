import { describe, expect, it } from "vitest";
import {
	bindCsrToPublicJwk,
	createDeviceCsr,
	leafMatchesCsr,
	signCsrWithCa,
} from "./csr";
import { generateEd25519KeyPair } from "./keys";
import { createSelfSignedCaPem } from "./platform-ca";

describe("PKCS#10 CSR bind", () => {
	it("binds a device CSR to its public JWK and SKI", async () => {
		const { key, csrPem } = await createDeviceCsr();
		const bound = await bindCsrToPublicJwk(csrPem, key.publicJwk);
		expect(bound.ski).toBe(key.ski);
		expect(bound.publicJwk.x).toBe(key.publicJwk.x);
	});

	it("extracts the public key when publicJwk is omitted", async () => {
		const { key, csrPem } = await createDeviceCsr();
		const bound = await bindCsrToPublicJwk(csrPem);
		expect(bound.ski).toBe(key.ski);
	});

	it("rejects a CSR that does not match publicJwk", async () => {
		const { csrPem } = await createDeviceCsr();
		const other = await generateEd25519KeyPair();
		await expect(bindCsrToPublicJwk(csrPem, other.publicJwk)).rejects.toThrow(
			"INVALID_CSR",
		);
	});

	it("rejects a private JWK sent as publicJwk", async () => {
		const { key, csrPem } = await createDeviceCsr();
		await expect(bindCsrToPublicJwk(csrPem, key.privateJwk)).rejects.toThrow(
			"INVALID_CSR",
		);
	});

	it("rejects garbage CSR PEM", async () => {
		await expect(bindCsrToPublicJwk("not-a-csr")).rejects.toThrow(
			"INVALID_CSR",
		);
	});
});

describe("Entity CA leaf vs CSR", () => {
	it("signs a CSR and matches the leaf SPKI", async () => {
		const { key, csrPem } = await createDeviceCsr();
		const caKeys = await generateEd25519KeyPair();
		const ca = await createSelfSignedCaPem(caKeys.privateJwk, "Entity CA test");
		const signed = await signCsrWithCa({
			csrPem,
			caCertPem: ca.rootPem,
			caPrivateJwk: caKeys.privateJwk,
			host: "laptop--acme.com",
		});
		expect(await leafMatchesCsr(signed.leafPem, csrPem)).toBe(true);
		expect(signed.chainPem).toContain(signed.leafPem.trim());
		expect(key.publicJwk.x).toBeTruthy();
	});

	it("detects a leaf that does not match the CSR", async () => {
		const a = await createDeviceCsr();
		const b = await createDeviceCsr();
		const caKeys = await generateEd25519KeyPair();
		const ca = await createSelfSignedCaPem(caKeys.privateJwk, "Entity CA test");
		const signed = await signCsrWithCa({
			csrPem: a.csrPem,
			caCertPem: ca.rootPem,
			caPrivateJwk: caKeys.privateJwk,
		});
		expect(await leafMatchesCsr(signed.leafPem, b.csrPem)).toBe(false);
	});
});
