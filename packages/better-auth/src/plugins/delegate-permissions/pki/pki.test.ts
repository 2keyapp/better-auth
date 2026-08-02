import { describe, expect, it } from "vitest";
import {
	attachIdrCosign,
	generateEd25519KeyPair,
	issueCredential,
	verifyCredentialSignature,
} from ".";

describe("pki credentials", () => {
	it("issues and verifies a signed capability credential", async () => {
		const issuer = await generateEd25519KeyPair();
		const subject = await generateEd25519KeyPair();
		const credential = await issueCredential({
			kind: "root_admin",
			entityId: "amazon.com",
			subject,
			permissions: [
				{ action: "machine.bind", scope: { name: "" }, delegable: true },
			],
			issuerSki: issuer.ski,
			issuerPrivateJwk: issuer.privateJwk,
			zone: "",
			package: "enterprise",
		});
		expect(credential.ski).toBe(subject.ski);
		expect(await verifyCredentialSignature(credential, issuer.publicJwk)).toBe(
			true,
		);
	});

	it("keeps issuer signature valid after IDR cosign attach", async () => {
		const issuer = await generateEd25519KeyPair();
		const idr = await generateEd25519KeyPair();
		const subject = await generateEd25519KeyPair();
		const credential = await issueCredential({
			kind: "machine",
			entityId: "amazon.com",
			subject,
			permissions: [
				{
					action: "machine.connect",
					scope: { name: "db1" },
					delegable: false,
				},
			],
			issuerSki: issuer.ski,
			issuerPrivateJwk: issuer.privateJwk,
			host: "db1--amazon.com",
		});
		const cosigned = await attachIdrCosign(credential, idr.privateJwk, idr.ski);
		expect(cosigned.idrCosign?.kid).toBe(idr.ski);
		expect(await verifyCredentialSignature(cosigned, issuer.publicJwk)).toBe(
			true,
		);
	});
});
