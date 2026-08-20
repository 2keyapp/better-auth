import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { delegatePermissions } from ".";
import { delegatePermissionsClient } from "./client";
import { createDeviceCsr, signCsrWithCa } from "./pki/csr";
import {
	generateEphemeralPlatformCa,
	verifyAgainstTrustAnchor,
} from "./pki/platform-ca";

describe("delegate-permissions machine enroll (mTLS litmus)", async () => {
	const platform = await generateEphemeralPlatformCa();
	const { client, signInWithTestUser } = await getTestInstance(
		{
			plugins: [
				delegatePermissions({
					serviceId: "demo",
					seed: "demo",
					allowClientSeed: true,
					allowServerKeygen: true,
					platformCa: {
						privateJwk: platform.key.privateJwk,
						rootPem: platform.rootPem,
					},
				}),
			],
			logger: { level: "error" },
		},
		{
			clientOptions: {
				plugins: [delegatePermissionsClient()],
			},
		},
	);

	it("exports the configured Platform Root for HAProxy ca-file", async () => {
		const root = await client.$fetch("/delegate-permissions/platform-root", {
			method: "GET",
		});
		expect(root.error).toBeNull();
		expect(
			(root.data as { platformRootPem: string }).platformRootPem.trim(),
		).toBe(platform.rootPem.trim());
		expect((root.data as { ski: string }).ski).toBe(platform.key.ski);
	});

	it("registers a machine via CSR enroll; Platform leaf verifies against that root", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});

		const kick = await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: {
				entityId: "acme.com",
				package: "enterprise",
			},
			headers,
		});
		expect(kick.error).toBeNull();
		const kickData = kick.data as {
			caCertPem: string;
			platformRootPem: string;
			root: { privateJwk: Record<string, unknown> };
			rootAdmin: {
				credential: { ski: string };
				privateJwk: Record<string, unknown>;
			};
		};
		expect(kickData.caCertPem).toContain("BEGIN CERTIFICATE");
		expect(kickData.platformRootPem.trim()).toBe(platform.rootPem.trim());

		const device = await createDeviceCsr();
		const host = "laptop--acme.com";
		const created = await client.$fetch("/delegate-permissions/enroll-create", {
			method: "POST",
			body: {
				entityId: "acme.com",
				host,
				kind: "machine_target",
				csrPem: device.csrPem,
			},
		});
		expect(created.error).toBeNull();
		const enroll = created.data as {
			enrollId: string;
			pullToken: string;
			subjectSki: string;
		};
		expect(enroll.subjectSki).toBe(device.key.ski);

		const signed = await signCsrWithCa({
			csrPem: device.csrPem,
			caCertPem: kickData.caCertPem,
			caPrivateJwk: kickData.root.privateJwk,
			host,
		});

		const approved = await client.$fetch(
			"/delegate-permissions/enroll-approve",
			{
				method: "POST",
				body: {
					enrollId: enroll.enrollId,
					leafPem: signed.leafPem,
					chainPem: signed.chainPem,
					credential: {},
					issuerSki: kickData.rootAdmin.credential.ski,
					issuerPrivateJwk: kickData.rootAdmin.privateJwk,
				},
				headers,
			},
		);
		expect(approved.error).toBeNull();
		const approveData = approved.data as {
			platformCertPem: string;
			platformRootPem: string;
		};

		const pulled = await client.$fetch("/delegate-permissions/enroll-pull", {
			method: "POST",
			body: { pullToken: enroll.pullToken },
		});
		expect(pulled.error).toBeNull();
		const identity = pulled.data as {
			status: string;
			platformCertPem: string;
			platformRootPem: string;
			certPem: string;
		};
		expect(identity.status).toBe("approved");
		expect(identity.platformCertPem).toBe(approveData.platformCertPem);

		const haproxyRoot = await client.$fetch(
			"/delegate-permissions/platform-root",
			{ method: "GET" },
		);
		const caFile = (haproxyRoot.data as { platformRootPem: string })
			.platformRootPem;
		expect(
			await verifyAgainstTrustAnchor(identity.platformCertPem, caFile),
		).toBe(true);
	});

	it("rejects enroll-create with a CSR that does not match publicJwk", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});
		await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "csr-mismatch.com", package: "personal" },
			headers,
		});
		const device = await createDeviceCsr();
		const other = await createDeviceCsr();
		const created = await client.$fetch("/delegate-permissions/enroll-create", {
			method: "POST",
			body: {
				entityId: "csr-mismatch.com",
				host: "phone--csr-mismatch.com",
				csrPem: device.csrPem,
				publicJwk: other.key.publicJwk,
			},
		});
		expect(created.error).toBeTruthy();
		expect((created.error as { code?: string }).code).toBe("INVALID_CSR");
	});
});

describe("delegate-permissions Platform CA fail-closed", async () => {
	const { client } = await getTestInstance(
		{
			plugins: [
				delegatePermissions({
					serviceId: "prod",
				}),
			],
			logger: { level: "error" },
		},
		{
			clientOptions: {
				plugins: [delegatePermissionsClient()],
			},
		},
	);

	it("refuses to export a throwaway Platform Root without platformCa", async () => {
		const root = await client.$fetch("/delegate-permissions/platform-root", {
			method: "GET",
		});
		expect(root.error).toBeTruthy();
		expect((root.error as { code?: string }).code).toBe("COSIGN_REQUIRED");
	});
});

describe("delegate-permissions demo seed Platform CA", async () => {
	const { client } = await getTestInstance(
		{
			plugins: [
				delegatePermissions({
					serviceId: "demo",
					seed: "demo",
				}),
			],
			logger: { level: "error" },
		},
		{
			clientOptions: {
				plugins: [delegatePermissionsClient()],
			},
		},
	);

	it("exports platform-root from the built-in demo CA without extra config", async () => {
		const root = await client.$fetch("/delegate-permissions/platform-root", {
			method: "GET",
		});
		expect(root.error).toBeNull();
		expect(
			(root.data as { platformRootPem: string }).platformRootPem,
		).toContain("BEGIN CERTIFICATE");
	});
});
