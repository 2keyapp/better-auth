import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { delegatePermissions } from ".";
import { delegatePermissionsClient } from "./client";
import { createDeviceCsr, signCsrWithCa } from "./pki/csr";
import { generateEphemeralPlatformCa } from "./pki/platform-ca";

async function setupWithEnrolledMachine() {
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

	const { headers } = await signInWithTestUser();
	await client.$fetch("/delegate-permissions/seed-catalog", {
		method: "POST",
		body: {},
		headers,
	});

	const kick = await client.$fetch("/delegate-permissions/kickstart-entity", {
		method: "POST",
		body: { entityId: "lifecycle.com", package: "enterprise" },
		headers,
	});
	const kickData = kick.data as {
		caCertPem: string;
		root: { privateJwk: Record<string, unknown> };
		rootAdmin: {
			credential: { ski: string };
			privateJwk: Record<string, unknown>;
		};
	};

	const device = await createDeviceCsr();
	const host = "db1--lifecycle.com";
	const created = await client.$fetch("/delegate-permissions/enroll-create", {
		method: "POST",
		body: {
			entityId: "lifecycle.com",
			host,
			kind: "machine_target",
			csrPem: device.csrPem,
		},
	});
	const enroll = created.data as {
		enrollId: string;
		pullToken: string;
		subjectSki: string;
	};

	const signed = await signCsrWithCa({
		csrPem: device.csrPem,
		caCertPem: kickData.caCertPem,
		caPrivateJwk: kickData.root.privateJwk,
		host,
	});

	await client.$fetch("/delegate-permissions/enroll-approve", {
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
	});

	return {
		client,
		headers,
		platform,
		kickData,
		device,
		enroll,
		host,
	};
}

describe("delegate-permissions credential lifecycle", async () => {
	const ctx = await setupWithEnrolledMachine();

	it("checks credential status for an active machine", async () => {
		const res = await ctx.client.$fetch(
			`/delegate-permissions/credential-status?ski=${ctx.enroll.subjectSki}`,
			{ method: "GET" },
		);
		expect(res.error).toBeNull();
		const data = res.data as { status: string; ski: string };
		expect(data.status).toBe("active");
		expect(data.ski).toBe(ctx.enroll.subjectSki);
	});

	it("lists active credentials for the entity", async () => {
		const res = await ctx.client.$fetch(
			"/delegate-permissions/credential-list?entityId=lifecycle.com&status=active",
			{ method: "GET", headers: ctx.headers },
		);
		expect(res.error).toBeNull();
		const data = res.data as {
			credentials: { ski: string; status: string }[];
		};
		const machine = data.credentials.find(
			(c) => c.ski === ctx.enroll.subjectSki,
		);
		expect(machine).toBeTruthy();
		expect(machine!.status).toBe("active");
	});

	it("revokes a credential with a reason", async () => {
		const res = await ctx.client.$fetch(
			"/delegate-permissions/credential-revoke",
			{
				method: "POST",
				body: {
					ski: ctx.enroll.subjectSki,
					reason: "key_compromise",
				},
				headers: ctx.headers,
			},
		);
		expect(res.error).toBeNull();
		const data = res.data as { status: string; reason: string };
		expect(data.status).toBe("revoked");
		expect(data.reason).toBe("key_compromise");
	});

	it("rejects double-revoke", async () => {
		const res = await ctx.client.$fetch(
			"/delegate-permissions/credential-revoke",
			{
				method: "POST",
				body: { ski: ctx.enroll.subjectSki, reason: "other" },
				headers: ctx.headers,
			},
		);
		expect(res.error).toBeTruthy();
		expect((res.error as { code?: string }).code).toBe(
			"CREDENTIAL_ALREADY_REVOKED",
		);
	});

	it("status shows revoked after revocation", async () => {
		const res = await ctx.client.$fetch(
			`/delegate-permissions/credential-status?ski=${ctx.enroll.subjectSki}`,
			{ method: "GET" },
		);
		expect(res.error).toBeNull();
		const data = res.data as {
			status: string;
			revokedReason: string;
			revokedAt: string;
		};
		expect(data.status).toBe("revoked");
		expect(data.revokedReason).toBe("key_compromise");
		expect(data.revokedAt).toBeTruthy();
	});
});

describe("delegate-permissions machine decommission", async () => {
	const ctx = await setupWithEnrolledMachine();

	it("decommissions a machine: status changes and name is released", async () => {
		const res = await ctx.client.$fetch(
			"/delegate-permissions/machine-decommission",
			{
				method: "POST",
				body: {
					ski: ctx.enroll.subjectSki,
					reason: "decommissioned",
				},
				headers: ctx.headers,
			},
		);
		expect(res.error).toBeNull();
		const data = res.data as { status: string; entityId: string };
		expect(data.status).toBe("decommissioned");
		expect(data.entityId).toBe("lifecycle.com");

		const status = await ctx.client.$fetch(
			`/delegate-permissions/credential-status?ski=${ctx.enroll.subjectSki}`,
			{ method: "GET" },
		);
		expect((status.data as { status: string }).status).toBe("decommissioned");

		// Name should be released, allowing re-enrollment with the same host
		const newDevice = await createDeviceCsr();
		const created = await ctx.client.$fetch(
			"/delegate-permissions/enroll-create",
			{
				method: "POST",
				body: {
					entityId: "lifecycle.com",
					host: ctx.host,
					kind: "machine_target",
					csrPem: newDevice.csrPem,
				},
			},
		);
		expect(created.error).toBeNull();
	});
});

describe("delegate-permissions machine renewal", async () => {
	const ctx = await setupWithEnrolledMachine();

	it("renews a machine with a new key/CSR; old credential marked renewed", async () => {
		const newDevice = await createDeviceCsr();
		const signed = await signCsrWithCa({
			csrPem: newDevice.csrPem,
			caCertPem: ctx.kickData.caCertPem,
			caPrivateJwk: ctx.kickData.root.privateJwk,
			host: ctx.host,
		});

		const perms = await ctx.client.$fetch(
			"/delegate-permissions/enroll-machine-permissions",
			{
				method: "POST",
				body: {
					entityId: "lifecycle.com",
					host: ctx.host,
					kind: "machine_target",
				},
				headers: ctx.headers,
			},
		);
		const permData = perms.data as { permissions: unknown[] };

		const { issueCredential } = await import("./pki/credential");
		const newCredential = await issueCredential({
			kind: "machine",
			entityId: "lifecycle.com",
			subject: {
				ski: newDevice.key.ski,
				publicJwk: newDevice.key.publicJwk,
				privateJwk: {},
			},
			permissions: permData.permissions as never,
			issuerSki: ctx.kickData.rootAdmin.credential.ski,
			issuerPrivateJwk: ctx.kickData.rootAdmin.privateJwk,
			host: ctx.host,
		});

		const res = await ctx.client.$fetch("/delegate-permissions/machine-renew", {
			method: "POST",
			body: {
				ski: ctx.enroll.subjectSki,
				csrPem: newDevice.csrPem,
				leafPem: signed.leafPem,
				chainPem: signed.chainPem,
				credential: newCredential as unknown as Record<string, unknown>,
				issuerSki: ctx.kickData.rootAdmin.credential.ski,
			},
			headers: ctx.headers,
		});
		expect(res.error).toBeNull();
		const data = res.data as {
			oldSki: string;
			newSki: string;
			status: string;
			platformCertPem: string;
		};
		expect(data.status).toBe("renewed");
		expect(data.oldSki).toBe(ctx.enroll.subjectSki);
		expect(data.newSki).toBe(newDevice.key.ski);
		expect(data.platformCertPem).toContain("BEGIN CERTIFICATE");

		const oldStatus = await ctx.client.$fetch(
			`/delegate-permissions/credential-status?ski=${ctx.enroll.subjectSki}`,
			{ method: "GET" },
		);
		const oldData = oldStatus.data as {
			status: string;
			renewedBySki: string;
		};
		expect(oldData.status).toBe("renewed");
		expect(oldData.renewedBySki).toBe(newDevice.key.ski);

		const newStatus = await ctx.client.$fetch(
			`/delegate-permissions/credential-status?ski=${data.newSki}`,
			{ method: "GET" },
		);
		expect((newStatus.data as { status: string }).status).toBe("active");
	});
});
