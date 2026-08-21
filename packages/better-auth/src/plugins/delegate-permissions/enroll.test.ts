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

	it("redeems an enroll invite for the invited org; device chooses the host", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});
		await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "invite.com", package: "enterprise" },
			headers,
		});
		const invited = await client.$fetch("/delegate-permissions/enroll-invite", {
			method: "POST",
			body: { entityId: "invite.com" },
			headers,
		});
		expect(invited.error).toBeNull();
		const invite = invited.data as {
			inviteId: string;
			inviteToken: string;
			entityId: string;
			expiresAt: string;
			host?: string;
		};
		expect(invite.entityId).toBe("invite.com");
		expect(invite.host).toBeUndefined();
		expect(invite.inviteToken.length).toBeGreaterThan(16);
		expect((invite as { maxUses?: number }).maxUses).toBe(1);
		expect(Date.parse(invite.expiresAt)).toBeGreaterThan(Date.now());

		const lookedUp = await client.$fetch(
			"/delegate-permissions/enroll-invite",
			{
				method: "GET",
				query: { inviteToken: invite.inviteToken },
			},
		);
		expect(lookedUp.error).toBeNull();
		const preview = lookedUp.data as {
			entityId: string;
			inviteToken?: string;
			host?: string;
		};
		expect(preview.entityId).toBe("invite.com");
		expect(preview.host).toBeUndefined();
		expect(preview.inviteToken).toBeUndefined();

		const device = await createDeviceCsr();
		const created = await client.$fetch("/delegate-permissions/enroll-create", {
			method: "POST",
			body: {
				inviteToken: invite.inviteToken,
				host: "laptop1--invite.com",
				kind: "machine_target",
				csrPem: device.csrPem,
			},
		});
		expect(created.error).toBeNull();
		const enroll = created.data as { enrollId: string; status: string };
		expect(enroll.status).toBe("pending");

		const list = await client.$fetch("/delegate-permissions/enroll-list", {
			method: "GET",
			query: { entityId: "invite.com", status: "pending" },
			headers,
		});
		expect(list.error).toBeNull();
		const rows = (list.data as { enrollments: { host: string | null }[] })
			.enrollments;
		expect(rows.some((r) => r.host === "laptop1--invite.com")).toBe(true);

		const reusedLookup = await client.$fetch(
			"/delegate-permissions/enroll-invite",
			{
				method: "GET",
				query: { inviteToken: invite.inviteToken },
			},
		);
		expect(reusedLookup.error).toBeTruthy();
		expect((reusedLookup.error as { code?: string }).code).toBe("INVITE_USED");

		const reusedCreate = await client.$fetch(
			"/delegate-permissions/enroll-create",
			{
				method: "POST",
				body: {
					inviteToken: invite.inviteToken,
					host: "laptop2--invite.com",
					csrPem: device.csrPem,
				},
			},
		);
		expect(reusedCreate.error).toBeTruthy();
		expect((reusedCreate.error as { code?: string }).code).toBe("INVITE_USED");
	});

	it("rejects invite redeem for a different org and leaves pull enroll working", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});
		await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "mismatch.com", package: "personal" },
			headers,
		});
		await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "other.com", package: "personal" },
			headers,
		});
		const invited = await client.$fetch("/delegate-permissions/enroll-invite", {
			method: "POST",
			body: { entityId: "mismatch.com" },
			headers,
		});
		expect(invited.error).toBeNull();
		const token = (invited.data as { inviteToken: string }).inviteToken;
		const device = await createDeviceCsr();
		const mismatch = await client.$fetch(
			"/delegate-permissions/enroll-create",
			{
				method: "POST",
				body: {
					entityId: "other.com",
					host: "laptop--other.com",
					inviteToken: token,
					csrPem: device.csrPem,
				},
			},
		);
		expect(mismatch.error).toBeTruthy();
		expect((mismatch.error as { code?: string }).code).toBe("INVITE_MISMATCH");

		const stillOpen = await client.$fetch(
			"/delegate-permissions/enroll-invite",
			{
				method: "GET",
				query: { inviteToken: token },
			},
		);
		expect(stillOpen.error).toBeNull();

		const pull = await client.$fetch("/delegate-permissions/enroll-create", {
			method: "POST",
			body: {
				entityId: "mismatch.com",
				host: "uninvited--mismatch.com",
				kind: "machine_target",
				csrPem: device.csrPem,
			},
		});
		expect(pull.error).toBeNull();
	});

	it("rejects an expired enroll invite", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});
		await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "expire.com", package: "personal" },
			headers,
		});
		const invited = await client.$fetch("/delegate-permissions/enroll-invite", {
			method: "POST",
			body: {
				entityId: "expire.com",
				expiresIn: 1,
			},
			headers,
		});
		expect(invited.error).toBeNull();
		const token = (invited.data as { inviteToken: string }).inviteToken;
		await new Promise((resolve) => setTimeout(resolve, 1100));
		const expired = await client.$fetch("/delegate-permissions/enroll-create", {
			method: "POST",
			body: {
				inviteToken: token,
				host: "tmp--expire.com",
				csrPem: (await createDeviceCsr()).csrPem,
			},
		});
		expect(expired.error).toBeTruthy();
		expect((expired.error as { code?: string }).code).toBe("INVITE_EXPIRED");
	});

	it("allows maxUses redeems then INVITE_USED; unlimited lasts until expiry", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});
		await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "uses.com", package: "personal" },
			headers,
		});

		const capped = await client.$fetch("/delegate-permissions/enroll-invite", {
			method: "POST",
			body: { entityId: "uses.com", maxUses: 2 },
			headers,
		});
		expect(capped.error).toBeNull();
		const capToken = (capped.data as { inviteToken: string; maxUses: number })
			.inviteToken;
		expect((capped.data as { maxUses: number }).maxUses).toBe(2);
		for (const host of ["a--uses.com", "b--uses.com"]) {
			const res = await client.$fetch("/delegate-permissions/enroll-create", {
				method: "POST",
				body: {
					inviteToken: capToken,
					host,
					csrPem: (await createDeviceCsr()).csrPem,
				},
			});
			expect(res.error).toBeNull();
		}
		const third = await client.$fetch("/delegate-permissions/enroll-create", {
			method: "POST",
			body: {
				inviteToken: capToken,
				host: "c--uses.com",
				csrPem: (await createDeviceCsr()).csrPem,
			},
		});
		expect(third.error).toBeTruthy();
		expect((third.error as { code?: string }).code).toBe("INVITE_USED");

		const open = await client.$fetch("/delegate-permissions/enroll-invite", {
			method: "POST",
			body: { entityId: "uses.com", maxUses: 0, expiresIn: 3600 },
			headers,
		});
		expect(open.error).toBeNull();
		expect((open.data as { maxUses: number }).maxUses).toBe(0);
		const openToken = (open.data as { inviteToken: string }).inviteToken;
		for (const host of ["d--uses.com", "e--uses.com"]) {
			const res = await client.$fetch("/delegate-permissions/enroll-create", {
				method: "POST",
				body: {
					inviteToken: openToken,
					host,
					csrPem: (await createDeviceCsr()).csrPem,
				},
			});
			expect(res.error).toBeNull();
		}
	});
});

describe("delegate-permissions plugin option defaults", async () => {
	const platform = await generateEphemeralPlatformCa();
	const { client, signInWithTestUser } = await getTestInstance(
		{
			plugins: [
				delegatePermissions({
					serviceId: "ttl",
					seed: "demo",
					allowClientSeed: true,
					allowServerKeygen: true,
					inviteExpiresIn: 2,
					inviteMaxExpiresIn: 5,
					inviteMaxUses: 4,
					credentialExpiresIn: 120,
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

	it("uses inviteExpiresIn when expiresIn is omitted and rejects above inviteMaxExpiresIn", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});
		await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "ttl.com", package: "personal" },
			headers,
		});
		const before = Date.now();
		const invited = await client.$fetch("/delegate-permissions/enroll-invite", {
			method: "POST",
			body: { entityId: "ttl.com" },
			headers,
		});
		expect(invited.error).toBeNull();
		const deltaSec =
			(Date.parse((invited.data as { expiresAt: string }).expiresAt) - before) /
			1000;
		expect(deltaSec).toBeGreaterThan(0.5);
		expect(deltaSec).toBeLessThanOrEqual(4);

		const over = await client.$fetch("/delegate-permissions/enroll-invite", {
			method: "POST",
			body: { entityId: "ttl.com", expiresIn: 6 },
			headers,
		});
		expect(over.error).toBeTruthy();
		expect((over.error as { code?: string }).code).toBe("INVALID_EXPIRES_IN");
	});

	it("uses inviteMaxUses and credentialExpiresIn when request fields are omitted", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});
		const before = Date.now();
		const kick = await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "cred-ttl.com", package: "personal" },
			headers,
		});
		expect(kick.error).toBeNull();
		const notAfter = Date.parse(
			(
				kick.data as {
					rootAdmin: { credential: { notAfter: string } };
				}
			).rootAdmin.credential.notAfter,
		);
		const credDelta = (notAfter - before) / 1000;
		expect(credDelta).toBeGreaterThan(60);
		expect(credDelta).toBeLessThanOrEqual(180);

		await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "uses-opt.com", package: "personal" },
			headers,
		});
		const invited = await client.$fetch("/delegate-permissions/enroll-invite", {
			method: "POST",
			body: { entityId: "uses-opt.com" },
			headers,
		});
		expect(invited.error).toBeNull();
		expect((invited.data as { maxUses: number }).maxUses).toBe(4);

		const override = await client.$fetch(
			"/delegate-permissions/enroll-invite",
			{
				method: "POST",
				body: { entityId: "uses-opt.com", maxUses: 1 },
				headers,
			},
		);
		expect(override.error).toBeNull();
		expect((override.data as { maxUses: number }).maxUses).toBe(1);
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
