/**
 * End-to-end smoke test: exercises every lifecycle endpoint via HTTP
 * against a real test instance. Run with:
 *   npx vitest packages/better-auth/src/plugins/delegate-permissions/e2e-smoke.test.ts --run
 */
import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { delegatePermissions } from ".";
import { delegatePermissionsClient } from "./client";
import { issueCredential } from "./pki/credential";
import { createDeviceCsr, signCsrWithCa } from "./pki/csr";
import {
	generateEphemeralPlatformCa,
	verifyAgainstTrustAnchor,
} from "./pki/platform-ca";

describe("delegate-permissions full lifecycle smoke test", async () => {
	const platform = await generateEphemeralPlatformCa();
	const { client, signInWithTestUser } = await getTestInstance(
		{
			plugins: [
				delegatePermissions({
					serviceId: "smoke",
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
	let kickData: {
		caCertPem: string;
		root: { privateJwk: Record<string, unknown> };
		rootAdmin: {
			credential: { ski: string };
			privateJwk: Record<string, unknown>;
		};
	};
	let enrolledSki: string;
	let enrolledPullToken: string;
	const host = "db1--smoke.test";

	it("1. GET /platform-root → returns PEM + SKI", async () => {
		const res = await client.$fetch("/delegate-permissions/platform-root", {
			method: "GET",
		});
		expect(res.error).toBeNull();
		const d = res.data as { platformRootPem: string; ski: string };
		expect(d.platformRootPem).toContain("BEGIN CERTIFICATE");
		expect(d.ski).toBe(platform.key.ski);
		console.log(
			"    ✓ Platform Root PEM received, SKI:",
			d.ski.slice(0, 16) + "...",
		);
	});

	it("2. POST /seed-catalog → seeds the catalog", async () => {
		const res = await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});
		expect(res.error).toBeNull();
		console.log("    ✓ Catalog seeded");
	});

	it("3. POST /kickstart-entity → creates entity + Entity CA", async () => {
		const res = await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: { entityId: "smoke.test", package: "enterprise" },
			headers,
		});
		expect(res.error).toBeNull();
		kickData = res.data as typeof kickData;
		expect(kickData.caCertPem).toContain("BEGIN CERTIFICATE");
		console.log("    ✓ Entity kickstarted, CA cert issued");
	});

	it("4. POST /enroll-create → device submits CSR", async () => {
		const device = await createDeviceCsr();
		const res = await client.$fetch("/delegate-permissions/enroll-create", {
			method: "POST",
			body: {
				entityId: "smoke.test",
				host,
				kind: "machine_target",
				csrPem: device.csrPem,
			},
		});
		expect(res.error).toBeNull();
		const d = res.data as {
			enrollId: string;
			pullToken: string;
			subjectSki: string;
			status: string;
		};
		expect(d.status).toBe("pending");
		enrolledSki = d.subjectSki;
		enrolledPullToken = d.pullToken;

		const signed = await signCsrWithCa({
			csrPem: device.csrPem,
			caCertPem: kickData.caCertPem,
			caPrivateJwk: kickData.root.privateJwk,
			host,
		});

		const approveRes = await client.$fetch(
			"/delegate-permissions/enroll-approve",
			{
				method: "POST",
				body: {
					enrollId: d.enrollId,
					leafPem: signed.leafPem,
					chainPem: signed.chainPem,
					credential: {},
					issuerSki: kickData.rootAdmin.credential.ski,
					issuerPrivateJwk: kickData.rootAdmin.privateJwk,
				},
				headers,
			},
		);
		expect(approveRes.error).toBeNull();
		console.log(
			"    ✓ CSR submitted and approved, SKI:",
			enrolledSki.slice(0, 16) + "...",
		);
	});

	it("5. POST /enroll-pull → device retrieves cert materials", async () => {
		const res = await client.$fetch("/delegate-permissions/enroll-pull", {
			method: "POST",
			body: { pullToken: enrolledPullToken },
		});
		expect(res.error).toBeNull();
		const d = res.data as {
			status: string;
			certPem: string;
			platformCertPem: string;
			platformRootPem: string;
		};
		expect(d.status).toBe("approved");
		expect(d.certPem).toContain("BEGIN CERTIFICATE");
		expect(d.platformCertPem).toContain("BEGIN CERTIFICATE");

		const verified = await verifyAgainstTrustAnchor(
			d.platformCertPem,
			platform.rootPem,
		);
		expect(verified).toBe(true);
		console.log(
			"    ✓ Device pulled cert, Platform cert verifies against trust anchor",
		);
	});

	it("6. GET /credential-status → active", async () => {
		const res = await client.$fetch(
			`/delegate-permissions/credential-status?ski=${enrolledSki}`,
			{ method: "GET" },
		);
		expect(res.error).toBeNull();
		const d = res.data as {
			ski: string;
			status: string;
			entityId: string;
			kind: string;
			host: string;
		};
		expect(d.status).toBe("active");
		expect(d.entityId).toBe("smoke.test");
		expect(d.host).toBe(host);
		console.log(
			`    ✓ Credential status: ${d.status}, kind: ${d.kind}, host: ${d.host}`,
		);
	});

	it("7. GET /credential-list → lists entity credentials", async () => {
		const res = await client.$fetch(
			"/delegate-permissions/credential-list?entityId=smoke.test",
			{ method: "GET", headers },
		);
		expect(res.error).toBeNull();
		const d = res.data as {
			credentials: { ski: string; status: string; kind: string }[];
		};
		expect(d.credentials.length).toBeGreaterThanOrEqual(2);
		const machine = d.credentials.find((c) => c.ski === enrolledSki);
		expect(machine).toBeTruthy();
		console.log(
			`    ✓ Listed ${d.credentials.length} credentials for smoke.test`,
		);
	});

	it("8. POST /machine-renew → rotates key, old marked renewed", async () => {
		const newDevice = await createDeviceCsr();
		const newSigned = await signCsrWithCa({
			csrPem: newDevice.csrPem,
			caCertPem: kickData.caCertPem,
			caPrivateJwk: kickData.root.privateJwk,
			host,
		});

		const permsRes = await client.$fetch(
			"/delegate-permissions/enroll-machine-permissions",
			{
				method: "POST",
				body: { entityId: "smoke.test", host, kind: "machine_target" },
				headers,
			},
		);
		const permData = permsRes.data as { permissions: unknown[] };

		const newCredential = await issueCredential({
			kind: "machine",
			entityId: "smoke.test",
			subject: {
				ski: newDevice.key.ski,
				publicJwk: newDevice.key.publicJwk,
				privateJwk: {},
			},
			permissions: permData.permissions as never,
			issuerSki: kickData.rootAdmin.credential.ski,
			issuerPrivateJwk: kickData.rootAdmin.privateJwk,
			host,
		});

		const res = await client.$fetch("/delegate-permissions/machine-renew", {
			method: "POST",
			body: {
				ski: enrolledSki,
				csrPem: newDevice.csrPem,
				leafPem: newSigned.leafPem,
				chainPem: newSigned.chainPem,
				credential: newCredential as unknown as Record<string, unknown>,
				issuerSki: kickData.rootAdmin.credential.ski,
			},
			headers,
		});
		expect(res.error).toBeNull();
		const d = res.data as {
			oldSki: string;
			newSki: string;
			status: string;
			platformCertPem: string;
		};
		expect(d.status).toBe("renewed");
		expect(d.platformCertPem).toContain("BEGIN CERTIFICATE");
		console.log(
			`    ✓ Renewed: old=${d.oldSki.slice(0, 12)}... → new=${d.newSki.slice(0, 12)}...`,
		);

		const oldStatus = await client.$fetch(
			`/delegate-permissions/credential-status?ski=${enrolledSki}`,
			{ method: "GET" },
		);
		const oldD = oldStatus.data as { status: string; renewedBySki: string };
		expect(oldD.status).toBe("renewed");
		expect(oldD.renewedBySki).toBe(d.newSki);
		console.log(
			`    ✓ Old credential status: ${oldD.status}, renewedBy: ${oldD.renewedBySki.slice(0, 12)}...`,
		);

		enrolledSki = d.newSki;
	});

	it("9. POST /machine-decommission → revokes + releases name", async () => {
		const device2 = await createDeviceCsr();
		const host2 = "web1--smoke.test";
		const create2 = await client.$fetch("/delegate-permissions/enroll-create", {
			method: "POST",
			body: {
				entityId: "smoke.test",
				host: host2,
				kind: "machine_target",
				csrPem: device2.csrPem,
			},
		});
		expect(create2.error).toBeNull();
		const e2 = create2.data as {
			enrollId: string;
			subjectSki: string;
		};
		const signed2 = await signCsrWithCa({
			csrPem: device2.csrPem,
			caCertPem: kickData.caCertPem,
			caPrivateJwk: kickData.root.privateJwk,
			host: host2,
		});
		await client.$fetch("/delegate-permissions/enroll-approve", {
			method: "POST",
			body: {
				enrollId: e2.enrollId,
				leafPem: signed2.leafPem,
				chainPem: signed2.chainPem,
				credential: {},
				issuerSki: kickData.rootAdmin.credential.ski,
				issuerPrivateJwk: kickData.rootAdmin.privateJwk,
			},
			headers,
		});

		const res = await client.$fetch(
			"/delegate-permissions/machine-decommission",
			{
				method: "POST",
				body: { ski: e2.subjectSki, reason: "decommissioned" },
				headers,
			},
		);
		expect(res.error).toBeNull();
		const d = res.data as { status: string; entityId: string };
		expect(d.status).toBe("decommissioned");
		console.log(`    ✓ Decommissioned web1--smoke.test`);

		const device3 = await createDeviceCsr();
		const reEnroll = await client.$fetch(
			"/delegate-permissions/enroll-create",
			{
				method: "POST",
				body: {
					entityId: "smoke.test",
					host: host2,
					kind: "machine_target",
					csrPem: device3.csrPem,
				},
			},
		);
		expect(reEnroll.error).toBeNull();
		console.log(
			`    ✓ Re-enrolled same host (web1--smoke.test) after decommission`,
		);
	});

	it("10. POST /credential-revoke → revokes with reason", async () => {
		const res = await client.$fetch("/delegate-permissions/credential-revoke", {
			method: "POST",
			body: { ski: enrolledSki, reason: "key_compromise" },
			headers,
		});
		expect(res.error).toBeNull();
		const d = res.data as { status: string; reason: string; revokedAt: string };
		expect(d.status).toBe("revoked");
		expect(d.reason).toBe("key_compromise");
		console.log(`    ✓ Revoked: reason=${d.reason}, at=${d.revokedAt}`);

		const doubleRevoke = await client.$fetch(
			"/delegate-permissions/credential-revoke",
			{
				method: "POST",
				body: { ski: enrolledSki, reason: "other" },
				headers,
			},
		);
		expect(doubleRevoke.error).toBeTruthy();
		console.log("    ✓ Double-revoke correctly rejected");

		const status = await client.$fetch(
			`/delegate-permissions/credential-status?ski=${enrolledSki}`,
			{ method: "GET" },
		);
		const sd = status.data as { status: string; revokedReason: string };
		expect(sd.status).toBe("revoked");
		expect(sd.revokedReason).toBe("key_compromise");
		console.log(
			`    ✓ Final status: ${sd.status}, reason: ${sd.revokedReason}`,
		);
	});
});
