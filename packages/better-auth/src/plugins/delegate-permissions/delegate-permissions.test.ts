import { describe, expect, it } from "vitest";
import { createAuthClient } from "../../client";
import { getTestInstance } from "../../test-utils/test-instance";
import { delegatePermissions } from ".";
import { delegatePermissionsClient } from "./client";

describe("delegate-permissions plugin", async () => {
	const { auth, signInWithTestUser } = await getTestInstance({
		plugins: [
			delegatePermissions({
				serviceId: "demo",
				seed: "demo",
				allowClientSeed: true,
				allowServerKeygen: true,
			}),
		],
		logger: {
			level: "error",
		},
	});

	const client = createAuthClient({
		plugins: [delegatePermissionsClient()],
		baseURL: "http://localhost:3000/api/auth",
		fetchOptions: {
			customFetchImpl: async (url, init) => {
				return auth.handler(new Request(url, init));
			},
		},
	});

	it("seeds demo catalog", async () => {
		const { headers } = await signInWithTestUser();
		const seeded = await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});
		expect(seeded.data).toMatchObject({
			seeded: true,
			catalog: {
				serviceId: "demo",
			},
		});

		const catalog = await client.$fetch("/delegate-permissions/catalog", {
			method: "GET",
			headers,
		});
		expect(catalog.data).toMatchObject({
			catalog: {
				serviceId: "demo",
			},
		});
		expect(
			(catalog.data as { profiles: unknown[] }).profiles.length,
		).toBeGreaterThan(0);
	});

	it("sets principal grant, issues session capabilities, and authorizes", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});

		const grant = await client.$fetch("/delegate-permissions/principal-grant", {
			method: "POST",
			body: {
				profile: "personal_root",
				entityId: "alice@example.com",
			},
			headers,
		});
		expect(grant.error).toBeNull();
		expect((grant.data as { grant: { profile: string } }).grant.profile).toBe(
			"personal_root",
		);

		const sessionCaps = await client.$fetch(
			"/delegate-permissions/issue-session-capabilities",
			{
				method: "POST",
				body: {},
				headers,
			},
		);
		expect(sessionCaps.error).toBeNull();
		expect(
			(sessionCaps.data as { permissions: unknown[] }).permissions.length,
		).toBeGreaterThan(0);

		const allowed = await client.$fetch("/delegate-permissions/authorize", {
			method: "POST",
			body: {
				action: "machine.bind",
				resource: { name: "laptop", entity: "alice@example.com" },
			},
			headers,
		});
		expect(allowed.data).toEqual({ allowed: true });

		const denied = await client.$fetch("/delegate-permissions/authorize", {
			method: "POST",
			body: {
				action: "zone.delegate",
				resource: { name: "us-east" },
			},
			headers,
		});
		expect(denied.data).toMatchObject({
			allowed: false,
			code: "NOT_AUTHORIZED",
		});
	});

	it("assert-subset endpoint enforces attenuation", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});

		const parent = [
			{
				action: "machine.bind",
				scope: { name: "us-east" },
				delegable: true,
			},
		];
		const okChild = [
			{
				action: "machine.bind",
				scope: { name: "zone6.us-east" },
				delegable: false,
			},
		];
		const badChild = [
			{
				action: "machine.bind",
				scope: { name: "" },
				delegable: true,
			},
		];

		const ok = await client.$fetch("/delegate-permissions/assert-subset", {
			method: "POST",
			body: { parent, child: okChild },
			headers,
		});
		expect(ok.data).toEqual({ ok: true });

		const bad = await client.$fetch("/delegate-permissions/assert-subset", {
			method: "POST",
			body: { parent, child: badChild },
			headers,
		});
		expect(bad.data).toMatchObject({
			ok: false,
			code: "SUBSET_VIOLATION",
		});
	});

	it("kickstarts entity, issues zone delegate, then machine with seat", async () => {
		const { headers } = await signInWithTestUser();
		await client.$fetch("/delegate-permissions/seed-catalog", {
			method: "POST",
			body: {},
			headers,
		});

		const missing = await client.$fetch(
			"/delegate-permissions/entity?entityId=amazon.com",
			{
				method: "GET",
				headers,
			},
		);
		expect(missing.error).toBeNull();
		expect(missing.data).toMatchObject({
			entityId: "amazon.com",
			exists: false,
		});

		const kick = await client.$fetch("/delegate-permissions/kickstart-entity", {
			method: "POST",
			body: {
				entityId: "amazon.com",
				package: "enterprise",
			},
			headers,
		});
		expect(kick.error).toBeNull();
		const present = await client.$fetch(
			"/delegate-permissions/entity?entityId=amazon.com",
			{
				method: "GET",
				headers,
			},
		);
		expect(present.data).toMatchObject({
			entityId: "amazon.com",
			exists: true,
			package: "enterprise",
		});
		const kickData = kick.data as {
			rootAdmin: {
				credential: { ski: string };
				privateJwk: Record<string, unknown>;
			};
		};

		const zone = await client.$fetch("/delegate-permissions/issue-delegate", {
			method: "POST",
			body: {
				entityId: "amazon.com",
				kind: "zone_authority",
				zone: "us-east",
				issuerSki: kickData.rootAdmin.credential.ski,
				issuerPrivateJwk: kickData.rootAdmin.privateJwk,
			},
			headers,
		});
		expect(zone.error).toBeNull();
		const zoneData = zone.data as {
			credential: { ski: string; zone?: string };
			privateJwk: Record<string, unknown>;
		};
		expect(zoneData.credential.zone).toBe("us-east");

		const machine = await client.$fetch("/delegate-permissions/issue-machine", {
			method: "POST",
			body: {
				entityId: "amazon.com",
				host: "db1.us-east--amazon.com",
				issuerSki: zoneData.credential.ski,
				issuerPrivateJwk: zoneData.privateJwk,
			},
			headers,
		});
		expect(machine.error).toBeNull();
		const machineData = machine.data as {
			credential: {
				kind: string;
				host?: string;
				platformCosign?: { kid: string };
			};
			seatId: string;
		};
		expect(machineData.credential.kind).toBe("machine");
		expect(machineData.credential.host).toBe("db1.us-east--amazon.com");
		expect(machineData.credential.platformCosign?.kid).toBeTruthy();
		expect(machineData.seatId).toBeTruthy();

		const conflict = await client.$fetch(
			"/delegate-permissions/issue-machine",
			{
				method: "POST",
				body: {
					entityId: "amazon.com",
					host: "us-east--amazon.com",
					issuerSki: kickData.rootAdmin.credential.ski,
					issuerPrivateJwk: kickData.rootAdmin.privateJwk,
				},
				headers,
			},
		);
		// us-east is already a ZA — must not also be a Machine
		expect(conflict.error).toBeTruthy();
	});
});
