import { describe, expect, it } from "vitest";
import { actionCovers } from "./action";
import { authorize } from "./authorize";
import { dnsPrefixSubset } from "./scope";
import { assertSubset } from "./subset";
import type { CapabilitySet, Catalog } from "./types";

const catalog: Catalog = {
	serviceId: "demo",
	generation: 1,
	actions: [
		{ action: "cert.issue" },
		{ action: "machine.bind" },
		{ action: "machine.connect" },
		{ action: "zone.delegate" },
		{ action: "entity.read" },
	],
	scopeDimensions: [
		{ dimension: "entity", algebra: "exact" },
		{ dimension: "name", algebra: "dns_prefix" },
		{ dimension: "service", algebra: "set" },
	],
};

describe("actionCovers", () => {
	it("matches exact actions", () => {
		expect(actionCovers("machine.bind", "machine.bind")).toBe(true);
		expect(actionCovers("machine.bind", "machine.connect")).toBe(false);
	});

	it("supports trailing .* wildcards", () => {
		expect(actionCovers("cert.*", "cert.issue")).toBe(true);
		expect(actionCovers("cert.*", "cert")).toBe(true);
		expect(actionCovers("cert.*", "certificate.issue")).toBe(false);
	});
});

describe("dnsPrefixSubset", () => {
	it("treats empty parent as all", () => {
		expect(dnsPrefixSubset("db1.zone6.us-east", "")).toBe(true);
	});

	it("allows equal and child labels to the left", () => {
		expect(dnsPrefixSubset("us-east", "us-east")).toBe(true);
		expect(dnsPrefixSubset("zone6.us-east", "us-east")).toBe(true);
		expect(dnsPrefixSubset("db1.zone6.us-east", "zone6.us-east")).toBe(true);
	});

	it("rejects siblings and parents", () => {
		expect(dnsPrefixSubset("us-east", "zone6.us-east")).toBe(false);
		expect(dnsPrefixSubset("eu-west", "us-east")).toBe(false);
		expect(dnsPrefixSubset("east", "us-east")).toBe(false);
	});
});

describe("assertSubset", () => {
	const parent: CapabilitySet = [
		{
			action: "cert.*",
			scope: { name: "us-east", entity: "amazon.com" },
			delegable: true,
		},
		{
			action: "machine.bind",
			scope: { name: "us-east" },
			delegable: true,
		},
	];

	it("allows attenuated child under dns_prefix and wildcard action", () => {
		const child: CapabilitySet = [
			{
				action: "cert.issue",
				scope: { name: "zone6.us-east", entity: "amazon.com" },
				delegable: false,
			},
		];
		expect(assertSubset(child, parent, catalog)).toEqual({ ok: true });
	});

	it("rejects broader name scope", () => {
		const child: CapabilitySet = [
			{
				action: "machine.bind",
				scope: { name: "" },
				delegable: true,
			},
		];
		const result = assertSubset(child, parent, catalog);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe("SUBSET_VIOLATION");
		}
	});

	it("rejects non-delegable parent coverage", () => {
		const nonDelegatingParent: CapabilitySet = [
			{
				action: "machine.bind",
				scope: { name: "" },
				delegable: false,
			},
		];
		const child: CapabilitySet = [
			{
				action: "machine.bind",
				scope: { name: "db1" },
				delegable: false,
			},
		];
		const result = assertSubset(child, nonDelegatingParent, catalog);
		expect(result.ok).toBe(false);
	});

	it("rejects unknown actions", () => {
		const child: CapabilitySet = [
			{ action: "not.real", scope: {}, delegable: true },
		];
		const result = assertSubset(child, parent, catalog);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe("UNKNOWN_ACTION");
		}
	});
});

describe("authorize", () => {
	const grants: CapabilitySet = [
		{
			action: "machine.connect",
			scope: { name: "zone6.us-east", entity: "amazon.com" },
			delegable: false,
		},
		{
			action: "acl.service",
			scope: { service: ["ssh", "http"] },
			delegable: false,
		},
	];

	const authCatalog: Catalog = {
		...catalog,
		actions: [...catalog.actions, { action: "acl.service" }],
	};

	it("allows when action and dns_prefix scope match", () => {
		const result = authorize(
			grants,
			"machine.connect",
			{ name: "db1.zone6.us-east", entity: "amazon.com" },
			authCatalog,
		);
		expect(result).toEqual({ ok: true });
	});

	it("denies outside zone", () => {
		const result = authorize(
			grants,
			"machine.connect",
			{ name: "db1.other.us-east", entity: "amazon.com" },
			authCatalog,
		);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe("NOT_AUTHORIZED");
		}
	});

	it("checks set algebra for services", () => {
		expect(
			authorize(grants, "acl.service", { service: "ssh" }, authCatalog).ok,
		).toBe(true);
		expect(
			authorize(grants, "acl.service", { service: "rdp" }, authCatalog).ok,
		).toBe(false);
	});
});
