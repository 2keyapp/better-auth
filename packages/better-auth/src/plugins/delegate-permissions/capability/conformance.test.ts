/**
 * @see 2key-core-sdk/conformance/dp-authz/fixtures.json
 * Keep `conformance.fixtures.json` identical to that file.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { actionCovers } from "./action";
import { authorize } from "./authorize";
import { dnsPrefixSubset, pathPrefixSubset } from "./scope";
import { semverRangeSubset, semverSatisfies } from "./semver";
import { assertSubset } from "./subset";
import type { CapabilitySet, Catalog, Resource } from "./types";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(
	readFileSync(join(here, "conformance.fixtures.json"), "utf8"),
) as {
	catalog: Catalog;
	actionCovers: { granted: string; requested: string; ok: boolean }[];
	dnsPrefixSubset: { child: string; parent: string; ok: boolean }[];
	pathPrefixSubset: { child: string; parent: string; ok: boolean }[];
	semverSatisfies: { version: string; range: string; ok: boolean }[];
	semverRangeSubset: { child: string; parent: string; ok: boolean }[];
	authorize: {
		name: string;
		grants: CapabilitySet;
		action: string;
		resource: Resource;
		ok: boolean;
		code?: string;
	}[];
	assertSubset: {
		name: string;
		parent: CapabilitySet;
		child: CapabilitySet;
		ok: boolean;
		code?: string;
	}[];
};

describe("shared conformance fixtures", () => {
	for (const row of fixtures.actionCovers) {
		it(`actionCovers ${row.granted} → ${row.requested}`, () => {
			expect(actionCovers(row.granted, row.requested)).toBe(row.ok);
		});
	}

	for (const row of fixtures.dnsPrefixSubset) {
		it(`dnsPrefixSubset ${row.child} ⊆ ${row.parent}`, () => {
			expect(dnsPrefixSubset(row.child, row.parent)).toBe(row.ok);
		});
	}

	for (const row of fixtures.pathPrefixSubset ?? []) {
		it(`pathPrefixSubset ${row.child} ⊆ ${row.parent}`, () => {
			expect(pathPrefixSubset(row.child, row.parent)).toBe(row.ok);
		});
	}

	for (const row of fixtures.semverSatisfies ?? []) {
		it(`semverSatisfies ${row.version} ∈ ${row.range}`, () => {
			expect(semverSatisfies(row.version, row.range)).toBe(row.ok);
		});
	}

	for (const row of fixtures.semverRangeSubset ?? []) {
		it(`semverRangeSubset ${row.child} ⊆ ${row.parent}`, () => {
			expect(semverRangeSubset(row.child, row.parent)).toBe(row.ok);
		});
	}

	for (const row of fixtures.authorize) {
		it(`authorize: ${row.name}`, () => {
			const result = authorize(
				row.grants,
				row.action,
				row.resource,
				fixtures.catalog,
			);
			expect(result.ok).toBe(row.ok);
			if (!row.ok && !result.ok && row.code) {
				expect(result.code).toBe(row.code);
			}
		});
	}

	for (const row of fixtures.assertSubset) {
		it(`assertSubset: ${row.name}`, () => {
			const result = assertSubset(row.child, row.parent, fixtures.catalog);
			expect(result.ok).toBe(row.ok);
			if (!row.ok && !result.ok && row.code) {
				expect(result.code).toBe(row.code);
			}
		});
	}
});
