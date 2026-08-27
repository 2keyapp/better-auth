import { actionCovers } from "./action";
import { scopeMapSubset, scopesOverlapDeny } from "./scope";
import type {
	Capability,
	CapabilitySet,
	Catalog,
	ScopeAlgebra,
	SubsetResult,
} from "./types";
import { effectOf } from "./types";

function algebraLookup(
	catalog: Catalog,
): (dimension: string) => ScopeAlgebra | undefined {
	const map = new Map(
		catalog.scopeDimensions.map((d) => [d.dimension, d.algebra] as const),
	);
	return (dimension) => map.get(dimension);
}

function actionKnown(catalog: Catalog, action: string): boolean {
	if (catalog.actions.some((a) => a.action === action)) {
		return true;
	}
	if (action.endsWith(".*")) {
		const prefix = action.slice(0, -2);
		return catalog.actions.some(
			(a) => a.action === prefix || a.action.startsWith(`${prefix}.`),
		);
	}
	return false;
}

function parentDenyBlocksAllow(
	childAllow: Capability,
	parentSet: CapabilitySet,
	catalog: Catalog,
): boolean {
	const algebraFor = algebraLookup(catalog);
	for (const parent of parentSet) {
		if (effectOf(parent) !== "deny") {
			continue;
		}
		if (!actionCovers(parent.action, childAllow.action)) {
			continue;
		}
		if (scopesOverlapDeny(childAllow.scope, parent.scope, algebraFor)) {
			return true;
		}
	}
	return false;
}

function allowCoveredByParent(
	child: Capability,
	parentSet: CapabilitySet,
	catalog: Catalog,
): SubsetResult {
	const algebraFor = algebraLookup(catalog);

	if (parentDenyBlocksAllow(child, parentSet, catalog)) {
		return {
			ok: false,
			code: "DENY_OVERRIDE_VIOLATION",
			message: `capability action "${child.action}" allow overlaps a parent deny`,
		};
	}

	for (const parent of parentSet) {
		if (effectOf(parent) !== "allow") {
			continue;
		}
		if (!parent.delegable) {
			continue;
		}
		if (!actionCovers(parent.action, child.action)) {
			continue;
		}
		const scopeResult = scopeMapSubset(child.scope, parent.scope, algebraFor);
		if (!scopeResult.ok) {
			continue;
		}
		return { ok: true };
	}

	return {
		ok: false,
		code: "SUBSET_VIOLATION",
		message: `capability action "${child.action}" is not covered by a delegable parent grant`,
	};
}

function denyCoveredByParent(
	child: Capability,
	parentSet: CapabilitySet,
	catalog: Catalog,
): SubsetResult {
	const algebraFor = algebraLookup(catalog);

	for (const parent of parentSet) {
		if (!parent.delegable) {
			continue;
		}
		if (!actionCovers(parent.action, child.action)) {
			continue;
		}
		const scopeResult = scopeMapSubset(child.scope, parent.scope, algebraFor);
		if (!scopeResult.ok) {
			continue;
		}
		// May refine an existing deny or add a deny inside a held allow.
		if (effectOf(parent) === "deny" || effectOf(parent) === "allow") {
			return { ok: true };
		}
	}

	return {
		ok: false,
		code: "SUBSET_VIOLATION",
		message: `deny capability action "${child.action}" is not covered by a delegable parent allow or deny`,
	};
}

function capabilityCoveredByParent(
	child: Capability,
	parentSet: CapabilitySet,
	catalog: Catalog,
): SubsetResult {
	if (effectOf(child) === "deny") {
		return denyCoveredByParent(child, parentSet, catalog);
	}
	return allowCoveredByParent(child, parentSet, catalog);
}

/**
 * Assert every child capability is ⊆ some delegable parent capability.
 * Parent denies are mandatory: child allows must not overlap them.
 */
export function assertSubset(
	child: CapabilitySet,
	parent: CapabilitySet,
	catalog: Catalog,
): SubsetResult {
	for (const cap of child) {
		if (!actionKnown(catalog, cap.action)) {
			return {
				ok: false,
				code: "UNKNOWN_ACTION",
				message: `unknown action "${cap.action}"`,
			};
		}
		for (const dimension of Object.keys(cap.scope)) {
			if (!catalog.scopeDimensions.some((d) => d.dimension === dimension)) {
				return {
					ok: false,
					code: "UNKNOWN_SCOPE_DIMENSION",
					message: `unknown scope dimension "${dimension}"`,
				};
			}
		}
		const covered = capabilityCoveredByParent(cap, parent, catalog);
		if (!covered.ok) {
			return covered;
		}
	}
	return { ok: true };
}
