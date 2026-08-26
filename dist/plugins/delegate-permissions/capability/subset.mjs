import { actionCovers } from "./action.mjs";
import { scopeMapSubset } from "./scope.mjs";
//#region src/plugins/delegate-permissions/capability/subset.ts
function algebraLookup(catalog) {
	const map = new Map(catalog.scopeDimensions.map((d) => [d.dimension, d.algebra]));
	return (dimension) => map.get(dimension);
}
function actionKnown(catalog, action) {
	if (catalog.actions.some((a) => a.action === action)) return true;
	if (action.endsWith(".*")) {
		const prefix = action.slice(0, -2);
		return catalog.actions.some((a) => a.action === prefix || a.action.startsWith(`${prefix}.`));
	}
	return false;
}
function capabilityCoveredByParent(child, parentSet, catalog) {
	const algebraFor = algebraLookup(catalog);
	for (const parent of parentSet) {
		if (!parent.delegable) continue;
		if (!actionCovers(parent.action, child.action)) continue;
		if (!scopeMapSubset(child.scope, parent.scope, algebraFor).ok) continue;
		return { ok: true };
	}
	return {
		ok: false,
		code: "SUBSET_VIOLATION",
		message: `capability action "${child.action}" is not covered by a delegable parent grant`
	};
}
/**
* Assert every child capability is ⊆ some delegable parent capability.
*/
function assertSubset(child, parent, catalog) {
	for (const cap of child) {
		if (!actionKnown(catalog, cap.action)) return {
			ok: false,
			code: "UNKNOWN_ACTION",
			message: `unknown action "${cap.action}"`
		};
		for (const dimension of Object.keys(cap.scope)) if (!catalog.scopeDimensions.some((d) => d.dimension === dimension)) return {
			ok: false,
			code: "UNKNOWN_SCOPE_DIMENSION",
			message: `unknown scope dimension "${dimension}"`
		};
		const covered = capabilityCoveredByParent(cap, parent, catalog);
		if (!covered.ok) return covered;
	}
	return { ok: true };
}
//#endregion
export { assertSubset };
