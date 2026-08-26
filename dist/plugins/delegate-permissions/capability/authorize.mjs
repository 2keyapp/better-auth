import { actionCovers } from "./action.mjs";
import { resourceSatisfiesScope } from "./scope.mjs";
//#region src/plugins/delegate-permissions/capability/authorize.ts
function algebraLookup(catalog) {
	const map = new Map(catalog.scopeDimensions.map((d) => [d.dimension, d.algebra]));
	return (dimension) => map.get(dimension);
}
/**
* Authorize `action` on `resource` against a principal CapabilitySet.
*/
function authorize(grants, action, resource, catalog) {
	if (!catalog.actions.some((a) => a.action === action)) return {
		ok: false,
		code: "UNKNOWN_ACTION",
		message: `unknown action "${action}"`
	};
	for (const dimension of Object.keys(resource)) if (!catalog.scopeDimensions.some((d) => d.dimension === dimension)) return {
		ok: false,
		code: "UNKNOWN_SCOPE_DIMENSION",
		message: `unknown scope dimension "${dimension}"`
	};
	const algebraFor = algebraLookup(catalog);
	for (const grant of grants) {
		if (!actionCovers(grant.action, action)) continue;
		if (resourceSatisfiesScope(resource, grant.scope, algebraFor)) return { ok: true };
	}
	return {
		ok: false,
		code: "NOT_AUTHORIZED",
		message: `not authorized for action "${action}"`
	};
}
//#endregion
export { authorize };
