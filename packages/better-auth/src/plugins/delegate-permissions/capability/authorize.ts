import { actionCovers } from "./action";
import { resourceSatisfiesScope } from "./scope";
import type {
	AuthorizeResult,
	CapabilitySet,
	Catalog,
	Resource,
	ScopeAlgebra,
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

/**
 * Authorize `action` on `resource` against a principal CapabilitySet.
 * Same function for client PEP and server PEP — do not fork logic.
 *
 * Precedence: matching explicit deny → EXPLICIT_DENY; else matching allow → ok;
 * else NOT_AUTHORIZED.
 */
export function authorize(
	grants: CapabilitySet,
	action: string,
	resource: Resource,
	catalog: Catalog,
): AuthorizeResult {
	if (!catalog.actions.some((a) => a.action === action)) {
		return {
			ok: false,
			code: "UNKNOWN_ACTION",
			message: `unknown action "${action}"`,
		};
	}

	for (const dimension of Object.keys(resource)) {
		if (!catalog.scopeDimensions.some((d) => d.dimension === dimension)) {
			return {
				ok: false,
				code: "UNKNOWN_SCOPE_DIMENSION",
				message: `unknown scope dimension "${dimension}"`,
			};
		}
	}

	const algebraFor = algebraLookup(catalog);

	// Pass 1: explicit denies win.
	for (const grant of grants) {
		if (effectOf(grant) !== "deny") {
			continue;
		}
		if (!actionCovers(grant.action, action)) {
			continue;
		}
		if (resourceSatisfiesScope(resource, grant.scope, algebraFor)) {
			return {
				ok: false,
				code: "EXPLICIT_DENY",
				message: `explicitly denied for action "${action}"`,
			};
		}
	}

	// Pass 2: allows.
	for (const grant of grants) {
		if (effectOf(grant) !== "allow") {
			continue;
		}
		if (!actionCovers(grant.action, action)) {
			continue;
		}
		if (resourceSatisfiesScope(resource, grant.scope, algebraFor)) {
			return { ok: true };
		}
	}

	return {
		ok: false,
		code: "NOT_AUTHORIZED",
		message: `not authorized for action "${action}"`,
	};
}
