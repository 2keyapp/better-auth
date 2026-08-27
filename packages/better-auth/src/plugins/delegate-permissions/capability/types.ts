/**
 * Capability / catalog types for Delegate Permissions AuthZ.
 * @see docs/adr/0001-delegate-permissions.md (better-auth)
 */

export type ScopeAlgebra =
	| "exact"
	| "dns_prefix"
	| "path_prefix"
	| "set"
	| "semver";

/** Allow (default) or explicit deny. Omitted `effect` means `"allow"`. */
export type CapabilityEffect = "allow" | "deny";

/** Scope map: omitted dimension = unrestricted (ALL). */
export type ScopeMap = {
	readonly [dimension: string]: string | readonly string[];
};

export type Capability = {
	readonly action: string;
	readonly scope: ScopeMap;
	readonly delegable: boolean;
	/** Defaults to `"allow"` when omitted (wire v1 compat). */
	readonly effect?: CapabilityEffect;
};

export type CapabilitySet = readonly Capability[];

export type ScopeDimensionDef = {
	readonly dimension: string;
	readonly algebra: ScopeAlgebra;
};

export type ActionDef = {
	readonly action: string;
	readonly description?: string | undefined;
};

export type Catalog = {
	readonly serviceId: string;
	readonly generation: number;
	readonly actions: readonly ActionDef[];
	readonly scopeDimensions: readonly ScopeDimensionDef[];
};

export type Resource = {
	readonly [dimension: string]: string | readonly string[];
};

export type AuthorizeResult =
	| { readonly ok: true }
	| { readonly ok: false; readonly code: string; readonly message: string };

export type SubsetResult =
	| { readonly ok: true }
	| { readonly ok: false; readonly code: string; readonly message: string };

export type ProfileDef = {
	readonly profile: string;
	readonly permissions: CapabilitySet;
};

/** Resolve capability effect with v1 default. */
export function effectOf(
	capability: Capability,
): CapabilityEffect {
	return capability.effect ?? "allow";
}
