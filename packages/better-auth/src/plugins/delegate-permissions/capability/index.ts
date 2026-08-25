/**
 * DP AuthZ algebra (inlined for the published better-auth fork).
 * Canonical package: `@2key/dp-authorize` in 2key-core-sdk.
 * Keep in sync via `conformance.fixtures.json` (copy of `conformance/dp-authz/fixtures.json`).
 * When the plugin moves to 2key-billing, replace this folder with a dependency on `@2key/dp-authorize`.
 */
export { actionCovers } from "./action";
export { authorize } from "./authorize";
export { expandProfile } from "./expand";
export {
	dnsPrefixSubset,
	resourceSatisfiesScope,
	scopeMapSubset,
	scopeValueSubset,
} from "./scope";
export { assertSubset } from "./subset";
export type {
	ActionDef,
	AuthorizeResult,
	Capability,
	CapabilitySet,
	Catalog,
	ProfileDef,
	Resource,
	ScopeAlgebra,
	ScopeDimensionDef,
	ScopeMap,
	SubsetResult,
} from "./types";
