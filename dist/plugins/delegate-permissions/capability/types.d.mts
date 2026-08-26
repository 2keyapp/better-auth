//#region src/plugins/delegate-permissions/capability/types.d.ts
/**
 * Capability / catalog types for delegate-permissions AuthZ.
 * @see docs/adr/0001-delegate-permissions.md
 */
type ScopeAlgebra = "exact" | "dns_prefix" | "set";
/** Scope map: omitted dimension = unrestricted (ALL). */
type ScopeMap = {
  readonly [dimension: string]: string | readonly string[];
};
type Capability = {
  readonly action: string;
  readonly scope: ScopeMap;
  readonly delegable: boolean;
};
type CapabilitySet = readonly Capability[];
type ScopeDimensionDef = {
  readonly dimension: string;
  readonly algebra: ScopeAlgebra;
};
type ActionDef = {
  readonly action: string;
  readonly description?: string | undefined;
};
type Catalog = {
  readonly serviceId: string;
  readonly generation: number;
  readonly actions: readonly ActionDef[];
  readonly scopeDimensions: readonly ScopeDimensionDef[];
};
type Resource = {
  readonly [dimension: string]: string | readonly string[];
};
type AuthorizeResult = {
  readonly ok: true;
} | {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
};
type SubsetResult = {
  readonly ok: true;
} | {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
};
type ProfileDef = {
  readonly profile: string;
  readonly permissions: CapabilitySet;
};
//#endregion
export { ActionDef, AuthorizeResult, Capability, CapabilitySet, Catalog, ProfileDef, Resource, ScopeAlgebra, ScopeDimensionDef, ScopeMap, SubsetResult };