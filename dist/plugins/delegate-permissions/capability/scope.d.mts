import { ScopeAlgebra, ScopeMap } from "./types.mjs";

//#region src/plugins/delegate-permissions/capability/scope.d.ts
/**
 * Whether `child` is a DNS-style prefix subset of `parent` for left-hand zone labels.
 * Parent `""` covers all. Child matches parent exactly or ends with `.${parent}`.
 */
declare function dnsPrefixSubset(child: string, parent: string): boolean;
/**
 * Whether child scope value is ⊆ parent scope value under the given algebra.
 */
declare function scopeValueSubset(child: string | readonly string[], parent: string | readonly string[], algebra: ScopeAlgebra): boolean;
/**
 * Whether child ScopeMap is ⊆ parent ScopeMap.
 * Dimensions present only on the child require the parent to be unrestricted
 * (dimension omitted on parent) or to cover via algebra.
 */
declare function scopeMapSubset(child: ScopeMap, parent: ScopeMap, algebraFor: (dimension: string) => ScopeAlgebra | undefined): {
  ok: true;
} | {
  ok: false;
  dimension: string;
  message: string;
};
/**
 * Whether a resource satisfies a grant scope for authorization.
 */
declare function resourceSatisfiesScope(resource: ScopeMap, grantScope: ScopeMap, algebraFor: (dimension: string) => ScopeAlgebra | undefined): boolean;
//#endregion
export { dnsPrefixSubset, resourceSatisfiesScope, scopeMapSubset, scopeValueSubset };