import { AuthorizeResult, CapabilitySet, Catalog, Resource } from "./types.mjs";

//#region src/plugins/delegate-permissions/capability/authorize.d.ts
/**
 * Authorize `action` on `resource` against a principal CapabilitySet.
 */
declare function authorize(grants: CapabilitySet, action: string, resource: Resource, catalog: Catalog): AuthorizeResult;
//#endregion
export { authorize };