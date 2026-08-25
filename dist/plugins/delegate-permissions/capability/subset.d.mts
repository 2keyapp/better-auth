import { CapabilitySet, Catalog, SubsetResult } from "./types.mjs";

//#region src/plugins/delegate-permissions/capability/subset.d.ts
/**
 * Assert every child capability is ⊆ some delegable parent capability.
 */
declare function assertSubset(child: CapabilitySet, parent: CapabilitySet, catalog: Catalog): SubsetResult;
//#endregion
export { assertSubset };