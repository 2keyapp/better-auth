import { CapabilitySet, Catalog, ProfileDef } from "./types.mjs";

//#region src/plugins/delegate-permissions/capability/expand.d.ts
/**
 * Expand a named profile into a CapabilitySet using catalog profile defs.
 */
declare function expandProfile(profile: string, profiles: readonly ProfileDef[], catalog: Catalog): CapabilitySet;
//#endregion
export { expandProfile };