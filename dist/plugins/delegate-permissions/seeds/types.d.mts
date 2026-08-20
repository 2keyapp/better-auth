import { ActionDef, CapabilitySet, ProfileDef, ScopeDimensionDef } from "../capability/types.mjs";

//#region src/plugins/delegate-permissions/seeds/types.d.ts
type CatalogSeed = {
  readonly serviceId: string;
  readonly actions: readonly ActionDef[];
  readonly scopeDimensions: readonly ScopeDimensionDef[];
  readonly profiles: readonly ProfileDef[];
};
//#endregion
export { CatalogSeed };