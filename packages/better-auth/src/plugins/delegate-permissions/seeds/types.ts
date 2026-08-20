import type {
	ActionDef,
	CapabilitySet,
	ProfileDef,
	ScopeDimensionDef,
} from "../capability/types";

export type CatalogSeed = {
	readonly serviceId: string;
	readonly actions: readonly ActionDef[];
	readonly scopeDimensions: readonly ScopeDimensionDef[];
	readonly profiles: readonly ProfileDef[];
};

export type { ActionDef, CapabilitySet, ProfileDef, ScopeDimensionDef };
