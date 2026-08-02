import type { CapabilitySet } from "./capability/types";
import type { CatalogSeed } from "./seeds/idr";

export type DelegatePermissionsOptions = {
	/**
	 * Service id for this app DB catalog.
	 * @default "default"
	 */
	serviceId?: string | undefined;
	/**
	 * Seed catalog when empty. Pass `"idr"` for the IDR default seed, or a custom seed.
	 */
	seed?: "idr" | CatalogSeed | undefined;
	/**
	 * Allow `/delegate-permissions/seed-catalog` from clients.
	 * @default false (server-only via `disableClientRequest`)
	 */
	allowClientSeed?: boolean | undefined;
	/**
	 * Session grant lifetime in seconds.
	 * @default 3600
	 */
	sessionGrantExpiresIn?: number | undefined;
};

export type DpActionRow = {
	id: string;
	serviceId: string;
	action: string;
	description: string | null;
	catalogGeneration: number;
	createdAt: Date;
};

export type DpScopeDimensionRow = {
	id: string;
	serviceId: string;
	dimension: string;
	algebra: string;
	catalogGeneration: number;
	createdAt: Date;
};

export type DpProfileRow = {
	id: string;
	serviceId: string;
	profile: string;
	permissions: CapabilitySet;
	catalogGeneration: number;
	createdAt: Date;
};

export type DpCatalogMetaRow = {
	id: string;
	serviceId: string;
	generation: number;
	updatedAt: Date;
};

export type DpPrincipalGrantRow = {
	id: string;
	userId: string;
	entityId: string | null;
	permissions: CapabilitySet;
	profile: string | null;
	expiresAt: Date | null;
	createdAt: Date;
	updatedAt: Date;
};

export type DpSessionGrantRow = {
	id: string;
	sessionId: string;
	userId: string;
	permissions: CapabilitySet;
	expiresAt: Date;
	createdAt: Date;
};
