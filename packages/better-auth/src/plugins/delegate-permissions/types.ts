import type { CapabilitySet } from "./capability/types";
import type { CosignProvider, SeatBinder } from "./pki/types";
import type { CatalogSeed } from "./seeds";

export type DelegatePermissionsOptions = {
	/**
	 * Service id for this app DB catalog.
	 * @default "default"
	 */
	serviceId?: string | undefined;
	/**
	 * Seed catalog when empty. Pass `"demo"` for the built-in example seed,
	 * or a custom CatalogSeed (tenant-specific actions/profiles).
	 */
	seed?: "demo" | CatalogSeed | undefined;
	/**
	 * Allow `/delegate-permissions/seed-catalog` from clients.
	 * @default false
	 */
	allowClientSeed?: boolean | undefined;
	/**
	 * Session grant lifetime in seconds.
	 * @default 3600
	 */
	sessionGrantExpiresIn?: number | undefined;
	/**
	 * Allow the server to generate Entity Root / subject keypairs during kickstart
	 * (returns private JWKs once). Prefer client-held keys in production.
	 * @default false
	 */
	allowServerKeygen?: boolean | undefined;
	/**
	 * Optional platform co-sign provider (root + machine).
	 */
	cosign?: CosignProvider | undefined;
	/**
	 * Optional permanent machine seat binder (billing integration).
	 */
	seatBinder?: SeatBinder | undefined;
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

export type DpEntityRow = {
	id: string;
	entityId: string;
	package: string;
	rootSki: string;
	ownerUserId: string;
	createdAt: Date;
	updatedAt: Date;
};

export type DpCredentialRow = {
	id: string;
	ski: string;
	entityId: string;
	kind: string;
	publicJwk: Record<string, unknown>;
	credential: Record<string, unknown>;
	zone: string | null;
	host: string | null;
	seatId: string | null;
	status: string;
	createdAt: Date;
};

export type DpNameOccupancyRow = {
	id: string;
	entityId: string;
	nameKey: string;
	kind: string;
	credentialSki: string;
	createdAt: Date;
};

export type DpUserCredentialBindRow = {
	id: string;
	userId: string;
	credentialSki: string;
	entityId: string;
	isPrimary: boolean;
	createdAt: Date;
};
