import type { CapabilitySet } from "../capability/types";

export type CredentialKind =
	| "entity_root"
	| "root_admin"
	| "interim_admin"
	| "zone_authority"
	| "machine";

export type EntityPackage = "personal" | "enterprise";

export type PublicJwk = {
	readonly kty: string;
	readonly crv?: string;
	readonly x?: string;
	readonly d?: never;
	readonly kid?: string;
	readonly alg?: string;
};

export type CapabilityCredential = {
	readonly version: 1;
	readonly kind: CredentialKind;
	readonly entityId: string;
	readonly ski: string;
	readonly publicJwk: PublicJwk;
	readonly permissions: CapabilitySet;
	/** Zone left-hand prefix; `""` = entity apex. Required for zone_authority. */
	readonly zone?: string;
	/** Fully-qualified machine host (`{path}--{entity}`). Required for machine. */
	readonly host?: string;
	readonly issuerSki: string;
	readonly notBefore: string;
	readonly notAfter: string;
	readonly package?: EntityPackage;
	readonly idrCosign?: {
		readonly kid: string;
		readonly signedAt: string;
		readonly signature: string;
	};
	readonly signature: string;
};

export type KeyPairMaterial = {
	readonly ski: string;
	readonly publicJwk: PublicJwk;
	readonly privateJwk: Record<string, unknown>;
};

export type CosignProvider = {
	cosignRoot: (
		credential: CapabilityCredential,
	) => Promise<CapabilityCredential>;
	cosignMachine: (
		credential: CapabilityCredential,
		seatId: string,
	) => Promise<CapabilityCredential>;
};

export type SeatBinder = {
	allocateAndBind: (input: {
		entityId: string;
		host: string;
		machineSki: string;
		payingPartyId?: string;
	}) => Promise<{ seatId: string }>;
	release?: (seatId: string) => Promise<void>;
};
