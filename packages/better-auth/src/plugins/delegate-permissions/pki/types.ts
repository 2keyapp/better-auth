import type { CapabilitySet } from "../capability/types";
import type { PlatformCertIssue } from "./platform-ca";

export type { PlatformCertCosign } from "./cert-cosign";
export type { PlatformCertIssue } from "./platform-ca";

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
	/** Platform authority co-sign (Entity Root + Machine). */
	readonly platformCosign?: {
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
	/**
	 * Platform CA X.509-signs an Entity CA certificate (endorsement for the
	 * same SPKI). Returns Platform-signed CA PEM + Platform Root PEM.
	 */
	cosignCaCert: (caCertPem: string) => Promise<PlatformCertIssue>;
	/**
	 * After Entity admin signs a leaf: Platform CA issues an endorsement
	 * certificate for the same device SPKI. Pass `chainPem` to verify the
	 * Entity signature before endorsement.
	 */
	cosignLeafCert: (
		leafCertPem: string,
		opts?: {
			chainPem?: string;
			subjectSki?: string;
			host?: string;
		},
	) => Promise<PlatformCertIssue>;
};

export type SeatBinder = {
	allocateAndBind: (input: {
		entityId: string;
		host: string;
		machineSki: string;
		payingPartyId?: string;
		/** Device role — both target and source consume device seats. */
		role?: "target" | "source";
	}) => Promise<{ seatId: string }>;
	release?: (seatId: string) => Promise<void>;
};
