import type {
	ActionDef,
	CapabilitySet,
	ProfileDef,
	ScopeDimensionDef,
} from "../capability/types";
import type { CatalogSeed } from "./types";

/** Built-in example service id for local/dev catalog seeding. */
export const DEMO_SERVICE_ID = "demo";

/**
 * Product-neutral hierarchical host catalog (ZA XOR machine naming).
 * Tenant apps (e.g. IDR) supply their own CatalogSeed — do not put product
 * actions here.
 */
const DEMO_ACTIONS: readonly ActionDef[] = [
	{ action: "admin.invite", description: "Create interim admin identity" },
	{ action: "cert.issue", description: "Sign downstream credentials" },
	{ action: "zone.ns", description: "Occupy a zone name as ZA" },
	{ action: "zone.delegate", description: "Create child zone under scope" },
	{ action: "machine.bind", description: "Occupy leaf host name as Machine" },
	{ action: "machine.connect", description: "Act as a machine peer" },
	{ action: "seat.bind", description: "Bind permanent machine seat" },
	{ action: "resource.access", description: "Access named resources" },
	{ action: "entity.read", description: "Read entity control-plane data" },
] as const;

const DEMO_SCOPE_DIMENSIONS: readonly ScopeDimensionDef[] = [
	{ dimension: "entity", algebra: "exact" },
	{ dimension: "name", algebra: "dns_prefix" },
	{ dimension: "seat", algebra: "exact" },
	{ dimension: "service", algebra: "set" },
] as const;

const rootAdminPermissions: CapabilitySet = [
	{ action: "admin.invite", scope: {}, delegable: true },
	{ action: "cert.issue", scope: { name: "" }, delegable: true },
	{ action: "zone.ns", scope: { name: "" }, delegable: true },
	{ action: "zone.delegate", scope: { name: "" }, delegable: true },
	{ action: "machine.bind", scope: { name: "" }, delegable: true },
	{ action: "machine.connect", scope: { name: "" }, delegable: true },
	{ action: "seat.bind", scope: {}, delegable: true },
	{ action: "resource.access", scope: { service: ["*"] }, delegable: true },
	{ action: "entity.read", scope: {}, delegable: true },
];

/** Personal: no zone.delegate / admin.invite chain; machines under apex only. */
const personalRootPermissions: CapabilitySet = [
	{ action: "cert.issue", scope: { name: "" }, delegable: true },
	{ action: "machine.bind", scope: { name: "" }, delegable: true },
	{ action: "machine.connect", scope: { name: "" }, delegable: true },
	{ action: "seat.bind", scope: {}, delegable: true },
	{ action: "resource.access", scope: { service: ["*"] }, delegable: true },
	{ action: "entity.read", scope: {}, delegable: true },
];

const interimAdminPermissions: CapabilitySet = [
	{ action: "admin.invite", scope: {}, delegable: true },
	{ action: "entity.read", scope: {}, delegable: true },
];

const zoneDelegatePermissions: CapabilitySet = [
	{ action: "cert.issue", scope: { name: "" }, delegable: true },
	{ action: "zone.ns", scope: { name: "" }, delegable: true },
	{ action: "zone.delegate", scope: { name: "" }, delegable: true },
	{ action: "machine.bind", scope: { name: "" }, delegable: true },
	{ action: "machine.connect", scope: { name: "" }, delegable: true },
	{ action: "seat.bind", scope: {}, delegable: true },
	{ action: "resource.access", scope: { service: ["*"] }, delegable: true },
	{ action: "entity.read", scope: {}, delegable: true },
];

const machinePermissions: CapabilitySet = [
	{ action: "machine.bind", scope: { name: "" }, delegable: false },
	{ action: "machine.connect", scope: { name: "" }, delegable: false },
	{ action: "resource.access", scope: { service: ["*"] }, delegable: false },
];

const DEMO_PROFILES: readonly ProfileDef[] = [
	{ profile: "root_admin", permissions: rootAdminPermissions },
	{ profile: "personal_root", permissions: personalRootPermissions },
	{ profile: "interim_admin", permissions: interimAdminPermissions },
	{ profile: "zone_delegate", permissions: zoneDelegatePermissions },
	{ profile: "machine", permissions: machinePermissions },
] as const;

export const DEMO_CATALOG_SEED: CatalogSeed = {
	serviceId: DEMO_SERVICE_ID,
	actions: DEMO_ACTIONS,
	scopeDimensions: DEMO_SCOPE_DIMENSIONS,
	profiles: DEMO_PROFILES,
};
