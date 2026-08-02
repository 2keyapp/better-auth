import type {
	ActionDef,
	CapabilitySet,
	ProfileDef,
	ScopeDimensionDef,
} from "../capability/types";

export const IDR_SERVICE_ID = "idr";

const IDR_ACTIONS: readonly ActionDef[] = [
	{ action: "admin.invite", description: "Create interim admin identity" },
	{ action: "cert.issue", description: "Sign downstream credentials" },
	{ action: "zone.ns", description: "Occupy a zone name as ZA" },
	{ action: "zone.delegate", description: "Create child zone under scope" },
	{ action: "machine.bind", description: "Occupy leaf host name as Machine" },
	{ action: "machine.connect", description: "Act as Source/Target peer" },
	{ action: "seat.bind", description: "Bind permanent machine seat" },
	{ action: "presence.register", description: "Register Target with Presence" },
	{ action: "session.accept", description: "Accept inbound sessions" },
	{ action: "acl.service", description: "Open named Target services" },
	{ action: "entity.read", description: "Read entity control-plane data" },
] as const;

const IDR_SCOPE_DIMENSIONS: readonly ScopeDimensionDef[] = [
	{ dimension: "entity", algebra: "exact" },
	{ dimension: "name", algebra: "dns_prefix" },
	{ dimension: "seat", algebra: "exact" },
	{ dimension: "service", algebra: "set" },
] as const;

const rootAdminPermissions: CapabilitySet = [
	{
		action: "admin.invite",
		scope: {},
		delegable: true,
	},
	{
		action: "cert.issue",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "zone.ns",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "zone.delegate",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "machine.bind",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "machine.connect",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "seat.bind",
		scope: {},
		delegable: true,
	},
	{
		action: "presence.register",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "session.accept",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "acl.service",
		scope: { service: ["*"] },
		delegable: true,
	},
	{
		action: "entity.read",
		scope: {},
		delegable: true,
	},
];

/** Personal: no zone.delegate / admin.invite chain; machines under apex only. */
const personalRootPermissions: CapabilitySet = [
	{
		action: "cert.issue",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "machine.bind",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "machine.connect",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "seat.bind",
		scope: {},
		delegable: true,
	},
	{
		action: "presence.register",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "session.accept",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "acl.service",
		scope: { service: ["*"] },
		delegable: true,
	},
	{
		action: "entity.read",
		scope: {},
		delegable: true,
	},
];

const interimAdminPermissions: CapabilitySet = [
	{
		action: "admin.invite",
		scope: {},
		delegable: true,
	},
	{
		action: "entity.read",
		scope: {},
		delegable: true,
	},
];

const zoneDelegatePermissions: CapabilitySet = [
	{
		action: "cert.issue",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "zone.ns",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "zone.delegate",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "machine.bind",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "machine.connect",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "seat.bind",
		scope: {},
		delegable: true,
	},
	{
		action: "presence.register",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "session.accept",
		scope: { name: "" },
		delegable: true,
	},
	{
		action: "acl.service",
		scope: { service: ["*"] },
		delegable: true,
	},
	{
		action: "entity.read",
		scope: {},
		delegable: true,
	},
];

const machinePermissions: CapabilitySet = [
	{
		action: "machine.bind",
		scope: { name: "" },
		delegable: false,
	},
	{
		action: "machine.connect",
		scope: { name: "" },
		delegable: false,
	},
	{
		action: "presence.register",
		scope: { name: "" },
		delegable: false,
	},
	{
		action: "session.accept",
		scope: { name: "" },
		delegable: false,
	},
	{
		action: "acl.service",
		scope: { service: ["*"] },
		delegable: false,
	},
];

const IDR_PROFILES: readonly ProfileDef[] = [
	{ profile: "root_admin", permissions: rootAdminPermissions },
	{ profile: "personal_root", permissions: personalRootPermissions },
	{ profile: "interim_admin", permissions: interimAdminPermissions },
	{ profile: "zone_delegate", permissions: zoneDelegatePermissions },
	{ profile: "machine", permissions: machinePermissions },
] as const;

export type CatalogSeed = {
	readonly serviceId: string;
	readonly actions: readonly ActionDef[];
	readonly scopeDimensions: readonly ScopeDimensionDef[];
	readonly profiles: readonly ProfileDef[];
};

export const IDR_CATALOG_SEED: CatalogSeed = {
	serviceId: IDR_SERVICE_ID,
	actions: IDR_ACTIONS,
	scopeDimensions: IDR_SCOPE_DIMENSIONS,
	profiles: IDR_PROFILES,
};
