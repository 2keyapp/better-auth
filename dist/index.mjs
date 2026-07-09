import { t as PACKAGE_VERSION } from "./version-YIydhdrs.mjs";
import { base64Url } from "@better-auth/utils/base64";
import { APIError, createAuthEndpoint, createAuthMiddleware, sessionMiddleware } from "better-auth/api";
import { constantTimeEqual, generateRandomString, symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { APIError as APIError$1, HIDE_METADATA } from "better-auth";
import { statusCodes } from "better-call";
import { createHash } from "@better-auth/utils/hash";
import { getOrgAdapter } from "better-auth/plugins";
import * as z from "zod";
//#region src/scim-error.ts
/**
* SCIM compliant error
* See: https://datatracker.ietf.org/doc/html/rfc7644#section-3.12
*/
var SCIMAPIError = class extends APIError$1 {
	constructor(status = "INTERNAL_SERVER_ERROR", overrides = {}) {
		const body = {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
			status: (typeof status === "number" ? status : statusCodes[status]).toString(),
			detail: overrides.detail,
			...overrides
		};
		super(status, body);
		this.message = body.detail ?? body.message;
	}
};
const SCIMErrorOpenAPISchema = {
	type: "object",
	properties: {
		schemas: {
			type: "array",
			items: { type: "string" }
		},
		status: { type: "string" },
		detail: { type: "string" },
		scimType: { type: "string" }
	}
};
const SCIMErrorOpenAPISchemas = {
	"400": {
		description: "Bad Request. Usually due to missing parameters, or invalid parameters",
		content: { "application/json": { schema: SCIMErrorOpenAPISchema } }
	},
	"401": {
		description: "Unauthorized. Due to missing or invalid authentication.",
		content: { "application/json": { schema: SCIMErrorOpenAPISchema } }
	},
	"403": {
		description: "Unauthorized. Due to missing or invalid authentication.",
		content: { "application/json": { schema: SCIMErrorOpenAPISchema } }
	},
	"404": {
		description: "Not Found. The requested resource was not found.",
		content: { "application/json": { schema: SCIMErrorOpenAPISchema } }
	},
	"429": {
		description: "Too Many Requests. You have exceeded the rate limit. Try again later.",
		content: { "application/json": { schema: SCIMErrorOpenAPISchema } }
	},
	"500": {
		description: "Internal Server Error. This is a problem with the server that you cannot fix.",
		content: { "application/json": { schema: SCIMErrorOpenAPISchema } }
	}
};
//#endregion
//#region src/scim-tokens.ts
const defaultKeyHasher = async (token) => {
	const hash = await createHash("SHA-256").digest(new TextEncoder().encode(token));
	return base64Url.encode(new Uint8Array(hash), { padding: false });
};
async function storeSCIMToken(ctx, opts, scimToken) {
	if (opts.storeSCIMToken === "encrypted") return await symmetricEncrypt({
		key: ctx.context.secretConfig,
		data: scimToken
	});
	if (opts.storeSCIMToken === "hashed") return await defaultKeyHasher(scimToken);
	if (typeof opts.storeSCIMToken === "object" && "hash" in opts.storeSCIMToken) return await opts.storeSCIMToken.hash(scimToken);
	if (typeof opts.storeSCIMToken === "object" && "encrypt" in opts.storeSCIMToken) return await opts.storeSCIMToken.encrypt(scimToken);
	return scimToken;
}
async function verifySCIMToken(ctx, opts, storedSCIMToken, scimToken) {
	if (opts.storeSCIMToken === "encrypted") return constantTimeEqual(await symmetricDecrypt({
		key: ctx.context.secretConfig,
		data: storedSCIMToken
	}), scimToken);
	if (opts.storeSCIMToken === "hashed") return constantTimeEqual(await defaultKeyHasher(scimToken), storedSCIMToken);
	if (typeof opts.storeSCIMToken === "object" && "hash" in opts.storeSCIMToken) return constantTimeEqual(await opts.storeSCIMToken.hash(scimToken), storedSCIMToken);
	if (typeof opts.storeSCIMToken === "object" && "decrypt" in opts.storeSCIMToken) return constantTimeEqual(await opts.storeSCIMToken.decrypt(storedSCIMToken), scimToken);
	return constantTimeEqual(scimToken, storedSCIMToken);
}
//#endregion
//#region src/middlewares.ts
/**
* The middleware forces the endpoint to have a valid token
*/
const authMiddlewareFactory = (opts) => createAuthMiddleware(async (ctx) => {
	const authSCIMToken = (ctx.headers?.get("Authorization"))?.replace(/^Bearer\s+/i, "");
	if (!authSCIMToken) throw new SCIMAPIError("UNAUTHORIZED", { detail: "SCIM token is required" });
	const baseScimTokenParts = new TextDecoder().decode(base64Url.decode(authSCIMToken)).split(":");
	const [scimToken, providerId] = baseScimTokenParts;
	const organizationId = baseScimTokenParts.slice(2).join(":");
	if (!scimToken || !providerId) throw new SCIMAPIError("UNAUTHORIZED", { detail: "Invalid SCIM token" });
	let scimProvider = opts.defaultSCIM?.find((p) => {
		if (p.providerId === providerId && !organizationId) return true;
		return !!(p.providerId === providerId && organizationId && p.organizationId === organizationId);
	}) ?? null;
	if (scimProvider) if (constantTimeEqual(scimProvider.scimToken, scimToken)) return {
		authSCIMToken: scimProvider.scimToken,
		scimProvider
	};
	else throw new SCIMAPIError("UNAUTHORIZED", { detail: "Invalid SCIM token" });
	scimProvider = await ctx.context.adapter.findOne({
		model: "scimProvider",
		where: [{
			field: "providerId",
			value: providerId
		}, ...organizationId ? [{
			field: "organizationId",
			value: organizationId
		}] : []]
	});
	if (!scimProvider) throw new SCIMAPIError("UNAUTHORIZED", { detail: "Invalid SCIM token" });
	if (!await verifySCIMToken(ctx, opts, scimProvider.scimToken, scimToken)) throw new SCIMAPIError("UNAUTHORIZED", { detail: "Invalid SCIM token" });
	return {
		authSCIMToken: scimToken,
		scimProvider
	};
});
//#endregion
//#region src/mappings.ts
const getAccountId = (userName, externalId) => {
	return externalId ?? userName;
};
const getFormattedName = (name) => {
	if (name.givenName && name.familyName) return `${name.givenName} ${name.familyName}`;
	if (name.givenName) return name.givenName;
	return name.familyName ?? "";
};
const getUserFullName = (email, name) => {
	if (name) {
		const formatted = name.formatted?.trim() ?? "";
		if (formatted.length > 0) return formatted;
		return getFormattedName(name) || email;
	}
	return email;
};
const getUserPrimaryEmail = (userName, emails) => {
	return emails?.find((email) => email.primary)?.value ?? emails?.[0]?.value ?? userName;
};
//#endregion
//#region src/patch-operations.ts
const identity = (user, op, resources) => {
	return op.value;
};
const lowerCase = (user, op, resources) => {
	return op.value.toLowerCase();
};
const givenName = (user, op, resources) => {
	const familyName = (resources.user.name ?? user.name).split(" ").slice(1).join(" ").trim();
	const givenName = op.value;
	return getUserFullName(user.email, {
		givenName,
		familyName
	});
};
const familyName = (user, op, resources) => {
	const currentName = resources.user.name ?? user.name;
	const givenName = (currentName.split(" ").slice(0, -1).join(" ") || currentName).trim();
	const familyName = op.value;
	return getUserFullName(user.email, {
		givenName,
		familyName
	});
};
const active = (user, op, resources) => {
	return op.value === false || op.value === "false";
};
const userPatchMappings = {
	"/active": {
		resource: "user",
		target: "banned",
		map: active
	},
	"/name/formatted": {
		resource: "user",
		target: "name",
		map: identity
	},
	"/name/givenName": {
		resource: "user",
		target: "name",
		map: givenName
	},
	"/name/familyName": {
		resource: "user",
		target: "name",
		map: familyName
	},
	"/externalId": {
		resource: "account",
		target: "accountId",
		map: identity
	},
	"/userName": {
		resource: "user",
		target: "email",
		map: lowerCase
	}
};
const normalizePath = (path) => {
	return `/${(path.startsWith("/") ? path.slice(1) : path).replaceAll(".", "/")}`;
};
const isNestedObject = (value) => {
	return typeof value === "object" && value !== null && !Array.isArray(value);
};
const applyMapping = (user, resources, path, value, op) => {
	const normalizedPath = normalizePath(path);
	const mapping = userPatchMappings[normalizedPath];
	if (!mapping) return;
	const newValue = mapping.map(user, {
		op,
		value,
		path: normalizedPath
	}, resources);
	if (op === "add" && mapping.resource === "user") {
		if (user[mapping.target] === newValue) return;
	}
	resources[mapping.resource][mapping.target] = newValue;
};
const applyPatchValue = (user, resources, value, op, path) => {
	if (isNestedObject(value)) for (const [key, nestedValue] of Object.entries(value)) applyPatchValue(user, resources, nestedValue, op, path ? `${path}.${key}` : key);
	else if (path) applyMapping(user, resources, path, value, op);
};
const buildUserPatch = (user, operations) => {
	const resources = {
		user: {},
		account: {}
	};
	for (const operation of operations) {
		if (operation.op !== "add" && operation.op !== "replace") continue;
		applyPatchValue(user, resources, operation.value, operation.op, operation.path);
	}
	return resources;
};
//#endregion
//#region src/user-schemas.ts
const APIUserSchema = z.object({
	userName: z.string().lowercase(),
	externalId: z.string().optional(),
	name: z.object({
		formatted: z.string().optional(),
		givenName: z.string().optional(),
		familyName: z.string().optional()
	}).optional(),
	emails: z.array(z.object({
		value: z.email(),
		primary: z.boolean().optional()
	})).optional(),
	active: z.boolean().optional()
});
const OpenAPIUserResourceSchema = {
	type: "object",
	properties: {
		id: { type: "string" },
		meta: {
			type: "object",
			properties: {
				resourceType: { type: "string" },
				created: {
					type: "string",
					format: "date-time"
				},
				lastModified: {
					type: "string",
					format: "date-time"
				},
				location: { type: "string" }
			}
		},
		userName: { type: "string" },
		name: {
			type: "object",
			properties: {
				formatted: { type: "string" },
				givenName: { type: "string" },
				familyName: { type: "string" }
			}
		},
		displayName: { type: "string" },
		active: { type: "boolean" },
		emails: {
			type: "array",
			items: {
				type: "object",
				properties: {
					value: { type: "string" },
					primary: { type: "boolean" }
				}
			}
		},
		schemas: {
			type: "array",
			items: { type: "string" }
		}
	}
};
const SCIMUserResourceSchema = {
	id: "urn:ietf:params:scim:schemas:core:2.0:User",
	schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
	name: "User",
	description: "User Account",
	attributes: [
		{
			name: "id",
			type: "string",
			multiValued: false,
			description: "Unique opaque identifier for the User",
			required: false,
			caseExact: true,
			mutability: "readOnly",
			returned: "default",
			uniqueness: "server"
		},
		{
			name: "userName",
			type: "string",
			multiValued: false,
			description: "Unique identifier for the User, typically used by the user to directly authenticate to the service provider",
			required: true,
			caseExact: false,
			mutability: "readWrite",
			returned: "default",
			uniqueness: "server"
		},
		{
			name: "displayName",
			type: "string",
			multiValued: false,
			description: "The name of the User, suitable for display to end-users.  The name SHOULD be the full name of the User being described, if known.",
			required: false,
			caseExact: true,
			mutability: "readOnly",
			returned: "default",
			uniqueness: "none"
		},
		{
			name: "active",
			type: "boolean",
			multiValued: false,
			description: "A Boolean value indicating the User's administrative status.",
			required: false,
			mutability: "readWrite",
			returned: "default"
		},
		{
			name: "name",
			type: "complex",
			multiValued: false,
			description: "The components of the user's real name.",
			required: false,
			subAttributes: [
				{
					name: "formatted",
					type: "string",
					multiValued: false,
					description: "The full name, including all middlenames, titles, and suffixes as appropriate, formatted for display(e.g., 'Ms. Barbara J Jensen, III').",
					required: false,
					caseExact: false,
					mutability: "readWrite",
					returned: "default",
					uniqueness: "none"
				},
				{
					name: "familyName",
					type: "string",
					multiValued: false,
					description: "The family name of the User, or last name in most Western languages (e.g., 'Jensen' given the fullname 'Ms. Barbara J Jensen, III').",
					required: false,
					caseExact: false,
					mutability: "readWrite",
					returned: "default",
					uniqueness: "none"
				},
				{
					name: "givenName",
					type: "string",
					multiValued: false,
					description: "The given name of the User, or first name in most Western languages (e.g., 'Barbara' given the full name 'Ms. Barbara J Jensen, III').",
					required: false,
					caseExact: false,
					mutability: "readWrite",
					returned: "default",
					uniqueness: "none"
				}
			]
		},
		{
			name: "emails",
			type: "complex",
			multiValued: true,
			description: "Email addresses for the user.  The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.",
			required: false,
			subAttributes: [{
				name: "value",
				type: "string",
				multiValued: false,
				description: "Email addresses for the user.  The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.",
				required: false,
				caseExact: false,
				mutability: "readWrite",
				returned: "default",
				uniqueness: "server"
			}, {
				name: "primary",
				type: "boolean",
				multiValued: false,
				description: "A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred mailing address or primary email address.  The primary attribute value 'true' MUST appear no more than once.",
				required: false,
				mutability: "readWrite",
				returned: "default"
			}],
			mutability: "readWrite",
			returned: "default",
			uniqueness: "none"
		}
	],
	meta: {
		resourceType: "Schema",
		location: "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
	}
};
const SCIMUserResourceType = {
	schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
	id: "User",
	name: "User",
	endpoint: "/Users",
	description: "User Account",
	schema: "urn:ietf:params:scim:schemas:core:2.0:User",
	meta: {
		resourceType: "ResourceType",
		location: "/scim/v2/ResourceTypes/User"
	}
};
//#endregion
//#region src/scim-filters.ts
const SCIMOperators = { eq: "eq" };
const SCIMUserAttributes = { userName: "email" };
var SCIMParseError = class extends Error {};
const SCIMFilterRegex = /^\s*(?<attribute>[^\s]+)\s+(?<op>eq|ne|co|sw|ew|pr)\s*(?:(?<value>"[^"]*"|[^\s]+))?\s*$/i;
const parseSCIMFilter = (filter) => {
	const match = filter.match(SCIMFilterRegex);
	if (!match) throw new SCIMParseError("Invalid filter expression");
	const attribute = match.groups?.attribute;
	const op = match.groups?.op?.toLowerCase();
	const value = match.groups?.value;
	if (!attribute || !op || !value) throw new SCIMParseError("Invalid filter expression");
	const operator = SCIMOperators[op];
	if (!operator) throw new SCIMParseError(`The operator "${op}" is not supported`);
	return {
		attribute,
		operator,
		value
	};
};
const parseSCIMUserFilter = (filter) => {
	const { attribute, operator, value } = parseSCIMFilter(filter);
	const filters = [];
	const targetAttribute = SCIMUserAttributes[attribute];
	const resourceAttribute = SCIMUserResourceSchema.attributes.find((attr) => attr.name === attribute);
	if (!targetAttribute || !resourceAttribute) throw new SCIMParseError(`The attribute "${attribute}" is not supported`);
	let finalValue = value.replaceAll("\"", "");
	if (!resourceAttribute.caseExact) finalValue = finalValue.toLowerCase();
	filters.push({
		field: targetAttribute,
		value: finalValue,
		operator
	});
	return filters;
};
//#endregion
//#region src/scim-metadata.ts
const MetadataFieldSupportOpenAPISchema = {
	type: "object",
	properties: { supported: { type: "boolean" } }
};
const ServiceProviderOpenAPISchema = {
	type: "object",
	properties: {
		patch: MetadataFieldSupportOpenAPISchema,
		bulk: MetadataFieldSupportOpenAPISchema,
		filter: MetadataFieldSupportOpenAPISchema,
		changePassword: MetadataFieldSupportOpenAPISchema,
		sort: MetadataFieldSupportOpenAPISchema,
		etag: MetadataFieldSupportOpenAPISchema,
		authenticationSchemes: {
			type: "array",
			items: {
				type: "object",
				properties: {
					name: { type: "string" },
					description: { type: "string" },
					specUri: { type: "string" },
					type: { type: "string" },
					primary: { type: "boolean" }
				}
			}
		},
		schemas: {
			type: "array",
			items: { type: "string" }
		},
		meta: {
			type: "object",
			properties: { resourceType: { type: "string" } }
		}
	}
};
const ResourceTypeOpenAPISchema = {
	type: "object",
	properties: {
		schemas: {
			type: "array",
			items: { type: "string" }
		},
		id: { type: "string" },
		name: { type: "string" },
		endpoint: { type: "string" },
		description: { type: "string" },
		schema: { type: "string" },
		meta: {
			type: "object",
			properties: {
				resourceType: { type: "string" },
				location: { type: "string" }
			}
		}
	}
};
const SCIMSchemaAttributesOpenAPISchema = {
	type: "object",
	properties: {
		name: { type: "string" },
		type: { type: "string" },
		multiValued: { type: "boolean" },
		description: { type: "string" },
		required: { type: "boolean" },
		caseExact: { type: "boolean" },
		mutability: { type: "string" },
		returned: { type: "string" },
		uniqueness: { type: "string" }
	}
};
const SCIMSchemaOpenAPISchema = {
	type: "object",
	properties: {
		id: { type: "string" },
		schemas: {
			type: "array",
			items: { type: "string" }
		},
		name: { type: "string" },
		description: { type: "string" },
		attributes: {
			type: "array",
			items: {
				...SCIMSchemaAttributesOpenAPISchema,
				properties: {
					...SCIMSchemaAttributesOpenAPISchema.properties,
					subAttributes: {
						type: "array",
						items: SCIMSchemaAttributesOpenAPISchema
					}
				}
			}
		},
		meta: {
			type: "object",
			properties: {
				resourceType: { type: "string" },
				location: { type: "string" }
			},
			required: ["resourceType", "location"]
		}
	}
};
//#endregion
//#region src/utils.ts
const getResourceURL = (path, baseURL) => {
	const normalizedBaseURL = baseURL.endsWith("/") ? baseURL : `${baseURL}/`;
	const normalizedPath = path.replace(/^\/+/, "");
	return new URL(normalizedPath, normalizedBaseURL).toString();
};
//#endregion
//#region src/scim-resources.ts
const createUserResource = (baseURL, user, account) => {
	return {
		id: user.id,
		externalId: account?.accountId,
		meta: {
			resourceType: "User",
			created: user.createdAt,
			lastModified: user.updatedAt,
			location: getResourceURL(`/scim/v2/Users/${user.id}`, baseURL)
		},
		userName: user.email,
		name: { formatted: user.name },
		displayName: user.name,
		active: !user.banned,
		emails: [{
			primary: true,
			value: user.email
		}],
		schemas: [SCIMUserResourceSchema.id]
	};
};
//#endregion
//#region src/routes.ts
const supportedSCIMSchemas = [SCIMUserResourceSchema];
const supportedSCIMResourceTypes = [SCIMUserResourceType];
const supportedMediaTypes = ["application/json", "application/scim+json"];
const generateSCIMTokenBodySchema = z.object({
	providerId: z.string().meta({ description: "Unique provider identifier" }),
	organizationId: z.string().optional().meta({ description: "Optional organization id" })
});
const getSCIMProviderConnectionQuerySchema = z.object({ providerId: z.string() });
const deleteSCIMProviderConnectionBodySchema = z.object({ providerId: z.string() });
function getDefaultSSOProviderIds(pluginOptions) {
	if (!pluginOptions || typeof pluginOptions !== "object" || !("defaultSSO" in pluginOptions) || !Array.isArray(pluginOptions.defaultSSO)) return [];
	return pluginOptions.defaultSSO.map((provider) => {
		if (provider && typeof provider === "object" && "providerId" in provider && typeof provider.providerId === "string") return provider.providerId;
		return null;
	}).filter((providerId) => providerId !== null);
}
function parseMemberRoles(role) {
	return role.split(",").map((entry) => entry.trim()).filter(Boolean);
}
function hasRequiredRole(memberRole, requiredRole) {
	return !requiredRole.length || parseMemberRoles(memberRole).some((role) => requiredRole.includes(role));
}
function resolveRequiredRoles(ctx, opts) {
	if (opts.requiredRole) return opts.requiredRole;
	const creatorRole = ctx.context.getPlugin("organization")?.options?.creatorRole;
	return Array.from(new Set(["admin", creatorRole ?? "owner"]));
}
function isProviderOwnershipEnabled(opts) {
	return opts.providerOwnership?.enabled ?? false;
}
async function getSCIMUserOrgMemberships(ctx, userId) {
	const members = await ctx.context.adapter.findMany({
		model: "member",
		where: [{
			field: "userId",
			value: userId
		}]
	});
	return new Map(members.map((member) => [member.organizationId, parseMemberRoles(member.role)]));
}
function normalizeSCIMProvider(provider) {
	return {
		id: provider.id,
		providerId: provider.providerId,
		organizationId: provider.organizationId ?? null
	};
}
async function findOrganizationMember(ctx, userId, organizationId) {
	return ctx.context.adapter.findOne({
		model: "member",
		where: [{
			field: "userId",
			value: userId
		}, {
			field: "organizationId",
			value: organizationId
		}]
	});
}
/**
* Decides whether SCIM provisioning may attach to a pre-existing user that
* matched by email. Linking by email alone would give the SCIM token full
* read/write/delete access to a user it never provisioned, so this returns
* `false` unless `opts.linkExistingUsers` explicitly opts in and every
* configured constraint passes.
*/
async function canLinkExistingUser(ctx, opts, existingUser, email) {
	const policy = opts.linkExistingUsers;
	if (!policy) return false;
	if (policy === true) return true;
	const { organizationId, providerId } = ctx.context.scimProvider;
	if (!((policy.trustedDomains?.length ?? 0) > 0 || policy.requireExistingOrgMembership === true || typeof policy.shouldLinkUser === "function")) return false;
	if (policy.requireExistingOrgMembership) {
		if (!organizationId) return false;
		if (!await findOrganizationMember(ctx, existingUser.id, organizationId)) return false;
	}
	if (policy.trustedDomains?.length) {
		const domain = email.split("@")[1]?.toLowerCase();
		if (!(!!domain && policy.trustedDomains.some((d) => d.toLowerCase() === domain))) return false;
	}
	if (policy.shouldLinkUser) {
		if (!await policy.shouldLinkUser({
			user: existingUser,
			email,
			provider: {
				providerId,
				organizationId
			}
		})) return false;
	}
	return true;
}
async function assertSCIMProviderAccess(ctx, userId, provider, requiredRole) {
	if (provider.organizationId) {
		if (!ctx.context.hasPlugin("organization")) throw new APIError("FORBIDDEN", { message: "Organization plugin is required to access this SCIM provider" });
		const member = await findOrganizationMember(ctx, userId, provider.organizationId);
		if (!member) throw new APIError("FORBIDDEN", { message: "You must be a member of the organization to access this provider" });
		if (!hasRequiredRole(member.role, requiredRole)) throw new APIError("FORBIDDEN", { message: "Insufficient role for this operation" });
	} else if (provider.userId && provider.userId !== userId) throw new APIError("FORBIDDEN", { message: "You must be the owner to access this provider" });
}
async function checkSCIMProviderAccess(ctx, userId, providerId, requiredRole) {
	const provider = await ctx.context.adapter.findOne({
		model: "scimProvider",
		where: [{
			field: "providerId",
			value: providerId
		}]
	});
	if (!provider) throw new APIError("NOT_FOUND", { message: "SCIM provider not found" });
	await assertSCIMProviderAccess(ctx, userId, provider, requiredRole);
	return provider;
}
/**
* Rejects a SCIM email change that would collide with another user. Mirrors the
* uniqueness guard `createSCIMUser` already performs, so PUT/PATCH cannot
* reassign one user's email onto another existing user (which corrupts
* email-keyed login on adapters without a unique index and 500s on those with
* one). Only call this when the email actually changes.
*/
async function assertSCIMEmailAvailable(ctx, email, userId) {
	const existing = await ctx.context.adapter.findOne({
		model: "user",
		where: [{
			field: "email",
			value: email.toLowerCase()
		}]
	});
	if (existing && existing.id !== userId) throw new SCIMAPIError("CONFLICT", {
		detail: "Email already in use",
		scimType: "uniqueness"
	});
}
/**
* Applies SCIM `active` semantics to a pending user update. `active` maps to the
* admin plugin's `banned` field, the only enforced disabled-user state in Better
* Auth, so honoring deactivation requires the admin plugin. Returns whether the
* update deactivates the user, so the caller can revoke their sessions. A
* deactivation without the admin plugin is rejected, never silently dropped.
*/
function resolveSCIMActiveDeactivation(ctx, userUpdate) {
	if (!("banned" in userUpdate)) return false;
	const deactivating = userUpdate.banned === true;
	if (!ctx.context.hasPlugin("admin")) {
		if (deactivating) throw new SCIMAPIError("BAD_REQUEST", { detail: "Setting `active: false` requires the admin plugin, which provides the enforced disabled-user state" });
		delete userUpdate.banned;
		return false;
	}
	if (deactivating) {
		userUpdate.banReason = "Deactivated via SCIM";
		return true;
	}
	userUpdate.banReason = null;
	userUpdate.banExpires = null;
	return false;
}
async function invokeAfterSCIMUserProvisioned(ctx, opts, payload) {
	if (!opts.afterSCIMUserProvisioned) return;
	await opts.afterSCIMUserProvisioned({
		user: payload.user,
		scimProvider: ctx.context.scimProvider,
		externalId: payload.externalId
	});
}
async function invokeAfterSCIMUserDeprovisioned(ctx, opts, user) {
	if (!opts.afterSCIMUserDeprovisioned) return;
	await opts.afterSCIMUserDeprovisioned({
		user,
		scimProvider: ctx.context.scimProvider
	});
}
const generateSCIMToken = (opts) => createAuthEndpoint("/scim/generate-token", {
	method: "POST",
	body: generateSCIMTokenBodySchema,
	metadata: { openapi: {
		summary: "Generates a new SCIM token for the given provider",
		description: "Generates a new SCIM token to be used for SCIM operations",
		responses: { "201": {
			description: "SCIM token response",
			content: { "application/json": { schema: {
				type: "object",
				properties: { scimToken: {
					description: "SCIM token",
					type: "string"
				} }
			} } }
		} }
	} },
	use: [sessionMiddleware]
}, async (ctx) => {
	const { providerId, organizationId } = ctx.body;
	const user = ctx.context.session.user;
	const requiredRole = resolveRequiredRoles(ctx, opts);
	if (providerId.includes(":")) throw new APIError("BAD_REQUEST", { message: "Provider id contains forbidden characters" });
	const defaultSSOProviderIds = getDefaultSSOProviderIds(ctx.context.getPlugin("sso")?.options);
	if (new Set([
		"credential",
		"email-otp",
		"magic-link",
		"phone-number",
		"anonymous",
		"siwe",
		...Object.keys(ctx.context.options.socialProviders ?? {}),
		...ctx.context.socialProviders.map((p) => p.id),
		...defaultSSOProviderIds
	]).has(providerId)) throw new APIError("BAD_REQUEST", { message: "Provider id collides with another account provider and cannot be used for SCIM" });
	if (ctx.context.hasPlugin("sso")) {
		if (await ctx.context.adapter.findOne({
			model: "ssoProvider",
			where: [{
				field: "providerId",
				value: providerId
			}]
		})) throw new APIError("BAD_REQUEST", { message: "Provider id collides with another account provider and cannot be used for SCIM" });
	}
	if (organizationId && !ctx.context.hasPlugin("organization")) throw new APIError("BAD_REQUEST", { message: "Restricting a token to an organization requires the organization plugin" });
	let member = null;
	if (organizationId) {
		member = await findOrganizationMember(ctx, user.id, organizationId);
		if (!member) throw new APIError("FORBIDDEN", { message: "You are not a member of the organization" });
		if (!hasRequiredRole(member.role, requiredRole)) throw new APIError("FORBIDDEN", { message: "Insufficient role for this operation" });
	}
	if (opts.canGenerateToken) {
		if (!await opts.canGenerateToken({
			user,
			providerId,
			organizationId,
			member
		})) throw new APIError("FORBIDDEN", { message: "You are not allowed to generate a SCIM token" });
	}
	const scimProvider = await ctx.context.adapter.findOne({
		model: "scimProvider",
		where: [{
			field: "providerId",
			value: providerId
		}, ...organizationId ? [{
			field: "organizationId",
			value: organizationId
		}] : []]
	});
	if (scimProvider) {
		await assertSCIMProviderAccess(ctx, user.id, scimProvider, requiredRole);
		await ctx.context.adapter.delete({
			model: "scimProvider",
			where: [{
				field: "id",
				value: scimProvider.id
			}]
		});
	}
	const baseToken = generateRandomString(24);
	const scimToken = base64Url.encode(`${baseToken}:${providerId}${organizationId ? `:${organizationId}` : ""}`);
	if (opts.beforeSCIMTokenGenerated) await opts.beforeSCIMTokenGenerated({
		user,
		member,
		scimToken
	});
	const newSCIMProvider = await ctx.context.adapter.create({
		model: "scimProvider",
		data: {
			providerId,
			organizationId,
			scimToken: await storeSCIMToken(ctx, opts, baseToken),
			...isProviderOwnershipEnabled(opts) ? { userId: user.id } : {}
		}
	});
	if (opts.afterSCIMTokenGenerated) await opts.afterSCIMTokenGenerated({
		user,
		member,
		scimToken,
		scimProvider: newSCIMProvider
	});
	ctx.setStatus(201);
	return ctx.json({ scimToken });
});
const listSCIMProviderConnections = (opts) => createAuthEndpoint("/scim/list-provider-connections", {
	method: "GET",
	use: [sessionMiddleware],
	metadata: { openapi: {
		operationId: "listSCIMProviderConnections",
		summary: "List SCIM providers",
		description: "Returns SCIM providers the user owns or has the required org role for.",
		responses: { "200": {
			description: "List of SCIM providers",
			content: { "application/json": { schema: {
				type: "object",
				properties: { providers: {
					type: "array",
					items: {
						type: "object",
						properties: {
							id: { type: "string" },
							providerId: { type: "string" },
							organizationId: {
								type: "string",
								nullable: true
							}
						}
					}
				} }
			} } }
		} }
	} }
}, async (ctx) => {
	const userId = ctx.context.session.user.id;
	const requiredRole = resolveRequiredRoles(ctx, opts);
	const orgMemberships = ctx.context.hasPlugin("organization") ? await getSCIMUserOrgMemberships(ctx, userId) : /* @__PURE__ */ new Map();
	const providers = (await ctx.context.adapter.findMany({ model: "scimProvider" })).filter((p) => {
		if (p.organizationId) {
			const roles = orgMemberships.get(p.organizationId);
			return roles ? !requiredRole.length || roles.some((role) => requiredRole.includes(role)) : false;
		}
		return p.userId === userId || !p.userId;
	}).map((p) => normalizeSCIMProvider(p));
	return ctx.json({ providers });
});
const getSCIMProviderConnection = (opts) => createAuthEndpoint("/scim/get-provider-connection", {
	method: "GET",
	use: [sessionMiddleware],
	query: getSCIMProviderConnectionQuerySchema,
	metadata: { openapi: {
		operationId: "getSCIMProviderConnection",
		summary: "Get SCIM provider details",
		description: "Returns details for a specific SCIM provider",
		responses: {
			"200": {
				description: "SCIM provider details",
				content: { "application/json": { schema: {
					type: "object",
					properties: {
						id: { type: "string" },
						providerId: { type: "string" },
						organizationId: {
							type: "string",
							nullable: true
						}
					}
				} } }
			},
			"404": { description: "Provider not found" },
			"403": { description: "Access denied" }
		}
	} }
}, async (ctx) => {
	const { providerId } = ctx.query;
	const userId = ctx.context.session.user.id;
	const provider = await checkSCIMProviderAccess(ctx, userId, providerId, resolveRequiredRoles(ctx, opts));
	return ctx.json(normalizeSCIMProvider(provider));
});
const deleteSCIMProviderConnection = (opts) => createAuthEndpoint("/scim/delete-provider-connection", {
	method: "POST",
	use: [sessionMiddleware],
	body: deleteSCIMProviderConnectionBodySchema,
	metadata: { openapi: {
		operationId: "deleteSCIMProviderConnection",
		summary: "Delete SCIM provider",
		description: "Deletes a SCIM provider and invalidates its token",
		responses: {
			"200": {
				description: "SCIM provider deleted successfully",
				content: { "application/json": { schema: {
					type: "object",
					properties: { success: { type: "boolean" } }
				} } }
			},
			"404": { description: "Provider not found" },
			"403": { description: "Access denied" }
		}
	} }
}, async (ctx) => {
	const { providerId } = ctx.body;
	const userId = ctx.context.session.user.id;
	await checkSCIMProviderAccess(ctx, userId, providerId, resolveRequiredRoles(ctx, opts));
	await ctx.context.adapter.delete({
		model: "scimProvider",
		where: [{
			field: "providerId",
			value: providerId
		}]
	});
	return ctx.json({ success: true });
});
const createSCIMUser = (authMiddleware, opts) => createAuthEndpoint("/scim/v2/Users", {
	method: "POST",
	body: APIUserSchema,
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "Create SCIM user.",
			description: "Provision a new user into the linked organization via SCIM. See https://datatracker.ietf.org/doc/html/rfc7644#section-3.3",
			responses: {
				"201": {
					description: "SCIM user resource",
					content: { "application/json": { schema: OpenAPIUserResourceSchema } }
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	},
	use: [authMiddleware]
}, async (ctx) => {
	const body = ctx.body;
	const providerId = ctx.context.scimProvider.providerId;
	const accountId = getAccountId(body.userName, body.externalId);
	if (await ctx.context.adapter.findOne({
		model: "account",
		where: [{
			field: "accountId",
			value: accountId
		}, {
			field: "providerId",
			value: providerId
		}]
	})) throw new SCIMAPIError("CONFLICT", {
		detail: "User already exists",
		scimType: "uniqueness"
	});
	if (body.active === false) resolveSCIMActiveDeactivation(ctx, { banned: true });
	const email = getUserPrimaryEmail(body.userName, body.emails).toLowerCase();
	const name = getUserFullName(email, body.name);
	const existingUser = await ctx.context.adapter.findOne({
		model: "user",
		where: [{
			field: "email",
			value: email
		}]
	});
	const createAccount = (userId) => ctx.context.internalAdapter.createAccount({
		userId,
		providerId,
		accountId,
		accessToken: "",
		refreshToken: ""
	});
	const createUser = () => ctx.context.internalAdapter.createUser({
		email,
		name
	});
	const createOrgMembership = async (userId) => {
		const organizationId = ctx.context.scimProvider.organizationId;
		if (organizationId) {
			if (!await ctx.context.adapter.findOne({
				model: "member",
				where: [{
					field: "organizationId",
					value: organizationId
				}, {
					field: "userId",
					value: userId
				}]
			})) return await ctx.context.adapter.create({
				model: "member",
				data: {
					userId,
					role: "member",
					createdAt: /* @__PURE__ */ new Date(),
					organizationId
				}
			});
		}
	};
	let user;
	let account;
	if (existingUser) {
		if (!await canLinkExistingUser(ctx, opts, existingUser, email)) throw new SCIMAPIError("CONFLICT", {
			detail: "User already exists",
			scimType: "uniqueness"
		});
		user = existingUser;
		account = await ctx.context.adapter.transaction(async () => {
			const account = await createAccount(user.id);
			await createOrgMembership(user.id);
			return account;
		});
	} else [user, account] = await ctx.context.adapter.transaction(async () => {
		const user = await createUser();
		const account = await createAccount(user.id);
		await createOrgMembership(user.id);
		return [user, account];
	});
	if (body.active === false) {
		const deactivation = { banned: true };
		resolveSCIMActiveDeactivation(ctx, deactivation);
		const banned = await ctx.context.internalAdapter.updateUser(user.id, deactivation);
		if (banned) user = banned;
		await ctx.context.internalAdapter.deleteUserSessions(user.id);
	}
	const userResource = createUserResource(ctx.context.baseURL, user, account);
	await invokeAfterSCIMUserProvisioned(ctx, opts, {
		user,
		externalId: account.accountId
	});
	ctx.setStatus(201);
	ctx.setHeader("location", userResource.meta.location);
	return ctx.json(userResource);
});
const updateSCIMUser = (authMiddleware, opts) => createAuthEndpoint("/scim/v2/Users/:userId", {
	method: "PUT",
	body: APIUserSchema,
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "Update SCIM user.",
			description: "Updates an existing user into the linked organization via SCIM. See https://datatracker.ietf.org/doc/html/rfc7644#section-3.3",
			responses: {
				"200": {
					description: "SCIM user resource",
					content: { "application/json": { schema: OpenAPIUserResourceSchema } }
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	},
	use: [authMiddleware]
}, async (ctx) => {
	const body = ctx.body;
	const userId = ctx.params.userId;
	const { organizationId, providerId } = ctx.context.scimProvider;
	const accountId = getAccountId(body.userName, body.externalId);
	const { user, account } = await findUserById(ctx.context.adapter, {
		userId,
		providerId,
		organizationId
	});
	if (!user) throw new SCIMAPIError("NOT_FOUND", { detail: "User not found" });
	const email = getUserPrimaryEmail(body.userName, body.emails).toLowerCase();
	const name = getUserFullName(email, body.name);
	const emailChanged = email !== user.email;
	if (emailChanged) await assertSCIMEmailAvailable(ctx, email, userId);
	const userUpdate = {
		email,
		name,
		updatedAt: /* @__PURE__ */ new Date()
	};
	if (emailChanged) userUpdate.emailVerified = false;
	if (body.active !== void 0) userUpdate.banned = body.active === false;
	const deactivating = resolveSCIMActiveDeactivation(ctx, userUpdate);
	const [updatedUser, updatedAccount] = await ctx.context.adapter.transaction(async () => {
		return [await ctx.context.internalAdapter.updateUser(userId, userUpdate), await ctx.context.internalAdapter.updateAccount(account.id, {
			accountId,
			updatedAt: /* @__PURE__ */ new Date()
		})];
	});
	if (deactivating) {
		await ctx.context.internalAdapter.deleteUserSessions(userId);
		await invokeAfterSCIMUserDeprovisioned(ctx, opts, updatedUser);
	}
	const userResource = createUserResource(ctx.context.baseURL, updatedUser, updatedAccount);
	return ctx.json(userResource);
});
const listSCIMUsersQuerySchema = z.object({ filter: z.string().optional() }).optional();
const listSCIMUsers = (authMiddleware) => createAuthEndpoint("/scim/v2/Users", {
	method: "GET",
	query: listSCIMUsersQuerySchema,
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "List SCIM users",
			description: "Returns all users provisioned via SCIM for the linked organization. See https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.2",
			responses: {
				"200": {
					description: "SCIM user list",
					content: { "application/json": { schema: {
						type: "object",
						properties: {
							totalResults: { type: "number" },
							itemsPerPage: { type: "number" },
							startIndex: { type: "number" },
							Resources: {
								type: "array",
								items: OpenAPIUserResourceSchema
							}
						}
					} } }
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	},
	use: [authMiddleware]
}, async (ctx) => {
	const emptyListResponse = {
		schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
		totalResults: 0,
		startIndex: 1,
		itemsPerPage: 0,
		Resources: []
	};
	const apiFilters = parseSCIMAPIUserFilter(ctx.query?.filter);
	const providerId = ctx.context.scimProvider.providerId;
	const accounts = await ctx.context.adapter.findMany({
		model: "account",
		where: [{
			field: "providerId",
			value: providerId
		}]
	});
	const accountUserIds = accounts.map((account) => account.userId);
	if (accountUserIds.length === 0) return ctx.json(emptyListResponse);
	let userFilters = [{
		field: "id",
		value: accountUserIds,
		operator: "in"
	}];
	const organizationId = ctx.context.scimProvider.organizationId;
	if (organizationId) {
		const memberUserIds = (await ctx.context.adapter.findMany({
			model: "member",
			where: [{
				field: "organizationId",
				value: organizationId
			}, {
				field: "userId",
				value: accountUserIds,
				operator: "in"
			}]
		})).map((member) => member.userId);
		if (memberUserIds.length === 0) return ctx.json(emptyListResponse);
		userFilters = [{
			field: "id",
			value: memberUserIds,
			operator: "in"
		}];
	}
	const users = await ctx.context.adapter.findMany({
		model: "user",
		where: [...userFilters, ...apiFilters]
	});
	return ctx.json({
		schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
		totalResults: users.length,
		startIndex: 1,
		itemsPerPage: users.length,
		Resources: users.map((user) => {
			const account = accounts.find((a) => a.userId === user.id);
			return createUserResource(ctx.context.baseURL, user, account);
		})
	});
});
const getSCIMUser = (authMiddleware) => createAuthEndpoint("/scim/v2/Users/:userId", {
	method: "GET",
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "Get SCIM user details",
			description: "Returns the provisioned SCIM user details. See https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1",
			responses: {
				"200": {
					description: "SCIM user resource",
					content: { "application/json": { schema: OpenAPIUserResourceSchema } }
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	},
	use: [authMiddleware]
}, async (ctx) => {
	const userId = ctx.params.userId;
	const providerId = ctx.context.scimProvider.providerId;
	const organizationId = ctx.context.scimProvider.organizationId;
	const { user, account } = await findUserById(ctx.context.adapter, {
		userId,
		providerId,
		organizationId
	});
	if (!user) throw new SCIMAPIError("NOT_FOUND", { detail: "User not found" });
	return ctx.json(createUserResource(ctx.context.baseURL, user, account));
});
const patchSCIMUserBodySchema = z.object({
	schemas: z.array(z.string()).refine((s) => s.includes("urn:ietf:params:scim:api:messages:2.0:PatchOp"), { message: "Invalid schemas for PatchOp" }),
	Operations: z.array(z.object({
		op: z.string().toLowerCase().default("replace").pipe(z.enum([
			"replace",
			"add",
			"remove"
		])),
		path: z.string().optional(),
		value: z.any()
	}))
});
const patchSCIMUser = (authMiddleware, opts) => createAuthEndpoint("/scim/v2/Users/:userId", {
	method: "PATCH",
	body: patchSCIMUserBodySchema,
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "Patch SCIM user",
			description: "Updates fields on a SCIM user record",
			responses: {
				"204": { description: "Patch update applied correctly" },
				...SCIMErrorOpenAPISchemas
			}
		}
	},
	use: [authMiddleware]
}, async (ctx) => {
	const userId = ctx.params.userId;
	const organizationId = ctx.context.scimProvider.organizationId;
	const providerId = ctx.context.scimProvider.providerId;
	const { user, account } = await findUserById(ctx.context.adapter, {
		userId,
		providerId,
		organizationId
	});
	if (!user) throw new SCIMAPIError("NOT_FOUND", { detail: "User not found" });
	const { user: userPatch, account: accountPatch } = buildUserPatch(user, ctx.body.Operations);
	if (Object.keys(userPatch).length === 0 && Object.keys(accountPatch).length === 0) throw new SCIMAPIError("BAD_REQUEST", { detail: "No valid fields to update" });
	if (typeof userPatch.email === "string" && userPatch.email !== user.email) {
		await assertSCIMEmailAvailable(ctx, userPatch.email, userId);
		userPatch.emailVerified = false;
	}
	const deactivating = resolveSCIMActiveDeactivation(ctx, userPatch);
	await Promise.all([Object.keys(userPatch).length > 0 ? ctx.context.internalAdapter.updateUser(userId, {
		...userPatch,
		updatedAt: /* @__PURE__ */ new Date()
	}) : Promise.resolve(), Object.keys(accountPatch).length > 0 ? ctx.context.internalAdapter.updateAccount(account.id, {
		...accountPatch,
		updatedAt: /* @__PURE__ */ new Date()
	}) : Promise.resolve()]);
	if (deactivating) {
		await ctx.context.internalAdapter.deleteUserSessions(userId);
		await invokeAfterSCIMUserDeprovisioned(ctx, opts, user);
	}
	ctx.setStatus(204);
});
const deleteSCIMUser = (authMiddleware, opts) => createAuthEndpoint("/scim/v2/Users/:userId", {
	method: "DELETE",
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: [...supportedMediaTypes, ""],
		openapi: {
			summary: "Delete SCIM user",
			description: "Deletes (or deactivates) a user within the linked organization.",
			responses: {
				"204": { description: "Delete applied successfully" },
				...SCIMErrorOpenAPISchemas
			}
		}
	},
	use: [authMiddleware]
}, async (ctx) => {
	const userId = ctx.params.userId;
	const providerId = ctx.context.scimProvider.providerId;
	const organizationId = ctx.context.scimProvider.organizationId;
	const { user, account } = await findUserById(ctx.context.adapter, {
		userId,
		providerId,
		organizationId
	});
	if (!user) throw new SCIMAPIError("NOT_FOUND", { detail: "User not found" });
	if (organizationId) {
		const organizationPlugin = ctx.context.getPlugin("organization");
		if (!organizationPlugin) throw new SCIMAPIError("BAD_REQUEST", { detail: "Organization-scoped SCIM deprovisioning requires the organization plugin" });
		const orgOptions = organizationPlugin.options;
		const orgAdapter = getOrgAdapter(ctx.context, orgOptions);
		const member = await findOrganizationMember(ctx, userId, organizationId);
		const organization = member ? await orgAdapter.findOrganizationById(organizationId) : null;
		if (member && organization) await orgOptions?.organizationHooks?.beforeRemoveMember?.({
			member,
			user,
			organization
		});
		await ctx.context.adapter.transaction(async (trx) => {
			if (member) {
				await trx.delete({
					model: "member",
					where: [{
						field: "id",
						value: member.id
					}]
				});
				if (orgOptions?.teams?.enabled) {
					const teams = await trx.findMany({
						model: "team",
						where: [{
							field: "organizationId",
							value: organizationId
						}]
					});
					if (teams.length > 0) await trx.deleteMany({
						model: "teamMember",
						where: [{
							field: "userId",
							value: userId
						}, {
							field: "teamId",
							value: teams.map((team) => team.id),
							operator: "in"
						}]
					});
				}
			}
			if (account) await trx.delete({
				model: "account",
				where: [{
					field: "id",
					value: account.id
				}]
			});
		});
		if (member && organization) await orgOptions?.organizationHooks?.afterRemoveMember?.({
			member,
			user,
			organization
		});
		await invokeAfterSCIMUserDeprovisioned(ctx, opts, user);
		ctx.setStatus(204);
		return;
	}
	if ((await ctx.context.internalAdapter.findAccounts(userId)).some((a) => a.id !== account.id)) {
		await ctx.context.internalAdapter.deleteAccount(account.id);
		ctx.setStatus(204);
		return;
	}
	await ctx.context.internalAdapter.deleteUserSessions(userId);
	await ctx.context.internalAdapter.deleteUser(userId);
	ctx.setStatus(204);
});
const getSCIMServiceProviderConfig = createAuthEndpoint("/scim/v2/ServiceProviderConfig", {
	method: "GET",
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "SCIM Service Provider Configuration",
			description: "Standard SCIM metadata endpoint used by identity providers. See https://datatracker.ietf.org/doc/html/rfc7644#section-4",
			responses: {
				"200": {
					description: "SCIM metadata object",
					content: { "application/json": { schema: ServiceProviderOpenAPISchema } }
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	}
}, async (ctx) => {
	return ctx.json({
		patch: { supported: true },
		bulk: { supported: false },
		filter: { supported: true },
		changePassword: { supported: false },
		sort: { supported: false },
		etag: { supported: false },
		authenticationSchemes: [{
			name: "OAuth Bearer Token",
			description: "Authentication scheme using the Authorization header with a bearer token tied to an organization.",
			specUri: "http://www.rfc-editor.org/info/rfc6750",
			type: "oauthbearertoken",
			primary: true
		}],
		schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
		meta: { resourceType: "ServiceProviderConfig" }
	});
});
const getSCIMSchemas = createAuthEndpoint("/scim/v2/Schemas", {
	method: "GET",
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "SCIM Service Provider Configuration Schemas",
			description: "Standard SCIM metadata endpoint used by identity providers to acquire information about supported schemas. See https://datatracker.ietf.org/doc/html/rfc7644#section-4",
			responses: {
				"200": {
					description: "SCIM metadata object",
					content: { "application/json": { schema: {
						type: "array",
						items: SCIMSchemaOpenAPISchema
					} } }
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	}
}, async (ctx) => {
	return ctx.json({
		totalResults: supportedSCIMSchemas.length,
		itemsPerPage: supportedSCIMSchemas.length,
		startIndex: 1,
		schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
		Resources: supportedSCIMSchemas.map((s) => {
			return {
				...s,
				meta: {
					...s.meta,
					location: getResourceURL(s.meta.location, ctx.context.baseURL)
				}
			};
		})
	});
});
const getSCIMSchema = createAuthEndpoint("/scim/v2/Schemas/:schemaId", {
	method: "GET",
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "SCIM a Service Provider Configuration Schema",
			description: "Standard SCIM metadata endpoint used by identity providers to acquire information about a given schema. See https://datatracker.ietf.org/doc/html/rfc7644#section-4",
			responses: {
				"200": {
					description: "SCIM metadata object",
					content: { "application/json": { schema: SCIMSchemaOpenAPISchema } }
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	}
}, async (ctx) => {
	const schema = supportedSCIMSchemas.find((s) => s.id === ctx.params.schemaId);
	if (!schema) throw new SCIMAPIError("NOT_FOUND", { detail: "Schema not found" });
	return ctx.json({
		...schema,
		meta: {
			...schema.meta,
			location: getResourceURL(schema.meta.location, ctx.context.baseURL)
		}
	});
});
const getSCIMResourceTypes = createAuthEndpoint("/scim/v2/ResourceTypes", {
	method: "GET",
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "SCIM Service Provider Supported Resource Types",
			description: "Standard SCIM metadata endpoint used by identity providers to get a list of server supported types. See https://datatracker.ietf.org/doc/html/rfc7644#section-4",
			responses: {
				"200": {
					description: "SCIM metadata object",
					content: { "application/json": { schema: {
						type: "object",
						properties: {
							totalResults: { type: "number" },
							itemsPerPage: { type: "number" },
							startIndex: { type: "number" },
							Resources: {
								type: "array",
								items: ResourceTypeOpenAPISchema
							}
						}
					} } }
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	}
}, async (ctx) => {
	return ctx.json({
		totalResults: supportedSCIMResourceTypes.length,
		itemsPerPage: supportedSCIMResourceTypes.length,
		startIndex: 1,
		schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
		Resources: supportedSCIMResourceTypes.map((s) => {
			return {
				...s,
				meta: {
					...s.meta,
					location: getResourceURL(s.meta.location, ctx.context.baseURL)
				}
			};
		})
	});
});
const getSCIMResourceType = createAuthEndpoint("/scim/v2/ResourceTypes/:resourceTypeId", {
	method: "GET",
	metadata: {
		...HIDE_METADATA,
		allowedMediaTypes: supportedMediaTypes,
		openapi: {
			summary: "SCIM Service Provider Supported Resource Type",
			description: "Standard SCIM metadata endpoint used by identity providers to get a server supported type. See https://datatracker.ietf.org/doc/html/rfc7644#section-4",
			responses: {
				"200": {
					description: "SCIM metadata object",
					content: { "application/json": { schema: ResourceTypeOpenAPISchema } }
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	}
}, async (ctx) => {
	const resourceType = supportedSCIMResourceTypes.find((s) => s.id === ctx.params.resourceTypeId);
	if (!resourceType) throw new SCIMAPIError("NOT_FOUND", { detail: "Resource type not found" });
	return ctx.json({
		...resourceType,
		meta: {
			...resourceType.meta,
			location: getResourceURL(resourceType.meta.location, ctx.context.baseURL)
		}
	});
});
const findUserById = async (adapter, { userId, providerId, organizationId }) => {
	const account = await adapter.findOne({
		model: "account",
		where: [{
			field: "userId",
			value: userId
		}, {
			field: "providerId",
			value: providerId
		}]
	});
	if (!account) return {
		user: null,
		account: null
	};
	let member = null;
	if (organizationId) member = await adapter.findOne({
		model: "member",
		where: [{
			field: "organizationId",
			value: organizationId
		}, {
			field: "userId",
			value: userId
		}]
	});
	if (organizationId && !member) return {
		user: null,
		account: null
	};
	const user = await adapter.findOne({
		model: "user",
		where: [{
			field: "id",
			value: userId
		}]
	});
	if (!user) return {
		user: null,
		account: null
	};
	return {
		user,
		account
	};
};
const parseSCIMAPIUserFilter = (filter) => {
	let filters = [];
	try {
		filters = filter ? parseSCIMUserFilter(filter) : [];
	} catch (error) {
		throw new SCIMAPIError("BAD_REQUEST", {
			detail: error instanceof SCIMParseError ? error.message : "Invalid SCIM filter",
			scimType: "invalidFilter"
		});
	}
	return filters;
};
//#endregion
//#region src/index.ts
const scim = (options) => {
	const opts = {
		storeSCIMToken: "plain",
		...options
	};
	const providerOwnershipEnabled = options?.providerOwnership?.enabled ?? false;
	const authMiddleware = authMiddlewareFactory(opts);
	return {
		id: "scim",
		version: PACKAGE_VERSION,
		endpoints: {
			generateSCIMToken: generateSCIMToken(opts),
			listSCIMProviderConnections: listSCIMProviderConnections(opts),
			getSCIMProviderConnection: getSCIMProviderConnection(opts),
			deleteSCIMProviderConnection: deleteSCIMProviderConnection(opts),
			getSCIMUser: getSCIMUser(authMiddleware),
			createSCIMUser: createSCIMUser(authMiddleware, opts),
			patchSCIMUser: patchSCIMUser(authMiddleware, opts),
			deleteSCIMUser: deleteSCIMUser(authMiddleware, opts),
			updateSCIMUser: updateSCIMUser(authMiddleware, opts),
			listSCIMUsers: listSCIMUsers(authMiddleware),
			getSCIMServiceProviderConfig,
			getSCIMSchemas,
			getSCIMSchema,
			getSCIMResourceTypes,
			getSCIMResourceType
		},
		schema: { scimProvider: { fields: {
			providerId: {
				type: "string",
				required: true,
				unique: true
			},
			scimToken: {
				type: "string",
				required: true,
				unique: true
			},
			organizationId: {
				type: "string",
				required: false
			},
			...providerOwnershipEnabled ? { userId: {
				type: "string",
				required: false
			} } : {}
		} } },
		options
	};
};
//#endregion
export { scim };
