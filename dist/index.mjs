import { APIError, BetterAuthError, HIDE_METADATA, generateId } from "better-auth";
import { APIError as APIError$1, createAuthEndpoint, createAuthMiddleware, isAPIError } from "better-auth/api";
import { statusCodes } from "better-call";
import * as z from "zod";
import { getCurrentAdapter, runWithTransaction } from "@better-auth/core/context";
import { constantTimeEqual, generateRandomString } from "better-auth/crypto";
import { base64Url } from "@better-auth/utils/base64";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { createHMAC } from "@better-auth/utils/hmac";
//#region src/group-schemas.ts
const SCIM_GROUP_SCHEMA$1 = "urn:ietf:params:scim:schemas:core:2.0:Group";
/**
* Attribute-less Group marker sent by Microsoft's classic Entra provisioning
* client. It is an input compatibility token, not a SCIM extension schema.
*/
const SCIM_MICROSOFT_ENTRA_LEGACY_GROUP_SCHEMA = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";
/** Maximum number of direct User members in one canonical SCIM Group. */
const SCIM_MAX_GROUP_MEMBERS = 1e3;
const groupMemberSchema = z.object({
	value: z.string().min(1),
	type: z.string().refine((type) => type.toLowerCase() === "user").optional()
});
const APIGroupSchema$1 = z.object({
	schemas: z.array(z.literal(SCIM_GROUP_SCHEMA$1)).length(1, "schemas must contain only the core SCIM Group schema"),
	externalId: z.string().min(1).optional(),
	displayName: z.string().trim().min(1),
	members: z.array(groupMemberSchema).max(SCIM_MAX_GROUP_MEMBERS).optional()
});
/**
* Remove the exact classic Entra Group marker from an enabled POST request.
* Marker attributes and duplicate marker declarations are always rejected.
*/
function normalizeMicrosoftEntraGroupSchema(body, enabled) {
	if (typeof body !== "object" || body === null || Array.isArray(body)) return {
		ok: true,
		body
	};
	if (Object.hasOwn(body, SCIM_MICROSOFT_ENTRA_LEGACY_GROUP_SCHEMA)) return {
		ok: false,
		detail: "The Microsoft Entra Group compatibility schema cannot contain attributes"
	};
	const schemas = Reflect.get(body, "schemas");
	if (!Array.isArray(schemas)) return {
		ok: true,
		body
	};
	const markerCount = schemas.filter((schema) => schema === SCIM_MICROSOFT_ENTRA_LEGACY_GROUP_SCHEMA).length;
	if (markerCount === 0 || !enabled) return {
		ok: true,
		body
	};
	if (markerCount !== 1) return {
		ok: false,
		detail: "The Microsoft Entra Group compatibility schema must not be duplicated"
	};
	return {
		ok: true,
		body: {
			...body,
			schemas: schemas.filter((schema) => schema !== SCIM_MICROSOFT_ENTRA_LEGACY_GROUP_SCHEMA)
		}
	};
}
const OpenAPIGroupResourceSchema$1 = {
	type: "object",
	properties: {
		id: { type: "string" },
		externalId: { type: "string" },
		displayName: { type: "string" },
		members: {
			type: "array",
			maxItems: SCIM_MAX_GROUP_MEMBERS,
			items: {
				type: "object",
				properties: {
					value: { type: "string" },
					$ref: { type: "string" },
					display: { type: "string" },
					type: {
						type: "string",
						enum: ["User"]
					}
				}
			}
		},
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
		schemas: {
			type: "array",
			items: { type: "string" }
		}
	},
	required: ["schemas", "id"]
};
const SCIMGroupResourceSchema = {
	id: "urn:ietf:params:scim:schemas:core:2.0:Group",
	schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
	name: "Group",
	description: "Group",
	attributes: [{
		name: "displayName",
		type: "string",
		multiValued: false,
		description: "A human-readable name for the Group.",
		required: true,
		caseExact: false,
		mutability: "readWrite",
		returned: "default",
		uniqueness: "server"
	}, {
		name: "members",
		type: "complex",
		multiValued: true,
		description: "A list of members of the Group.",
		required: false,
		mutability: "readWrite",
		returned: "default",
		uniqueness: "none",
		subAttributes: [
			{
				name: "value",
				type: "string",
				multiValued: false,
				description: "Identifier of the member of this Group.",
				required: true,
				caseExact: false,
				mutability: "immutable",
				returned: "default",
				uniqueness: "none"
			},
			{
				name: "$ref",
				type: "reference",
				referenceTypes: ["User"],
				multiValued: false,
				description: "The URI corresponding to a SCIM member resource.",
				required: false,
				caseExact: false,
				mutability: "immutable",
				returned: "default",
				uniqueness: "none"
			},
			{
				name: "display",
				type: "string",
				multiValued: false,
				description: "A human-readable name for the member.",
				required: false,
				caseExact: false,
				mutability: "readOnly",
				returned: "default",
				uniqueness: "none"
			},
			{
				name: "type",
				type: "string",
				multiValued: false,
				description: "A label indicating the member resource type.",
				required: false,
				caseExact: false,
				canonicalValues: ["User"],
				mutability: "immutable",
				returned: "default",
				uniqueness: "none"
			}
		]
	}],
	meta: {
		resourceType: "Schema",
		location: "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"
	}
};
const SCIMGroupResourceType = {
	schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
	id: "Group",
	name: "Group",
	endpoint: "/Groups",
	description: "Group",
	schema: "urn:ietf:params:scim:schemas:core:2.0:Group",
	meta: {
		resourceType: "ResourceType",
		location: "/scim/v2/ResourceTypes/Group"
	}
};
//#endregion
//#region src/user-email.ts
/** Create a case-insensitive identity for one complex email value. */
function createSCIMEmailTupleKey(email) {
	return JSON.stringify([email.type?.trim().toLowerCase() ?? null, email.value.trim().toLowerCase()]);
}
/** Serialize the 1.7 compatibility mirror for canonical email values. */
function serializeSCIMEmails(emails) {
	return JSON.stringify(emails);
}
//#endregion
//#region src/user-schemas.ts
const SCIM_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema";
const SCIM_RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
/** Standard SCIM core User schema URI. */
const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
/** Standard SCIM Enterprise User extension schema URI. */
const SCIM_ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const SCIM_MAX_MULTI_VALUE_COUNT = 20;
const SCIM_MAX_STRUCTURED_VALUE_COUNT = 10;
const scimStringSchema = z.string().trim().min(1).max(256);
const scimLongStringSchema = z.string().trim().min(1).max(1024);
const scimReferenceSchema = z.string().trim().min(1).max(2048);
const scimEmailValueSchema$1 = z.email().max(254);
/**
* Unwrap a single-element array before validation. Microsoft Entra sometimes
* wraps a single-valued attribute's PATCH replace value in an array.
*/
function scimSingleValueScalar(schema) {
	return z.preprocess((value) => Array.isArray(value) && value.length === 1 ? value[0] : value, schema);
}
function atMostOnePrimary(values) {
	return values.filter((value) => value.primary).length <= 1;
}
function primaryRefinement() {
	return (values) => atMostOnePrimary(values);
}
/**
* Whether every defined complex-value type occurs at most once,
* case-insensitively. Untyped values do not participate in this constraint.
*/
function hasUniqueSCIMDefinedTypes(values) {
	const definedTypes = values.flatMap((value) => value.type === void 0 ? [] : [value.type.trim().toLowerCase()]);
	return new Set(definedTypes).size === definedTypes.length;
}
const scimNameSchema = z.object({
	formatted: scimLongStringSchema.optional(),
	givenName: scimStringSchema.optional(),
	familyName: scimStringSchema.optional(),
	middleName: scimStringSchema.optional(),
	honorificPrefix: scimStringSchema.optional(),
	honorificSuffix: scimStringSchema.optional()
});
const scimCanonicalNameSchema = scimNameSchema.extend({ formatted: scimLongStringSchema });
const scimEmailSchema = z.object({
	value: scimEmailValueSchema$1,
	primary: z.boolean().optional(),
	type: scimStringSchema.transform((type) => type.toLowerCase()).optional()
});
const scimCanonicalEmailSchema = scimEmailSchema.extend({ primary: z.boolean() });
const scimPhoneNumberSchema = z.object({
	value: scimLongStringSchema,
	type: scimStringSchema.transform((type) => type.toLowerCase()).optional(),
	primary: z.boolean().optional()
});
const scimAddressSchema = z.object({
	formatted: scimLongStringSchema.optional(),
	streetAddress: scimLongStringSchema.optional(),
	locality: scimStringSchema.optional(),
	region: scimStringSchema.optional(),
	postalCode: scimStringSchema.optional(),
	country: scimStringSchema.optional(),
	type: scimStringSchema.transform((type) => type.toLowerCase()).optional(),
	primary: z.boolean().optional()
}).refine((address) => Object.entries(address).some(([attribute, value]) => attribute !== "primary" && attribute !== "type" && value !== void 0), { message: "addresses must contain at least one address value" });
const scimRoleSchema = z.object({
	value: scimLongStringSchema,
	display: scimLongStringSchema.optional(),
	type: scimStringSchema.transform((type) => type.toLowerCase()).optional(),
	primary: z.boolean().optional()
});
const scimEntitlementSchema = scimRoleSchema;
const scimCanonicalManagerSchema = z.object({
	value: scimStringSchema.optional(),
	$ref: scimReferenceSchema.optional()
}).refine((manager) => manager.value !== void 0 || manager.$ref !== void 0, { message: "manager must contain value or $ref" }).transform((manager) => {
	if (manager.value !== void 0) return {
		value: manager.value,
		...manager.$ref === void 0 ? {} : { $ref: manager.$ref }
	};
	if (manager.$ref !== void 0) return { $ref: manager.$ref };
	throw new Error("Validated manager is missing value and $ref");
});
const scimManagerInputObjectSchema = z.object({
	value: scimStringSchema.optional(),
	$ref: scimReferenceSchema.optional(),
	displayName: scimLongStringSchema.optional()
});
const scimManagerInputSchema = z.union([
	scimStringSchema,
	scimManagerInputObjectSchema,
	z.array(scimManagerInputObjectSchema).length(1)
]).transform((manager) => {
	if (typeof manager === "string") return { value: manager };
	const candidate = Array.isArray(manager) ? manager[0] : manager;
	if (!candidate) return void 0;
	const { value, $ref } = candidate;
	if (value !== void 0) return {
		value,
		...$ref === void 0 ? {} : { $ref }
	};
	if ($ref !== void 0) return { $ref };
});
const scimEnterpriseUserAttributeShape = {
	employeeNumber: scimSingleValueScalar(scimStringSchema).optional(),
	costCenter: scimSingleValueScalar(scimStringSchema).optional(),
	organization: scimSingleValueScalar(scimLongStringSchema).optional(),
	division: scimSingleValueScalar(scimLongStringSchema).optional(),
	department: scimSingleValueScalar(scimLongStringSchema).optional()
};
const SCIMEnterpriseUserInputSchema = z.object({
	...scimEnterpriseUserAttributeShape,
	manager: scimManagerInputSchema.optional()
}).transform(({ manager, ...enterprise }) => ({
	...enterprise,
	...manager === void 0 ? {} : { manager }
}));
const SCIMEnterpriseUserCanonicalSchema = z.object({
	...scimEnterpriseUserAttributeShape,
	manager: scimCanonicalManagerSchema.optional()
});
function stringAttribute(name, description, options = {}) {
	return {
		name,
		type: "string",
		multiValued: false,
		description,
		required: options.required ?? false,
		caseExact: false,
		mutability: options.mutability ?? "readWrite",
		returned: "default",
		uniqueness: options.uniqueness ?? "none"
	};
}
function typeSubAttribute() {
	return { ...stringAttribute("type", "A label indicating the attribute's function.") };
}
function primarySubAttribute() {
	return {
		name: "primary",
		type: "boolean",
		multiValued: false,
		description: "Whether this is the primary value for the attribute.",
		required: false,
		mutability: "readWrite",
		returned: "default"
	};
}
function multiValuedAttribute(name, description, subAttributes) {
	return {
		name,
		type: "complex",
		multiValued: true,
		description,
		required: false,
		subAttributes,
		mutability: "readWrite",
		returned: "default",
		uniqueness: "none"
	};
}
const SCIMUserResourceSchema = {
	id: SCIM_USER_SCHEMA,
	schemas: [SCIM_SCHEMA_SCHEMA],
	name: "User",
	description: "User Account",
	attributes: [
		stringAttribute("userName", "Unique identifier for the User within its provisioning connection.", {
			required: true,
			uniqueness: "server"
		}),
		stringAttribute("displayName", "The name of the User, suitable for display to end-users."),
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
			description: "The components of the User's real name.",
			required: false,
			subAttributes: [
				stringAttribute("formatted", "The complete formatted name."),
				stringAttribute("givenName", "The given name of the User."),
				stringAttribute("familyName", "The family name of the User."),
				stringAttribute("middleName", "The middle name of the User."),
				stringAttribute("honorificPrefix", "The honorific prefix of the User."),
				stringAttribute("honorificSuffix", "The honorific suffix of the User.")
			],
			mutability: "readWrite",
			returned: "default",
			uniqueness: "none"
		},
		multiValuedAttribute("emails", "Email addresses for the User.", [
			stringAttribute("value", "Email address for the User.", { required: true }),
			typeSubAttribute(),
			primarySubAttribute()
		]),
		stringAttribute("title", "The User's title."),
		stringAttribute("userType", "The User's relationship to the organization."),
		stringAttribute("preferredLanguage", "The User's preferred written or spoken language."),
		stringAttribute("locale", "The User's default location."),
		stringAttribute("timezone", "The User's time zone."),
		multiValuedAttribute("phoneNumbers", "Phone numbers for the User.", [
			stringAttribute("value", "Phone number for the User.", { required: true }),
			typeSubAttribute(),
			primarySubAttribute()
		]),
		multiValuedAttribute("addresses", "Postal addresses for the User.", [
			stringAttribute("formatted", "The complete formatted address."),
			stringAttribute("streetAddress", "The full street address."),
			stringAttribute("locality", "The city or locality."),
			stringAttribute("region", "The state or region."),
			stringAttribute("postalCode", "The postal code."),
			stringAttribute("country", "The country."),
			typeSubAttribute(),
			primarySubAttribute()
		]),
		multiValuedAttribute("roles", "Roles for the User.", [
			stringAttribute("value", "The role value.", { required: true }),
			stringAttribute("display", "A human-readable role name."),
			typeSubAttribute(),
			primarySubAttribute()
		]),
		multiValuedAttribute("entitlements", "Entitlements for the User.", [
			stringAttribute("value", "The entitlement value.", { required: true }),
			stringAttribute("display", "A human-readable entitlement name."),
			typeSubAttribute(),
			primarySubAttribute()
		])
	],
	meta: {
		resourceType: "Schema",
		location: `/scim/v2/Schemas/${SCIM_USER_SCHEMA}`
	}
};
const SCIMEnterpriseUserResourceSchema = {
	id: SCIM_ENTERPRISE_USER_SCHEMA,
	schemas: [SCIM_SCHEMA_SCHEMA],
	name: "EnterpriseUser",
	description: "Enterprise User",
	attributes: [
		stringAttribute("employeeNumber", "A number assigned to the User."),
		stringAttribute("costCenter", "The User's cost center."),
		stringAttribute("organization", "The User's organization."),
		stringAttribute("division", "The User's division."),
		stringAttribute("department", "The User's department."),
		{
			name: "manager",
			type: "complex",
			multiValued: false,
			description: "The User's manager.",
			required: false,
			subAttributes: [
				stringAttribute("value", "The manager's identifier.", { required: false }),
				{
					name: "$ref",
					type: "reference",
					referenceTypes: ["User"],
					multiValued: false,
					description: "The URI of the manager's SCIM User resource.",
					required: false,
					caseExact: false,
					mutability: "readWrite",
					returned: "default",
					uniqueness: "none"
				},
				stringAttribute("displayName", "The manager's display name.", { mutability: "readOnly" })
			],
			mutability: "readWrite",
			returned: "default",
			uniqueness: "none"
		}
	],
	meta: {
		resourceType: "Schema",
		location: `/scim/v2/Schemas/${SCIM_ENTERPRISE_USER_SCHEMA}`
	}
};
/**
* Complete protocol and storage behavior for the standard Enterprise User
* extension.
*/
const SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR = {
	kind: "extension",
	id: SCIM_ENTERPRISE_USER_SCHEMA,
	required: false,
	inputPathAliases: [{
		path: "manager",
		relativePath: "manager"
	}],
	inputSchema: SCIMEnterpriseUserInputSchema,
	canonicalSchema: SCIMEnterpriseUserCanonicalSchema,
	canonicalAttribute: "enterprise",
	responseAttribute: SCIM_ENTERPRISE_USER_SCHEMA,
	discoverySchema: SCIMEnterpriseUserResourceSchema,
	openAPISchema: {
		type: "object",
		properties: {
			employeeNumber: {
				type: "string",
				maxLength: 256
			},
			costCenter: {
				type: "string",
				maxLength: 256
			},
			organization: {
				type: "string",
				maxLength: 1024
			},
			division: {
				type: "string",
				maxLength: 1024
			},
			department: {
				type: "string",
				maxLength: 1024
			},
			manager: {
				type: "object",
				properties: {
					value: {
						type: "string",
						maxLength: 256
					},
					$ref: {
						type: "string",
						maxLength: 2048
					}
				}
			}
		}
	}
};
const SCIM_CORE_USER_SCHEMA_DESCRIPTOR = {
	kind: "core",
	id: SCIM_USER_SCHEMA,
	required: true,
	discoverySchema: SCIMUserResourceSchema
};
/**
* Ordered built-in schema descriptors for the SCIM User resource.
*
* Validation, discovery, ResourceType metadata, OpenAPI, persistence, and
* response serialization consume these descriptors.
*/
const SCIM_USER_SCHEMA_DESCRIPTORS = [SCIM_CORE_USER_SCHEMA_DESCRIPTOR, SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR];
const supportedUserSchemaIds = new Set(SCIM_USER_SCHEMA_DESCRIPTORS.map((descriptor) => descriptor.id));
const scimUserSchemasSchema = z.array(z.string()).min(1).max(SCIM_USER_SCHEMA_DESCRIPTORS.length).superRefine((schemas, context) => {
	for (const schema of schemas) {
		if (!supportedUserSchemaIds.has(schema)) context.addIssue({
			code: "custom",
			message: `Unsupported SCIM User schema ${schema}`
		});
		if (schemas.indexOf(schema) !== schemas.lastIndexOf(schema)) context.addIssue({
			code: "custom",
			message: `SCIM User schema ${schema} must not be duplicated`
		});
	}
	for (const descriptor of SCIM_USER_SCHEMA_DESCRIPTORS) if (descriptor.required && !schemas.includes(descriptor.id)) context.addIssue({
		code: "custom",
		message: `schemas must contain ${descriptor.id}`
	});
}).transform((schemas) => SCIM_USER_SCHEMA_DESCRIPTORS.filter((descriptor) => schemas.includes(descriptor.id)).map((descriptor) => descriptor.id));
function validateEnterpriseDeclaration(user, context) {
	if (user.enterprise !== void 0 && !user.schemas.includes(SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.id)) context.addIssue({
		code: "custom",
		path: ["schemas"],
		message: `The Enterprise User extension requires ${SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.id} in schemas`
	});
}
const APIUserSchema$1 = z.object({
	schemas: scimUserSchemasSchema,
	userName: z.string().trim().min(1).max(512),
	externalId: scimLongStringSchema.optional(),
	displayName: scimLongStringSchema.optional(),
	name: scimNameSchema.optional(),
	emails: z.array(scimEmailSchema).max(SCIM_MAX_MULTI_VALUE_COUNT).refine(primaryRefinement(), { message: "emails cannot contain multiple primary values" }).refine((emails) => new Set(emails.map(createSCIMEmailTupleKey)).size === emails.length, { message: "emails cannot contain duplicate type and value pairs" }).refine(hasUniqueSCIMDefinedTypes, { message: "emails cannot contain duplicate defined types" }).optional(),
	title: scimSingleValueScalar(scimLongStringSchema).optional(),
	userType: scimSingleValueScalar(scimStringSchema).optional(),
	preferredLanguage: scimSingleValueScalar(scimStringSchema).optional(),
	locale: scimSingleValueScalar(scimStringSchema).optional(),
	timezone: scimSingleValueScalar(scimStringSchema).optional(),
	phoneNumbers: z.array(scimPhoneNumberSchema).max(SCIM_MAX_STRUCTURED_VALUE_COUNT).refine(primaryRefinement(), { message: "phoneNumbers cannot contain multiple primary values" }).refine(hasUniqueSCIMDefinedTypes, { message: "phoneNumbers cannot contain duplicate defined types" }).optional(),
	addresses: z.array(scimAddressSchema).max(SCIM_MAX_STRUCTURED_VALUE_COUNT).refine(primaryRefinement(), { message: "addresses cannot contain multiple primary values" }).refine(hasUniqueSCIMDefinedTypes, { message: "addresses cannot contain duplicate defined types" }).optional(),
	roles: z.array(scimRoleSchema).max(SCIM_MAX_STRUCTURED_VALUE_COUNT).refine(primaryRefinement(), { message: "roles cannot contain multiple primary values" }).refine(hasUniqueSCIMDefinedTypes, { message: "roles cannot contain duplicate defined types" }).optional(),
	entitlements: z.array(scimEntitlementSchema).max(SCIM_MAX_STRUCTURED_VALUE_COUNT).refine(primaryRefinement(), { message: "entitlements cannot contain multiple primary values" }).refine(hasUniqueSCIMDefinedTypes, { message: "entitlements cannot contain duplicate defined types" }).optional(),
	active: z.boolean().optional(),
	[SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.id]: SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.inputSchema.optional()
}).superRefine((user, context) => {
	if ((user.emails === void 0 || user.emails.length === 0) && !scimEmailValueSchema$1.safeParse(user.userName).success) context.addIssue({
		code: "custom",
		path: ["emails"],
		message: "emails must contain an email when userName is not an email address"
	});
	validateEnterpriseDeclaration({
		schemas: user.schemas,
		enterprise: user[SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.id]
	}, context);
	if (JSON.stringify(user).length > 65535) context.addIssue({
		code: "custom",
		message: "SCIM User attributes exceed the supported serialized size"
	});
});
const SCIMCanonicalUserAttributesSchema = z.object({
	schemas: scimUserSchemasSchema,
	name: scimCanonicalNameSchema,
	emails: z.array(scimCanonicalEmailSchema).min(1).max(SCIM_MAX_MULTI_VALUE_COUNT).refine((emails) => emails.filter((email) => email.primary).length === 1, { message: "stored emails must contain exactly one primary value" }).refine((emails) => new Set(emails.map(createSCIMEmailTupleKey)).size === emails.length, { message: "stored emails must contain unique type and value pairs" }).refine(hasUniqueSCIMDefinedTypes, { message: "stored emails must contain unique defined types" }),
	title: scimLongStringSchema.optional(),
	userType: scimStringSchema.optional(),
	preferredLanguage: scimStringSchema.optional(),
	locale: scimStringSchema.optional(),
	timezone: scimStringSchema.optional(),
	phoneNumbers: z.array(scimPhoneNumberSchema).max(SCIM_MAX_STRUCTURED_VALUE_COUNT).refine(primaryRefinement()).refine(hasUniqueSCIMDefinedTypes).optional(),
	addresses: z.array(scimAddressSchema).max(SCIM_MAX_STRUCTURED_VALUE_COUNT).refine(primaryRefinement()).refine(hasUniqueSCIMDefinedTypes).optional(),
	roles: z.array(scimRoleSchema).max(SCIM_MAX_STRUCTURED_VALUE_COUNT).refine(primaryRefinement()).refine(hasUniqueSCIMDefinedTypes).optional(),
	entitlements: z.array(scimEntitlementSchema).max(SCIM_MAX_STRUCTURED_VALUE_COUNT).refine(primaryRefinement()).refine(hasUniqueSCIMDefinedTypes).optional(),
	[SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.canonicalAttribute]: SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.canonicalSchema.optional()
}).superRefine(validateEnterpriseDeclaration);
const complexMultiValueOpenAPISchema = {
	type: "array",
	maxItems: SCIM_MAX_STRUCTURED_VALUE_COUNT
};
const commonMultiValueProperties = {
	type: {
		type: "string",
		maxLength: 256
	},
	primary: { type: "boolean" }
};
const OpenAPIUserResourceSchema$1 = {
	type: "object",
	properties: {
		id: { type: "string" },
		externalId: {
			type: "string",
			maxLength: 1024
		},
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
		userName: {
			type: "string",
			maxLength: 512
		},
		name: {
			type: "object",
			properties: {
				formatted: {
					type: "string",
					maxLength: 1024
				},
				givenName: {
					type: "string",
					maxLength: 256
				},
				familyName: {
					type: "string",
					maxLength: 256
				},
				middleName: {
					type: "string",
					maxLength: 256
				},
				honorificPrefix: {
					type: "string",
					maxLength: 256
				},
				honorificSuffix: {
					type: "string",
					maxLength: 256
				}
			}
		},
		displayName: {
			type: "string",
			maxLength: 1024
		},
		title: {
			type: "string",
			maxLength: 1024
		},
		userType: {
			type: "string",
			maxLength: 256
		},
		preferredLanguage: {
			type: "string",
			maxLength: 256
		},
		locale: {
			type: "string",
			maxLength: 256
		},
		timezone: {
			type: "string",
			maxLength: 256
		},
		active: { type: "boolean" },
		emails: {
			type: "array",
			maxItems: SCIM_MAX_MULTI_VALUE_COUNT,
			items: {
				type: "object",
				properties: {
					value: {
						type: "string",
						format: "email",
						maxLength: 254
					},
					...commonMultiValueProperties
				}
			}
		},
		phoneNumbers: {
			...complexMultiValueOpenAPISchema,
			items: {
				type: "object",
				properties: {
					value: {
						type: "string",
						maxLength: 1024
					},
					...commonMultiValueProperties
				}
			}
		},
		addresses: {
			...complexMultiValueOpenAPISchema,
			items: {
				type: "object",
				properties: {
					formatted: {
						type: "string",
						maxLength: 1024
					},
					streetAddress: {
						type: "string",
						maxLength: 1024
					},
					locality: {
						type: "string",
						maxLength: 256
					},
					region: {
						type: "string",
						maxLength: 256
					},
					postalCode: {
						type: "string",
						maxLength: 256
					},
					country: {
						type: "string",
						maxLength: 256
					},
					...commonMultiValueProperties
				}
			}
		},
		roles: {
			...complexMultiValueOpenAPISchema,
			items: {
				type: "object",
				properties: {
					value: {
						type: "string",
						maxLength: 1024
					},
					display: {
						type: "string",
						maxLength: 1024
					},
					...commonMultiValueProperties
				}
			}
		},
		entitlements: {
			...complexMultiValueOpenAPISchema,
			items: {
				type: "object",
				properties: {
					value: {
						type: "string",
						maxLength: 1024
					},
					display: {
						type: "string",
						maxLength: 1024
					},
					...commonMultiValueProperties
				}
			}
		},
		[SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.responseAttribute]: SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.openAPISchema,
		schemas: {
			type: "array",
			maxItems: SCIM_USER_SCHEMA_DESCRIPTORS.length,
			items: {
				type: "string",
				enum: SCIM_USER_SCHEMA_DESCRIPTORS.map((descriptor) => descriptor.id)
			}
		}
	},
	required: ["schemas", "id"]
};
const SCIMUserResourceType = {
	schemas: [SCIM_RESOURCE_TYPE_SCHEMA],
	id: "User",
	name: "User",
	endpoint: "/Users",
	description: "User Account",
	schema: SCIM_CORE_USER_SCHEMA_DESCRIPTOR.id,
	schemaExtensions: SCIM_USER_SCHEMA_DESCRIPTORS.filter((descriptor) => !descriptor.required).map((descriptor) => ({
		schema: descriptor.id,
		required: descriptor.required
	})),
	meta: {
		resourceType: "ResourceType",
		location: "/scim/v2/ResourceTypes/User"
	}
};
//#endregion
//#region src/resource-schema-registry.ts
/**
* The supported SCIM resource contract.
*
* Protocol consumers use this registry instead of maintaining independent
* lists for validation, discovery, filtering, and response metadata.
*/
const SCIM_RESOURCE_SCHEMA_REGISTRY = {
	User: {
		type: "User",
		schemaId: SCIMUserResourceSchema.id,
		schemas: SCIM_USER_SCHEMA_DESCRIPTORS,
		inputSchema: APIUserSchema$1,
		openAPISchema: OpenAPIUserResourceSchema$1,
		discoverySchema: SCIMUserResourceSchema,
		resourceType: SCIMUserResourceType,
		filterAttributes: [
			"id",
			"userName",
			"externalId",
			"emails.value",
			"emails.work.value"
		]
	},
	Group: {
		type: "Group",
		schemaId: SCIMGroupResourceSchema.id,
		schemas: [{
			id: SCIMGroupResourceSchema.id,
			required: true,
			discoverySchema: SCIMGroupResourceSchema
		}],
		inputSchema: APIGroupSchema$1,
		openAPISchema: OpenAPIGroupResourceSchema$1,
		discoverySchema: SCIMGroupResourceSchema,
		resourceType: SCIMGroupResourceType,
		filterAttributes: [
			"id",
			"displayName",
			"externalId"
		]
	}
};
/** Ordered registry entries used by SCIM discovery collection endpoints. */
const SCIM_RESOURCE_SCHEMAS = [SCIM_RESOURCE_SCHEMA_REGISTRY.User, SCIM_RESOURCE_SCHEMA_REGISTRY.Group];
/** Ordered built-in schema descriptors advertised by SCIM discovery. */
const SCIM_DISCOVERY_SCHEMA_DESCRIPTORS = [...SCIM_RESOURCE_SCHEMA_REGISTRY.User.schemas, ...SCIM_RESOURCE_SCHEMA_REGISTRY.Group.schemas];
/** Return the case-insensitive prefix accepted on core attribute paths. */
function getSCIMCoreAttributePrefix(resourceType) {
	return `${SCIM_RESOURCE_SCHEMA_REGISTRY[resourceType].schemaId}:`;
}
/** Remove a core schema prefix from an attribute path, case-insensitively. */
function stripSCIMCoreAttributePrefix(resourceType, attributePath) {
	const prefix = getSCIMCoreAttributePrefix(resourceType);
	return attributePath.toLowerCase().startsWith(prefix.toLowerCase()) ? attributePath.slice(prefix.length) : attributePath;
}
/**
* Resolve a schema-qualified or explicitly supported input-alias path to the
* attribute path used on one side of the wire (response serialization or
* canonical persistence). Longest schema identifiers win because SCIM URNs
* contain colons. Shares the extension's `inputPathAliases` table between
* both sides so a provider-side bare sub-attribute name (Microsoft Entra
* sends `attributes=...,manager` rather than the schema-qualified path) also
* matches. `mapAttribute` selects which descriptor field names the target
* container (`responseAttribute` or `canonicalAttribute`) so the two sides
* cannot drift out of sync with each other.
*/
function resolveSCIMAttributePath(resourceType, attributePath, mapAttribute) {
	const descriptors = [...SCIM_RESOURCE_SCHEMA_REGISTRY[resourceType].schemas].sort((left, right) => right.id.length - left.id.length);
	const normalizedPath = attributePath.toLowerCase();
	for (const descriptor of descriptors) {
		const mappedAttribute = mapAttribute(descriptor);
		if ("inputPathAliases" in descriptor) for (const alias of descriptor.inputPathAliases) {
			const normalizedAlias = alias.path.toLowerCase();
			if (normalizedPath !== normalizedAlias && !normalizedPath.startsWith(`${normalizedAlias}.`)) continue;
			const suffix = attributePath.slice(alias.path.length);
			return mappedAttribute ? `${mappedAttribute}.${alias.relativePath}${suffix}` : `${alias.relativePath}${suffix}`;
		}
		const normalizedSchemaId = descriptor.id.toLowerCase();
		if (normalizedPath === normalizedSchemaId) return mappedAttribute ?? attributePath;
		const prefix = `${normalizedSchemaId}:`;
		if (!normalizedPath.startsWith(prefix)) continue;
		const relativePath = attributePath.slice(descriptor.id.length + 1);
		return mappedAttribute ? `${mappedAttribute}.${relativePath}` : relativePath;
	}
	return attributePath;
}
/** Resolve a schema-qualified or input-alias path to the response object's attribute path. */
function resolveSCIMResponseAttributePath(resourceType, attributePath) {
	return resolveSCIMAttributePath(resourceType, attributePath, (descriptor) => "responseAttribute" in descriptor ? descriptor.responseAttribute : void 0);
}
/** Resolve a schema-qualified or input-alias path to the canonical persistence attribute path. */
function resolveSCIMCanonicalAttributePath(resourceType, attributePath) {
	return resolveSCIMAttributePath(resourceType, attributePath, (descriptor) => "canonicalAttribute" in descriptor ? descriptor.canonicalAttribute : void 0);
}
//#endregion
//#region src/active-normalization.ts
function isRecord$4(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
/** Normalize the exact string Boolean forms accepted from SCIM providers. */
function normalizeSCIMStringBooleanValue(value) {
	if (typeof value !== "string") return value;
	const normalized = value.toLowerCase();
	if (normalized === "true") return true;
	if (normalized === "false") return false;
	return value;
}
function normalizeActiveProperty(value) {
	if (!Object.hasOwn(value, "active")) return value;
	const active = normalizeSCIMStringBooleanValue(value.active);
	return active === value.active ? value : {
		...value,
		active
	};
}
const SCIM_MULTI_VALUED_PRIMARY_ATTRIBUTES = [
	"emails",
	"phoneNumbers",
	"addresses",
	"roles",
	"entitlements"
];
function normalizeMultiValuedPrimaryEntry(entry) {
	if (!isRecord$4(entry) || !Object.hasOwn(entry, "primary")) return entry;
	const primary = normalizeSCIMStringBooleanValue(entry.primary);
	return primary === entry.primary ? entry : {
		...entry,
		primary
	};
}
function normalizeMultiValuedPrimaryValue(value) {
	if (!Array.isArray(value)) return normalizeMultiValuedPrimaryEntry(value);
	let changed = false;
	const normalized = value.map((entry) => {
		const result = normalizeMultiValuedPrimaryEntry(entry);
		if (result !== entry) changed = true;
		return result;
	});
	return changed ? normalized : value;
}
function normalizeResourceMultiValuedPrimaries(value) {
	const updates = {};
	for (const attribute of SCIM_MULTI_VALUED_PRIMARY_ATTRIBUTES) {
		if (!Object.hasOwn(value, attribute)) continue;
		const normalized = normalizeMultiValuedPrimaryValue(value[attribute]);
		if (normalized !== value[attribute]) updates[attribute] = normalized;
	}
	return Object.keys(updates).length === 0 ? value : {
		...value,
		...updates
	};
}
function normalizeUserResourceEntraCompatibility(value) {
	return normalizeResourceMultiValuedPrimaries(normalizeActiveProperty(value));
}
function isActivePath(path) {
	return typeof path === "string" && stripSCIMCoreAttributePrefix("User", path.trim()).toLowerCase() === "active";
}
const MULTI_VALUED_PRIMARY_PATH_PATTERN = /^(emails|phonenumbers|addresses|roles|entitlements)\s*(\[[^\]]*\])?(?:\s*\.\s*(primary))?$/i;
/**
* Matches a path targeting one of the multi-valued `primary` attributes,
* with or without a `[type eq "..."]` filter. `targetsPrimary` is true only
* when the path ends in `.primary`, in which case the operation value is the
* primary value itself rather than a container that holds it.
*/
function matchMultiValuedPrimaryPath(path) {
	if (typeof path !== "string") return null;
	const stripped = stripSCIMCoreAttributePrefix("User", path.trim());
	const match = MULTI_VALUED_PRIMARY_PATH_PATTERN.exec(stripped);
	return match ? { targetsPrimary: Boolean(match[3]) } : null;
}
function isPathless(path) {
	return path === void 0 || typeof path === "string" && path.trim().length === 0;
}
function normalizePatchOperation(operation) {
	if (!isRecord$4(operation)) return operation;
	if (isActivePath(operation.path)) {
		const value = normalizeSCIMStringBooleanValue(operation.value);
		return value === operation.value ? operation : {
			...operation,
			value
		};
	}
	const primaryMatch = matchMultiValuedPrimaryPath(operation.path);
	if (primaryMatch) {
		const value = primaryMatch.targetsPrimary ? normalizeSCIMStringBooleanValue(operation.value) : normalizeMultiValuedPrimaryValue(operation.value);
		return value === operation.value ? operation : {
			...operation,
			value
		};
	}
	if (isPathless(operation.path) && isRecord$4(operation.value)) {
		const value = normalizeUserResourceEntraCompatibility(operation.value);
		return value === operation.value ? operation : {
			...operation,
			value
		};
	}
	return operation;
}
/**
* Normalize provider-compatible User `active` and multi-valued `primary`
* string Boolean values (Microsoft Entra) without widening the endpoint
* schemas or mutating the parsed request body.
*/
function normalizeSCIMUserEntraCompatibilityRequestBody(method, body) {
	if (!isRecord$4(body)) return body;
	if (method === "POST" || method === "PUT") return normalizeUserResourceEntraCompatibility(body);
	if (method !== "PATCH" || !Array.isArray(body.Operations)) return body;
	let changed = false;
	const operations = body.Operations.map((operation) => {
		const normalized = normalizePatchOperation(operation);
		if (normalized !== operation) changed = true;
		return normalized;
	});
	return changed ? {
		...body,
		Operations: operations
	} : body;
}
//#endregion
//#region src/resource-key.ts
/** Create a fixed-size key that preserves tuple and connection boundaries. */
function createScopedKey(parts) {
	return base64Url.encode(sha256(utf8ToBytes(JSON.stringify(parts))), { padding: false });
}
/** Create the canonical lookup key for a connection-owned SCIM User externalId. */
function createSCIMUserExternalIdKey(connectionId, externalId) {
	return createScopedKey([
		"scim-user-external-id",
		connectionId,
		externalId
	]);
}
/** Create one unique, lexicographically stable classic-pagination key. */
function createSCIMOrderKey(createdAt) {
	return `${createdAt.getTime().toString().padStart(15, "0")}:${generateId(16)}`;
}
//#endregion
//#region src/scim-metadata.ts
const SCIM_MEDIA_TYPE = "application/scim+json";
const SCIM_REQUEST_MEDIA_TYPES = ["application/json", SCIM_MEDIA_TYPE];
/** Keep endpoint metadata out of the public endpoint input and output types. */
function defineSCIMEndpointMetadata(metadata) {
	return metadata;
}
/**
* Builds OpenAPI response content for the SCIM media type.
*
* Better Call's endpoint metadata names its built-in media types explicitly.
* Returning a content map keeps SCIM's registered media type visible to the
* OpenAPI generator without widening endpoint metadata or response inference.
*/
function createSCIMOpenAPIContent(schema) {
	return { [SCIM_MEDIA_TYPE]: { schema } };
}
/** Resolve one SCIM resource path against the configured Better Auth URL. */
function getResourceURL(path, baseURL) {
	const normalizedBaseURL = baseURL.endsWith("/") ? baseURL : `${baseURL}/`;
	const normalizedPath = path.replace(/^\/+/, "");
	return new URL(normalizedPath, normalizedBaseURL).toString();
}
const MetadataFieldSupportOpenAPISchema = {
	type: "object",
	properties: { supported: { type: "boolean" } },
	required: ["supported"]
};
const ServiceProviderOpenAPISchema = {
	type: "object",
	properties: {
		patch: MetadataFieldSupportOpenAPISchema,
		bulk: {
			type: "object",
			properties: {
				...MetadataFieldSupportOpenAPISchema.properties,
				maxOperations: { type: "integer" },
				maxPayloadSize: { type: "integer" }
			},
			required: [
				"supported",
				"maxOperations",
				"maxPayloadSize"
			]
		},
		filter: {
			type: "object",
			properties: {
				...MetadataFieldSupportOpenAPISchema.properties,
				maxResults: { type: "integer" }
			},
			required: ["supported", "maxResults"]
		},
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
					documentationUri: { type: "string" },
					type: { type: "string" },
					primary: { type: "boolean" }
				},
				required: [
					"type",
					"name",
					"description"
				]
			}
		},
		schemas: {
			type: "array",
			items: { type: "string" }
		},
		meta: {
			type: "object",
			properties: {
				resourceType: { type: "string" },
				location: { type: "string" }
			}
		}
	},
	required: [
		"schemas",
		"patch",
		"bulk",
		"filter",
		"changePassword",
		"sort",
		"etag",
		"authenticationSchemes"
	]
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
		schemaExtensions: {
			type: "array",
			items: {
				type: "object",
				properties: {
					schema: { type: "string" },
					required: { type: "boolean" }
				},
				required: ["schema", "required"]
			}
		},
		meta: {
			type: "object",
			properties: {
				resourceType: { type: "string" },
				location: { type: "string" }
			}
		}
	},
	required: [
		"schemas",
		"name",
		"endpoint",
		"schema"
	]
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
		uniqueness: { type: "string" },
		canonicalValues: {
			type: "array",
			items: { type: "string" }
		},
		referenceTypes: {
			type: "array",
			items: { type: "string" }
		}
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
	},
	required: [
		"schemas",
		"id",
		"attributes"
	]
};
//#endregion
//#region src/scim-error.ts
const SCIM_ERROR_SCHEMA$1 = "urn:ietf:params:scim:api:messages:2.0:Error";
/**
* Create a SCIM-compliant API error.
*
* See: https://datatracker.ietf.org/doc/html/rfc7644#section-3.12
*/
function createSCIMError(status = "INTERNAL_SERVER_ERROR", options = {}) {
	const error = new APIError(status, {
		schemas: [SCIM_ERROR_SCHEMA$1],
		status: (typeof status === "number" ? status : statusCodes[status]).toString(),
		...options.detail !== void 0 ? { detail: options.detail } : {},
		...options.scimType !== void 0 ? { scimType: options.scimType } : {}
	});
	if (options.detail !== void 0) error.message = options.detail;
	return error;
}
/**
* Keeps application-owned SCIM extension failures inside the SCIM error
* contract while preserving the original exception as a non-response cause.
*/
async function runSCIMApplicationCallback(callback, detail) {
	try {
		return await callback();
	} catch (error) {
		if (isAPIError(error)) throw error;
		const scimError = createSCIMError("INTERNAL_SERVER_ERROR", { detail });
		Object.defineProperty(scimError, "cause", {
			configurable: true,
			value: error
		});
		throw scimError;
	}
}
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
	},
	required: ["schemas", "status"]
};
const SCIMErrorOpenAPISchemas = {
	"400": {
		description: "Bad Request. Usually due to missing parameters, or invalid parameters",
		content: createSCIMOpenAPIContent(SCIMErrorOpenAPISchema)
	},
	"401": {
		description: "Unauthorized. Due to missing or invalid authentication.",
		content: createSCIMOpenAPIContent(SCIMErrorOpenAPISchema)
	},
	"403": {
		description: "Forbidden. The authenticated principal lacks permission.",
		content: createSCIMOpenAPIContent(SCIMErrorOpenAPISchema)
	},
	"404": {
		description: "Not Found. The requested resource was not found.",
		content: createSCIMOpenAPIContent(SCIMErrorOpenAPISchema)
	},
	"409": {
		description: "Conflict. A resource uniqueness constraint was violated.",
		content: createSCIMOpenAPIContent(SCIMErrorOpenAPISchema)
	},
	"415": {
		description: "Unsupported Media Type.",
		content: createSCIMOpenAPIContent(SCIMErrorOpenAPISchema)
	},
	"429": {
		description: "Too Many Requests. You have exceeded the rate limit. Try again later.",
		content: createSCIMOpenAPIContent(SCIMErrorOpenAPISchema)
	},
	"500": {
		description: "Internal Server Error. This is a problem with the server that you cannot fix.",
		content: createSCIMOpenAPIContent(SCIMErrorOpenAPISchema)
	}
};
//#endregion
//#region src/connection-state.ts
/** Creates the stable lookup key for a code-defined connection id. */
function createSCIMConnectionKey(connectionId) {
	return createScopedKey(["scim-connection", connectionId]);
}
/**
* Finds a connection's persisted binding, or creates it with the caller's
* initial lifecycle fields. Concurrent creators race on the unique
* connectionKey; the loser re-reads and validates the winner's row instead
* of failing.
*/
async function findOrCreateSCIMConnectionBinding(database, connectionId, provisioningDomainId, now, initialFields, assertBinding) {
	const connectionKey = createSCIMConnectionKey(connectionId);
	const findBinding = () => database.findOne({
		model: "scimConnectionBinding",
		where: [{
			field: "connectionKey",
			value: connectionKey
		}]
	});
	const existing = await findBinding();
	if (existing) {
		assertBinding(existing);
		return existing;
	}
	if (!provisioningDomainId) throw new BetterAuthError(`SCIM connection "${connectionId}" has no persisted binding.`);
	try {
		return await database.create({
			model: "scimConnectionBinding",
			data: {
				connectionId,
				connectionKey,
				provisioningDomainId,
				createdAt: now,
				decommissionReconciledUserCount: 0,
				decommissionBatchCount: 0,
				decommissionRevision: 0,
				...initialFields
			}
		});
	} catch (error) {
		const concurrentlyCreated = await findBinding();
		if (!concurrentlyCreated) throw error;
		assertBinding(concurrentlyCreated);
		return concurrentlyCreated;
	}
}
/** Finds connections that no longer participate in lifecycle or access state. */
async function findDecommissionedSCIMConnectionIds(database, connectionIds) {
	if (connectionIds.length === 0) return /* @__PURE__ */ new Set();
	const bindings = await database.findMany({
		model: "scimConnectionBinding",
		where: [{
			field: "connectionId",
			value: [...new Set(connectionIds)],
			operator: "in"
		}]
	});
	return new Set(bindings.filter((binding) => binding.decommissionStatus !== "active").map((binding) => binding.connectionId));
}
/**
* Fence a completed resource mutation against concurrent connection
* retirement. The atomic update orders decommission after this transaction,
* or fails the transaction when retirement won the race.
*/
async function fenceActiveSCIMConnection(database, connectionId) {
	const binding = await tryFenceActiveSCIMConnection(database, connectionId);
	if (binding) return binding;
	throw createSCIMError("UNAUTHORIZED", { detail: "SCIM connection is decommissioned" });
}
/** Attempts to fence a connection without assigning an HTTP failure policy. */
async function tryFenceActiveSCIMConnection(database, connectionId) {
	return database.incrementOne({
		model: "scimConnectionBinding",
		where: [
			{
				field: "connectionKey",
				value: createSCIMConnectionKey(connectionId)
			},
			{
				field: "connectionId",
				value: connectionId
			},
			{
				field: "decommissionStatus",
				value: "active"
			}
		],
		increment: { decommissionRevision: 1 }
	});
}
//#endregion
//#region src/projection.ts
const SCIM_PROJECTION_BATCH_SIZE = 50;
const SCIM_PROJECTION_SUBJECT_CONFLICT = Symbol("scim-projection-subject-conflict");
const reconcileProjectionBodySchema = z.object({ provisioningDomainId: z.string().trim().min(1).max(255) });
function normalizeMappedRoles(roles) {
	if (!roles) return [];
	const normalizedRoles = /* @__PURE__ */ new Set();
	for (const candidate of roles) {
		const role = candidate.trim();
		if (!role) continue;
		normalizedRoles.add(role);
	}
	return [...normalizedRoles];
}
function concurrentProjectionSubjectMutation() {
	const error = new BetterAuthError("The SCIM projection subject changed concurrently; retry the request.");
	error[SCIM_PROJECTION_SUBJECT_CONFLICT] = true;
	throw error;
}
/** Whether a complete-state projection must be retried in a fresh transaction. */
function isSCIMProjectionSubjectConflict(error) {
	return error instanceof BetterAuthError && SCIM_PROJECTION_SUBJECT_CONFLICT in error;
}
async function acquireProjectionSubjectLocks(database, provisioningDomainId, scimUserIds) {
	const affectedUserIds = /* @__PURE__ */ new Set();
	for (let offset = 0; offset < scimUserIds.length; offset += SCIM_PROJECTION_BATCH_SIZE) {
		const scimUsers = await database.findMany({
			model: "scimUser",
			where: [{
				field: "id",
				value: scimUserIds.slice(offset, offset + SCIM_PROJECTION_BATCH_SIZE),
				operator: "in"
			}, {
				field: "provisioningDomainId",
				value: provisioningDomainId
			}]
		});
		for (const scimUser of scimUsers) affectedUserIds.add(scimUser.userId);
	}
	const userIds = [...affectedUserIds].sort();
	if (userIds.length === 0) return;
	const subjectByUserId = /* @__PURE__ */ new Map();
	for (let offset = 0; offset < userIds.length; offset += SCIM_PROJECTION_BATCH_SIZE) {
		const subjects = await database.findMany({
			model: "scimSubject",
			where: [{
				field: "userId",
				value: userIds.slice(offset, offset + SCIM_PROJECTION_BATCH_SIZE),
				operator: "in"
			}]
		});
		for (const subject of subjects) subjectByUserId.set(subject.userId, subject);
	}
	if (subjectByUserId.size !== userIds.length) throw new BetterAuthError("A SCIM User selected for projection has no subject aggregate.");
	const updatedAt = /* @__PURE__ */ new Date();
	for (const userId of userIds) {
		const subject = subjectByUserId.get(userId);
		if (!subject) throw new BetterAuthError("A SCIM User selected for projection has no subject aggregate.");
		if (!await database.incrementOne({
			model: "scimSubject",
			where: [{
				field: "id",
				value: subject.id
			}, {
				field: "revision",
				value: subject.revision
			}],
			increment: { revision: 1 },
			set: { updatedAt }
		})) concurrentProjectionSubjectMutation();
	}
}
function createProjectionGrantKey(input) {
	return createScopedKey([
		"scim-projection-grant",
		input.connectionId,
		input.scimUserId,
		input.sourceKind,
		input.sourceId,
		input.role
	]);
}
async function buildDesiredGrants(options, database, input) {
	const roleProjection = options.projection?.roles;
	if (!roleProjection || input.activeSCIMUsers.length === 0) return [];
	const scimUserById = new Map(input.activeSCIMUsers.map((scimUser) => [scimUser.id, scimUser]));
	const memberships = input.memberships ?? await database.findMany({
		model: "scimGroupMember",
		where: [{
			field: "scimUserId",
			value: input.activeSCIMUsers.map((scimUser) => scimUser.id),
			operator: "in"
		}]
	});
	if (memberships.length === 0) return [];
	const groupById = input.groupById ?? new Map((await database.findMany({
		model: "scimGroup",
		where: [{
			field: "id",
			value: [...new Set(memberships.map((membership) => membership.groupId))],
			operator: "in"
		}]
	})).map((group) => [group.id, group]));
	const desiredGrants = /* @__PURE__ */ new Map();
	const roleExistenceByKey = /* @__PURE__ */ new Map();
	for (const membership of memberships) {
		const scimUser = scimUserById.get(membership.scimUserId);
		const group = groupById.get(membership.groupId);
		if (!scimUser || !group || group.connectionId !== scimUser.connectionId || group.provisioningDomainId !== input.provisioningDomainId) continue;
		const source = {
			type: "group",
			id: group.id,
			...group.externalId ? { externalId: group.externalId } : {},
			displayName: group.displayName
		};
		const mappedRoles = await runSCIMApplicationCallback(async () => normalizeMappedRoles(await roleProjection.map({
			connectionId: scimUser.connectionId,
			provisioningDomainId: input.provisioningDomainId,
			scimUserId: scimUser.id,
			userId: input.userId,
			source
		}, { database })), "SCIM role mapping failed");
		for (const role of mappedRoles) {
			const roleExistenceKey = createScopedKey([
				"scim-role-existence",
				scimUser.connectionId,
				input.provisioningDomainId,
				role
			]);
			let exists = roleExistenceByKey.get(roleExistenceKey);
			if (exists === void 0) {
				exists = await runSCIMApplicationCallback(() => roleProjection.exists({
					connectionId: scimUser.connectionId,
					provisioningDomainId: input.provisioningDomainId,
					role
				}, { database }), "SCIM role validation failed");
				roleExistenceByKey.set(roleExistenceKey, exists);
			}
			if (!exists) continue;
			const grantKey = createProjectionGrantKey({
				connectionId: scimUser.connectionId,
				scimUserId: scimUser.id,
				sourceKind: source.type,
				sourceId: source.id,
				role
			});
			desiredGrants.set(grantKey, {
				connectionId: scimUser.connectionId,
				provisioningDomainId: input.provisioningDomainId,
				scimUserId: scimUser.id,
				userId: input.userId,
				sourceKind: source.type,
				sourceId: source.id,
				sourceValue: source.externalId ?? source.displayName,
				source,
				role,
				grantKey
			});
		}
	}
	return [...desiredGrants.values()];
}
async function reconcileProjectionUserState(options, database, input) {
	const projection = options.projection;
	const activeSCIMUsers = input.sourcesSCIMUsers.filter((scimUser) => scimUser.active);
	const desiredGrants = await buildDesiredGrants(options, database, {
		provisioningDomainId: input.provisioningDomainId,
		userId: input.userId,
		activeSCIMUsers,
		memberships: input.memberships,
		groupById: input.groupById
	});
	const existingGrants = input.existingGrants ?? await database.findMany({
		model: "scimProjectionGrant",
		where: [{
			field: "provisioningDomainId",
			value: input.provisioningDomainId
		}, {
			field: "userId",
			value: input.userId
		}]
	});
	const desiredGrantByKey = new Map(desiredGrants.map((grant) => [grant.grantKey, grant]));
	const existingGrantByKey = new Map(existingGrants.map((grant) => [grant.grantKey, grant]));
	const removedGrantKeys = existingGrants.filter((grant) => !desiredGrantByKey.has(grant.grantKey)).map((grant) => grant.grantKey);
	if (removedGrantKeys.length > 0) await database.deleteMany({
		model: "scimProjectionGrant",
		where: [
			{
				field: "provisioningDomainId",
				value: input.provisioningDomainId
			},
			{
				field: "userId",
				value: input.userId
			},
			{
				field: "grantKey",
				value: removedGrantKeys,
				operator: "in"
			}
		]
	});
	const now = /* @__PURE__ */ new Date();
	for (const desiredGrant of desiredGrants) {
		if (existingGrantByKey.has(desiredGrant.grantKey)) continue;
		const { source: _source, ...grantRecord } = desiredGrant;
		await database.create({
			model: "scimProjectionGrant",
			data: {
				...grantRecord,
				createdAt: now,
				updatedAt: now
			}
		});
	}
	if (!projection) return;
	const grants = [...desiredGrants].sort((left, right) => left.grantKey.localeCompare(right.grantKey)).map((grant) => ({
		source: grant.source,
		role: grant.role
	}));
	const sources = input.sourcesSCIMUsers.map((scimUser) => ({
		id: scimUser.id,
		connectionId: scimUser.connectionId,
		provisioningDomainId: scimUser.provisioningDomainId,
		active: scimUser.active
	})).sort((left, right) => left.id.localeCompare(right.id));
	await runSCIMApplicationCallback(() => projection.reconcileUser({
		provisioningDomainId: input.provisioningDomainId,
		userId: input.userId,
		active: activeSCIMUsers.length > 0,
		sources,
		grants
	}, { database }), "SCIM projection reconciliation failed");
}
async function reconcileSCIMUserBatch(options, input) {
	if (input.scimUserIds.length === 0) return;
	const requestedSCIMUsers = await input.database.findMany({
		model: "scimUser",
		where: [{
			field: "id",
			value: [...input.scimUserIds],
			operator: "in"
		}, {
			field: "provisioningDomainId",
			value: input.provisioningDomainId
		}]
	});
	const requestedSCIMUserById = new Map(requestedSCIMUsers.map((scimUser) => [scimUser.id, scimUser]));
	const userIds = [];
	const seenUserIds = /* @__PURE__ */ new Set();
	for (const scimUserId of input.scimUserIds) {
		const userId = requestedSCIMUserById.get(scimUserId)?.userId;
		if (!userId || seenUserIds.has(userId)) continue;
		seenUserIds.add(userId);
		userIds.push(userId);
	}
	if (userIds.length === 0) return;
	const provisioningDomainSCIMUsers = await input.database.findMany({
		model: "scimUser",
		where: [{
			field: "userId",
			value: userIds,
			operator: "in"
		}, {
			field: "provisioningDomainId",
			value: input.provisioningDomainId
		}]
	});
	const connectionIds = [...new Set(provisioningDomainSCIMUsers.map((scimUser) => scimUser.connectionId))];
	const decommissionedConnectionIds = await findDecommissionedSCIMConnectionIds(input.database, connectionIds);
	const activeSCIMUserIds = provisioningDomainSCIMUsers.filter((scimUser) => !decommissionedConnectionIds.has(scimUser.connectionId)).filter((scimUser) => scimUser.active).map((scimUser) => scimUser.id);
	const memberships = options.projection?.roles && activeSCIMUserIds.length > 0 ? await input.database.findMany({
		model: "scimGroupMember",
		where: [{
			field: "scimUserId",
			value: activeSCIMUserIds,
			operator: "in"
		}]
	}) : [];
	const groupIds = [...new Set(memberships.map((membership) => membership.groupId))];
	const groups = groupIds.length === 0 ? [] : await input.database.findMany({
		model: "scimGroup",
		where: [{
			field: "id",
			value: groupIds,
			operator: "in"
		}]
	});
	const existingGrants = await input.database.findMany({
		model: "scimProjectionGrant",
		where: [{
			field: "provisioningDomainId",
			value: input.provisioningDomainId
		}, {
			field: "userId",
			value: userIds,
			operator: "in"
		}]
	});
	const scimUsersByUserId = /* @__PURE__ */ new Map();
	for (const scimUser of provisioningDomainSCIMUsers) {
		const userSCIMUsers = scimUsersByUserId.get(scimUser.userId) ?? [];
		userSCIMUsers.push(scimUser);
		scimUsersByUserId.set(scimUser.userId, userSCIMUsers);
	}
	const membershipsBySCIMUserId = /* @__PURE__ */ new Map();
	for (const membership of memberships) {
		const userMemberships = membershipsBySCIMUserId.get(membership.scimUserId) ?? [];
		userMemberships.push(membership);
		membershipsBySCIMUserId.set(membership.scimUserId, userMemberships);
	}
	const existingGrantsByUserId = /* @__PURE__ */ new Map();
	for (const grant of existingGrants) {
		const userGrants = existingGrantsByUserId.get(grant.userId) ?? [];
		userGrants.push(grant);
		existingGrantsByUserId.set(grant.userId, userGrants);
	}
	const groupById = new Map(groups.map((group) => [group.id, group]));
	for (const userId of userIds) {
		const userSources = (scimUsersByUserId.get(userId) ?? []).filter((scimUser) => !decommissionedConnectionIds.has(scimUser.connectionId));
		const userMemberships = userSources.filter((scimUser) => scimUser.active).flatMap((scimUser) => membershipsBySCIMUserId.get(scimUser.id) ?? []);
		await reconcileProjectionUserState(options, input.database, {
			provisioningDomainId: input.provisioningDomainId,
			userId,
			sourcesSCIMUsers: userSources,
			memberships: userMemberships,
			groupById,
			existingGrants: existingGrantsByUserId.get(userId) ?? []
		});
	}
}
/** Creates the transaction-bound projection orchestrator for one plugin. */
function createSCIMProjectionCoordinator(options) {
	return {
		async acquireUserLocks(input) {
			const scimUserIds = [...new Set(input.scimUserIds)];
			if (scimUserIds.length === 0) return;
			await acquireProjectionSubjectLocks(input.database, input.provisioningDomainId, scimUserIds);
		},
		async reconcileUser(input) {
			const subject = input.userId ? {
				id: input.scimUserId,
				userId: input.userId,
				provisioningDomainId: input.provisioningDomainId
			} : await input.database.findOne({
				model: "scimUser",
				where: [{
					field: "id",
					value: input.scimUserId
				}]
			});
			if (!subject) return;
			const provisioningDomainId = subject.provisioningDomainId;
			if (!provisioningDomainId) return;
			const scimUsers = await input.database.findMany({
				model: "scimUser",
				where: [{
					field: "userId",
					value: subject.userId
				}, {
					field: "provisioningDomainId",
					value: provisioningDomainId
				}]
			});
			const connectionIds = [...new Set(scimUsers.map((scimUser) => scimUser.connectionId))];
			const decommissionedConnectionIds = await findDecommissionedSCIMConnectionIds(input.database, connectionIds);
			const sourcesSCIMUsers = scimUsers.filter((scimUser) => !decommissionedConnectionIds.has(scimUser.connectionId));
			await reconcileProjectionUserState(options, input.database, {
				provisioningDomainId,
				userId: subject.userId,
				sourcesSCIMUsers
			});
		},
		async reconcileUsers(input) {
			const scimUserIds = [...new Set(input.scimUserIds)];
			if (scimUserIds.length === 0) return;
			if (!input.subjectLocksAcquired) await acquireProjectionSubjectLocks(input.database, input.provisioningDomainId, scimUserIds);
			for (let offset = 0; offset < scimUserIds.length; offset += SCIM_PROJECTION_BATCH_SIZE) await reconcileSCIMUserBatch(options, {
				...input,
				scimUserIds: scimUserIds.slice(offset, offset + SCIM_PROJECTION_BATCH_SIZE)
			});
		}
	};
}
function requireConfiguredProjection(options) {
	if (options.projection) return;
	throw new BetterAuthError("SCIM projection reconciliation requires projection.reconcileUser to be configured.");
}
async function findSCIMProjectionDomainBatch(input) {
	const candidates = await input.database.findMany({
		model: "scimUser",
		where: [{
			field: "provisioningDomainId",
			value: input.provisioningDomainId
		}, ...input.cursorUserId ? [{
			field: "userId",
			value: input.cursorUserId,
			operator: "gt"
		}] : []],
		limit: SCIM_PROJECTION_BATCH_SIZE + 1,
		sortBy: {
			field: "userId",
			direction: "asc"
		}
	});
	if (candidates.length === 0) return null;
	const rows = candidates.slice(0, SCIM_PROJECTION_BATCH_SIZE);
	const subjectByUserId = new Map(rows.map((scimUser) => [scimUser.userId, scimUser]));
	const cursorUserId = rows.at(-1)?.userId;
	if (!cursorUserId) return null;
	return {
		scimUserIds: [...subjectByUserId.values()].map((subject) => subject.id),
		userIds: [...subjectByUserId.keys()],
		cursorUserId,
		hasMore: candidates.length > SCIM_PROJECTION_BATCH_SIZE
	};
}
async function reconcileSCIMProjectionDomainBatch(input) {
	await input.projection.reconcileUsers({
		database: input.database,
		auth: input.auth,
		provisioningDomainId: input.provisioningDomainId,
		scimUserIds: input.batch.scimUserIds,
		subjectLocksAcquired: input.subjectLocksAcquired
	});
	if (!input.identity) return;
	const subjects = await input.database.findMany({
		model: "scimSubject",
		where: [{
			field: "userId",
			value: input.batch.userIds,
			operator: "in"
		}]
	});
	const aggregateByUserId = new Map(subjects.map((subject) => [subject.userId, subject]));
	for (const userId of input.batch.userIds) {
		const subject = aggregateByUserId.get(userId);
		if (!subject) continue;
		await input.identity.reconcileUser({
			database: input.database,
			auth: input.auth,
			subject
		});
	}
}
async function reconcileProjectionDomain(input) {
	let cursor;
	let reconciledUsers = 0;
	let batches = 0;
	while (true) {
		const batch = await findSCIMProjectionDomainBatch({
			database: input.database,
			provisioningDomainId: input.provisioningDomainId,
			cursorUserId: cursor
		});
		if (!batch) break;
		await runWithTransaction(input.database, async () => {
			await reconcileSCIMProjectionDomainBatch({
				database: await getCurrentAdapter(input.database),
				auth: input.auth,
				provisioningDomainId: input.provisioningDomainId,
				projection: input.projection,
				identity: input.identity,
				batch
			});
		});
		batches++;
		reconciledUsers += batch.userIds.length;
		cursor = batch.cursorUserId;
		if (!batch.hasMore) break;
	}
	return {
		provisioningDomainId: input.provisioningDomainId,
		reconciledUsers,
		batches
	};
}
/** Creates the trusted server API for replaying one provisioning domain. */
function createReconcileSCIMProjectionEndpoint(options, projection) {
	return createAuthEndpoint.serverOnly({
		method: "POST",
		body: reconcileProjectionBodySchema
	}, async (ctx) => {
		requireConfiguredProjection(options);
		const result = await reconcileProjectionDomain({
			database: ctx.context.adapter,
			auth: ctx.context,
			projection,
			provisioningDomainId: ctx.body.provisioningDomainId
		});
		return ctx.json(result);
	});
}
//#endregion
//#region src/connection-decommission.ts
const SCIM_DECOMMISSION_LEASE_DURATION_MS = 300 * 1e3;
const decommissionConnectionBodySchema = z.object({
	connectionId: z.string().trim().min(1).max(255),
	provisioningDomainId: z.string().trim().min(1).max(255).optional()
});
function createDecommissionResult(binding) {
	if (binding.decommissionStatus === "active") throw new BetterAuthError(`SCIM connection "${binding.connectionId}" has not started decommissioning.`);
	return {
		connectionId: binding.connectionId,
		provisioningDomainId: binding.provisioningDomainId,
		status: binding.decommissionStatus,
		decommissionedAt: binding.decommissionedAt ?? null,
		completedAt: binding.decommissionCompletedAt ?? null,
		retryAfter: binding.decommissionStatus === "reconciling" ? binding.decommissionLeaseExpiresAt ?? null : null,
		reconciledUsers: binding.decommissionReconciledUserCount,
		batches: binding.decommissionBatchCount
	};
}
function assertProvisioningDomainBinding(binding, provisioningDomainId) {
	if (binding.provisioningDomainId === provisioningDomainId) return;
	throw new BetterAuthError(`SCIM connection "${binding.connectionId}" is already bound to provisioning domain "${binding.provisioningDomainId}".`);
}
async function findOrCreateConnectionBinding(database, connectionId, provisioningDomainId) {
	const completedAt = /* @__PURE__ */ new Date();
	return findOrCreateSCIMConnectionBinding(database, connectionId, provisioningDomainId, completedAt, {
		decommissionStatus: "complete",
		decommissionedAt: completedAt,
		decommissionCompletedAt: completedAt
	}, (binding) => {
		if (provisioningDomainId) assertProvisioningDomainBinding(binding, provisioningDomainId);
	});
}
async function findConnectionBinding(database, connectionId) {
	const binding = await database.findOne({
		model: "scimConnectionBinding",
		where: [{
			field: "connectionKey",
			value: createSCIMConnectionKey(connectionId)
		}]
	});
	if (binding) return binding;
	throw new BetterAuthError(`SCIM connection "${connectionId}" has no persisted binding.`);
}
async function acquireDecommissionLease(database, connectionId, provisioningDomainId) {
	const currentDatabase = await getCurrentAdapter(database);
	const leaseId = generateId(32);
	for (let attempt = 0; attempt < 10; attempt++) {
		const binding = attempt === 0 ? await findOrCreateConnectionBinding(currentDatabase, connectionId, provisioningDomainId) : await findConnectionBinding(currentDatabase, connectionId);
		if (provisioningDomainId) assertProvisioningDomainBinding(binding, provisioningDomainId);
		if (binding.decommissionStatus === "complete") return { binding };
		const now = /* @__PURE__ */ new Date();
		if (binding.decommissionStatus === "reconciling" && binding.decommissionLeaseId && binding.decommissionLeaseExpiresAt && binding.decommissionLeaseExpiresAt.getTime() > now.getTime()) return { binding };
		const acquired = await currentDatabase.incrementOne({
			model: "scimConnectionBinding",
			where: [
				{
					field: "id",
					value: binding.id
				},
				{
					field: "decommissionRevision",
					value: binding.decommissionRevision
				},
				{
					field: "decommissionStatus",
					value: binding.decommissionStatus
				}
			],
			increment: { decommissionRevision: 1 },
			set: {
				decommissionStatus: "reconciling",
				decommissionedAt: binding.decommissionedAt ?? now,
				decommissionCompletedAt: null,
				decommissionLeaseId: leaseId,
				decommissionLeaseExpiresAt: new Date(now.getTime() + SCIM_DECOMMISSION_LEASE_DURATION_MS)
			}
		});
		if (acquired) return {
			binding: acquired,
			leaseId
		};
	}
	throw new BetterAuthError(`SCIM connection "${connectionId}" changed repeatedly while decommissioning; retry the operation.`);
}
async function releaseDecommissionLease(input) {
	const currentDatabase = await getCurrentAdapter(input.database);
	for (let attempt = 0; attempt < 3; attempt++) {
		const binding = await currentDatabase.findOne({
			model: "scimConnectionBinding",
			where: [{
				field: "id",
				value: input.bindingId
			}]
		});
		if (!binding || binding.decommissionStatus === "complete" || binding.decommissionLeaseId !== input.leaseId) return;
		if (await currentDatabase.incrementOne({
			model: "scimConnectionBinding",
			where: [
				{
					field: "id",
					value: binding.id
				},
				{
					field: "decommissionRevision",
					value: binding.decommissionRevision
				},
				{
					field: "decommissionLeaseId",
					value: input.leaseId
				}
			],
			increment: { decommissionRevision: 1 },
			set: {
				decommissionLeaseId: null,
				decommissionLeaseExpiresAt: null
			}
		})) return;
	}
}
/**
* Renews the lease and holds the binding write through the current transaction.
* The write prevents an expired-lease takeover while reconciliation callbacks run.
*/
async function lockAndRenewDecommissionLease(input) {
	const renewed = await input.database.incrementOne({
		model: "scimConnectionBinding",
		where: [
			{
				field: "id",
				value: input.binding.id
			},
			{
				field: "decommissionRevision",
				value: input.binding.decommissionRevision
			},
			{
				field: "decommissionStatus",
				value: "reconciling"
			},
			{
				field: "decommissionLeaseId",
				value: input.leaseId
			}
		],
		increment: {},
		set: { decommissionLeaseExpiresAt: new Date(Date.now() + SCIM_DECOMMISSION_LEASE_DURATION_MS) }
	});
	if (renewed) return renewed;
	throw new BetterAuthError(`SCIM connection "${input.binding.connectionId}" decommission lease changed before reconciliation.`);
}
async function reconcileDecommissionedConnection(input) {
	try {
		while (true) {
			const checkpoint = await runWithTransaction(input.database, async () => {
				const trx = await getCurrentAdapter(input.database);
				const storedBinding = await trx.findOne({
					model: "scimConnectionBinding",
					where: [{
						field: "id",
						value: input.binding.id
					}]
				});
				if (!storedBinding) throw new BetterAuthError(`SCIM connection "${input.binding.connectionId}" binding disappeared during decommissioning.`);
				if (storedBinding.decommissionStatus === "complete") return storedBinding;
				if (storedBinding.decommissionLeaseId !== input.leaseId) throw new BetterAuthError(`SCIM connection "${storedBinding.connectionId}" decommission lease was taken over by another worker.`);
				const batch = await findSCIMProjectionDomainBatch({
					database: trx,
					provisioningDomainId: storedBinding.provisioningDomainId,
					cursorUserId: storedBinding.decommissionCursorUserId
				});
				if (batch) await input.projection.acquireUserLocks({
					database: trx,
					provisioningDomainId: storedBinding.provisioningDomainId,
					scimUserIds: batch.scimUserIds
				});
				const binding = await lockAndRenewDecommissionLease({
					database: trx,
					binding: storedBinding,
					leaseId: input.leaseId
				});
				if (!batch) {
					const completed = await trx.incrementOne({
						model: "scimConnectionBinding",
						where: [
							{
								field: "id",
								value: binding.id
							},
							{
								field: "decommissionRevision",
								value: binding.decommissionRevision
							},
							{
								field: "decommissionLeaseId",
								value: input.leaseId
							}
						],
						increment: { decommissionRevision: 1 },
						set: {
							decommissionStatus: "complete",
							decommissionCompletedAt: /* @__PURE__ */ new Date(),
							decommissionLeaseId: null,
							decommissionLeaseExpiresAt: null
						}
					});
					if (completed) return completed;
					throw new BetterAuthError(`SCIM connection "${binding.connectionId}" decommission checkpoint changed concurrently.`);
				}
				await reconcileSCIMProjectionDomainBatch({
					database: trx,
					auth: input.auth,
					projection: input.projection,
					identity: input.identity,
					provisioningDomainId: binding.provisioningDomainId,
					batch,
					subjectLocksAcquired: true
				});
				const now = /* @__PURE__ */ new Date();
				const set = {
					decommissionCursorUserId: batch.cursorUserId,
					...batch.hasMore ? { decommissionLeaseExpiresAt: new Date(now.getTime() + SCIM_DECOMMISSION_LEASE_DURATION_MS) } : {
						decommissionStatus: "complete",
						decommissionCompletedAt: now,
						decommissionLeaseId: null,
						decommissionLeaseExpiresAt: null
					}
				};
				const advanced = await trx.incrementOne({
					model: "scimConnectionBinding",
					where: [
						{
							field: "id",
							value: binding.id
						},
						{
							field: "decommissionRevision",
							value: binding.decommissionRevision
						},
						{
							field: "decommissionLeaseId",
							value: input.leaseId
						}
					],
					increment: {
						decommissionRevision: 1,
						decommissionReconciledUserCount: batch.userIds.length,
						decommissionBatchCount: 1
					},
					set
				});
				if (advanced) return advanced;
				throw new BetterAuthError(`SCIM connection "${binding.connectionId}" decommission checkpoint changed concurrently.`);
			});
			if (checkpoint.decommissionStatus === "complete") return checkpoint;
		}
	} catch (error) {
		try {
			await releaseDecommissionLease({
				database: input.database,
				bindingId: input.binding.id,
				leaseId: input.leaseId
			});
		} catch {}
		throw error;
	}
}
/**
* Permanently retires one connection through the leased canonical
* reconciliation saga.
*/
async function decommissionSCIMConnection(input) {
	const acquired = await acquireDecommissionLease(input.database, input.connectionId, input.provisioningDomainId);
	if (!acquired.leaseId) return createDecommissionResult(acquired.binding);
	return createDecommissionResult(await reconcileDecommissionedConnection({
		database: input.database,
		auth: input.auth,
		projection: input.projection,
		identity: input.identity,
		binding: acquired.binding,
		leaseId: acquired.leaseId
	}));
}
/**
* Creates the trusted server API for permanently retiring one connection.
* A provisioning domain may be supplied to retain a terminal binding before
* the connection's first authenticated request.
*/
function createDecommissionSCIMConnectionEndpoint(projection, identity) {
	return createAuthEndpoint.serverOnly({
		method: "POST",
		body: decommissionConnectionBodySchema
	}, async (ctx) => {
		return ctx.json(await decommissionSCIMConnection({
			database: ctx.context.adapter,
			auth: ctx.context,
			projection,
			identity,
			connectionId: ctx.body.connectionId,
			provisioningDomainId: ctx.body.provisioningDomainId
		}));
	});
}
//#endregion
//#region src/managed-connections.ts
const SCIM_MANAGED_CONNECTION_ID_PREFIX = "ba_scim_connection_";
const SCIM_MANAGED_CREDENTIAL_ID_PREFIX = "ba_scim_credential_";
/** Error code returned when a managed connection creation request ID is reused. */
const SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT = "SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT";
const SCIM_MANAGED_HASH_VERSION = "v1";
const SCIM_MANAGED_EVENT_LIMIT = 100;
const SCIM_MANAGED_DEFAULT_MAX_ACTIVE_CREDENTIALS = 5;
const SCIM_MANAGED_DEFAULT_LAST_USED_WRITE_INTERVAL_SECONDS = 300;
const SCIM_MANAGED_ACTIVE_CREDENTIAL_SCAN_LIMIT = 101;
const SCIM_MANAGED_IDENTIFIER_LENGTH = 32;
const SCIM_MANAGED_SECRET_LENGTH = 48;
const scimScopeSchema = z.enum([
	"scim.users.read",
	"scim.users.write",
	"scim.groups.read",
	"scim.groups.write"
]);
const creationRequestIdSchema = z.string().trim().min(16).max(255);
const provisioningDomainIdSchema = z.string().trim().min(1).max(255);
const connectionIdSchema = z.string().startsWith(SCIM_MANAGED_CONNECTION_ID_PREFIX).max(255);
const credentialIdSchema = z.string().startsWith(SCIM_MANAGED_CREDENTIAL_ID_PREFIX).max(255);
const actorIdSchema = z.string().trim().min(1).max(255);
const credentialPolicySchema = {
	scopes: z.array(scimScopeSchema).min(1).readonly(),
	expiresAt: z.date()
};
const createManagedConnectionBodySchema = z.object({
	creationRequestId: creationRequestIdSchema,
	provisioningDomainId: provisioningDomainIdSchema,
	actorId: actorIdSchema,
	...credentialPolicySchema
});
const listManagedConnectionsBodySchema = z.object({ provisioningDomainId: provisioningDomainIdSchema });
const getManagedConnectionBodySchema = z.object({
	connectionId: connectionIdSchema,
	provisioningDomainId: provisioningDomainIdSchema
});
const rotateManagedCredentialBodySchema = z.object({
	connectionId: connectionIdSchema,
	provisioningDomainId: provisioningDomainIdSchema,
	actorId: actorIdSchema,
	...credentialPolicySchema
});
const revokeManagedCredentialBodySchema = z.object({
	connectionId: connectionIdSchema,
	provisioningDomainId: provisioningDomainIdSchema,
	credentialId: credentialIdSchema,
	actorId: actorIdSchema
});
const decommissionManagedConnectionBodySchema = z.object({
	connectionId: connectionIdSchema,
	provisioningDomainId: provisioningDomainIdSchema,
	actorId: actorIdSchema
});
function createManagedNotFoundError() {
	return new APIError$1("NOT_FOUND", { message: "Managed SCIM connection not found" });
}
function createManagedConflictError(message) {
	return new APIError$1("CONFLICT", { message });
}
function createManagedCreationRequestConflictError() {
	return new APIError$1("CONFLICT", {
		code: SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT,
		message: "Managed SCIM connection creation request ID already exists"
	});
}
function createActiveSlotKey(connectionRecordId, slotIndex) {
	return `${connectionRecordId}:active:${slotIndex}`;
}
function createInactiveSlotKey(credentialId) {
	return `${credentialId}:inactive`;
}
function assertFutureExpiry(expiresAt) {
	if (expiresAt.getTime() <= Date.now()) throw new APIError$1("BAD_REQUEST", { message: "Managed SCIM credential expiry must be in the future" });
}
function generateOpaqueIdentifier(prefix) {
	return `${prefix}${generateRandomString(SCIM_MANAGED_IDENTIFIER_LENGTH, "a-z", "A-Z", "0-9", "-_")}`;
}
function createManagedToken(credentialId) {
	return `${credentialId}.${generateRandomString(SCIM_MANAGED_SECRET_LENGTH, "a-z", "A-Z", "0-9", "-_")}`;
}
async function digestManagedToken(token, options) {
	return await createHMAC("SHA-256", "base64urlnopad").sign(options.credentialHashSecret, token);
}
function parseManagedScopes(serializedScopes) {
	let parsed;
	try {
		parsed = JSON.parse(serializedScopes);
	} catch {
		throw new APIError$1("INTERNAL_SERVER_ERROR", { message: "Managed SCIM credential scope policy is invalid" });
	}
	const result = z.array(scimScopeSchema).min(1).safeParse(parsed);
	if (!result.success || new Set(result.data).size !== result.data.length) throw new APIError$1("INTERNAL_SERVER_ERROR", { message: "Managed SCIM credential scope policy is invalid" });
	return result.data;
}
function toManagedConnection(connection) {
	return {
		creationRequestId: connection.creationRequestId,
		connectionId: connection.connectionId,
		provisioningDomainId: connection.provisioningDomainId,
		status: connection.status,
		createdAt: connection.createdAt,
		createdBy: connection.createdBy,
		decommissionStartedAt: connection.decommissionStartedAt ?? null,
		decommissionStartedBy: connection.decommissionStartedBy ?? null,
		decommissionedAt: connection.decommissionedAt ?? null,
		decommissionedBy: connection.decommissionedBy ?? null
	};
}
function toManagedCredential(credential, observedAt = /* @__PURE__ */ new Date()) {
	return {
		credentialId: credential.credentialId,
		status: credential.status === "active" && credential.expiresAt.getTime() <= observedAt.getTime() ? "expired" : credential.status,
		scopes: parseManagedScopes(credential.serializedScopes),
		expiresAt: credential.expiresAt,
		createdAt: credential.createdAt,
		createdBy: credential.createdBy,
		lastUsedAt: credential.lastUsedAt ?? null,
		revokedAt: credential.revokedAt ?? null,
		revokedBy: credential.revokedBy ?? null
	};
}
async function findManagedConnectionByCreationRequestId(database, creationRequestId) {
	return await database.findOne({
		model: "scimManagedConnection",
		where: [{
			field: "creationRequestId",
			value: creationRequestId
		}]
	});
}
async function findManagedConnection(database, connectionId, provisioningDomainId) {
	return await database.findOne({
		model: "scimManagedConnection",
		where: [{
			field: "connectionId",
			value: connectionId
		}, {
			field: "provisioningDomainId",
			value: provisioningDomainId
		}]
	});
}
async function getManagedConnectionState(database, connection) {
	const credentials = await database.findMany({
		model: "scimManagedCredential",
		where: [{
			field: "connectionRecordId",
			value: connection.id
		}],
		sortBy: {
			field: "createdAt",
			direction: "desc"
		}
	});
	return {
		connection: toManagedConnection(connection),
		credentials: credentials.map((credential) => toManagedCredential(credential))
	};
}
async function createManagedEvent(database, input) {
	await database.create({
		model: "scimManagedConnectionEvent",
		data: {
			connectionRecordId: input.connectionRecordId,
			eventKey: `${input.connectionRecordId}:${input.sequence}`,
			sequence: input.sequence,
			type: input.type,
			actorId: input.actorId,
			...input.credentialId ? { credentialId: input.credentialId } : {},
			createdAt: input.createdAt
		}
	});
}
async function runManagedMutationTransaction(baseAdapter, mutation) {
	const currentAdapter = await getCurrentAdapter(baseAdapter);
	if (currentAdapter !== baseAdapter) return await mutation(currentAdapter);
	return await baseAdapter.transaction(async (transaction) => {
		return await mutation(transaction);
	});
}
async function createManagedConnectionInCurrentTransaction(database, input, generated) {
	if (await findManagedConnectionByCreationRequestId(database, input.creationRequestId)) throw createManagedCreationRequestConflictError();
	const connection = await database.create({
		model: "scimManagedConnection",
		data: {
			creationRequestId: input.creationRequestId,
			connectionId: generated.connectionId,
			provisioningDomainId: input.provisioningDomainId,
			status: "active",
			revision: 2,
			createdAt: generated.createdAt,
			createdBy: input.actorId
		}
	});
	const credential = await database.create({
		model: "scimManagedCredential",
		data: {
			connectionRecordId: connection.id,
			credentialId: generated.credentialId,
			tokenDigest: generated.tokenDigest,
			hashVersion: SCIM_MANAGED_HASH_VERSION,
			activeSlotKey: createActiveSlotKey(connection.id, 0),
			status: "active",
			serializedScopes: JSON.stringify(input.scopes),
			expiresAt: input.expiresAt,
			createdAt: generated.createdAt,
			createdBy: input.actorId
		}
	});
	await createManagedEvent(database, {
		connectionRecordId: connection.id,
		sequence: 1,
		type: "connection.created",
		actorId: input.actorId,
		createdAt: generated.createdAt
	});
	await createManagedEvent(database, {
		connectionRecordId: connection.id,
		sequence: 2,
		type: "credential.issued",
		actorId: input.actorId,
		credentialId: generated.credentialId,
		createdAt: generated.createdAt
	});
	return {
		connection,
		credential
	};
}
async function rotateManagedCredentialInCurrentTransaction(database, options, input, generated) {
	const connection = await findManagedConnection(database, input.connectionId, input.provisioningDomainId);
	if (!connection) throw createManagedNotFoundError();
	if (connection.status !== "active") throw createManagedConflictError("Managed SCIM connection is not active");
	const fenced = await database.incrementOne({
		model: "scimManagedConnection",
		where: [
			{
				field: "id",
				value: connection.id
			},
			{
				field: "status",
				value: "active"
			},
			{
				field: "revision",
				value: connection.revision
			}
		],
		increment: { revision: 1 }
	});
	if (!fenced) return null;
	const activeCredentials = await database.findMany({
		model: "scimManagedCredential",
		where: [{
			field: "connectionRecordId",
			value: connection.id
		}, {
			field: "status",
			value: "active"
		}],
		limit: SCIM_MANAGED_ACTIVE_CREDENTIAL_SCAN_LIMIT
	});
	const liveSlotKeys = /* @__PURE__ */ new Set();
	for (const credential of activeCredentials) if (credential.expiresAt.getTime() <= generated.createdAt.getTime()) await database.update({
		model: "scimManagedCredential",
		where: [
			{
				field: "id",
				value: credential.id
			},
			{
				field: "status",
				value: "active"
			},
			{
				field: "activeSlotKey",
				value: credential.activeSlotKey
			}
		],
		update: {
			status: "expired",
			activeSlotKey: createInactiveSlotKey(credential.credentialId)
		}
	});
	else liveSlotKeys.add(credential.activeSlotKey);
	if (liveSlotKeys.size >= options.maxActiveCredentials) throw createManagedConflictError("Managed SCIM connection has the maximum number of active credentials");
	let slotIndex;
	for (let candidate = 0; candidate < options.maxActiveCredentials; candidate++) if (!liveSlotKeys.has(createActiveSlotKey(connection.id, candidate))) {
		slotIndex = candidate;
		break;
	}
	if (slotIndex === void 0) throw createManagedConflictError("Managed SCIM connection has the maximum number of active credentials");
	const credential = await database.create({
		model: "scimManagedCredential",
		data: {
			connectionRecordId: connection.id,
			credentialId: generated.credentialId,
			tokenDigest: generated.tokenDigest,
			hashVersion: SCIM_MANAGED_HASH_VERSION,
			activeSlotKey: createActiveSlotKey(connection.id, slotIndex),
			status: "active",
			serializedScopes: JSON.stringify(input.scopes),
			expiresAt: input.expiresAt,
			createdAt: generated.createdAt,
			createdBy: input.actorId
		}
	});
	await createManagedEvent(database, {
		connectionRecordId: connection.id,
		sequence: fenced.revision,
		type: "credential.rotated",
		actorId: input.actorId,
		credentialId: generated.credentialId,
		createdAt: generated.createdAt
	});
	return {
		connection: fenced,
		credential
	};
}
async function revokeManagedCredentialInCurrentTransaction(database, input) {
	const connection = await findManagedConnection(database, input.connectionId, input.provisioningDomainId);
	if (!connection) throw createManagedNotFoundError();
	const credential = await database.findOne({
		model: "scimManagedCredential",
		where: [{
			field: "credentialId",
			value: input.credentialId
		}, {
			field: "connectionRecordId",
			value: connection.id
		}]
	});
	if (!credential) throw createManagedNotFoundError();
	if (credential.status === "revoked") return connection;
	if (connection.status !== "active" || credential.status !== "active") throw createManagedConflictError("Managed SCIM credential is not active");
	const fenced = await database.incrementOne({
		model: "scimManagedConnection",
		where: [
			{
				field: "id",
				value: connection.id
			},
			{
				field: "status",
				value: "active"
			},
			{
				field: "revision",
				value: connection.revision
			}
		],
		increment: { revision: 1 }
	});
	if (!fenced) return null;
	const revokedAt = /* @__PURE__ */ new Date();
	if (!await database.update({
		model: "scimManagedCredential",
		where: [
			{
				field: "id",
				value: credential.id
			},
			{
				field: "status",
				value: "active"
			},
			{
				field: "activeSlotKey",
				value: credential.activeSlotKey
			}
		],
		update: {
			status: "revoked",
			activeSlotKey: createInactiveSlotKey(credential.credentialId),
			revokedAt,
			revokedBy: input.actorId
		}
	})) return null;
	await createManagedEvent(database, {
		connectionRecordId: connection.id,
		sequence: fenced.revision,
		type: "credential.revoked",
		actorId: input.actorId,
		credentialId: credential.credentialId,
		createdAt: revokedAt
	});
	return fenced;
}
async function beginManagedConnectionDecommissionInCurrentTransaction(database, input) {
	const connection = await findManagedConnection(database, input.connectionId, input.provisioningDomainId);
	if (!connection) throw createManagedNotFoundError();
	if (connection.status === "decommissioning" || connection.status === "decommissioned") return connection;
	const decommissionStartedAt = /* @__PURE__ */ new Date();
	const fenced = await database.incrementOne({
		model: "scimManagedConnection",
		where: [
			{
				field: "id",
				value: connection.id
			},
			{
				field: "status",
				value: "active"
			},
			{
				field: "revision",
				value: connection.revision
			}
		],
		increment: { revision: 1 },
		set: {
			status: "decommissioning",
			decommissionStartedAt,
			decommissionStartedBy: input.actorId
		}
	});
	if (!fenced) return null;
	const activeCredentials = await database.findMany({
		model: "scimManagedCredential",
		where: [{
			field: "connectionRecordId",
			value: connection.id
		}, {
			field: "status",
			value: "active"
		}],
		limit: 100
	});
	for (const credential of activeCredentials) await database.update({
		model: "scimManagedCredential",
		where: [
			{
				field: "id",
				value: credential.id
			},
			{
				field: "status",
				value: "active"
			},
			{
				field: "activeSlotKey",
				value: credential.activeSlotKey
			}
		],
		update: {
			status: "decommissioned",
			activeSlotKey: createInactiveSlotKey(credential.credentialId),
			decommissionedAt: decommissionStartedAt
		}
	});
	await createManagedEvent(database, {
		connectionRecordId: connection.id,
		sequence: fenced.revision,
		type: "connection.decommissioning",
		actorId: input.actorId,
		createdAt: decommissionStartedAt
	});
	return fenced;
}
async function completeManagedConnectionDecommissionInCurrentTransaction(database, input) {
	const connection = await findManagedConnection(database, input.connectionId, input.provisioningDomainId);
	if (!connection) throw createManagedNotFoundError();
	if (connection.status === "decommissioned") return connection;
	if (connection.status !== "decommissioning") throw createManagedConflictError("Managed SCIM connection did not begin decommissioning");
	const decommissionedAt = /* @__PURE__ */ new Date();
	const fenced = await database.incrementOne({
		model: "scimManagedConnection",
		where: [
			{
				field: "id",
				value: connection.id
			},
			{
				field: "status",
				value: "decommissioning"
			},
			{
				field: "revision",
				value: connection.revision
			}
		],
		increment: { revision: 1 },
		set: {
			status: "decommissioned",
			decommissionedAt,
			decommissionedBy: input.actorId
		}
	});
	if (!fenced) return null;
	await createManagedEvent(database, {
		connectionRecordId: connection.id,
		sequence: fenced.revision,
		type: "connection.decommissioned",
		actorId: input.actorId,
		createdAt: decommissionedAt
	});
	return fenced;
}
function resolveManagedConnectionOptions(options) {
	return {
		credentialHashSecret: options.credentialHashSecret,
		maxActiveCredentials: options.maxActiveCredentials ?? SCIM_MANAGED_DEFAULT_MAX_ACTIVE_CREDENTIALS,
		lastUsedWriteIntervalSeconds: options.lastUsedWriteIntervalSeconds ?? SCIM_MANAGED_DEFAULT_LAST_USED_WRITE_INTERVAL_SECONDS
	};
}
function isManagedSCIMBearerToken(token) {
	return token.startsWith(SCIM_MANAGED_CREDENTIAL_ID_PREFIX);
}
function parseManagedCredentialId(token) {
	return token.match(/^(ba_scim_credential_[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/)?.[1];
}
async function verifyManagedSCIMBearerToken(database, token, options) {
	const credentialId = parseManagedCredentialId(token);
	if (!credentialId) return;
	const credential = await database.findOne({
		model: "scimManagedCredential",
		where: [{
			field: "credentialId",
			value: credentialId
		}]
	});
	if (!credential || credential.hashVersion !== SCIM_MANAGED_HASH_VERSION || credential.status !== "active" || credential.expiresAt.getTime() <= Date.now()) return;
	if (!await createHMAC("SHA-256", "base64urlnopad").verify(options.credentialHashSecret, token, credential.tokenDigest)) return;
	const connection = await database.findOne({
		model: "scimManagedConnection",
		where: [{
			field: "id",
			value: credential.connectionRecordId
		}, {
			field: "status",
			value: "active"
		}]
	});
	if (!connection) return;
	const now = /* @__PURE__ */ new Date();
	const lastUsedAt = credential.lastUsedAt ?? null;
	if (!lastUsedAt || lastUsedAt.getTime() + options.lastUsedWriteIntervalSeconds * 1e3 <= now.getTime()) try {
		await database.update({
			model: "scimManagedCredential",
			where: [
				{
					field: "id",
					value: credential.id
				},
				{
					field: "status",
					value: "active"
				},
				{
					field: "lastUsedAt",
					value: lastUsedAt
				}
			],
			update: { lastUsedAt: now }
		});
	} catch {}
	return {
		type: "managed-bearer",
		connectionId: connection.connectionId,
		provisioningDomainId: connection.provisioningDomainId,
		credentialId,
		scopes: parseManagedScopes(credential.serializedScopes),
		expiresAt: credential.expiresAt
	};
}
function createSCIMManagedConnectionEndpoints(configuredOptions, projection, identity) {
	const requireManagedOptions = () => {
		if (!configuredOptions) throw new APIError$1("BAD_REQUEST", { message: "SCIM managed connections are not configured" });
		return configuredOptions;
	};
	return {
		createSCIMManagedConnection: createAuthEndpoint.serverOnly({
			method: "POST",
			body: createManagedConnectionBodySchema,
			metadata: { noStore: true }
		}, async (ctx) => {
			const options = requireManagedOptions();
			assertFutureExpiry(ctx.body.expiresAt);
			if (new Set(ctx.body.scopes).size !== ctx.body.scopes.length) throw new APIError$1("BAD_REQUEST", { message: "Managed SCIM credential scopes must be unique" });
			const joinsAmbientTransaction = await getCurrentAdapter(ctx.context.adapter) !== ctx.context.adapter;
			const createdAt = /* @__PURE__ */ new Date();
			const connectionId = generateOpaqueIdentifier(SCIM_MANAGED_CONNECTION_ID_PREFIX);
			const credentialId = generateOpaqueIdentifier(SCIM_MANAGED_CREDENTIAL_ID_PREFIX);
			const token = createManagedToken(credentialId);
			const tokenDigest = await digestManagedToken(token, options);
			let created;
			try {
				created = await runManagedMutationTransaction(ctx.context.adapter, async (database) => {
					return await createManagedConnectionInCurrentTransaction(database, ctx.body, {
						connectionId,
						credentialId,
						tokenDigest,
						createdAt
					});
				});
			} catch (error) {
				if (error instanceof APIError$1) throw error;
				if (joinsAmbientTransaction) throw error;
				if (await findManagedConnectionByCreationRequestId(ctx.context.adapter, ctx.body.creationRequestId)) throw createManagedCreationRequestConflictError();
				throw error;
			}
			return ctx.json({
				connection: toManagedConnection(created.connection),
				credential: toManagedCredential(created.credential, createdAt),
				token
			});
		}),
		listSCIMManagedConnections: createAuthEndpoint.serverOnly({
			method: "POST",
			body: listManagedConnectionsBodySchema
		}, async (ctx) => {
			requireManagedOptions();
			const connections = await (await getCurrentAdapter(ctx.context.adapter)).findMany({
				model: "scimManagedConnection",
				where: [{
					field: "provisioningDomainId",
					value: ctx.body.provisioningDomainId
				}],
				sortBy: {
					field: "createdAt",
					direction: "desc"
				}
			});
			return ctx.json({ connections: connections.map((connection) => toManagedConnection(connection)) });
		}),
		getSCIMManagedConnection: createAuthEndpoint.serverOnly({
			method: "POST",
			body: getManagedConnectionBodySchema
		}, async (ctx) => {
			requireManagedOptions();
			const database = await getCurrentAdapter(ctx.context.adapter);
			const connection = await findManagedConnection(database, ctx.body.connectionId, ctx.body.provisioningDomainId);
			if (!connection) throw createManagedNotFoundError();
			return ctx.json(await getManagedConnectionState(database, connection));
		}),
		rotateSCIMManagedCredential: createAuthEndpoint.serverOnly({
			method: "POST",
			body: rotateManagedCredentialBodySchema,
			metadata: { noStore: true }
		}, async (ctx) => {
			const options = requireManagedOptions();
			assertFutureExpiry(ctx.body.expiresAt);
			if (new Set(ctx.body.scopes).size !== ctx.body.scopes.length) throw new APIError$1("BAD_REQUEST", { message: "Managed SCIM credential scopes must be unique" });
			const createdAt = /* @__PURE__ */ new Date();
			const credentialId = generateOpaqueIdentifier(SCIM_MANAGED_CREDENTIAL_ID_PREFIX);
			const token = createManagedToken(credentialId);
			const tokenDigest = await digestManagedToken(token, options);
			for (let attempt = 0; attempt < 5; attempt++) {
				const rotated = await runManagedMutationTransaction(ctx.context.adapter, async (database) => await rotateManagedCredentialInCurrentTransaction(database, options, ctx.body, {
					credentialId,
					tokenDigest,
					createdAt
				}));
				if (!rotated) continue;
				return ctx.json({
					connection: toManagedConnection(rotated.connection),
					credential: toManagedCredential(rotated.credential, createdAt),
					token
				});
			}
			throw createManagedConflictError("Managed SCIM connection changed repeatedly during credential rotation");
		}),
		revokeSCIMManagedCredential: createAuthEndpoint.serverOnly({
			method: "POST",
			body: revokeManagedCredentialBodySchema
		}, async (ctx) => {
			requireManagedOptions();
			for (let attempt = 0; attempt < 5; attempt++) {
				const revoked = await runManagedMutationTransaction(ctx.context.adapter, async (database) => await revokeManagedCredentialInCurrentTransaction(database, ctx.body));
				if (!revoked) continue;
				const database = await getCurrentAdapter(ctx.context.adapter);
				return ctx.json(await getManagedConnectionState(database, revoked));
			}
			throw createManagedConflictError("Managed SCIM connection changed repeatedly during credential revocation");
		}),
		listSCIMManagedConnectionEvents: createAuthEndpoint.serverOnly({
			method: "POST",
			body: getManagedConnectionBodySchema
		}, async (ctx) => {
			requireManagedOptions();
			const database = await getCurrentAdapter(ctx.context.adapter);
			const connection = await findManagedConnection(database, ctx.body.connectionId, ctx.body.provisioningDomainId);
			if (!connection) throw createManagedNotFoundError();
			const events = await database.findMany({
				model: "scimManagedConnectionEvent",
				where: [{
					field: "connectionRecordId",
					value: connection.id
				}],
				limit: SCIM_MANAGED_EVENT_LIMIT,
				sortBy: {
					field: "sequence",
					direction: "desc"
				}
			});
			return ctx.json({ events: events.reverse().map((event) => ({
				sequence: event.sequence,
				type: event.type,
				actorId: event.actorId,
				credentialId: event.credentialId ?? null,
				createdAt: event.createdAt
			})) });
		}),
		decommissionSCIMManagedConnection: createAuthEndpoint.serverOnly({
			method: "POST",
			body: decommissionManagedConnectionBodySchema
		}, async (ctx) => {
			requireManagedOptions();
			const database = await getCurrentAdapter(ctx.context.adapter);
			let started;
			for (let attempt = 0; attempt < 5; attempt++) {
				const result = await runManagedMutationTransaction(ctx.context.adapter, async (transaction) => await beginManagedConnectionDecommissionInCurrentTransaction(transaction, ctx.body));
				if (!result) continue;
				started = result;
				break;
			}
			if (!started) throw createManagedConflictError("Managed SCIM connection changed repeatedly while decommissioning began");
			if (started.status === "decommissioned") return ctx.json({
				...await getManagedConnectionState(database, started),
				decommission: {
					status: "complete",
					retryAfter: null
				}
			});
			const coreResult = await decommissionSCIMConnection({
				database: ctx.context.adapter,
				auth: ctx.context,
				projection,
				identity,
				connectionId: started.connectionId,
				provisioningDomainId: started.provisioningDomainId
			});
			if (coreResult.status !== "complete") return ctx.json({
				...await getManagedConnectionState(database, started),
				decommission: coreResult
			});
			for (let attempt = 0; attempt < 5; attempt++) {
				const completed = await runManagedMutationTransaction(ctx.context.adapter, async (transaction) => await completeManagedConnectionDecommissionInCurrentTransaction(transaction, ctx.body));
				if (!completed) continue;
				return ctx.json({
					...await getManagedConnectionState(database, completed),
					decommission: coreResult
				});
			}
			throw createManagedConflictError("Managed SCIM connection changed repeatedly while decommissioning completed");
		})
	};
}
const managedSCIMSchema = {
	scimManagedConnection: { fields: {
		creationRequestId: {
			type: "string",
			required: true,
			unique: true
		},
		connectionId: {
			type: "string",
			required: true,
			unique: true
		},
		provisioningDomainId: {
			type: "string",
			required: true,
			index: true
		},
		status: {
			type: "string",
			required: true
		},
		revision: {
			type: "number",
			required: true,
			returned: false
		},
		createdAt: {
			type: "date",
			required: true
		},
		createdBy: {
			type: "string",
			required: true
		},
		decommissionStartedAt: {
			type: "date",
			required: false
		},
		decommissionStartedBy: {
			type: "string",
			required: false
		},
		decommissionedAt: {
			type: "date",
			required: false
		},
		decommissionedBy: {
			type: "string",
			required: false
		}
	} },
	scimManagedCredential: { fields: {
		connectionRecordId: {
			type: "string",
			required: true,
			index: true,
			references: {
				model: "scimManagedConnection",
				field: "id",
				onDelete: "cascade"
			}
		},
		credentialId: {
			type: "string",
			required: true,
			unique: true
		},
		tokenDigest: {
			type: "string",
			required: true,
			returned: false
		},
		hashVersion: {
			type: "string",
			required: true,
			returned: false
		},
		activeSlotKey: {
			type: "string",
			required: true,
			unique: true,
			returned: false
		},
		status: {
			type: "string",
			required: true
		},
		serializedScopes: {
			type: "string",
			required: true,
			returned: false
		},
		expiresAt: {
			type: "date",
			required: true
		},
		createdAt: {
			type: "date",
			required: true
		},
		createdBy: {
			type: "string",
			required: true
		},
		lastUsedAt: {
			type: "date",
			required: false
		},
		revokedAt: {
			type: "date",
			required: false
		},
		revokedBy: {
			type: "string",
			required: false
		},
		decommissionedAt: {
			type: "date",
			required: false
		}
	} },
	scimManagedConnectionEvent: { fields: {
		connectionRecordId: {
			type: "string",
			required: true,
			index: true,
			references: {
				model: "scimManagedConnection",
				field: "id",
				onDelete: "cascade"
			}
		},
		eventKey: {
			type: "string",
			required: true,
			unique: true,
			returned: false
		},
		sequence: {
			type: "number",
			required: true
		},
		type: {
			type: "string",
			required: true
		},
		actorId: {
			type: "string",
			required: true
		},
		credentialId: {
			type: "string",
			required: false
		},
		createdAt: {
			type: "date",
			required: true
		}
	} }
};
//#endregion
//#region src/connection-authentication.ts
const SCIM_SCOPES = [
	"scim.users.read",
	"scim.users.write",
	"scim.groups.read",
	"scim.groups.write"
];
function getRequiredSCIMScope(path, method) {
	const operation = method === "GET" || method === "HEAD" ? "read" : "write";
	return path.includes("/Groups") ? `scim.groups.${operation}` : `scim.users.${operation}`;
}
function isValidSCIMConnectionIdentifier(value) {
	return typeof value === "string" && value.length > 0 && value.length <= 255 && value === value.trim();
}
function isValidSCIMCredentialId(value) {
	return isValidSCIMConnectionIdentifier(value);
}
function areValidSCIMScopes(scopes) {
	return Array.isArray(scopes) && scopes.length > 0 && new Set(scopes).size === scopes.length && scopes.every((scope) => SCIM_SCOPES.some((candidate) => candidate === scope));
}
function isSCIMDeclaredConnectionVerificationResult(value) {
	return typeof value === "object" && value !== null && "connectionId" in value && !("connection" in value) && isValidSCIMConnectionIdentifier(value.connectionId) && "credentialId" in value && isValidSCIMCredentialId(value.credentialId) && "scopes" in value && areValidSCIMScopes(value.scopes) && (!("expiresAt" in value) || value.expiresAt === void 0 || value.expiresAt instanceof Date && !Number.isNaN(value.expiresAt.getTime()));
}
function resolveVerifiedPrincipal(verified, configuredConnections) {
	if (typeof verified !== "object" || verified === null) return;
	const hasConnectionId = "connectionId" in verified;
	const hasConnection = "connection" in verified;
	const expiresAt = "expiresAt" in verified ? verified.expiresAt : void 0;
	if (hasConnectionId === hasConnection) return;
	if (!("credentialId" in verified) || !isValidSCIMCredentialId(verified.credentialId) || !("scopes" in verified) || !areValidSCIMScopes(verified.scopes) || expiresAt !== void 0 && (!(expiresAt instanceof Date) || Number.isNaN(expiresAt.getTime()))) return;
	if (expiresAt instanceof Date && expiresAt.getTime() <= Date.now()) return;
	let connection;
	if (isSCIMDeclaredConnectionVerificationResult(verified)) connection = configuredConnections.get(verified.connectionId);
	else if (hasConnection && typeof verified.connection === "object" && verified.connection !== null && "id" in verified.connection && isValidSCIMConnectionIdentifier(verified.connection.id) && !verified.connection.id.startsWith("ba_scim_connection_") && "provisioningDomainId" in verified.connection && isValidSCIMConnectionIdentifier(verified.connection.provisioningDomainId) && !configuredConnections.has(verified.connection.id)) connection = {
		id: verified.connection.id,
		provisioningDomainId: verified.connection.provisioningDomainId
	};
	if (!connection) return;
	const result = verified;
	return {
		type: "oauth-bearer",
		connectionId: connection.id,
		provisioningDomainId: connection.provisioningDomainId,
		credentialId: result.credentialId,
		scopes: result.scopes,
		...result.expiresAt ? { expiresAt: result.expiresAt } : {}
	};
}
function assertConnectionBinding(binding, connection) {
	if (binding.connectionId !== connection.id || binding.provisioningDomainId !== connection.provisioningDomainId) throw createSCIMError("CONFLICT", { detail: "The connection provisioningDomainId changed after the connection was first used" });
}
async function bindSCIMConnection(adapter, connection) {
	return findOrCreateSCIMConnectionBinding(adapter, connection.id, connection.provisioningDomainId, /* @__PURE__ */ new Date(), { decommissionStatus: "active" }, (binding) => assertConnectionBinding(binding, connection));
}
/** Resolves one immutable SCIM connection from a bearer credential. */
function createSCIMConnectionMiddleware(options) {
	const configuredConnections = new Map(options.connections.map((connection) => [connection.id, {
		id: connection.id,
		provisioningDomainId: connection.provisioningDomainId ?? connection.id
	}]));
	const managedConnectionOptions = options.managedConnections ? resolveManagedConnectionOptions(options.managedConnections) : void 0;
	return createAuthMiddleware(async (ctx) => {
		const bearerToken = (ctx.headers?.get("authorization"))?.match(/^Bearer\s+(.+)$/i)?.[1];
		const rejectAuthentication = (detail) => {
			ctx.setHeader("www-authenticate", "Bearer realm=\"SCIM\"");
			throw createSCIMError("UNAUTHORIZED", { detail });
		};
		if (!bearerToken) return rejectAuthentication("SCIM bearer token is required");
		let principal;
		for (const configuredConnection of options.connections) for (const credential of configuredConnection.credentials) {
			const matches = constantTimeEqual(credential.token, bearerToken);
			const active = credential.expiresAt === void 0 || credential.expiresAt.getTime() > Date.now();
			if (!principal && matches && active) principal = {
				type: "static-bearer",
				connectionId: configuredConnection.id,
				provisioningDomainId: configuredConnection.provisioningDomainId ?? configuredConnection.id,
				credentialId: credential.id,
				scopes: credential.scopes ?? SCIM_SCOPES,
				...credential.expiresAt ? { expiresAt: credential.expiresAt } : {}
			};
		}
		const managedToken = isManagedSCIMBearerToken(bearerToken);
		if (!principal && managedToken && managedConnectionOptions) principal = await verifyManagedSCIMBearerToken(await getCurrentAdapter(ctx.context.adapter), bearerToken, managedConnectionOptions);
		if (!principal && !managedToken && options.authentication) principal = resolveVerifiedPrincipal(await options.authentication.verifyBearerToken({
			token: bearerToken,
			method: ctx.method,
			path: ctx.path,
			headers: new Headers(ctx.headers)
		}, { database: {
			findOne: ctx.context.adapter.findOne,
			update: ctx.context.adapter.update
		} }), configuredConnections);
		if (!principal) return rejectAuthentication("Invalid SCIM bearer token");
		const requiredScope = getRequiredSCIMScope(ctx.path, ctx.method);
		if (!principal.scopes.includes(requiredScope)) throw createSCIMError("FORBIDDEN", { detail: `The SCIM bearer token is missing the ${requiredScope} scope` });
		const connection = {
			id: principal.connectionId,
			provisioningDomainId: principal.provisioningDomainId
		};
		if ((await bindSCIMConnection(ctx.context.adapter, connection)).decommissionStatus !== "active") return rejectAuthentication("SCIM connection is decommissioned");
		return {
			scimConnection: connection,
			scimPrincipal: principal
		};
	});
}
/** HTTP query shape shared by resource-returning SCIM endpoints. */
const scimAttributeProjectionQuerySchema = z.object({
	attributes: z.union([z.string(), z.array(z.string())]).optional(),
	excludedAttributes: z.union([z.string(), z.array(z.string())]).optional()
});
/** HTTP query shape shared by the User and Group collection endpoints. */
const scimCollectionQuerySchema = scimAttributeProjectionQuerySchema.extend({
	filter: z.string().optional(),
	startIndex: z.union([z.string(), z.number()]).optional(),
	count: z.union([z.string(), z.number()]).optional()
});
function parseInteger(input, parameter) {
	if (input === void 0) return {
		ok: true,
		value: void 0
	};
	const parsed = typeof input === "number" ? input : /^-?\d+$/.test(input.trim()) ? Number(input.trim()) : NaN;
	if (!Number.isSafeInteger(parsed)) return {
		ok: false,
		error: parameter === "startIndex" ? {
			code: "invalid-start-index",
			parameter,
			scimType: "invalidValue",
			detail: "startIndex must be an integer"
		} : {
			code: "invalid-count",
			parameter,
			scimType: "invalidValue",
			detail: "count must be an integer"
		}
	};
	return {
		ok: true,
		value: parsed
	};
}
/** Parse and normalize RFC 7644 classic pagination parameters. */
function parseSCIMClassicPagination(input) {
	const parsedStartIndex = parseInteger(input.startIndex, "startIndex");
	if (!parsedStartIndex.ok) return parsedStartIndex;
	const parsedCount = parseInteger(input.count, "count");
	if (!parsedCount.ok) return parsedCount;
	const startIndex = Math.max(parsedStartIndex.value ?? 1, 1);
	const count = Math.min(Math.max(parsedCount.value ?? 100, 0), 100);
	return {
		ok: true,
		value: {
			startIndex,
			offset: startIndex - 1,
			count
		}
	};
}
function canonicalizeFilterAttribute(resourceType, attribute) {
	const normalizedAttribute = stripSCIMCoreAttributePrefix(resourceType, attribute);
	if (/^emails\[\s*type\s+eq\s+"work"\s*\]\.value$/i.test(normalizedAttribute)) return resourceType === "User" ? "emails.work.value" : void 0;
	if (!/^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)?$/.test(normalizedAttribute)) return;
	switch (normalizedAttribute.toLowerCase()) {
		case "id": return "id";
		case "externalid": return "externalId";
		case "username": return resourceType === "User" ? "userName" : void 0;
		case "emails.value": return resourceType === "User" ? "emails.value" : void 0;
		case "displayname": return resourceType === "Group" ? "displayName" : void 0;
		default: return;
	}
}
function invalidFilterSyntax(detail) {
	return {
		ok: false,
		error: {
			code: "invalid-filter-syntax",
			parameter: "filter",
			scimType: "invalidFilter",
			detail
		}
	};
}
function scanSCIMFilterTopLevel(filter) {
	const words = [];
	let bracketDepth = 0;
	let quoted = false;
	let escaped = false;
	for (let index = 0; index < filter.length; index += 1) {
		const character = filter[index];
		if (quoted) {
			if (escaped) {
				escaped = false;
				continue;
			}
			if (character === "\\") {
				escaped = true;
				continue;
			}
			if (character === "\"") quoted = false;
			continue;
		}
		if (character === "\"") {
			quoted = true;
			continue;
		}
		if (character === "[") {
			bracketDepth += 1;
			continue;
		}
		if (character === "]") {
			if (bracketDepth === 0) return invalidFilterSyntax("filter contains malformed quotes or brackets");
			bracketDepth -= 1;
			continue;
		}
		if (bracketDepth !== 0 || !character || !/[A-Za-z]/.test(character)) continue;
		const start = index;
		while (/[A-Za-z]/.test(filter[index + 1] ?? "")) index += 1;
		const end = index + 1;
		words.push({
			start,
			end,
			value: filter.slice(start, end)
		});
	}
	if (quoted || bracketDepth !== 0) return invalidFilterSyntax("filter contains malformed quotes or brackets");
	return {
		ok: true,
		value: words
	};
}
function findTopLevelFilterOperation(filter) {
	const scan = scanSCIMFilterTopLevel(filter);
	if (!scan.ok) return scan;
	for (const word of scan.value) {
		const before = filter[word.start - 1];
		const after = filter[word.end];
		if (before === void 0 || after === void 0 || !/\s/.test(before) || !/\s/.test(after)) continue;
		const rawAttribute = filter.slice(0, word.start).trim();
		const rawValue = filter.slice(word.end).trim();
		if (!rawAttribute || !rawValue) continue;
		return {
			ok: true,
			value: {
				rawAttribute,
				rawOperator: word.value,
				rawValue
			}
		};
	}
	return {
		ok: true,
		value: void 0
	};
}
/** Parse the deliberately small P0 equality-filter grammar. */
function parseSCIMEqualityFilter(resourceType, filter) {
	if (filter === void 0 || filter.trim() === "") return {
		ok: true,
		value: void 0
	};
	const parsedOperation = findTopLevelFilterOperation(filter.trim());
	if (!parsedOperation.ok) return parsedOperation;
	const operation = parsedOperation.value;
	if (!operation) return invalidFilterSyntax("filter must use the form attribute eq \"value\"");
	const { rawAttribute, rawOperator, rawValue } = operation;
	if (rawOperator.toLowerCase() !== "eq") return {
		ok: false,
		error: {
			code: "unsupported-filter-operator",
			parameter: "filter",
			scimType: "invalidFilter",
			detail: `filter operator ${rawOperator} is not supported`
		}
	};
	const attribute = canonicalizeFilterAttribute(resourceType, rawAttribute);
	if (!attribute) return {
		ok: false,
		error: {
			code: "unsupported-filter-attribute",
			parameter: "filter",
			scimType: "invalidFilter",
			detail: `filter attribute ${rawAttribute} is not supported for ${resourceType}`
		}
	};
	let value;
	try {
		value = JSON.parse(rawValue);
	} catch {
		return {
			ok: false,
			error: {
				code: "invalid-filter-value",
				parameter: "filter",
				scimType: "invalidFilter",
				detail: "filter equality value must be a valid quoted JSON string"
			}
		};
	}
	if (typeof value !== "string") return {
		ok: false,
		error: {
			code: "invalid-filter-value",
			parameter: "filter",
			scimType: "invalidFilter",
			detail: "filter equality value must be a quoted string"
		}
	};
	return {
		ok: true,
		value: {
			attribute,
			operator: "eq",
			value
		}
	};
}
function splitFilterConjunction(filter) {
	const scan = scanSCIMFilterTopLevel(filter);
	if (!scan.ok) return scan;
	const expressions = [];
	let expressionStart = 0;
	for (const word of scan.value) {
		const before = filter[word.start - 1];
		const after = filter[word.end];
		if (word.value.toLowerCase() === "and" && before !== void 0 && after !== void 0 && /\s/.test(before) && /\s/.test(after)) {
			const expression = filter.slice(expressionStart, word.start).trim();
			if (!expression) return invalidFilterSyntax("filter contains an invalid conjunction");
			expressions.push(expression);
			expressionStart = word.end;
		}
	}
	const finalExpression = filter.slice(expressionStart).trim();
	if (!finalExpression) return invalidFilterSyntax("filter contains an invalid conjunction");
	if (expressions.length >= 10) return invalidFilterSyntax("filter supports at most 10 equality expressions");
	expressions.push(finalExpression);
	return {
		ok: true,
		value: expressions
	};
}
/** Parse the supported conjunction of case-insensitive equality expressions. */
function parseSCIMFilter(resourceType, filter) {
	if (filter === void 0 || filter.trim() === "") return {
		ok: true,
		value: []
	};
	const expressions = splitFilterConjunction(filter);
	if (!expressions.ok) return expressions;
	const filters = [];
	for (const expression of expressions.value) {
		const parsed = resourceType === "User" ? parseSCIMEqualityFilter("User", expression) : parseSCIMEqualityFilter("Group", expression);
		if (!parsed.ok) return parsed;
		if (parsed.value) filters.push(parsed.value);
	}
	return {
		ok: true,
		value: filters
	};
}
function normalizeAttributeList(resourceType, input, parameter) {
	if (input === void 0) return {
		ok: true,
		value: void 0
	};
	const values = typeof input === "string" ? [input] : input;
	if (values.length === 0) return {
		ok: true,
		value: void 0
	};
	const attributes = /* @__PURE__ */ new Set();
	for (const value of values) {
		if (value.trim() === "") continue;
		for (const part of value.split(",")) {
			const attribute = part.trim();
			if (!attribute || !/^\S+$/.test(attribute)) return {
				ok: false,
				error: {
					code: "invalid-attribute-list",
					parameter,
					scimType: "invalidValue",
					detail: `${parameter} must be a comma-separated list of attribute paths`
				}
			};
			const normalizedAttribute = resolveSCIMResponseAttributePath(resourceType, attribute);
			attributes.add(normalizedAttribute.toLowerCase());
		}
	}
	return attributes.size > 0 ? {
		ok: true,
		value: attributes
	} : {
		ok: true,
		value: void 0
	};
}
/** Parse mutually exclusive response attribute projection parameters. */
function parseSCIMAttributeProjection(resourceType, input) {
	const attributes = normalizeAttributeList(resourceType, input.attributes, "attributes");
	if (!attributes.ok) return attributes;
	const excludedAttributes = normalizeAttributeList(resourceType, input.excludedAttributes, "excludedAttributes");
	if (!excludedAttributes.ok) return excludedAttributes;
	if (attributes.value && excludedAttributes.value) return {
		ok: false,
		error: {
			code: "conflicting-attribute-projection",
			parameter: "attributes",
			scimType: "invalidValue",
			detail: "attributes and excludedAttributes cannot be used together"
		}
	};
	if (attributes.value) return {
		ok: true,
		value: {
			mode: "include",
			attributes: attributes.value
		}
	};
	if (excludedAttributes.value) return {
		ok: true,
		value: {
			mode: "exclude",
			excludedAttributes: excludedAttributes.value
		}
	};
	return {
		ok: true,
		value: { mode: "default" }
	};
}
/** Parse endpoint input into a typed, resource-specific collection query. */
function parseSCIMCollectionQuery(resourceType, input) {
	const pagination = parseSCIMClassicPagination(input);
	if (!pagination.ok) return pagination;
	const filters = resourceType === "User" ? parseSCIMFilter("User", input.filter) : parseSCIMFilter("Group", input.filter);
	if (!filters.ok) return filters;
	const projection = parseSCIMAttributeProjection(resourceType, input);
	if (!projection.ok) return projection;
	return {
		ok: true,
		value: {
			filters: filters.value,
			pagination: pagination.value,
			projection: projection.value
		}
	};
}
//#endregion
//#region src/discovery.ts
const SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const supportedSCIMSchemas = SCIM_DISCOVERY_SCHEMA_DESCRIPTORS.map((descriptor) => descriptor.discoverySchema);
const supportedSCIMResourceTypes = SCIM_RESOURCE_SCHEMAS.map((resource) => resource.resourceType);
function createListResponseOpenAPISchema(resourceSchema) {
	return {
		type: "object",
		properties: {
			schemas: {
				type: "array",
				items: { type: "string" }
			},
			totalResults: { type: "number" },
			itemsPerPage: { type: "number" },
			startIndex: { type: "number" },
			Resources: {
				type: "array",
				items: resourceSchema
			}
		}
	};
}
function createListResponse(resources) {
	return {
		schemas: [SCIM_LIST_RESPONSE_SCHEMA],
		totalResults: resources.length,
		startIndex: 1,
		itemsPerPage: resources.length,
		Resources: resources
	};
}
function readSCIMPathIdentifier(identifier) {
	try {
		return decodeURIComponent(identifier);
	} catch {
		return identifier;
	}
}
const getSCIMServiceProviderConfig = createAuthEndpoint("/scim/v2/ServiceProviderConfig", {
	method: "GET",
	metadata: defineSCIMEndpointMetadata({
		...HIDE_METADATA,
		allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
		openapi: {
			summary: "Get SCIM service provider configuration",
			description: "Describes the SCIM protocol features supported by this service provider.",
			responses: {
				"200": {
					description: "SCIM service provider configuration",
					content: createSCIMOpenAPIContent(ServiceProviderOpenAPISchema)
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	})
}, async (ctx) => {
	return ctx.json({
		schemas: [SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
		patch: { supported: true },
		bulk: {
			supported: false,
			maxOperations: 0,
			maxPayloadSize: 0
		},
		filter: {
			supported: true,
			maxResults: 100
		},
		changePassword: { supported: false },
		sort: { supported: false },
		etag: { supported: false },
		authenticationSchemes: [{
			name: "OAuth Bearer Token",
			description: "Authentication using a bearer token in the Authorization header.",
			specUri: "https://www.rfc-editor.org/info/rfc6750",
			type: "oauthbearertoken",
			primary: true
		}],
		meta: {
			resourceType: "ServiceProviderConfig",
			location: getResourceURL("/scim/v2/ServiceProviderConfig", ctx.context.baseURL)
		}
	});
});
const getSCIMSchemas = createAuthEndpoint("/scim/v2/Schemas", {
	method: "GET",
	metadata: defineSCIMEndpointMetadata({
		...HIDE_METADATA,
		allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
		openapi: {
			summary: "List SCIM schemas",
			description: "Lists the resource schemas supported by this SCIM service provider.",
			responses: {
				"200": {
					description: "SCIM schema ListResponse",
					content: createSCIMOpenAPIContent(createListResponseOpenAPISchema(SCIMSchemaOpenAPISchema))
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	})
}, async (ctx) => {
	const schemas = supportedSCIMSchemas.map((schema) => ({
		...schema,
		meta: {
			...schema.meta,
			location: getResourceURL(schema.meta.location, ctx.context.baseURL)
		}
	}));
	return ctx.json(createListResponse(schemas));
});
const getSCIMSchema = createAuthEndpoint("/scim/v2/Schemas/:schemaId", {
	method: "GET",
	metadata: defineSCIMEndpointMetadata({
		...HIDE_METADATA,
		allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
		openapi: {
			summary: "Get a SCIM schema",
			description: "Returns one resource schema supported by this SCIM service provider.",
			responses: {
				"200": {
					description: "SCIM schema",
					content: createSCIMOpenAPIContent(SCIMSchemaOpenAPISchema)
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	})
}, async (ctx) => {
	const schemaId = readSCIMPathIdentifier(ctx.params.schemaId);
	const schema = supportedSCIMSchemas.find((supportedSchema) => supportedSchema.id === schemaId);
	if (!schema) throw createSCIMError("NOT_FOUND", { detail: "Schema not found" });
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
	metadata: defineSCIMEndpointMetadata({
		...HIDE_METADATA,
		allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
		openapi: {
			summary: "List SCIM resource types",
			description: "Lists the resource types supported by this SCIM service provider.",
			responses: {
				"200": {
					description: "SCIM resource type ListResponse",
					content: createSCIMOpenAPIContent(createListResponseOpenAPISchema(ResourceTypeOpenAPISchema))
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	})
}, async (ctx) => {
	const resourceTypes = supportedSCIMResourceTypes.map((resourceType) => ({
		...resourceType,
		meta: {
			...resourceType.meta,
			location: getResourceURL(resourceType.meta.location, ctx.context.baseURL)
		}
	}));
	return ctx.json(createListResponse(resourceTypes));
});
const getSCIMResourceType = createAuthEndpoint("/scim/v2/ResourceTypes/:resourceTypeId", {
	method: "GET",
	metadata: defineSCIMEndpointMetadata({
		...HIDE_METADATA,
		allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
		openapi: {
			summary: "Get a SCIM resource type",
			description: "Returns one resource type supported by this SCIM service provider.",
			responses: {
				"200": {
					description: "SCIM resource type",
					content: createSCIMOpenAPIContent(ResourceTypeOpenAPISchema)
				},
				...SCIMErrorOpenAPISchemas
			}
		}
	})
}, async (ctx) => {
	const resourceType = supportedSCIMResourceTypes.find((supportedResourceType) => supportedResourceType.id === ctx.params.resourceTypeId);
	if (!resourceType) throw createSCIMError("NOT_FOUND", { detail: "Resource type not found" });
	return ctx.json({
		...resourceType,
		meta: {
			...resourceType.meta,
			location: getResourceURL(resourceType.meta.location, ctx.context.baseURL)
		}
	});
});
//#endregion
//#region src/identity.ts
/**
* Acquires an active provisioned User link inside the caller's transaction.
*
* The lookup is scoped to the exact SCIM connection and externalId. It never
* falls back to userName, email, or deleted identity tombstones. Pass the
* active transaction adapter supplied by the authentication resolver. A
* concurrent lifecycle mutation throws a SCIM conflict. A direct caller can
* choose to retry its entire transaction after starting from fresh state.
*/
async function acquireActiveSCIMUserLink(reference, context) {
	const externalIdKey = createSCIMUserExternalIdKey(reference.connectionId, reference.externalId);
	const source = await context.database.findOne({
		model: "scimUser",
		where: [
			{
				field: "connectionId",
				value: reference.connectionId
			},
			{
				field: "externalIdKey",
				value: externalIdKey
			},
			{
				field: "externalId",
				value: reference.externalId
			},
			{
				field: "active",
				value: true
			}
		]
	});
	if (!source) return null;
	const binding = await context.database.findOne({
		model: "scimConnectionBinding",
		where: [
			{
				field: "connectionKey",
				value: createSCIMConnectionKey(reference.connectionId)
			},
			{
				field: "connectionId",
				value: reference.connectionId
			},
			{
				field: "decommissionStatus",
				value: "active"
			}
		]
	});
	if (!binding || binding.provisioningDomainId !== source.provisioningDomainId) return null;
	if (await context.database.findOne({
		model: "scimIdentityTombstone",
		where: [
			{
				field: "connectionId",
				value: reference.connectionId
			},
			{
				field: "externalIdKey",
				value: externalIdKey
			},
			{
				field: "externalId",
				value: reference.externalId
			}
		]
	})) return null;
	const subject = await context.database.findOne({
		model: "scimSubject",
		where: [{
			field: "userId",
			value: source.userId
		}]
	});
	if (!subject) return null;
	if (!await context.database.findOne({
		model: "user",
		where: [{
			field: "id",
			value: source.userId
		}]
	})) return null;
	const acquiredSubject = await context.database.incrementOne({
		model: "scimSubject",
		where: [
			{
				field: "id",
				value: subject.id
			},
			{
				field: "userId",
				value: source.userId
			},
			{
				field: "revision",
				value: subject.revision
			}
		],
		increment: { revision: 1 },
		set: { updatedAt: /* @__PURE__ */ new Date() }
	});
	if (!acquiredSubject) concurrentIdentityMutation();
	const acquiredSource = await context.database.findOne({
		model: "scimUser",
		where: [
			{
				field: "id",
				value: source.id
			},
			{
				field: "connectionId",
				value: reference.connectionId
			},
			{
				field: "provisioningDomainId",
				value: binding.provisioningDomainId
			},
			{
				field: "userId",
				value: source.userId
			},
			{
				field: "connectionUserKey",
				value: source.connectionUserKey
			},
			{
				field: "externalIdKey",
				value: externalIdKey
			},
			{
				field: "externalId",
				value: reference.externalId
			},
			{
				field: "active",
				value: true
			}
		]
	});
	if (!acquiredSource || !acquiredSource.active || acquiredSource.userId !== acquiredSubject.userId) concurrentIdentityMutation();
	if (!await context.database.findOne({
		model: "user",
		where: [{
			field: "id",
			value: acquiredSource.userId
		}]
	})) concurrentIdentityMutation();
	if (await context.database.findOne({
		model: "scimIdentityTombstone",
		where: [
			{
				field: "connectionId",
				value: reference.connectionId
			},
			{
				field: "externalIdKey",
				value: externalIdKey
			},
			{
				field: "externalId",
				value: reference.externalId
			}
		]
	})) concurrentIdentityMutation();
	const acquiredBinding = await tryFenceActiveSCIMConnection(context.database, reference.connectionId);
	if (!acquiredBinding || acquiredBinding.id !== binding.id || acquiredBinding.provisioningDomainId !== acquiredSource.provisioningDomainId) concurrentIdentityMutation();
	return {
		scimUserId: source.id,
		userId: source.userId
	};
}
const SCIM_IDENTITY_MUTATION_CONFLICT = Symbol("scim-identity-mutation-conflict");
const SCIM_IDENTITY_TRANSACTION_ATTEMPTS = 3;
function concurrentIdentityMutation() {
	const error = createSCIMError("CONFLICT", { detail: "The SCIM identity changed concurrently; retry the request" });
	error[SCIM_IDENTITY_MUTATION_CONFLICT] = true;
	throw error;
}
function isSCIMIdentityMutationConflict(error) {
	return typeof error === "object" && error !== null && SCIM_IDENTITY_MUTATION_CONFLICT in error;
}
async function runIdentityMutationTransaction(adapter, callback, options = {}) {
	let subjectCreationObserved = options.subjectCreationUserId ? Boolean(await adapter.findOne({
		model: "scimSubject",
		where: [{
			field: "userId",
			value: options.subjectCreationUserId
		}]
	})) : false;
	for (let attempt = 1; attempt <= SCIM_IDENTITY_TRANSACTION_ATTEMPTS; attempt++) try {
		return await runWithTransaction(adapter, async () => callback(await getCurrentAdapter(adapter)));
	} catch (error) {
		if (isSCIMIdentityMutationConflict(error)) continue;
		if (!options.subjectCreationUserId || subjectCreationObserved) throw error;
		if (!await adapter.findOne({
			model: "scimSubject",
			where: [{
				field: "userId",
				value: options.subjectCreationUserId
			}]
		})) throw error;
		subjectCreationObserved = true;
	}
	throw createSCIMError("CONFLICT", { detail: "The SCIM identity changed concurrently; retry the request" });
}
async function advanceSubjectRevision(database, subject, now) {
	return await database.incrementOne({
		model: "scimSubject",
		where: [{
			field: "id",
			value: subject.id
		}, {
			field: "revision",
			value: subject.revision
		}],
		increment: { revision: 1 },
		set: { updatedAt: now }
	}) ?? concurrentIdentityMutation();
}
async function clearProfileSource(database, subject, scimUserId, now) {
	if (subject.profileSourceId !== scimUserId) return subject;
	return await database.incrementOne({
		model: "scimSubject",
		where: [
			{
				field: "id",
				value: subject.id
			},
			{
				field: "revision",
				value: subject.revision
			},
			{
				field: "profileSourceId",
				value: scimUserId
			}
		],
		increment: { revision: 1 },
		set: {
			profileSourceId: null,
			updatedAt: now
		}
	}) ?? concurrentIdentityMutation();
}
/** Create the user-level identity coordinator for one plugin instance. */
function createSCIMIdentityCoordinator(options) {
	return {
		async resolveUser(input, context) {
			if (input.resource.externalId) {
				const externalIdKey = createSCIMUserExternalIdKey(input.connectionId, input.resource.externalId);
				const tombstone = await context.database.findOne({
					model: "scimIdentityTombstone",
					where: [{
						field: "connectionId",
						value: input.connectionId
					}, {
						field: "externalIdKey",
						value: externalIdKey
					}]
				});
				if (tombstone) {
					if (tombstone.provisioningDomainId !== input.provisioningDomainId) throw createSCIMError("CONFLICT", { detail: "The connection provisioningDomainId changed after this User was deleted" });
					return {
						resolution: {
							action: "link",
							userId: tombstone.userId,
							profile: tombstone.profile
						},
						tombstoneId: tombstone.id
					};
				}
			}
			return { resolution: await runSCIMApplicationCallback(() => options.identity?.resolveUser?.(input, context), "SCIM identity resolution failed") ?? { action: "create" } };
		},
		async consumeTombstone(database, tombstoneId) {
			if (!tombstoneId) return;
			await database.delete({
				model: "scimIdentityTombstone",
				where: [{
					field: "id",
					value: tombstoneId
				}]
			});
		},
		async preserveDeletedSource(database, input) {
			if (!input.source.externalId || !input.source.externalIdKey) return;
			const profile = input.subject.profileSourceId === input.source.id ? "manage" : "preserve";
			const existing = await database.findOne({
				model: "scimIdentityTombstone",
				where: [{
					field: "externalIdKey",
					value: input.source.externalIdKey
				}]
			});
			if (existing) {
				await database.update({
					model: "scimIdentityTombstone",
					where: [{
						field: "id",
						value: existing.id
					}],
					update: {
						userId: input.source.userId,
						profile,
						deletedAt: input.deletedAt
					}
				});
				return;
			}
			await database.create({
				model: "scimIdentityTombstone",
				data: {
					connectionId: input.source.connectionId,
					provisioningDomainId: input.source.provisioningDomainId,
					externalId: input.source.externalId,
					externalIdKey: input.source.externalIdKey,
					userId: input.source.userId,
					profile,
					deletedAt: input.deletedAt
				}
			});
		},
		async acquireSubject(database, userId, now) {
			const existing = await database.findOne({
				model: "scimSubject",
				where: [{
					field: "userId",
					value: userId
				}]
			});
			if (!existing) return database.create({
				model: "scimSubject",
				data: {
					userId,
					profileSourceId: null,
					revision: 1,
					createdAt: now,
					updatedAt: now
				}
			});
			return advanceSubjectRevision(database, existing, now);
		},
		async acquireSubjectRevision(database, subject, now) {
			return advanceSubjectRevision(database, subject, now);
		},
		async claimProfileSource(database, subject, scimUserId, now) {
			if (subject.profileSourceId && subject.profileSourceId !== scimUserId) throw createSCIMError("CONFLICT", {
				detail: "Another SCIM source already manages this User profile",
				scimType: "uniqueness"
			});
			return await database.incrementOne({
				model: "scimSubject",
				where: [
					{
						field: "id",
						value: subject.id
					},
					{
						field: "revision",
						value: subject.revision
					},
					{
						field: "profileSourceId",
						value: null
					}
				],
				increment: { revision: 1 },
				set: {
					profileSourceId: scimUserId,
					updatedAt: now
				}
			}) ?? concurrentIdentityMutation();
		},
		async clearProfileSource(database, subject, scimUserId, now) {
			return clearProfileSource(database, subject, scimUserId, now);
		},
		async reconcileUser(input) {
			const scimUsers = await input.database.findMany({
				model: "scimUser",
				where: [{
					field: "userId",
					value: input.subject.userId
				}]
			});
			const connectionIds = [...new Set(scimUsers.map((scimUser) => scimUser.connectionId))];
			const decommissionedConnectionIds = await findDecommissionedSCIMConnectionIds(input.database, connectionIds);
			const participatingSCIMUsers = scimUsers.filter((scimUser) => !decommissionedConnectionIds.has(scimUser.connectionId));
			let subject = input.subject;
			if (subject.profileSourceId && !participatingSCIMUsers.some((source) => source.id === subject.profileSourceId)) subject = await clearProfileSource(input.database, subject, subject.profileSourceId, /* @__PURE__ */ new Date());
			const sources = participatingSCIMUsers.map((scimUser) => ({
				id: scimUser.id,
				connectionId: scimUser.connectionId,
				provisioningDomainId: scimUser.provisioningDomainId,
				active: scimUser.active
			})).sort((left, right) => left.id.localeCompare(right.id));
			const userId = input.subject.userId;
			const active = sources.some((source) => source.active);
			const state = {
				userId,
				active,
				...subject.profileSourceId ? { profileSourceId: subject.profileSourceId } : {},
				sources: sources.map((source) => ({ ...source }))
			};
			await runSCIMApplicationCallback(() => options.identity?.reconcileUser?.(state, { database: input.database }), "SCIM identity reconciliation failed");
			if (!active) await input.auth.internalAdapter.deleteUserSessions(userId);
			return {
				userId,
				active,
				...subject.profileSourceId ? { profileSourceId: subject.profileSourceId } : {},
				sources
			};
		}
	};
}
//#endregion
//#region src/group-state.ts
const SCIM_GROUP_TRANSACTION_ATTEMPTS = 3;
const SCIM_GROUP_MUTATION_CONFLICT = Symbol("scim-group-mutation-conflict");
function throwConcurrentSCIMGroupMutation() {
	const error = new BetterAuthError("The SCIM Group changed concurrently; retry the request.");
	error[SCIM_GROUP_MUTATION_CONFLICT] = true;
	throw error;
}
function isSCIMGroupMutationConflict(error) {
	return error instanceof BetterAuthError && SCIM_GROUP_MUTATION_CONFLICT in error;
}
async function runGroupMutationTransaction(adapter, callback) {
	for (let attempt = 1; attempt <= SCIM_GROUP_TRANSACTION_ATTEMPTS; attempt++) try {
		return await runWithTransaction(adapter, async () => callback(await getCurrentAdapter(adapter)));
	} catch (error) {
		if (!isSCIMIdentityMutationConflict(error) && !isSCIMProjectionSubjectConflict(error) && !isSCIMGroupMutationConflict(error)) throw error;
	}
	throw createSCIMError("CONFLICT", { detail: "The SCIM Group changed concurrently; retry the request" });
}
async function findSCIMGroup(adapter, connection, groupId) {
	const group = await adapter.findOne({
		model: "scimGroup",
		where: [{
			field: "id",
			value: groupId
		}, {
			field: "connectionId",
			value: connection.id
		}]
	});
	if (group && group.provisioningDomainId !== connection.provisioningDomainId) throw createSCIMError("CONFLICT", { detail: "The connection provisioningDomainId changed after resources were created" });
	return group;
}
async function acquireSCIMGroupMutationLock(database, connection, groupId, missingGroup = "not-found") {
	const group = await findSCIMGroup(database, connection, groupId);
	if (!group) {
		if (missingGroup === "conflict") throwConcurrentSCIMGroupMutation();
		throw createSCIMError("NOT_FOUND", { detail: "SCIM Group not found" });
	}
	const lockedGroup = await database.incrementOne({
		model: "scimGroup",
		where: [
			{
				field: "id",
				value: group.id
			},
			{
				field: "connectionId",
				value: connection.id
			},
			{
				field: "revision",
				value: group.revision
			}
		],
		increment: { revision: 1 }
	});
	if (!lockedGroup) throwConcurrentSCIMGroupMutation();
	return lockedGroup;
}
async function acquireSCIMGroupMutationLocks(database, connection, groupIds) {
	const groups = [];
	for (const groupId of [...new Set(groupIds)].sort()) groups.push(await acquireSCIMGroupMutationLock(database, connection, groupId, "conflict"));
	return groups;
}
async function markSCIMGroupsModified(database, connectionId, groups, updatedAt) {
	for (const group of groups) if (!await database.incrementOne({
		model: "scimGroup",
		where: [
			{
				field: "id",
				value: group.id
			},
			{
				field: "connectionId",
				value: connectionId
			},
			{
				field: "revision",
				value: group.revision
			}
		],
		increment: {},
		set: { updatedAt }
	})) throwConcurrentSCIMGroupMutation();
}
//#endregion
//#region src/resource-attribute-projection.ts
function createAttributePathNode() {
	return {
		selected: false,
		children: /* @__PURE__ */ new Map()
	};
}
function createAttributePathTree(attributePaths, resourceAttributeNames) {
	const root = createAttributePathNode();
	const orderedResourceAttributeNames = [...resourceAttributeNames].sort((left, right) => right.length - left.length);
	for (const attributePath of attributePaths) {
		const rootAttribute = orderedResourceAttributeNames.find((attributeName) => {
			const normalizedName = attributeName.toLowerCase();
			return attributePath === normalizedName || attributePath.startsWith(`${normalizedName}.`);
		});
		const relativePath = rootAttribute ? attributePath.slice(rootAttribute.length).replace(/^\./, "") : attributePath;
		const segments = [...rootAttribute ? [rootAttribute] : [], ...relativePath ? relativePath.split(".") : []];
		let node = root;
		for (const segment of segments) {
			const normalizedSegment = segment.toLowerCase();
			let child = node.children.get(normalizedSegment);
			if (!child) {
				child = createAttributePathNode();
				node.children.set(normalizedSegment, child);
			}
			node = child;
		}
		node.selected = true;
	}
	return root;
}
function isRecord$3(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function includeSelectedValue(value, node) {
	if (node.selected) return {
		selected: true,
		value
	};
	if (Array.isArray(value)) {
		const selectedItems = [];
		for (const item of value) {
			const selectedItem = includeSelectedValue(item, node);
			if (selectedItem.selected) selectedItems.push(selectedItem.value);
		}
		return selectedItems.length > 0 ? {
			selected: true,
			value: selectedItems
		} : { selected: false };
	}
	if (!isRecord$3(value)) return { selected: false };
	const selectedObject = {};
	for (const [key, childValue] of Object.entries(value)) {
		const childNode = node.children.get(key.toLowerCase());
		if (!childNode) continue;
		const selectedChild = includeSelectedValue(childValue, childNode);
		if (selectedChild.selected) selectedObject[key] = selectedChild.value;
	}
	return Object.keys(selectedObject).length > 0 ? {
		selected: true,
		value: selectedObject
	} : { selected: false };
}
function excludeSelectedValue(value, node) {
	if (node.selected) return { selected: false };
	if (Array.isArray(value)) return {
		selected: true,
		value: value.flatMap((item) => {
			const selectedItem = excludeSelectedValue(item, node);
			return selectedItem.selected ? [selectedItem.value] : [];
		})
	};
	if (!isRecord$3(value)) return {
		selected: true,
		value
	};
	const selectedObject = {};
	for (const [key, childValue] of Object.entries(value)) {
		const childNode = node.children.get(key.toLowerCase());
		if (!childNode) {
			selectedObject[key] = childValue;
			continue;
		}
		const selectedChild = excludeSelectedValue(childValue, childNode);
		if (selectedChild.selected) selectedObject[key] = selectedChild.value;
	}
	return {
		selected: true,
		value: selectedObject
	};
}
/**
* Apply SCIM `attributes` or `excludedAttributes` selection without mutating
* the canonical resource. Attribute matching is case-insensitive while output
* retains the resource's original key spelling.
*/
function projectSCIMResourceAttributes(resource, projection) {
	if (projection.mode === "default") return { ...resource };
	const tree = createAttributePathTree(projection.mode === "include" ? projection.attributes : projection.excludedAttributes, Object.keys(resource));
	const output = {
		schemas: resource.schemas,
		id: resource.id
	};
	for (const [key, value] of Object.entries(resource)) {
		const normalizedKey = key.toLowerCase();
		if (normalizedKey === "schemas" || normalizedKey === "id") continue;
		const node = tree.children.get(normalizedKey);
		if (projection.mode === "include") {
			if (!node) continue;
			const selectedValue = includeSelectedValue(value, node);
			if (selectedValue.selected) output[key] = selectedValue.value;
			continue;
		}
		if (!node) {
			output[key] = value;
			continue;
		}
		const selectedValue = excludeSelectedValue(value, node);
		if (selectedValue.selected) output[key] = selectedValue.value;
	}
	return output;
}
//#endregion
//#region src/resource-uniqueness.ts
function isSCIMUniquenessError(error) {
	if (!isAPIError(error)) return false;
	const body = error.body;
	return typeof body === "object" && body !== null && "status" in body && body.status === "409" && "scimType" in body && body.scimType === "uniqueness";
}
/**
* Converts a failed resource create to SCIM uniqueness only when a post-rollback
* read observes the competing committed resource.
*/
async function runSCIMCreateWithUniquenessCheck(createResource, assertResourceAvailable) {
	try {
		return await createResource();
	} catch (createError) {
		if (isAPIError(createError)) throw createError;
		try {
			await assertResourceAvailable();
		} catch (availabilityError) {
			if (isSCIMUniquenessError(availabilityError)) throw availabilityError;
		}
		throw createError;
	}
}
//#endregion
//#region src/group-provisioning.ts
const { inputSchema: APIGroupSchema, openAPISchema: OpenAPIGroupResourceSchema, schemaId: SCIM_GROUP_SCHEMA } = SCIM_RESOURCE_SCHEMA_REGISTRY.Group;
const SCIM_PATCH_SCHEMA$1 = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCIM_USER_ID_QUERY_CHUNK_SIZE = 500;
function requireGroupAttributeProjection(input) {
	const projection = parseSCIMAttributeProjection("Group", input);
	if (!projection.ok) throw createSCIMError("BAD_REQUEST", {
		detail: projection.error.detail,
		scimType: projection.error.scimType
	});
	return projection.value;
}
const patchSCIMGroupBodySchema = z.object({
	schemas: z.array(z.literal(SCIM_PATCH_SCHEMA$1)).length(1, "schemas must contain only the PatchOp schema"),
	Operations: z.array(z.object({
		op: z.string().toLowerCase().default("replace").pipe(z.enum([
			"replace",
			"add",
			"remove"
		])),
		path: z.string().optional(),
		value: z.unknown().optional()
	}))
});
const GROUP_MEMBER_VALUE_PATH = /^members\s*\[\s*value\s+eq\s+("(?:\\.|[^"\\])*")\s*\]$/i;
function createGroupExternalIdKey(connectionId, externalId) {
	if (!externalId) return void 0;
	return createScopedKey([
		"scim-group-external-id",
		connectionId,
		externalId
	]);
}
function createGroupDisplayNameKey(connectionId, displayName) {
	return createScopedKey([
		"scim-group-display-name",
		connectionId,
		displayName.toLowerCase()
	]);
}
function createGroupMembershipKey(connectionId, groupId, scimUserId) {
	return createScopedKey([
		"scim-group-member",
		connectionId,
		groupId,
		scimUserId
	]);
}
function createGroupCollectionWhere(connectionId, filters) {
	const where = [{
		field: "connectionId",
		value: connectionId
	}];
	for (const filter of filters) switch (filter.attribute) {
		case "id":
			where.push({
				field: "id",
				value: filter.value
			});
			break;
		case "displayName":
			where.push({
				field: "displayNameKey",
				value: createGroupDisplayNameKey(connectionId, filter.value)
			});
			break;
		case "externalId":
			where.push({
				field: "externalIdKey",
				value: createGroupExternalIdKey(connectionId, filter.value) ?? ""
			});
			break;
	}
	return where;
}
async function assertGroupConnectionDomainStable(adapter, connection) {
	if (await adapter.findOne({
		model: "scimGroup",
		where: [{
			field: "connectionId",
			value: connection.id
		}, {
			field: "provisioningDomainId",
			value: connection.provisioningDomainId,
			operator: "ne"
		}]
	})) throw createSCIMError("CONFLICT", { detail: "The connection provisioningDomainId changed after resources were created" });
}
async function assertExternalIdAvailable(adapter, connectionId, externalIdKey, excludeGroupId) {
	if (!externalIdKey) return;
	const existingGroup = await adapter.findOne({
		model: "scimGroup",
		where: [{
			field: "connectionId",
			value: connectionId
		}, {
			field: "externalIdKey",
			value: externalIdKey
		}]
	});
	if (existingGroup && existingGroup.id !== excludeGroupId) throw createSCIMError("CONFLICT", {
		detail: "SCIM Group externalId already exists",
		scimType: "uniqueness"
	});
}
async function assertDisplayNameAvailable(adapter, connectionId, displayNameKey, excludeGroupId) {
	const existingGroup = await adapter.findOne({
		model: "scimGroup",
		where: [{
			field: "connectionId",
			value: connectionId
		}, {
			field: "displayNameKey",
			value: displayNameKey
		}]
	});
	if (existingGroup && existingGroup.id !== excludeGroupId) throw createSCIMError("CONFLICT", {
		detail: "SCIM Group displayName already exists",
		scimType: "uniqueness"
	});
}
function normalizeGroupMemberIds(members) {
	const memberIds = /* @__PURE__ */ new Set();
	for (const member of members) {
		if (!member.value?.trim() || member.type !== void 0 && member.type.toLowerCase() !== "user") throw createSCIMError("BAD_REQUEST", {
			detail: "Group members must reference a SCIM User",
			scimType: "invalidValue"
		});
		memberIds.add(member.value);
	}
	return [...memberIds];
}
function assertGroupMemberCount(memberCount) {
	if (memberCount <= 1e3) return;
	throw createSCIMError("BAD_REQUEST", {
		detail: `Groups cannot contain more than ${SCIM_MAX_GROUP_MEMBERS} direct members`,
		scimType: "invalidValue"
	});
}
function isRecord$2(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function readPatchMemberIds(value) {
	if (!Array.isArray(value)) throw createSCIMError("BAD_REQUEST", {
		detail: "members must be an array",
		scimType: "invalidValue"
	});
	assertGroupMemberCount(value.length);
	return normalizeGroupMemberIds(value.map((member) => {
		if (!isRecord$2(member)) throw createSCIMError("BAD_REQUEST", {
			detail: "Group members must reference a SCIM User",
			scimType: "invalidValue"
		});
		return {
			value: typeof member.value === "string" ? member.value : void 0,
			type: typeof member.type === "string" ? member.type : void 0
		};
	}));
}
function readMemberIdFromValuePath(path) {
	const quotedMemberId = normalizeGroupPatchPath(path).match(GROUP_MEMBER_VALUE_PATH)?.[1];
	if (!quotedMemberId) return void 0;
	try {
		const memberId = JSON.parse(quotedMemberId);
		return typeof memberId === "string" && memberId ? memberId : void 0;
	} catch {
		return;
	}
}
function normalizeGroupPatchPath(path) {
	return stripSCIMCoreAttributePrefix("Group", path.trim());
}
function parseIncrementalMembershipPatch(operations) {
	const desiredMembershipByUserId = /* @__PURE__ */ new Map();
	const memberIdsToValidate = /* @__PURE__ */ new Set();
	for (const operation of operations) {
		const path = operation.path?.trim();
		if (!path) return void 0;
		if (normalizeGroupPatchPath(path).toLowerCase() === "members") {
			if (operation.op === "replace" || operation.value === void 0) return;
			const memberIds = readPatchMemberIds(operation.value);
			const desired = operation.op === "add";
			for (const memberId of memberIds) {
				desiredMembershipByUserId.set(memberId, desired);
				if (desired) memberIdsToValidate.add(memberId);
			}
			continue;
		}
		const valuePathMemberId = readMemberIdFromValuePath(path);
		if (operation.op !== "remove" || !valuePathMemberId) return void 0;
		desiredMembershipByUserId.set(valuePathMemberId, false);
	}
	return {
		desiredMembershipByUserId,
		memberIdsToValidate: [...memberIdsToValidate]
	};
}
function readPatchString(value, attribute) {
	const scalar = Array.isArray(value) && value.length === 1 ? value[0] : value;
	if (typeof scalar !== "string" || !scalar.trim()) throw createSCIMError("BAD_REQUEST", {
		detail: `${attribute} must be a non-empty string`,
		scimType: "invalidValue"
	});
	return scalar.trim();
}
function applyGroupPatch(group, currentMemberIds, operations) {
	const memberIds = new Set(currentMemberIds);
	let displayName = group.displayName;
	let externalId = group.externalId ?? void 0;
	function applyAttribute(op, path, value) {
		const normalizedPath = normalizeGroupPatchPath(path).toLowerCase();
		if (normalizedPath === "id" || normalizedPath === "schemas" || normalizedPath === "meta" || normalizedPath.startsWith("meta.")) throw createSCIMError("BAD_REQUEST", {
			detail: `${path} is read-only`,
			scimType: "mutability"
		});
		if (normalizedPath === "displayname") {
			if (op === "remove") throw createSCIMError("BAD_REQUEST", {
				detail: "displayName is required and cannot be removed",
				scimType: "mutability"
			});
			displayName = readPatchString(value, "displayName");
			return;
		}
		if (normalizedPath === "externalid") {
			externalId = op === "remove" ? void 0 : readPatchString(value, "externalId");
			return;
		}
		throw createSCIMError("BAD_REQUEST", {
			detail: "Unsupported Group PATCH path",
			scimType: "invalidPath"
		});
	}
	for (const operation of operations) {
		const path = operation.path?.trim();
		if (!path) {
			if (operation.op === "remove") throw createSCIMError("BAD_REQUEST", {
				detail: "A pathless remove operation has no target",
				scimType: "noTarget"
			});
			if (!isRecord$2(operation.value)) throw createSCIMError("BAD_REQUEST", {
				detail: "A pathless Group PATCH value must be an object",
				scimType: "invalidValue"
			});
			for (const [attribute, value] of Object.entries(operation.value)) {
				const normalizedAttribute = attribute.toLowerCase();
				if (normalizedAttribute === "id") {
					if (value !== group.id) throw createSCIMError("BAD_REQUEST", {
						detail: "A Group PATCH cannot change id",
						scimType: "mutability"
					});
					continue;
				}
				if (normalizedAttribute === "schemas" || normalizedAttribute === "meta") continue;
				if (normalizedAttribute === "members") {
					const patchMemberIds = readPatchMemberIds(value);
					if (operation.op === "replace") memberIds.clear();
					for (const memberId of patchMemberIds) memberIds.add(memberId);
					continue;
				}
				applyAttribute(operation.op, attribute, value);
			}
			continue;
		}
		if (normalizeGroupPatchPath(path).toLowerCase() === "members") {
			if (operation.op === "add") {
				for (const memberId of readPatchMemberIds(operation.value)) memberIds.add(memberId);
				continue;
			}
			if (operation.op === "replace") {
				memberIds.clear();
				for (const memberId of readPatchMemberIds(operation.value)) memberIds.add(memberId);
				continue;
			}
			if (operation.value === void 0) {
				memberIds.clear();
				continue;
			}
			for (const memberId of readPatchMemberIds(operation.value)) memberIds.delete(memberId);
			continue;
		}
		const valuePathMemberId = path ? readMemberIdFromValuePath(path) : void 0;
		if (operation.op === "remove" && valuePathMemberId) {
			memberIds.delete(valuePathMemberId);
			continue;
		}
		applyAttribute(operation.op, path, operation.value);
	}
	assertGroupMemberCount(memberIds.size);
	return {
		displayName,
		externalId,
		memberIds: [...memberIds]
	};
}
async function assertConnectionOwnsUsers(adapter, connectionId, scimUserIds) {
	if (scimUserIds.length === 0) return;
	if ((await adapter.findMany({
		model: "scimUser",
		where: [{
			field: "connectionId",
			value: connectionId
		}, {
			field: "id",
			value: scimUserIds,
			operator: "in"
		}]
	})).length !== scimUserIds.length) throw createSCIMError("BAD_REQUEST", {
		detail: "One or more Group members are invalid",
		scimType: "invalidValue"
	});
}
async function applyIncrementalGroupMembershipPatch(adapter, input) {
	await assertConnectionOwnsUsers(adapter, input.connectionId, [...input.patch.memberIdsToValidate]);
	const targetedUserIds = [...input.patch.desiredMembershipByUserId.keys()];
	if (targetedUserIds.length === 0) return {
		addedMemberships: [],
		removedMemberships: []
	};
	const existingMemberships = await adapter.findMany({
		model: "scimGroupMember",
		where: [
			{
				field: "connectionId",
				value: input.connectionId
			},
			{
				field: "groupId",
				value: input.groupId
			},
			{
				field: "scimUserId",
				value: targetedUserIds,
				operator: "in"
			}
		]
	});
	const existingByUserId = new Map(existingMemberships.map((membership) => [membership.scimUserId, membership]));
	const removedMemberships = existingMemberships.filter((membership) => input.patch.desiredMembershipByUserId.get(membership.scimUserId) === false);
	const addedSCIMUserIds = [...input.patch.desiredMembershipByUserId].filter(([scimUserId, desired]) => desired && !existingByUserId.has(scimUserId)).map(([scimUserId]) => scimUserId);
	assertGroupMemberCount(await adapter.count({
		model: "scimGroupMember",
		where: [{
			field: "connectionId",
			value: input.connectionId
		}, {
			field: "groupId",
			value: input.groupId
		}]
	}) + addedSCIMUserIds.length - removedMemberships.length);
	if (removedMemberships.length > 0) await adapter.deleteMany({
		model: "scimGroupMember",
		where: [
			{
				field: "connectionId",
				value: input.connectionId
			},
			{
				field: "groupId",
				value: input.groupId
			},
			{
				field: "scimUserId",
				value: removedMemberships.map((membership) => membership.scimUserId),
				operator: "in"
			}
		]
	});
	const addedMemberships = [];
	for (const scimUserId of addedSCIMUserIds) {
		const membership = await adapter.create({
			model: "scimGroupMember",
			data: {
				connectionId: input.connectionId,
				groupId: input.groupId,
				scimUserId,
				membershipKey: createGroupMembershipKey(input.connectionId, input.groupId, scimUserId),
				createdAt: input.createdAt
			}
		});
		addedMemberships.push(membership);
	}
	return {
		addedMemberships,
		removedMemberships
	};
}
async function replaceGroupMemberships(adapter, input) {
	await assertConnectionOwnsUsers(adapter, input.connectionId, input.scimUserIds);
	const existingMemberships = input.existingMemberships ?? await adapter.findMany({
		model: "scimGroupMember",
		where: [{
			field: "connectionId",
			value: input.connectionId
		}, {
			field: "groupId",
			value: input.groupId
		}]
	});
	const existingMemberIds = new Set(existingMemberships.map((membership) => membership.scimUserId));
	const requestedMemberIds = new Set(input.scimUserIds);
	const removedMemberships = existingMemberships.filter((membership) => !requestedMemberIds.has(membership.scimUserId));
	if (removedMemberships.length > 0) await adapter.deleteMany({
		model: "scimGroupMember",
		where: [
			{
				field: "connectionId",
				value: input.connectionId
			},
			{
				field: "groupId",
				value: input.groupId
			},
			{
				field: "scimUserId",
				value: removedMemberships.map((membership) => membership.scimUserId),
				operator: "in"
			}
		]
	});
	const addedMemberships = [];
	for (const scimUserId of input.scimUserIds) {
		if (existingMemberIds.has(scimUserId)) continue;
		const membership = await adapter.create({
			model: "scimGroupMember",
			data: {
				connectionId: input.connectionId,
				groupId: input.groupId,
				scimUserId,
				membershipKey: createGroupMembershipKey(input.connectionId, input.groupId, scimUserId),
				createdAt: input.createdAt
			}
		});
		addedMemberships.push(membership);
	}
	return {
		addedMemberships,
		removedMemberships
	};
}
function createGroupResourceBase(baseURL, group) {
	return {
		schemas: [SCIM_GROUP_SCHEMA],
		id: group.id,
		...group.externalId ? { externalId: group.externalId } : {},
		displayName: group.displayName,
		meta: {
			resourceType: "Group",
			created: group.createdAt,
			lastModified: group.updatedAt,
			location: getResourceURL(`/scim/v2/Groups/${encodeURIComponent(group.id)}`, baseURL)
		}
	};
}
function createGroupResourceFromMemberships(baseURL, group, memberships, scimUserById) {
	if (memberships.length > 1e3) throw createSCIMError("INTERNAL_SERVER_ERROR", { detail: "Persisted SCIM Group membership exceeds the server limit" });
	const members = memberships.flatMap((membership) => {
		const scimUser = scimUserById.get(membership.scimUserId);
		return scimUser ? [{
			value: scimUser.id,
			$ref: getResourceURL(`/scim/v2/Users/${encodeURIComponent(scimUser.id)}`, baseURL),
			display: scimUser.displayName,
			type: "User"
		}] : [];
	});
	return {
		...createGroupResourceBase(baseURL, group),
		members
	};
}
async function findSCIMUsersForMemberships(adapter, connectionId, memberships) {
	const scimUserIds = [...new Set(memberships.map((membership) => membership.scimUserId))];
	const scimUsers = [];
	for (let offset = 0; offset < scimUserIds.length; offset += SCIM_USER_ID_QUERY_CHUNK_SIZE) {
		const chunk = scimUserIds.slice(offset, offset + SCIM_USER_ID_QUERY_CHUNK_SIZE);
		scimUsers.push(...await adapter.findMany({
			model: "scimUser",
			where: [{
				field: "connectionId",
				value: connectionId
			}, {
				field: "id",
				value: chunk,
				operator: "in"
			}],
			limit: chunk.length
		}));
	}
	return new Map(scimUsers.map((scimUser) => [scimUser.id, scimUser]));
}
async function createGroupResource(adapter, baseURL, group) {
	const memberships = await adapter.findMany({
		model: "scimGroupMember",
		where: [{
			field: "connectionId",
			value: group.connectionId
		}, {
			field: "groupId",
			value: group.id
		}],
		limit: SCIM_MAX_GROUP_MEMBERS + 1,
		sortBy: {
			field: "createdAt",
			direction: "asc"
		}
	});
	if (memberships.length > 1e3) throw createSCIMError("INTERNAL_SERVER_ERROR", { detail: "Persisted SCIM Group membership exceeds the server limit" });
	return createGroupResourceFromMemberships(baseURL, group, memberships, await findSCIMUsersForMemberships(adapter, group.connectionId, memberships));
}
function projectionRequestsGroupMembers(projection) {
	if (projection.mode === "default") return true;
	if (projection.mode === "exclude") return !projection.excludedAttributes.has("members");
	return [...projection.attributes].some((attribute) => attribute === "members" || attribute.startsWith("members."));
}
async function createProjectedGroupResource(adapter, baseURL, group, projection) {
	return projectSCIMResourceAttributes(projectionRequestsGroupMembers(projection) ? await createGroupResource(adapter, baseURL, group) : {
		...createGroupResourceBase(baseURL, group),
		members: []
	}, projection);
}
async function createProjectedGroupResources(adapter, baseURL, groups, projection) {
	if (!projectionRequestsGroupMembers(projection)) return groups.map((group) => projectSCIMResourceAttributes({
		...createGroupResourceBase(baseURL, group),
		members: []
	}, projection));
	const [firstGroup] = groups;
	if (!firstGroup) return [];
	const maximumMembershipRows = groups.length * SCIM_MAX_GROUP_MEMBERS;
	const memberships = await adapter.findMany({
		model: "scimGroupMember",
		where: [{
			field: "connectionId",
			value: firstGroup.connectionId
		}, {
			field: "groupId",
			value: groups.map((group) => group.id),
			operator: "in"
		}],
		limit: maximumMembershipRows + 1,
		sortBy: {
			field: "createdAt",
			direction: "asc"
		}
	});
	if (memberships.length > maximumMembershipRows) throw createSCIMError("INTERNAL_SERVER_ERROR", { detail: "Persisted SCIM Group membership exceeds the server limit" });
	const membershipsByGroupId = /* @__PURE__ */ new Map();
	for (const membership of memberships) {
		const groupMemberships = membershipsByGroupId.get(membership.groupId) ?? [];
		groupMemberships.push(membership);
		membershipsByGroupId.set(membership.groupId, groupMemberships);
	}
	for (const groupMemberships of membershipsByGroupId.values()) if (groupMemberships.length > 1e3) throw createSCIMError("INTERNAL_SERVER_ERROR", { detail: "Persisted SCIM Group membership exceeds the server limit" });
	const scimUserById = await findSCIMUsersForMemberships(adapter, firstGroup.connectionId, memberships);
	return groups.map((group) => projectSCIMResourceAttributes(createGroupResourceFromMemberships(baseURL, group, membershipsByGroupId.get(group.id) ?? [], scimUserById), projection));
}
function createSCIMGroup(authMiddleware, projection) {
	return createAuthEndpoint("/scim/v2/Groups", {
		method: "POST",
		body: APIGroupSchema,
		query: scimAttributeProjectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Create SCIM Group",
				responses: {
					"201": {
						description: "SCIM Group resource",
						content: createSCIMOpenAPIContent(OpenAPIGroupResourceSchema)
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const connection = ctx.context.scimConnection;
		const attributeProjection = requireGroupAttributeProjection(ctx.query ?? {});
		await assertGroupConnectionDomainStable(adapter, connection);
		const displayName = ctx.body.displayName.trim();
		if (!displayName) throw createSCIMError("BAD_REQUEST", {
			detail: "displayName cannot be empty",
			scimType: "invalidValue"
		});
		const scimUserIds = normalizeGroupMemberIds(ctx.body.members ?? []);
		assertGroupMemberCount(scimUserIds.length);
		const externalIdKey = createGroupExternalIdKey(connection.id, ctx.body.externalId);
		const displayNameKey = createGroupDisplayNameKey(connection.id, displayName);
		await assertDisplayNameAvailable(adapter, connection.id, displayNameKey);
		await assertExternalIdAvailable(adapter, connection.id, externalIdKey);
		const group = await runSCIMCreateWithUniquenessCheck(() => runGroupMutationTransaction(adapter, async (trx) => {
			await assertDisplayNameAvailable(trx, connection.id, displayNameKey);
			await assertExternalIdAvailable(trx, connection.id, externalIdKey);
			const now = /* @__PURE__ */ new Date();
			const createdGroup = await trx.create({
				model: "scimGroup",
				data: {
					connectionId: connection.id,
					provisioningDomainId: connection.provisioningDomainId,
					revision: 0,
					displayName,
					displayNameKey,
					externalId: ctx.body.externalId,
					externalIdKey,
					orderKey: createSCIMOrderKey(now),
					createdAt: now,
					updatedAt: now
				}
			});
			await projection.acquireUserLocks({
				database: trx,
				provisioningDomainId: connection.provisioningDomainId,
				scimUserIds
			});
			await replaceGroupMemberships(trx, {
				connectionId: connection.id,
				groupId: createdGroup.id,
				scimUserIds,
				createdAt: now
			});
			await projection.reconcileUsers({
				database: trx,
				auth: ctx.context,
				provisioningDomainId: connection.provisioningDomainId,
				scimUserIds,
				subjectLocksAcquired: true
			});
			await fenceActiveSCIMConnection(trx, connection.id);
			return createdGroup;
		}), async () => {
			await assertDisplayNameAvailable(adapter, connection.id, displayNameKey);
			await assertExternalIdAvailable(adapter, connection.id, externalIdKey);
		});
		const completeResource = createGroupResourceBase(ctx.context.baseURL, group);
		const resource = await createProjectedGroupResource(adapter, ctx.context.baseURL, group, attributeProjection);
		ctx.setStatus(201);
		ctx.setHeader("location", completeResource.meta.location);
		ctx.setHeader("content-location", completeResource.meta.location);
		return ctx.json(resource);
	});
}
function getSCIMGroup(authMiddleware) {
	return createAuthEndpoint("/scim/v2/Groups/:groupId", {
		method: "GET",
		query: scimAttributeProjectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Get SCIM Group",
				responses: {
					"200": {
						description: "SCIM Group resource",
						content: createSCIMOpenAPIContent(OpenAPIGroupResourceSchema)
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const group = await findSCIMGroup(adapter, ctx.context.scimConnection, ctx.params.groupId);
		if (!group) throw createSCIMError("NOT_FOUND", { detail: "SCIM Group not found" });
		const attributeProjection = parseSCIMAttributeProjection("Group", ctx.query ?? {});
		if (!attributeProjection.ok) throw createSCIMError("BAD_REQUEST", {
			detail: attributeProjection.error.detail,
			scimType: attributeProjection.error.scimType
		});
		const resource = await createProjectedGroupResource(adapter, ctx.context.baseURL, group, attributeProjection.value);
		return ctx.json(resource);
	});
}
function listSCIMGroups(authMiddleware) {
	return createAuthEndpoint("/scim/v2/Groups", {
		method: "GET",
		query: scimCollectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "List SCIM Groups",
				responses: {
					"200": {
						description: "SCIM Group list",
						content: createSCIMOpenAPIContent({
							type: "object",
							properties: {
								totalResults: { type: "number" },
								itemsPerPage: { type: "number" },
								startIndex: { type: "number" },
								Resources: {
									type: "array",
									items: OpenAPIGroupResourceSchema
								}
							}
						})
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		await assertGroupConnectionDomainStable(adapter, ctx.context.scimConnection);
		const parsedQuery = parseSCIMCollectionQuery("Group", ctx.query ?? {});
		if (!parsedQuery.ok) throw createSCIMError("BAD_REQUEST", {
			detail: parsedQuery.error.detail,
			scimType: parsedQuery.error.scimType
		});
		const { filters, pagination, projection: attributeProjection } = parsedQuery.value;
		const where = createGroupCollectionWhere(ctx.context.scimConnection.id, filters);
		const totalResults = await adapter.count({
			model: "scimGroup",
			where
		});
		const groups = pagination.count === 0 ? [] : await adapter.findMany({
			model: "scimGroup",
			where,
			limit: pagination.count,
			offset: pagination.offset,
			sortBy: {
				field: "orderKey",
				direction: "asc"
			}
		});
		const resources = await createProjectedGroupResources(adapter, ctx.context.baseURL, groups, attributeProjection);
		return ctx.json({
			schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
			totalResults,
			startIndex: pagination.startIndex,
			itemsPerPage: resources.length,
			Resources: resources
		});
	});
}
function replaceSCIMGroup(authMiddleware, projection) {
	return createAuthEndpoint("/scim/v2/Groups/:groupId", {
		method: "PUT",
		body: APIGroupSchema,
		query: scimAttributeProjectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Replace SCIM Group",
				responses: {
					"200": {
						description: "SCIM Group resource",
						content: createSCIMOpenAPIContent(OpenAPIGroupResourceSchema)
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const connection = ctx.context.scimConnection;
		const attributeProjection = requireGroupAttributeProjection(ctx.query ?? {});
		const group = await findSCIMGroup(adapter, connection, ctx.params.groupId);
		if (!group) throw createSCIMError("NOT_FOUND", { detail: "SCIM Group not found" });
		const displayName = ctx.body.displayName.trim();
		if (!displayName) throw createSCIMError("BAD_REQUEST", {
			detail: "displayName cannot be empty",
			scimType: "invalidValue"
		});
		const scimUserIds = normalizeGroupMemberIds(ctx.body.members ?? []);
		assertGroupMemberCount(scimUserIds.length);
		const externalIdKey = createGroupExternalIdKey(connection.id, ctx.body.externalId);
		const displayNameKey = createGroupDisplayNameKey(connection.id, displayName);
		await assertDisplayNameAvailable(adapter, connection.id, displayNameKey, group.id);
		await assertExternalIdAvailable(adapter, connection.id, externalIdKey, group.id);
		const updatedGroup = await runGroupMutationTransaction(adapter, async (trx) => {
			const currentGroup = await acquireSCIMGroupMutationLock(trx, connection, group.id);
			const updatedAt = /* @__PURE__ */ new Date();
			await assertDisplayNameAvailable(trx, connection.id, displayNameKey, currentGroup.id);
			await assertExternalIdAvailable(trx, connection.id, externalIdKey, currentGroup.id);
			const currentMemberships = await trx.findMany({
				model: "scimGroupMember",
				where: [{
					field: "connectionId",
					value: connection.id
				}, {
					field: "groupId",
					value: currentGroup.id
				}]
			});
			await projection.acquireUserLocks({
				database: trx,
				provisioningDomainId: connection.provisioningDomainId,
				scimUserIds: [...new Set([...scimUserIds, ...currentMemberships.map((membership) => membership.scimUserId)])]
			});
			const membershipDelta = await replaceGroupMemberships(trx, {
				connectionId: connection.id,
				groupId: currentGroup.id,
				scimUserIds,
				createdAt: updatedAt,
				existingMemberships: currentMemberships
			});
			const updated = await trx.update({
				model: "scimGroup",
				where: [{
					field: "id",
					value: currentGroup.id
				}, {
					field: "connectionId",
					value: connection.id
				}],
				update: {
					displayName,
					displayNameKey,
					externalId: ctx.body.externalId ?? null,
					externalIdKey: externalIdKey ?? null,
					updatedAt
				}
			});
			if (!updated) throw createSCIMError("NOT_FOUND", { detail: "SCIM Group not found" });
			const affectedSCIMUserIds = new Set([...scimUserIds, ...membershipDelta.removedMemberships.map((membership) => membership.scimUserId)]);
			await projection.reconcileUsers({
				database: trx,
				auth: ctx.context,
				provisioningDomainId: connection.provisioningDomainId,
				scimUserIds: [...affectedSCIMUserIds],
				subjectLocksAcquired: true
			});
			await fenceActiveSCIMConnection(trx, connection.id);
			return updated;
		});
		const completeResource = createGroupResourceBase(ctx.context.baseURL, updatedGroup);
		const resource = await createProjectedGroupResource(adapter, ctx.context.baseURL, updatedGroup, attributeProjection);
		ctx.setHeader("location", completeResource.meta.location);
		return ctx.json(resource);
	});
}
function patchSCIMGroup(authMiddleware, projection) {
	return createAuthEndpoint("/scim/v2/Groups/:groupId", {
		method: "PATCH",
		body: patchSCIMGroupBodySchema,
		query: scimAttributeProjectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Patch SCIM Group",
				responses: {
					"200": {
						description: "Updated SCIM Group resource",
						content: createSCIMOpenAPIContent(OpenAPIGroupResourceSchema)
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const connection = ctx.context.scimConnection;
		const attributeProjection = requireGroupAttributeProjection(ctx.query ?? {});
		const group = await findSCIMGroup(adapter, connection, ctx.params.groupId);
		if (!group) throw createSCIMError("NOT_FOUND", { detail: "SCIM Group not found" });
		const incrementalPatch = parseIncrementalMembershipPatch(ctx.body.Operations);
		const updatedGroup = await runGroupMutationTransaction(adapter, async (trx) => {
			const currentGroup = await acquireSCIMGroupMutationLock(trx, connection, group.id);
			const updatedAt = /* @__PURE__ */ new Date();
			let affectedSCIMUserIds;
			let resourceChanged;
			let update = { updatedAt };
			if (incrementalPatch) {
				await projection.acquireUserLocks({
					database: trx,
					provisioningDomainId: connection.provisioningDomainId,
					scimUserIds: [...incrementalPatch.desiredMembershipByUserId.keys()]
				});
				const membershipDelta = await applyIncrementalGroupMembershipPatch(trx, {
					connectionId: connection.id,
					groupId: currentGroup.id,
					patch: incrementalPatch,
					createdAt: updatedAt
				});
				affectedSCIMUserIds = new Set([...membershipDelta.addedMemberships.map((membership) => membership.scimUserId), ...membershipDelta.removedMemberships.map((membership) => membership.scimUserId)]);
				resourceChanged = affectedSCIMUserIds.size > 0;
			} else {
				const currentMemberships = await trx.findMany({
					model: "scimGroupMember",
					where: [{
						field: "connectionId",
						value: connection.id
					}, {
						field: "groupId",
						value: currentGroup.id
					}]
				});
				const patch = applyGroupPatch(currentGroup, currentMemberships.map((membership) => membership.scimUserId), ctx.body.Operations);
				await projection.acquireUserLocks({
					database: trx,
					provisioningDomainId: connection.provisioningDomainId,
					scimUserIds: [...new Set([...patch.memberIds, ...currentMemberships.map((membership) => membership.scimUserId)])]
				});
				const externalIdKey = createGroupExternalIdKey(connection.id, patch.externalId);
				const displayNameKey = createGroupDisplayNameKey(connection.id, patch.displayName);
				await assertDisplayNameAvailable(trx, connection.id, displayNameKey, currentGroup.id);
				await assertExternalIdAvailable(trx, connection.id, externalIdKey, currentGroup.id);
				const membershipDelta = await replaceGroupMemberships(trx, {
					connectionId: connection.id,
					groupId: currentGroup.id,
					scimUserIds: patch.memberIds,
					createdAt: updatedAt,
					existingMemberships: currentMemberships
				});
				const metadataChanged = patch.displayName !== currentGroup.displayName || patch.externalId !== (currentGroup.externalId ?? void 0);
				affectedSCIMUserIds = new Set([
					...metadataChanged ? patch.memberIds : [],
					...membershipDelta.addedMemberships.map((membership) => membership.scimUserId),
					...membershipDelta.removedMemberships.map((membership) => membership.scimUserId)
				]);
				resourceChanged = metadataChanged || affectedSCIMUserIds.size > 0;
				update = {
					displayName: patch.displayName,
					displayNameKey,
					externalId: patch.externalId ?? null,
					externalIdKey: externalIdKey ?? null,
					updatedAt
				};
			}
			let mutationResult = currentGroup;
			if (resourceChanged) {
				const updated = await trx.update({
					model: "scimGroup",
					where: [{
						field: "id",
						value: currentGroup.id
					}, {
						field: "connectionId",
						value: connection.id
					}],
					update
				});
				if (!updated) throw createSCIMError("NOT_FOUND", { detail: "SCIM Group not found" });
				await projection.reconcileUsers({
					database: trx,
					auth: ctx.context,
					provisioningDomainId: connection.provisioningDomainId,
					scimUserIds: [...affectedSCIMUserIds],
					subjectLocksAcquired: true
				});
				mutationResult = updated;
			}
			await fenceActiveSCIMConnection(trx, connection.id);
			return mutationResult;
		});
		const completeResource = createGroupResourceBase(ctx.context.baseURL, updatedGroup);
		ctx.setHeader("location", completeResource.meta.location);
		return ctx.json(await createProjectedGroupResource(adapter, ctx.context.baseURL, updatedGroup, attributeProjection));
	});
}
function deleteSCIMGroup(authMiddleware, projection) {
	return createAuthEndpoint("/scim/v2/Groups/:groupId", {
		method: "DELETE",
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Delete SCIM Group",
				responses: {
					"204": { description: "SCIM Group deleted" },
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const connection = ctx.context.scimConnection;
		const group = await findSCIMGroup(adapter, connection, ctx.params.groupId);
		if (!group) throw createSCIMError("NOT_FOUND", { detail: "SCIM Group not found" });
		await runGroupMutationTransaction(adapter, async (trx) => {
			const currentGroup = await acquireSCIMGroupMutationLock(trx, connection, group.id);
			const memberships = await trx.findMany({
				model: "scimGroupMember",
				where: [{
					field: "connectionId",
					value: connection.id
				}, {
					field: "groupId",
					value: currentGroup.id
				}]
			});
			await projection.acquireUserLocks({
				database: trx,
				provisioningDomainId: connection.provisioningDomainId,
				scimUserIds: memberships.map((membership) => membership.scimUserId)
			});
			await trx.deleteMany({
				model: "scimGroupMember",
				where: [{
					field: "connectionId",
					value: connection.id
				}, {
					field: "groupId",
					value: currentGroup.id
				}]
			});
			await trx.delete({
				model: "scimGroup",
				where: [{
					field: "id",
					value: currentGroup.id
				}, {
					field: "connectionId",
					value: connection.id
				}]
			});
			await projection.reconcileUsers({
				database: trx,
				auth: ctx.context,
				provisioningDomainId: connection.provisioningDomainId,
				scimUserIds: memberships.map((membership) => membership.scimUserId),
				subjectLocksAcquired: true
			});
			await fenceActiveSCIMConnection(trx, connection.id);
		});
		ctx.setStatus(204);
	});
}
//#endregion
//#region src/transaction.ts
/** Rejects adapters whose transaction method is only the sequential fallback. */
function assertNativeSCIMTransactions(adapter) {
	if (typeof adapter.options?.adapterConfig.transaction === "function") return;
	throw new BetterAuthError("The scim plugin requires a database adapter with native transaction support.");
}
//#endregion
//#region src/user-attributes.ts
function invalidStoredUserAttributes() {
	throw createSCIMError("INTERNAL_SERVER_ERROR", { detail: "Stored SCIM User attribute state is invalid" });
}
/** Serialize one validated, bounded canonical User attribute payload. */
function serializeSCIMUserAttributes(attributes) {
	const parsed = SCIMCanonicalUserAttributesSchema.safeParse(attributes);
	if (!parsed.success) return invalidStoredUserAttributes();
	const serialized = JSON.stringify(parsed.data);
	if (serialized.length > 65535) return invalidStoredUserAttributes();
	return serialized;
}
/**
* Derive canonical User attributes for a row persisted before
* `serializedAttributes` existed, from its compatibility mirror columns.
* These rows predate Enterprise User support, so only the core schema and
* the mirrored name/email fields can be reconstructed.
*/
function deriveSCIMUserAttributesFromMirrors(user) {
	let emails;
	try {
		emails = JSON.parse(user.serializedEmails);
	} catch {
		return invalidStoredUserAttributes();
	}
	const attributes = SCIMCanonicalUserAttributesSchema.safeParse({
		schemas: [SCIM_USER_SCHEMA],
		name: {
			formatted: user.formattedName,
			...user.givenName ? { givenName: user.givenName } : {},
			...user.familyName ? { familyName: user.familyName } : {}
		},
		emails
	});
	if (!attributes.success) return invalidStoredUserAttributes();
	return attributes.data;
}
/** Read and validate one complete canonical User attribute payload. */
function readSCIMUserAttributes(user) {
	if (!user.serializedAttributes) return deriveSCIMUserAttributesFromMirrors(user);
	if (user.serializedAttributes.length > 65535) return invalidStoredUserAttributes();
	let parsed;
	try {
		parsed = JSON.parse(user.serializedAttributes);
	} catch {
		return invalidStoredUserAttributes();
	}
	const attributes = SCIMCanonicalUserAttributesSchema.safeParse(parsed);
	if (!attributes.success) return invalidStoredUserAttributes();
	return attributes.data;
}
//#endregion
//#region src/user-profile.ts
function normalizeOptionalString(value) {
	const normalized = value?.trim();
	return normalized ? normalized : void 0;
}
/** Normalize the supported multi-valued email set and select one primary. */
function normalizeSCIMEmails(userName, emails) {
	const normalized = (emails ?? []).map((email) => ({
		value: email.value.trim().toLowerCase(),
		...email.type?.trim() ? { type: email.type.trim().toLowerCase() } : {},
		primary: email.primary === true
	}));
	if (normalized.length === 0) return [{
		value: userName.toLowerCase(),
		primary: true
	}];
	const explicitPrimaryIndex = normalized.findIndex((email) => email.primary);
	const workEmailIndex = normalized.findIndex((email) => email.type === "work");
	const primaryIndex = explicitPrimaryIndex >= 0 ? explicitPrimaryIndex : workEmailIndex >= 0 ? workEmailIndex : 0;
	return normalized.map((email, index) => ({
		...email,
		primary: index === primaryIndex
	}));
}
/** Resolve the provider profile independently from the Better Auth User row. */
function createCanonicalSCIMUserProfile(input) {
	const userName = input.userName.trim();
	const emails = normalizeSCIMEmails(userName, input.emails);
	const primaryEmail = emails.find((email) => email.primary)?.value ?? emails[0]?.value ?? userName;
	const givenName = normalizeOptionalString(input.name?.givenName);
	const familyName = normalizeOptionalString(input.name?.familyName);
	const middleName = normalizeOptionalString(input.name?.middleName);
	const honorificPrefix = normalizeOptionalString(input.name?.honorificPrefix);
	const honorificSuffix = normalizeOptionalString(input.name?.honorificSuffix);
	const composedName = [givenName, familyName].filter(Boolean).join(" ");
	const formattedName = normalizeOptionalString(input.name?.formatted) ?? normalizeOptionalString(input.displayName) ?? (composedName || primaryEmail);
	const displayName = normalizeOptionalString(input.displayName) ?? formattedName;
	const name = {
		formatted: formattedName,
		...givenName ? { givenName } : {},
		...familyName ? { familyName } : {},
		...middleName ? { middleName } : {},
		...honorificPrefix ? { honorificPrefix } : {},
		...honorificSuffix ? { honorificSuffix } : {}
	};
	return {
		userName,
		displayName,
		formattedName,
		name,
		emails,
		primaryEmail,
		attributes: {
			schemas: input.schemas,
			name,
			emails,
			...input.title ? { title: input.title } : {},
			...input.userType ? { userType: input.userType } : {},
			...input.preferredLanguage ? { preferredLanguage: input.preferredLanguage } : {},
			...input.locale ? { locale: input.locale } : {},
			...input.timezone ? { timezone: input.timezone } : {},
			...input.phoneNumbers ? { phoneNumbers: input.phoneNumbers } : {},
			...input.addresses ? { addresses: input.addresses } : {},
			...input.roles ? { roles: input.roles } : {},
			...input.entitlements ? { entitlements: input.entitlements } : {},
			...input[SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.id] ? { [SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.canonicalAttribute]: input[SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.id] } : {}
		}
	};
}
/** Build an adapter-portable exact-membership index for email equality filters. */
function createSCIMEmailValueIndex(emails, type) {
	const normalizedType = type?.trim().toLowerCase();
	return `|${[...new Set(emails.filter((email) => normalizedType === void 0 || email.type === normalizedType).map((email) => createSCIMEmailValueToken(email.value)))].sort().join("|")}|`;
}
/** Create one delimiter-safe token used by an email equality query. */
function createSCIMEmailValueToken(email) {
	return createScopedKey(["scim-email-value", email.trim().toLowerCase()]);
}
//#endregion
//#region src/user-patch.ts
const SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const EMAIL_TYPE_VALUE_PATH = /^emails\s*\[\s*type\s+eq\s+"([^"]+)"\s*\]\s*\.\s*value$/i;
/** Matches Microsoft Entra's `emails[primary eq true].value` PATCH path. */
const EMAIL_PRIMARY_VALUE_PATH = /^emails\s*\[\s*primary\s+eq\s+"?true"?\s*\]\s*\.\s*value$/i;
const scimEmailValueSchema = z.email().max(254);
const patchSCIMUserBodySchema = z.object({
	schemas: z.array(z.literal(SCIM_PATCH_SCHEMA)).length(1, "schemas must contain only the PatchOp schema"),
	Operations: z.array(z.object({
		op: z.string().toLowerCase().default("replace").pipe(z.enum([
			"replace",
			"add",
			"remove"
		])),
		path: z.string().optional(),
		value: z.unknown().optional()
	}))
});
const patchEmailSchema = z.object({
	value: scimEmailValueSchema,
	primary: z.boolean().optional(),
	type: z.string().trim().min(1).optional()
});
function createComparableSCIMPatchValue(value) {
	if (Array.isArray(value)) return value.map(createComparableSCIMPatchValue);
	if (!isRecord$1(value)) return value;
	return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== void 0).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, createComparableSCIMPatchValue(item)]));
}
/** Whether an applied PATCH changes the canonical persisted User resource. */
function scimUserPatchChangesState(user, state) {
	const attributes = readSCIMUserAttributes(user);
	return user.userName !== state.userName || user.primaryEmail !== state.primaryEmail || JSON.stringify(createComparableSCIMPatchValue(attributes.emails)) !== JSON.stringify(createComparableSCIMPatchValue(state.emails)) || user.displayName !== state.displayName || attributes.name.formatted !== state.formattedName || attributes.name.givenName !== state.givenName || attributes.name.familyName !== state.familyName || attributes.name.middleName !== state.middleName || attributes.name.honorificPrefix !== state.honorificPrefix || attributes.name.honorificSuffix !== state.honorificSuffix || (user.externalId ?? void 0) !== state.externalId || user.active !== state.active || JSON.stringify(createComparableSCIMPatchValue(attributes)) !== JSON.stringify(createComparableSCIMPatchValue(state.attributes));
}
function isRecord$1(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function invalidPatchValue(detail) {
	throw createSCIMError("BAD_REQUEST", {
		detail,
		scimType: "invalidValue"
	});
}
/**
* Unwrap a PATCH operation value Microsoft Entra sent as a single-element
* array for what is actually a single-valued attribute.
*/
function unwrapSinglePatchValue(value) {
	return Array.isArray(value) && value.length === 1 ? value[0] : value;
}
function readNonEmptyString(value, attribute) {
	const scalar = unwrapSinglePatchValue(value);
	if (typeof scalar !== "string" || !scalar.trim()) return invalidPatchValue(`${attribute} must be a non-empty string`);
	return scalar.trim();
}
function readEmail(value) {
	const parsed = scimEmailValueSchema.safeParse(value);
	if (!parsed.success) return invalidPatchValue("emails.value must be an email");
	return parsed.data.toLowerCase();
}
function readEmailValues(value) {
	const parsed = z.array(patchEmailSchema).min(1).max(20).safeParse(value);
	if (!parsed.success) return invalidPatchValue("emails must contain between 1 and 20 valid emails");
	return parsed.data;
}
function readEmailSet(value, userName) {
	const emails = readEmailValues(value);
	if (emails.filter((email) => email.primary).length > 1) return invalidPatchValue("emails cannot contain multiple primary values");
	if (new Set(emails.map(createSCIMEmailTupleKey)).size !== emails.length) return invalidPatchValue("emails cannot contain duplicate type and value pairs");
	if (!hasUniqueSCIMDefinedTypes(emails)) return invalidPatchValue("emails cannot contain duplicate defined types");
	return normalizeSCIMEmails(userName, emails);
}
function readName(value) {
	if (!isRecord$1(value)) return invalidPatchValue("name must be an object");
	const name = {};
	for (const [attribute, attributeValue] of Object.entries(value)) switch (attribute.toLowerCase()) {
		case "formatted":
			name.formatted = readNonEmptyString(attributeValue, "name.formatted");
			break;
		case "givenname":
			name.givenName = readNonEmptyString(attributeValue, "name.givenName");
			break;
		case "familyname":
			name.familyName = readNonEmptyString(attributeValue, "name.familyName");
			break;
		case "middlename":
			name.middleName = readNonEmptyString(attributeValue, "name.middleName");
			break;
		case "honorificprefix":
			name.honorificPrefix = readNonEmptyString(attributeValue, "name.honorificPrefix");
			break;
		case "honorificsuffix":
			name.honorificSuffix = readNonEmptyString(attributeValue, "name.honorificSuffix");
			break;
		default: throw createSCIMError("BAD_REQUEST", {
			detail: `User attribute name.${attribute} is not supported`,
			scimType: "invalidPath"
		});
	}
	return name;
}
function rejectReadOnlyAttribute(attribute) {
	throw createSCIMError("BAD_REQUEST", {
		detail: `${attribute} is read-only`,
		scimType: "mutability"
	});
}
function setFormattedName(state, formattedName) {
	const displayNameWasDerived = state.displayName === state.formattedName;
	state.formattedName = formattedName;
	if (displayNameWasDerived) state.displayName = formattedName;
}
function composeName(state) {
	return [state.givenName, state.familyName].filter(Boolean).join(" ");
}
function setNamePart(state, attribute, value) {
	state[attribute] = value;
}
function setEmails(state, emails) {
	state.emails = readEmailSet(emails, state.userName);
	state.primaryEmail = state.emails.find((email) => email.primary)?.value ?? state.emails[0]?.value ?? invalidPatchValue("emails must contain at least one value");
}
function coalesceEmailTuples(emails) {
	const byTuple = /* @__PURE__ */ new Map();
	for (const email of emails) {
		const key = createSCIMEmailTupleKey(email);
		const existing = byTuple.get(key);
		if (!existing) {
			byTuple.set(key, email);
			continue;
		}
		if (email.primary && !existing.primary) byTuple.set(key, {
			...existing,
			primary: true
		});
	}
	return [...byTuple.values()];
}
function addEmails(state, value) {
	const additions = coalesceEmailTuples(readEmailValues(value).map((email) => ({
		value: email.value.trim().toLowerCase(),
		...email.type?.trim() ? { type: email.type.trim().toLowerCase() } : {},
		primary: email.primary === true
	})));
	if (additions.filter((email) => email.primary).length > 1) invalidPatchValue("emails cannot contain multiple primary values");
	const existingTupleKeys = new Set(state.emails.map(createSCIMEmailTupleKey));
	const newEmails = additions.filter((email) => !existingTupleKeys.has(createSCIMEmailTupleKey(email)));
	if (newEmails.length === 0) return;
	setEmails(state, [...newEmails.some((email) => email.primary) ? state.emails.map((email) => ({
		...email,
		primary: false
	})) : state.emails, ...newEmails]);
}
function replaceAllEmailValues(state, value) {
	const replacement = readEmail(value);
	setEmails(state, state.emails.map((email) => ({
		...email,
		value: replacement
	})));
}
function replaceSelectedEmail(state, selector, value) {
	const replacement = readEmail(value);
	const matches = (email) => email.type === selector;
	if (!state.emails.some(matches)) {
		setEmails(state, [...state.emails, {
			value: replacement,
			type: selector,
			primary: false
		}]);
		return;
	}
	setEmails(state, state.emails.map((email) => matches(email) ? {
		...email,
		value: replacement
	} : email));
}
/** Replace the currently primary email's value, keeping `primary` on it. */
function replacePrimaryEmail(state, value) {
	const replacement = readEmail(value);
	if (!state.emails.some((email) => email.primary)) throw createSCIMError("BAD_REQUEST", {
		detail: "No primary email matches the PATCH path",
		scimType: "noTarget"
	});
	setEmails(state, state.emails.map((email) => email.primary ? {
		...email,
		value: replacement
	} : email));
}
function normalizePatchPath(path) {
	return resolveSCIMCanonicalAttributePath("User", path.trim()).toLowerCase();
}
const SCIM_VALUE_PATH = /^([A-Za-z$][\w$-]*)\s*\[\s*type\s+eq\s+"([^"]+)"\s*\](?:\s*\.\s*([A-Za-z$][\w$-]*))?$/i;
/** Matches Microsoft Entra's `attr[primary eq true]` and `attr[primary eq "true"]` filters. */
const SCIM_PRIMARY_VALUE_PATH = /^([A-Za-z$][\w$-]*)\s*\[\s*primary\s+eq\s+"?(true|false)"?\s*\](?:\s*\.\s*([A-Za-z$][\w$-]*))?$/i;
function clonePatchValue(value) {
	if (Array.isArray(value)) return value.map(clonePatchValue);
	if (!isRecord$1(value)) return value;
	return clonePatchRecord(value);
}
function clonePatchRecord(value) {
	return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clonePatchValue(item)]));
}
function findPatchAttribute(attributes, name) {
	return attributes.find((attribute) => attribute.name.toLowerCase() === name.toLowerCase());
}
function resolveMutableSCIMUserPatchPath(path) {
	const canonicalPath = resolveSCIMCanonicalAttributePath("User", path.trim());
	const enterprise = canonicalPath.toLowerCase() === "enterprise" || canonicalPath.toLowerCase().startsWith("enterprise.");
	if (canonicalPath.toLowerCase() === "enterprise") return { enterpriseRoot: true };
	const relativePath = enterprise ? canonicalPath.slice(11) : canonicalPath;
	const attributes = enterprise ? SCIMEnterpriseUserResourceSchema.attributes : SCIMUserResourceSchema.attributes;
	const valuePathMatch = SCIM_VALUE_PATH.exec(relativePath);
	const primaryValuePathMatch = valuePathMatch ? null : SCIM_PRIMARY_VALUE_PATH.exec(relativePath);
	const filterMatch = valuePathMatch ?? primaryValuePathMatch;
	const pathSegments = relativePath.split(".");
	const [attributePath, subAttributePath] = filterMatch ? [filterMatch[1], filterMatch[3]] : pathSegments;
	if (!attributePath || !filterMatch && (pathSegments.length > 2 || pathSegments.some((segment) => segment.length === 0))) throw createSCIMError("BAD_REQUEST", {
		detail: `User PATCH path ${path} is not supported`,
		scimType: "invalidPath"
	});
	const attribute = findPatchAttribute(attributes, attributePath);
	if (!attribute) throw createSCIMError("BAD_REQUEST", {
		detail: `User PATCH path ${path} is not supported`,
		scimType: "invalidPath"
	});
	if (attribute.mutability === "readOnly") rejectReadOnlyAttribute(path);
	const subAttribute = subAttributePath ? findPatchAttribute(attribute.subAttributes ?? [], subAttributePath) : void 0;
	if (subAttributePath && !subAttribute) throw createSCIMError("BAD_REQUEST", {
		detail: `User PATCH path ${path} is not supported`,
		scimType: "invalidPath"
	});
	if (subAttribute?.mutability === "readOnly") rejectReadOnlyAttribute(path);
	if (filterMatch && !attribute.multiValued) throw createSCIMError("BAD_REQUEST", {
		detail: `User PATCH path ${path} is not a multi-valued attribute`,
		scimType: "invalidPath"
	});
	return {
		attribute,
		attributeName: attribute.name,
		enterprise,
		...valuePathMatch?.[2] ? { selectorType: valuePathMatch[2].trim().toLowerCase() } : {},
		...primaryValuePathMatch ? { selectorPrimary: primaryValuePathMatch[2]?.toLowerCase() === "true" } : {},
		...subAttribute ? {
			subAttribute,
			subAttributeName: subAttribute.name
		} : {}
	};
}
function getSCIMPatchContainer(document, enterprise, create) {
	if (!enterprise) return document;
	const current = document[SCIM_ENTERPRISE_USER_SCHEMA];
	if (isRecord$1(current)) return current;
	if (!create) return void 0;
	const extension = {};
	document[SCIM_ENTERPRISE_USER_SCHEMA] = extension;
	return extension;
}
function setEnterpriseSchemaDeclaration(document, declared) {
	const withoutEnterprise = (Array.isArray(document.schemas) ? document.schemas.filter((schema) => typeof schema === "string") : []).filter((schema) => schema !== SCIM_ENTERPRISE_USER_SCHEMA);
	document.schemas = declared ? [...withoutEnterprise, SCIM_ENTERPRISE_USER_SCHEMA] : withoutEnterprise;
}
function removeEmptyEnterpriseExtension(document) {
	const extension = document[SCIM_ENTERPRISE_USER_SCHEMA];
	if (!isRecord$1(extension) || Object.keys(extension).length > 0) return;
	delete document[SCIM_ENTERPRISE_USER_SCHEMA];
	setEnterpriseSchemaDeclaration(document, false);
}
function mergePatchObject(current, value, attribute) {
	if (!isRecord$1(value)) return invalidPatchValue(`${attribute} must be an object`);
	return {
		...isRecord$1(current) ? current : {},
		...clonePatchRecord(value)
	};
}
function parseEnterprisePatchObject(value, attribute) {
	if (!isRecord$1(value)) return invalidPatchValue(`${attribute} must be an object`);
	for (const key of Object.keys(value)) if (!findPatchAttribute(SCIMEnterpriseUserResourceSchema.attributes, key)) throw createSCIMError("BAD_REQUEST", {
		detail: `User PATCH path ${SCIM_ENTERPRISE_USER_SCHEMA}:${key} is not supported`,
		scimType: "invalidPath"
	});
	const parsed = SCIMEnterpriseUserInputSchema.safeParse(value);
	if (!parsed.success) {
		const issue = parsed.error.issues[0];
		return invalidPatchValue(issue ? `${attribute}.${issue.path.join(".")}: ${issue.message}` : `${attribute} is invalid`);
	}
	return clonePatchRecord(parsed.data);
}
function mergeEnterprisePatchObject(current, value, attribute) {
	const currentEnterprise = isRecord$1(current) ? current : {};
	const patch = parseEnterprisePatchObject(value, attribute);
	const currentManager = currentEnterprise.manager;
	const patchManager = patch.manager;
	return {
		...currentEnterprise,
		...patch,
		...isRecord$1(patchManager) ? { manager: {
			...isRecord$1(currentManager) ? currentManager : {},
			...patchManager
		} } : {}
	};
}
function normalizeManagerPatchValue(value) {
	const manager = parseEnterprisePatchObject({ manager: value }, `${SCIM_ENTERPRISE_USER_SCHEMA}:manager`).manager;
	return isRecord$1(manager) ? manager : invalidPatchValue("manager must contain value or $ref");
}
function normalizeMultiValueAdditions(value) {
	return (Array.isArray(value) ? value : [value]).map(clonePatchValue);
}
function valueSetsPrimary(value) {
	return Array.isArray(value) ? value.some(valueSetsPrimary) : isRecord$1(value) && value.primary === true;
}
function enforceSinglePatchedPrimary(values, preferredIndex) {
	if (preferredIndex === void 0) return values;
	return values.map((item, index) => isRecord$1(item) && item.primary === true && index !== preferredIndex ? {
		...item,
		primary: false
	} : item);
}
function matchesSCIMType(value, selectorType) {
	return isRecord$1(value) && typeof value.type === "string" && value.type.trim().toLowerCase() === selectorType;
}
function matchesSCIMPrimary(value, selectorPrimary) {
	return isRecord$1(value) && value.primary === selectorPrimary;
}
function applySCIMMultiValuePatch(container, resolved, op, value, path) {
	const current = container[resolved.attributeName];
	const currentValues = Array.isArray(current) ? current.map(clonePatchValue) : [];
	if (!resolved.selectorType && resolved.selectorPrimary === void 0 && !resolved.subAttributeName) {
		if (op === "remove") {
			delete container[resolved.attributeName];
			return;
		}
		const additions = normalizeMultiValueAdditions(value);
		const nextValues = op === "add" ? [...currentValues, ...additions] : additions;
		const firstAddedPrimary = additions.findIndex((item) => isRecord$1(item) && item.primary === true);
		const preferredPrimary = firstAddedPrimary < 0 ? void 0 : (op === "add" ? currentValues.length : 0) + firstAddedPrimary;
		container[resolved.attributeName] = enforceSinglePatchedPrimary(nextValues, preferredPrimary);
		return;
	}
	const matches = currentValues.map((item) => {
		if (resolved.selectorPrimary !== void 0) return matchesSCIMPrimary(item, resolved.selectorPrimary);
		return resolved.selectorType ? matchesSCIMType(item, resolved.selectorType) : true;
	});
	if (!matches.some(Boolean)) {
		if (op === "remove") return;
		if (!resolved.subAttributeName) {
			const additions = normalizeMultiValueAdditions(value).map((item) => isRecord$1(item) ? {
				...item,
				...resolved.selectorType ? { type: resolved.selectorType } : {},
				...resolved.selectorPrimary === void 0 ? {} : { primary: resolved.selectorPrimary }
			} : item);
			const nextValues = [...currentValues, ...additions];
			const firstAddedPrimary = additions.findIndex((item) => isRecord$1(item) && item.primary === true);
			container[resolved.attributeName] = enforceSinglePatchedPrimary(nextValues, firstAddedPrimary < 0 ? void 0 : currentValues.length + firstAddedPrimary);
			return;
		}
		const nextValues = [...currentValues, {
			...resolved.selectorType ? { type: resolved.selectorType } : {},
			...resolved.selectorPrimary === void 0 ? {} : { primary: resolved.selectorPrimary },
			[resolved.subAttributeName]: clonePatchValue(value)
		}];
		container[resolved.attributeName] = enforceSinglePatchedPrimary(nextValues, resolved.subAttributeName.toLowerCase() === "primary" && value === true ? nextValues.length - 1 : void 0);
		return;
	}
	if (!resolved.subAttributeName) {
		if (op === "remove") {
			const remainingValues = currentValues.filter((_, index) => !matches[index]);
			if (remainingValues.length === 0) delete container[resolved.attributeName];
			else container[resolved.attributeName] = remainingValues;
			return;
		}
		const replacements = normalizeMultiValueAdditions(value);
		if (replacements.length !== 1 || !isRecord$1(replacements[0])) return invalidPatchValue(`User PATCH path ${path} requires one complex value`);
		const replacement = replacements[0];
		const nextValues = currentValues.map((item, index) => {
			if (!matches[index]) return item;
			if (!isRecord$1(item)) return invalidPatchValue(`${resolved.attributeName} must contain objects`);
			return {
				...item,
				...replacement
			};
		});
		const firstReplacedIndex = matches.findIndex(Boolean);
		container[resolved.attributeName] = enforceSinglePatchedPrimary(nextValues, replacement.primary === true && firstReplacedIndex >= 0 ? firstReplacedIndex : void 0);
		return;
	}
	const subAttributeName = resolved.subAttributeName;
	const nextValues = currentValues.map((item, index) => {
		if (!matches[index]) return item;
		if (!isRecord$1(item)) return invalidPatchValue(`${resolved.attributeName} must contain objects`);
		if (op === "remove") {
			const { [resolved.subAttributeName]: _removed, ...remaining } = item;
			return remaining;
		}
		return {
			...item,
			[subAttributeName]: clonePatchValue(value)
		};
	});
	const selectedIndex = matches.findIndex(Boolean);
	container[resolved.attributeName] = enforceSinglePatchedPrimary(nextValues, subAttributeName.toLowerCase() === "primary" && value === true && selectedIndex >= 0 ? selectedIndex : valueSetsPrimary(value) ? selectedIndex : void 0);
}
function applyGenericSCIMUserAttributePatch(document, op, path, value) {
	const resolved = resolveMutableSCIMUserPatchPath(path);
	if ("enterpriseRoot" in resolved) {
		if (op === "remove") {
			delete document[SCIM_ENTERPRISE_USER_SCHEMA];
			setEnterpriseSchemaDeclaration(document, false);
			return;
		}
		document[SCIM_ENTERPRISE_USER_SCHEMA] = mergeEnterprisePatchObject(document[SCIM_ENTERPRISE_USER_SCHEMA], value, SCIM_ENTERPRISE_USER_SCHEMA);
		setEnterpriseSchemaDeclaration(document, true);
		return;
	}
	if (!resolved.enterprise && (resolved.attributeName === "emails" || resolved.attributeName === "name")) throw createSCIMError("BAD_REQUEST", {
		detail: `User PATCH path ${path} is not supported`,
		scimType: "invalidPath"
	});
	const container = getSCIMPatchContainer(document, resolved.enterprise, op !== "remove");
	if (!container) return;
	if (resolved.enterprise && op !== "remove") setEnterpriseSchemaDeclaration(document, true);
	if (resolved.attribute.multiValued) {
		applySCIMMultiValuePatch(container, resolved, op, value, path);
		removeEmptyEnterpriseExtension(document);
		return;
	}
	if (resolved.subAttributeName) {
		const current = container[resolved.attributeName];
		if (!isRecord$1(current)) {
			if (op === "remove") return;
			container[resolved.attributeName] = { [resolved.subAttributeName]: clonePatchValue(value) };
			return;
		}
		if (op === "remove") {
			delete current[resolved.subAttributeName];
			if (Object.keys(current).length === 0) delete container[resolved.attributeName];
		} else current[resolved.subAttributeName] = clonePatchValue(value);
		removeEmptyEnterpriseExtension(document);
		return;
	}
	if (op === "remove") {
		delete container[resolved.attributeName];
		removeEmptyEnterpriseExtension(document);
		return;
	}
	if (resolved.enterprise && resolved.attributeName === "manager" && resolved.attribute.type === "complex") {
		if (value === "") {
			delete container[resolved.attributeName];
			removeEmptyEnterpriseExtension(document);
			return;
		}
		const currentManager = container[resolved.attributeName];
		container[resolved.attributeName] = {
			...isRecord$1(currentManager) ? currentManager : {},
			...normalizeManagerPatchValue(value)
		};
		return;
	}
	container[resolved.attributeName] = resolved.attribute.type === "complex" && isRecord$1(value) ? mergePatchObject(container[resolved.attributeName], value, resolved.attributeName) : clonePatchValue(value);
}
function createSCIMUserPatchDocument(user, attributes) {
	const { enterprise, ...coreAttributes } = attributes;
	return {
		...clonePatchRecord(coreAttributes),
		userName: user.userName,
		...user.externalId === null ? {} : { externalId: user.externalId },
		displayName: user.displayName,
		active: user.active,
		...enterprise ? { [SCIM_ENTERPRISE_USER_SCHEMA]: clonePatchValue(enterprise) } : {}
	};
}
function finalizeSCIMUserPatch(state, document) {
	document.userName = state.userName;
	document.externalId = state.externalId;
	document.displayName = state.displayName;
	document.active = state.active;
	document.name = {
		formatted: state.formattedName,
		...state.givenName ? { givenName: state.givenName } : {},
		...state.familyName ? { familyName: state.familyName } : {},
		...state.middleName ? { middleName: state.middleName } : {},
		...state.honorificPrefix ? { honorificPrefix: state.honorificPrefix } : {},
		...state.honorificSuffix ? { honorificSuffix: state.honorificSuffix } : {}
	};
	document.emails = clonePatchValue(state.emails);
	const parsed = APIUserSchema$1.safeParse(document);
	if (!parsed.success) {
		const issue = parsed.error.issues[0];
		return invalidPatchValue(issue ? `${issue.path.join(".") || "User"}: ${issue.message}` : "The patched User resource is invalid");
	}
	const profile = createCanonicalSCIMUserProfile(parsed.data);
	return {
		userName: profile.userName,
		primaryEmail: profile.primaryEmail,
		emails: profile.emails,
		displayName: profile.displayName,
		formattedName: profile.formattedName,
		givenName: profile.name.givenName,
		familyName: profile.name.familyName,
		middleName: profile.name.middleName,
		honorificPrefix: profile.name.honorificPrefix,
		honorificSuffix: profile.name.honorificSuffix,
		externalId: parsed.data.externalId,
		active: parsed.data.active !== false,
		attributes: profile.attributes
	};
}
/** Apply ordered User PatchOp operations without mutating persisted state. */
function applySCIMUserPatch(user, operations) {
	const attributes = readSCIMUserAttributes(user);
	const document = createSCIMUserPatchDocument(user, attributes);
	const state = {
		userName: user.userName,
		primaryEmail: user.primaryEmail,
		emails: attributes.emails,
		displayName: user.displayName,
		formattedName: attributes.name.formatted,
		givenName: attributes.name.givenName,
		familyName: attributes.name.familyName,
		middleName: attributes.name.middleName,
		honorificPrefix: attributes.name.honorificPrefix,
		honorificSuffix: attributes.name.honorificSuffix,
		externalId: user.externalId ?? void 0,
		active: user.active,
		attributes
	};
	function applyAttribute(op, path, value) {
		const schemaRelativePath = stripSCIMCoreAttributePrefix("User", path.trim());
		const normalizedPath = normalizePatchPath(path);
		if (normalizedPath === "id" || normalizedPath === "schemas" || normalizedPath === "meta" || normalizedPath.startsWith("meta.")) rejectReadOnlyAttribute(path);
		switch (normalizedPath) {
			case "username":
				if (op === "remove") rejectReadOnlyAttribute("userName");
				state.userName = readNonEmptyString(value, "userName");
				return;
			case "externalid":
				state.externalId = op === "remove" ? void 0 : readNonEmptyString(value, "externalId");
				return;
			case "active": {
				if (op === "remove") {
					state.active = true;
					return;
				}
				const scalar = unwrapSinglePatchValue(value);
				if (typeof scalar !== "boolean") invalidPatchValue("active must be a boolean");
				state.active = scalar;
				return;
			}
			case "displayname":
				state.displayName = op === "remove" ? state.formattedName : readNonEmptyString(value, "displayName");
				return;
			case "name": {
				if (op === "remove") {
					state.givenName = void 0;
					state.familyName = void 0;
					state.middleName = void 0;
					state.honorificPrefix = void 0;
					state.honorificSuffix = void 0;
					setFormattedName(state, state.displayName || state.primaryEmail);
					return;
				}
				const name = readName(value);
				if (name.givenName !== void 0) setNamePart(state, "givenName", name.givenName);
				if (name.familyName !== void 0) setNamePart(state, "familyName", name.familyName);
				if (name.middleName !== void 0) setNamePart(state, "middleName", name.middleName);
				if (name.honorificPrefix !== void 0) setNamePart(state, "honorificPrefix", name.honorificPrefix);
				if (name.honorificSuffix !== void 0) setNamePart(state, "honorificSuffix", name.honorificSuffix);
				if (name.formatted !== void 0) setFormattedName(state, name.formatted);
				return;
			}
			case "name.formatted":
				setFormattedName(state, op === "remove" ? composeName(state) || state.displayName || state.primaryEmail : readNonEmptyString(value, "name.formatted"));
				return;
			case "name.givenname":
				setNamePart(state, "givenName", op === "remove" ? void 0 : readNonEmptyString(value, "name.givenName"));
				return;
			case "name.familyname":
				setNamePart(state, "familyName", op === "remove" ? void 0 : readNonEmptyString(value, "name.familyName"));
				return;
			case "name.middlename":
				setNamePart(state, "middleName", op === "remove" ? void 0 : readNonEmptyString(value, "name.middleName"));
				return;
			case "name.honorificprefix":
				setNamePart(state, "honorificPrefix", op === "remove" ? void 0 : readNonEmptyString(value, "name.honorificPrefix"));
				return;
			case "name.honorificsuffix":
				setNamePart(state, "honorificSuffix", op === "remove" ? void 0 : readNonEmptyString(value, "name.honorificSuffix"));
				return;
			case "emails":
				if (op === "remove") invalidPatchValue("emails cannot be removed");
				if (op === "add") {
					addEmails(state, value);
					return;
				}
				setEmails(state, readEmailSet(value, state.userName));
				return;
			case "emails.value":
				if (op === "remove") invalidPatchValue("emails.value cannot be removed");
				replaceAllEmailValues(state, value);
				return;
			default: {
				const emailTypeMatch = EMAIL_TYPE_VALUE_PATH.exec(schemaRelativePath);
				if (emailTypeMatch?.[1]) {
					const selectorType = emailTypeMatch[1].trim().toLowerCase();
					if (op === "remove") {
						const remaining = state.emails.filter((email) => email.type !== selectorType);
						if (remaining.length === state.emails.length) return;
						setEmails(state, remaining);
						return;
					}
					replaceSelectedEmail(state, selectorType, value);
					return;
				}
				if (EMAIL_PRIMARY_VALUE_PATH.test(schemaRelativePath)) {
					if (op === "remove") invalidPatchValue("emails.value cannot be removed");
					replacePrimaryEmail(state, value);
					return;
				}
				applyGenericSCIMUserAttributePatch(document, op, path, value);
				return;
			}
		}
	}
	for (const operation of operations) {
		const path = operation.path?.trim();
		if (path) {
			applyAttribute(operation.op, path, operation.value);
			continue;
		}
		if (operation.op === "remove") throw createSCIMError("BAD_REQUEST", {
			detail: "A remove User PATCH operation requires a path",
			scimType: "noTarget"
		});
		if (!isRecord$1(operation.value)) invalidPatchValue("A pathless User PATCH value must be an object");
		for (const [attribute, value] of Object.entries(operation.value)) applyAttribute(operation.op, attribute, value);
	}
	return finalizeSCIMUserPatch(state, document);
}
//#endregion
//#region src/user-provisioning.ts
const { inputSchema: APIUserSchema, openAPISchema: OpenAPIUserResourceSchema } = SCIM_RESOURCE_SCHEMA_REGISTRY.User;
function requireUserAttributeProjection(input) {
	const projection = parseSCIMAttributeProjection("User", input);
	if (!projection.ok) throw createSCIMError("BAD_REQUEST", {
		detail: projection.error.detail,
		scimType: projection.error.scimType
	});
	return projection.value;
}
function createUserNameKey(connectionId, userName) {
	return createScopedKey([
		"scim-user-name",
		connectionId,
		userName
	]);
}
function createExternalIdKey(connectionId, externalId) {
	if (!externalId) return void 0;
	return createSCIMUserExternalIdKey(connectionId, externalId);
}
function createConnectionUserKey(connectionId, userId) {
	return createScopedKey([
		"scim-user",
		connectionId,
		userId
	]);
}
function areMembershipGroupsLocked(memberships, lockedGroups) {
	const membershipGroupIds = new Set(memberships.map((membership) => membership.groupId));
	return membershipGroupIds.size === lockedGroups.length && lockedGroups.every((group) => membershipGroupIds.has(group.id));
}
function createUserCollectionWhere(connectionId, filters) {
	const where = [{
		field: "connectionId",
		value: connectionId
	}];
	for (const filter of filters) switch (filter.attribute) {
		case "id":
			where.push({
				field: "id",
				value: filter.value
			});
			break;
		case "userName":
			where.push({
				field: "userNameKey",
				value: createUserNameKey(connectionId, filter.value.toLowerCase())
			});
			break;
		case "externalId":
			where.push({
				field: "externalIdKey",
				value: createExternalIdKey(connectionId, filter.value) ?? ""
			});
			break;
		case "emails.value":
			where.push({
				field: "emailValueIndex",
				value: `|${createSCIMEmailValueToken(filter.value)}|`,
				operator: "contains"
			});
			break;
		case "emails.work.value":
			where.push({
				field: "workEmailValueIndex",
				value: `|${createSCIMEmailValueToken(filter.value)}|`,
				operator: "contains"
			});
			break;
	}
	return where;
}
function createUserResource(baseURL, scimUser) {
	const { [SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.canonicalAttribute]: enterprise, ...attributes } = readSCIMUserAttributes(scimUser);
	return {
		...attributes,
		id: scimUser.id,
		...scimUser.externalId ? { externalId: scimUser.externalId } : {},
		userName: scimUser.userName,
		displayName: scimUser.displayName,
		active: scimUser.active,
		...enterprise ? { [SCIM_ENTERPRISE_USER_SCHEMA_DESCRIPTOR.responseAttribute]: enterprise } : {},
		meta: {
			resourceType: "User",
			created: scimUser.createdAt,
			lastModified: scimUser.updatedAt,
			location: getResourceURL(`/scim/v2/Users/${encodeURIComponent(scimUser.id)}`, baseURL)
		}
	};
}
async function findSCIMUser(adapter, connection, scimUserId) {
	const scimUser = await adapter.findOne({
		model: "scimUser",
		where: [{
			field: "id",
			value: scimUserId
		}, {
			field: "connectionId",
			value: connection.id
		}]
	});
	if (scimUser && scimUser.provisioningDomainId !== connection.provisioningDomainId) throw createSCIMError("CONFLICT", { detail: "The connection provisioningDomainId changed after resources were created" });
	return scimUser;
}
async function requireSCIMSubject(adapter, userId) {
	const subject = await adapter.findOne({
		model: "scimSubject",
		where: [{
			field: "userId",
			value: userId
		}]
	});
	if (!subject) throw createSCIMError("INTERNAL_SERVER_ERROR", { detail: "The SCIM User subject is missing" });
	return subject;
}
async function assertConnectionUserAvailable(adapter, connectionId, userId) {
	if (await adapter.findOne({
		model: "scimUser",
		where: [{
			field: "connectionId",
			value: connectionId
		}, {
			field: "connectionUserKey",
			value: createConnectionUserKey(connectionId, userId)
		}]
	})) throw createSCIMError("CONFLICT", {
		detail: "This connection already provisions the resolved Better Auth User",
		scimType: "uniqueness"
	});
}
async function assertUserConnectionDomainStable(adapter, connection) {
	if (await adapter.findOne({
		model: "scimUser",
		where: [{
			field: "connectionId",
			value: connection.id
		}, {
			field: "provisioningDomainId",
			value: connection.provisioningDomainId,
			operator: "ne"
		}]
	})) throw createSCIMError("CONFLICT", { detail: "The connection provisioningDomainId changed after resources were created" });
}
async function assertSCIMUserKeysAvailable(adapter, input) {
	const existingUserName = await adapter.findOne({
		model: "scimUser",
		where: [{
			field: "connectionId",
			value: input.connectionId
		}, {
			field: "userNameKey",
			value: input.userNameKey
		}]
	});
	if (existingUserName && existingUserName.id !== input.excludeSCIMUserId) throw createSCIMError("CONFLICT", {
		detail: "SCIM User userName already exists",
		scimType: "uniqueness"
	});
	if (!input.externalIdKey) return;
	const existingExternalId = await adapter.findOne({
		model: "scimUser",
		where: [{
			field: "connectionId",
			value: input.connectionId
		}, {
			field: "externalIdKey",
			value: input.externalIdKey
		}]
	});
	if (existingExternalId && existingExternalId.id !== input.excludeSCIMUserId) throw createSCIMError("CONFLICT", {
		detail: "SCIM User externalId already exists",
		scimType: "uniqueness"
	});
}
async function assertBetterAuthEmailAvailable(adapter, email, excludeUserId) {
	const existingUser = await adapter.findOne({
		model: "user",
		where: [{
			field: "email",
			value: email
		}]
	});
	if (existingUser && existingUser.id !== excludeUserId) throw createSCIMError("CONFLICT", {
		detail: "A Better Auth User already uses this email",
		scimType: "uniqueness"
	});
}
async function updateManagedBetterAuthUser(adapter, internalAdapter, input) {
	const user = await adapter.findOne({
		model: "user",
		where: [{
			field: "id",
			value: input.userId
		}]
	});
	if (!user) throw createSCIMError("CONFLICT", { detail: "The linked Better Auth User no longer exists" });
	await assertBetterAuthEmailAvailable(adapter, input.email, user.id);
	const updatedUser = await internalAdapter.updateUser(user.id, {
		email: input.email,
		name: input.name,
		...user.email !== input.email ? { emailVerified: false } : {},
		updatedAt: input.updatedAt
	});
	if (!updatedUser) throw createSCIMError("CONFLICT", { detail: "The linked Better Auth User no longer exists" });
	return updatedUser;
}
function createSCIMUser(authMiddleware, identity, projection) {
	return createAuthEndpoint("/scim/v2/Users", {
		method: "POST",
		body: APIUserSchema,
		query: scimAttributeProjectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Create SCIM User",
				responses: {
					"201": {
						description: "SCIM User resource",
						content: createSCIMOpenAPIContent(OpenAPIUserResourceSchema)
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const connection = ctx.context.scimConnection;
		const attributeProjection = requireUserAttributeProjection(ctx.query ?? {});
		const profile = createCanonicalSCIMUserProfile(ctx.body);
		const active = ctx.body.active !== false;
		const userNameKey = createUserNameKey(connection.id, profile.userName.toLowerCase());
		const externalIdKey = createExternalIdKey(connection.id, ctx.body.externalId);
		await assertUserConnectionDomainStable(adapter, connection);
		await assertSCIMUserKeysAvailable(adapter, {
			connectionId: connection.id,
			userNameKey,
			externalIdKey
		});
		const resolvedIdentity = await identity.resolveUser({
			connectionId: connection.id,
			provisioningDomainId: connection.provisioningDomainId,
			resource: {
				...profile.attributes,
				...ctx.body.externalId ? { externalId: ctx.body.externalId } : {},
				userName: profile.userName,
				primaryEmail: profile.primaryEmail,
				displayName: profile.displayName,
				active
			}
		}, { database: adapter });
		const { resolution } = resolvedIdentity;
		const scimUser = await runSCIMCreateWithUniquenessCheck(() => runIdentityMutationTransaction(adapter, async (trx) => {
			await assertSCIMUserKeysAvailable(trx, {
				connectionId: connection.id,
				userNameKey,
				externalIdKey
			});
			let user;
			if (resolution.action === "create") {
				await assertBetterAuthEmailAvailable(trx, profile.primaryEmail);
				user = await ctx.context.internalAdapter.createUser({
					email: profile.primaryEmail,
					name: profile.displayName
				}, { method: "scim" });
			} else {
				const linkedUser = await trx.findOne({
					model: "user",
					where: [{
						field: "id",
						value: resolution.userId
					}]
				});
				if (!linkedUser) throw createSCIMError("CONFLICT", { detail: "The resolved Better Auth User does not exist" });
				user = linkedUser;
			}
			await assertConnectionUserAvailable(trx, connection.id, user.id);
			const now = /* @__PURE__ */ new Date();
			let subject = await identity.acquireSubject(trx, user.id, now);
			const createdSCIMUser = await trx.create({
				model: "scimUser",
				data: {
					connectionId: connection.id,
					provisioningDomainId: connection.provisioningDomainId,
					userId: user.id,
					connectionUserKey: createConnectionUserKey(connection.id, user.id),
					userName: profile.userName,
					userNameKey,
					primaryEmail: profile.primaryEmail,
					workEmailValueIndex: createSCIMEmailValueIndex(profile.emails, "work"),
					emailValueIndex: createSCIMEmailValueIndex(profile.emails),
					displayName: profile.displayName,
					formattedName: profile.formattedName,
					givenName: profile.name.givenName,
					familyName: profile.name.familyName,
					serializedEmails: serializeSCIMEmails(profile.emails),
					serializedAttributes: serializeSCIMUserAttributes(profile.attributes),
					externalId: ctx.body.externalId,
					externalIdKey,
					active,
					orderKey: createSCIMOrderKey(now),
					createdAt: now,
					updatedAt: now
				}
			});
			if (resolution.action === "create" || resolution.profile === "manage") {
				subject = await identity.claimProfileSource(trx, subject, createdSCIMUser.id, now);
				if (resolution.action === "link") await updateManagedBetterAuthUser(trx, ctx.context.internalAdapter, {
					userId: user.id,
					email: profile.primaryEmail,
					name: profile.displayName,
					updatedAt: now
				});
			}
			await identity.consumeTombstone(trx, resolvedIdentity.tombstoneId);
			await projection.reconcileUser({
				database: trx,
				auth: ctx.context,
				provisioningDomainId: connection.provisioningDomainId,
				scimUserId: createdSCIMUser.id
			});
			await identity.reconcileUser({
				database: trx,
				auth: ctx.context,
				subject
			});
			await fenceActiveSCIMConnection(trx, connection.id);
			return createdSCIMUser;
		}, resolution.action === "link" ? { subjectCreationUserId: resolution.userId } : void 0), async () => {
			await assertSCIMUserKeysAvailable(adapter, {
				connectionId: connection.id,
				userNameKey,
				externalIdKey
			});
			if (resolution.action === "create") {
				await assertBetterAuthEmailAvailable(adapter, profile.primaryEmail);
				return;
			}
			await assertConnectionUserAvailable(adapter, connection.id, resolution.userId);
		});
		const completeResource = createUserResource(ctx.context.baseURL, scimUser);
		const resource = projectSCIMResourceAttributes(completeResource, attributeProjection);
		ctx.setStatus(201);
		ctx.setHeader("location", completeResource.meta.location);
		ctx.setHeader("content-location", completeResource.meta.location);
		return ctx.json(resource);
	});
}
function getSCIMUser(authMiddleware) {
	return createAuthEndpoint("/scim/v2/Users/:userId", {
		method: "GET",
		query: scimAttributeProjectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Get SCIM User",
				responses: {
					"200": {
						description: "SCIM User resource",
						content: createSCIMOpenAPIContent(OpenAPIUserResourceSchema)
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const scimUser = await findSCIMUser(adapter, ctx.context.scimConnection, ctx.params.userId);
		if (!scimUser) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
		const attributeProjection = requireUserAttributeProjection(ctx.query ?? {});
		return ctx.json(projectSCIMResourceAttributes(createUserResource(ctx.context.baseURL, scimUser), attributeProjection));
	});
}
function listSCIMUsers(authMiddleware) {
	return createAuthEndpoint("/scim/v2/Users", {
		method: "GET",
		query: scimCollectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "List SCIM Users",
				responses: {
					"200": {
						description: "SCIM User list",
						content: createSCIMOpenAPIContent({
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
						})
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		await assertUserConnectionDomainStable(adapter, ctx.context.scimConnection);
		const parsedQuery = parseSCIMCollectionQuery("User", ctx.query ?? {});
		if (!parsedQuery.ok) throw createSCIMError("BAD_REQUEST", {
			detail: parsedQuery.error.detail,
			scimType: parsedQuery.error.scimType
		});
		const { filters, pagination, projection: attributeProjection } = parsedQuery.value;
		const where = createUserCollectionWhere(ctx.context.scimConnection.id, filters);
		const totalResults = await adapter.count({
			model: "scimUser",
			where
		});
		const resources = (pagination.count === 0 ? [] : await adapter.findMany({
			model: "scimUser",
			where,
			limit: pagination.count,
			offset: pagination.offset,
			sortBy: {
				field: "orderKey",
				direction: "asc"
			}
		})).map((scimUser) => projectSCIMResourceAttributes(createUserResource(ctx.context.baseURL, scimUser), attributeProjection));
		return ctx.json({
			schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
			totalResults,
			startIndex: pagination.startIndex,
			itemsPerPage: resources.length,
			Resources: resources
		});
	});
}
function replaceSCIMUser(authMiddleware, identity, projection) {
	return createAuthEndpoint("/scim/v2/Users/:userId", {
		method: "PUT",
		body: APIUserSchema,
		query: scimAttributeProjectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Replace SCIM User",
				responses: {
					"200": {
						description: "SCIM User resource",
						content: createSCIMOpenAPIContent(OpenAPIUserResourceSchema)
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const connection = ctx.context.scimConnection;
		const attributeProjection = requireUserAttributeProjection(ctx.query ?? {});
		const scimUser = await findSCIMUser(adapter, connection, ctx.params.userId);
		if (!scimUser) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
		const profile = createCanonicalSCIMUserProfile(ctx.body);
		const userNameKey = createUserNameKey(connection.id, profile.userName.toLowerCase());
		const externalIdKey = createExternalIdKey(connection.id, ctx.body.externalId);
		await assertSCIMUserKeysAvailable(adapter, {
			connectionId: connection.id,
			userNameKey,
			externalIdKey,
			excludeSCIMUserId: scimUser.id
		});
		const active = ctx.body.active !== false;
		const updatedSCIMUser = await runIdentityMutationTransaction(adapter, async (trx) => {
			const currentSource = await findSCIMUser(trx, connection, scimUser.id);
			if (!currentSource) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
			const updatedAt = /* @__PURE__ */ new Date();
			const subject = await identity.acquireSubject(trx, currentSource.userId, updatedAt);
			await assertSCIMUserKeysAvailable(trx, {
				connectionId: connection.id,
				userNameKey,
				externalIdKey,
				excludeSCIMUserId: currentSource.id
			});
			if (subject.profileSourceId === currentSource.id) await updateManagedBetterAuthUser(trx, ctx.context.internalAdapter, {
				userId: currentSource.userId,
				email: profile.primaryEmail,
				name: profile.displayName,
				updatedAt
			});
			const updatedSource = await trx.update({
				model: "scimUser",
				where: [{
					field: "id",
					value: currentSource.id
				}, {
					field: "connectionId",
					value: connection.id
				}],
				update: {
					userName: profile.userName,
					userNameKey,
					primaryEmail: profile.primaryEmail,
					workEmailValueIndex: createSCIMEmailValueIndex(profile.emails, "work"),
					emailValueIndex: createSCIMEmailValueIndex(profile.emails),
					displayName: profile.displayName,
					formattedName: profile.formattedName,
					givenName: profile.name.givenName ?? null,
					familyName: profile.name.familyName ?? null,
					serializedEmails: serializeSCIMEmails(profile.emails),
					serializedAttributes: serializeSCIMUserAttributes(profile.attributes),
					externalId: ctx.body.externalId ?? null,
					externalIdKey: externalIdKey ?? null,
					active,
					updatedAt
				}
			});
			if (!updatedSource) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
			await projection.reconcileUser({
				database: trx,
				auth: ctx.context,
				provisioningDomainId: connection.provisioningDomainId,
				scimUserId: updatedSource.id
			});
			await identity.reconcileUser({
				database: trx,
				auth: ctx.context,
				subject
			});
			await fenceActiveSCIMConnection(trx, connection.id);
			return updatedSource;
		});
		const completeResource = createUserResource(ctx.context.baseURL, updatedSCIMUser);
		ctx.setHeader("location", completeResource.meta.location);
		return ctx.json(projectSCIMResourceAttributes(completeResource, attributeProjection));
	});
}
function patchSCIMUser(authMiddleware, identity, projection) {
	return createAuthEndpoint("/scim/v2/Users/:userId", {
		method: "PATCH",
		body: patchSCIMUserBodySchema,
		query: scimAttributeProjectionQuerySchema.optional(),
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Patch SCIM User",
				responses: {
					"200": {
						description: "Updated SCIM User resource",
						content: createSCIMOpenAPIContent(OpenAPIUserResourceSchema)
					},
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const attributeProjection = requireUserAttributeProjection(ctx.query ?? {});
		const scimUser = await findSCIMUser(adapter, ctx.context.scimConnection, ctx.params.userId);
		if (!scimUser) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
		const connection = ctx.context.scimConnection;
		const updatedSCIMUser = await runIdentityMutationTransaction(adapter, async (trx) => {
			const sourceBeforeLock = await findSCIMUser(trx, connection, scimUser.id);
			if (!sourceBeforeLock) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
			const subjectBeforeLock = await requireSCIMSubject(trx, sourceBeforeLock.userId);
			const updatedAt = /* @__PURE__ */ new Date();
			const subject = await identity.acquireSubjectRevision(trx, subjectBeforeLock, updatedAt);
			const currentSource = await findSCIMUser(trx, connection, sourceBeforeLock.id);
			if (!currentSource) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
			if (currentSource.userId !== sourceBeforeLock.userId) throw createSCIMError("CONFLICT", { detail: "The SCIM User identity changed concurrently" });
			const patch = applySCIMUserPatch(currentSource, ctx.body.Operations);
			if (!scimUserPatchChangesState(currentSource, patch)) {
				await fenceActiveSCIMConnection(trx, connection.id);
				return currentSource;
			}
			const userNameKey = createUserNameKey(connection.id, patch.userName.toLowerCase());
			const externalIdKey = createExternalIdKey(connection.id, patch.externalId);
			await assertSCIMUserKeysAvailable(trx, {
				connectionId: connection.id,
				userNameKey,
				externalIdKey,
				excludeSCIMUserId: currentSource.id
			});
			if (subject.profileSourceId === currentSource.id) await updateManagedBetterAuthUser(trx, ctx.context.internalAdapter, {
				userId: currentSource.userId,
				email: patch.primaryEmail,
				name: patch.displayName,
				updatedAt
			});
			const updatedSCIMUser = await trx.update({
				model: "scimUser",
				where: [{
					field: "id",
					value: currentSource.id
				}, {
					field: "connectionId",
					value: connection.id
				}],
				update: {
					userName: patch.userName,
					userNameKey,
					primaryEmail: patch.primaryEmail,
					workEmailValueIndex: createSCIMEmailValueIndex(patch.emails, "work"),
					emailValueIndex: createSCIMEmailValueIndex(patch.emails),
					displayName: patch.displayName,
					formattedName: patch.formattedName,
					givenName: patch.givenName ?? null,
					familyName: patch.familyName ?? null,
					serializedEmails: serializeSCIMEmails(patch.emails),
					serializedAttributes: serializeSCIMUserAttributes(patch.attributes),
					externalId: patch.externalId ?? null,
					externalIdKey: externalIdKey ?? null,
					active: patch.active,
					updatedAt
				}
			});
			if (!updatedSCIMUser) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
			await projection.reconcileUser({
				database: trx,
				auth: ctx.context,
				provisioningDomainId: connection.provisioningDomainId,
				scimUserId: updatedSCIMUser.id
			});
			await identity.reconcileUser({
				database: trx,
				auth: ctx.context,
				subject
			});
			await fenceActiveSCIMConnection(trx, connection.id);
			return updatedSCIMUser;
		});
		const completeResource = createUserResource(ctx.context.baseURL, updatedSCIMUser);
		ctx.setHeader("location", completeResource.meta.location);
		return ctx.json(projectSCIMResourceAttributes(completeResource, attributeProjection));
	});
}
function deleteSCIMUser(authMiddleware, identity, projection) {
	return createAuthEndpoint("/scim/v2/Users/:userId", {
		method: "DELETE",
		metadata: defineSCIMEndpointMetadata({
			...HIDE_METADATA,
			allowedMediaTypes: SCIM_REQUEST_MEDIA_TYPES,
			openapi: {
				summary: "Delete SCIM User",
				responses: {
					"204": { description: "SCIM User deleted" },
					...SCIMErrorOpenAPISchemas
				}
			}
		}),
		use: [authMiddleware]
	}, async (ctx) => {
		const adapter = ctx.context.adapter;
		const scimUser = await findSCIMUser(adapter, ctx.context.scimConnection, ctx.params.userId);
		if (!scimUser) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
		await runGroupMutationTransaction(adapter, async (trx) => {
			const sourceBeforeLocks = await findSCIMUser(trx, ctx.context.scimConnection, scimUser.id);
			if (!sourceBeforeLocks) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
			const subjectBeforeLocks = await requireSCIMSubject(trx, sourceBeforeLocks.userId);
			const memberships = await trx.findMany({
				model: "scimGroupMember",
				where: [{
					field: "connectionId",
					value: ctx.context.scimConnection.id
				}, {
					field: "scimUserId",
					value: sourceBeforeLocks.id
				}]
			});
			const lockedGroups = await acquireSCIMGroupMutationLocks(trx, ctx.context.scimConnection, memberships.map((membership) => membership.groupId));
			const now = /* @__PURE__ */ new Date();
			let subject = await identity.acquireSubjectRevision(trx, subjectBeforeLocks, now);
			const currentSource = await findSCIMUser(trx, ctx.context.scimConnection, sourceBeforeLocks.id);
			if (!currentSource) throw createSCIMError("NOT_FOUND", { detail: "SCIM User not found" });
			if (currentSource.userId !== sourceBeforeLocks.userId) throw createSCIMError("CONFLICT", { detail: "The SCIM User identity changed concurrently" });
			if (!areMembershipGroupsLocked(await trx.findMany({
				model: "scimGroupMember",
				where: [{
					field: "connectionId",
					value: ctx.context.scimConnection.id
				}, {
					field: "scimUserId",
					value: currentSource.id
				}]
			}), lockedGroups)) throwConcurrentSCIMGroupMutation();
			await identity.preserveDeletedSource(trx, {
				source: currentSource,
				subject,
				deletedAt: now
			});
			await trx.deleteMany({
				model: "scimGroupMember",
				where: [{
					field: "connectionId",
					value: ctx.context.scimConnection.id
				}, {
					field: "scimUserId",
					value: currentSource.id
				}]
			});
			await markSCIMGroupsModified(trx, ctx.context.scimConnection.id, lockedGroups, now);
			await trx.deleteMany({
				model: "scimProjectionGrant",
				where: [{
					field: "scimUserId",
					value: currentSource.id
				}]
			});
			await trx.delete({
				model: "scimUser",
				where: [{
					field: "id",
					value: currentSource.id
				}, {
					field: "connectionId",
					value: ctx.context.scimConnection.id
				}]
			});
			subject = await identity.clearProfileSource(trx, subject, currentSource.id, now);
			await projection.reconcileUser({
				database: trx,
				auth: ctx.context,
				provisioningDomainId: currentSource.provisioningDomainId,
				scimUserId: currentSource.id,
				userId: currentSource.userId
			});
			await identity.reconcileUser({
				database: trx,
				auth: ctx.context,
				subject
			});
			await fenceActiveSCIMConnection(trx, ctx.context.scimConnection.id);
		});
		ctx.setStatus(204);
	});
}
//#endregion
//#region src/version.ts
const PACKAGE_VERSION = "1.7.1";
//#endregion
//#region src/index.ts
const SCIM_RESPONSE_MARKER = "x-better-auth-scim-response";
const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
function isRecord(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isSCIMErrorBody(value) {
	return isRecord(value) && Array.isArray(value.schemas) && value.schemas.includes(SCIM_ERROR_SCHEMA);
}
function isAPIErrorLike(value) {
	return isRecord(value) && (typeof value.status === "string" && value.status in statusCodes || typeof value.status === "number" && Object.values(statusCodes).includes(value.status)) && typeof value.statusCode === "number" && typeof value.message === "string" && "body" in value;
}
function createSCIMErrorResponse(status, detail, scimType) {
	const error = createSCIMError(status, {
		detail,
		...scimType ? { scimType } : {}
	});
	return new Response(JSON.stringify(error.body), {
		status: error.statusCode,
		headers: { "content-type": SCIM_MEDIA_TYPE }
	});
}
function validateConnections(options) {
	const authenticationProvided = options.authentication !== void 0;
	const managedConnectionsProvided = options.managedConnections !== void 0;
	const hasBearerTokenVerifier = typeof options.authentication?.verifyBearerToken === "function";
	if (authenticationProvided && !hasBearerTokenVerifier) throw new BetterAuthError("SCIM authentication requires a callable verifyBearerToken.");
	if (managedConnectionsProvided) {
		if (typeof options.managedConnections?.credentialHashSecret !== "string" || options.managedConnections.credentialHashSecret.length < 32) throw new BetterAuthError("SCIM managed credentialHashSecret must contain at least 32 characters.");
		const maxActiveCredentials = options.managedConnections.maxActiveCredentials ?? 5;
		if (!Number.isInteger(maxActiveCredentials) || maxActiveCredentials < 1 || maxActiveCredentials > 100) throw new BetterAuthError("SCIM managed maxActiveCredentials must be an integer between 1 and 100.");
		const lastUsedWriteIntervalSeconds = options.managedConnections.lastUsedWriteIntervalSeconds ?? 300;
		if (!Number.isInteger(lastUsedWriteIntervalSeconds) || lastUsedWriteIntervalSeconds < 0) throw new BetterAuthError("SCIM managed lastUsedWriteIntervalSeconds must be a non-negative integer.");
	}
	if (options.connections.length === 0 && !hasBearerTokenVerifier && !managedConnectionsProvided) throw new BetterAuthError("The scim plugin requires a provisioning connection, bearer token verifier, or managed connection catalog.");
	const connectionIds = /* @__PURE__ */ new Set();
	const bearerTokens = /* @__PURE__ */ new Set();
	for (const connection of options.connections) {
		if (!isValidSCIMConnectionIdentifier(connection.id)) throw new BetterAuthError("SCIM connection ids must be trimmed and contain between 1 and 255 characters.");
		if (connection.id.startsWith("ba_scim_connection_")) throw new BetterAuthError(`Static SCIM connection ids cannot use the reserved "${SCIM_MANAGED_CONNECTION_ID_PREFIX}" prefix.`);
		if (connection.credentials.length === 0 && !hasBearerTokenVerifier) throw new BetterAuthError("SCIM connections require a static credential or bearer token verifier.");
		if (connection.provisioningDomainId !== void 0 && !isValidSCIMConnectionIdentifier(connection.provisioningDomainId)) throw new BetterAuthError("SCIM provisioning domain ids must be trimmed and contain between 1 and 255 characters.");
		if (connectionIds.has(connection.id)) throw new BetterAuthError("SCIM connection ids must be unique.");
		connectionIds.add(connection.id);
		const credentialIds = /* @__PURE__ */ new Set();
		for (const credential of connection.credentials) {
			if (!isValidSCIMCredentialId(credential.id)) throw new BetterAuthError("SCIM credential ids must be trimmed and contain between 1 and 255 characters.");
			if (credentialIds.has(credential.id)) throw new BetterAuthError("SCIM credential ids must be unique within a connection.");
			credentialIds.add(credential.id);
			if (!credential.token || /\s/.test(credential.token)) throw new BetterAuthError("SCIM bearer tokens cannot be empty or contain whitespace.");
			if (credential.scopes && !areValidSCIMScopes(credential.scopes)) throw new BetterAuthError("SCIM credential scopes must be non-empty, unique, and supported.");
			if (credential.expiresAt !== void 0 && (!(credential.expiresAt instanceof Date) || Number.isNaN(credential.expiresAt.getTime()))) throw new BetterAuthError("SCIM credential expiry must be a valid Date.");
			if (bearerTokens.has(credential.token)) throw new BetterAuthError("SCIM bearer tokens must be unique.");
			bearerTokens.add(credential.token);
		}
	}
}
/**
* Adds an inbound SCIM 2.0 service provider to Better Auth.
*
* Every configured connection owns an isolated set of SCIM resources. The
* plugin does not require the organization plugin and never represents a
* provisioned identity as an authentication account.
*/
function createSCIMPlugin(options) {
	const connectionMiddleware = createSCIMConnectionMiddleware(options);
	const identity = createSCIMIdentityCoordinator(options);
	const projection = createSCIMProjectionCoordinator(options);
	return {
		id: "scim",
		version: PACKAGE_VERSION,
		init(ctx) {
			assertNativeSCIMTransactions(ctx.adapter);
		},
		async onRequest(request) {
			const path = new URL(request.url).pathname;
			if (!path.includes("/scim/v2/")) return;
			if (request.method === "DELETE") return { request: new Request(request.url, {
				method: "DELETE",
				headers: request.headers,
				signal: request.signal
			}) };
			if (![
				"POST",
				"PUT",
				"PATCH"
			].includes(request.method)) return;
			const mediaType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
			if (mediaType !== "application/json" && mediaType !== "application/scim+json") return { response: createSCIMErrorResponse("UNSUPPORTED_MEDIA_TYPE", "SCIM requests must use application/scim+json or application/json") };
			let body;
			try {
				body = JSON.parse(await request.clone().text());
			} catch {
				return { response: createSCIMErrorResponse("BAD_REQUEST", "SCIM request body must contain valid JSON", "invalidSyntax") };
			}
			const isUserMutation = /\/scim\/v2\/Users(?:\/[^/]+)?$/.test(path) && (request.method === "POST" && path.endsWith("/Users") || ["PUT", "PATCH"].includes(request.method) && !path.endsWith("/Users"));
			const isGroupCreate = request.method === "POST" && /\/scim\/v2\/Groups$/.test(path);
			const isGroupMutation = /\/scim\/v2\/Groups(?:\/[^/]+)?$/.test(path) && (isGroupCreate || ["PUT", "PATCH"].includes(request.method) && !path.endsWith("/Groups"));
			let normalizedBody = body;
			if (isGroupMutation) {
				const groupNormalization = normalizeMicrosoftEntraGroupSchema(normalizedBody, isGroupCreate && options.compatibility?.microsoftEntra?.acceptLegacyGroupSchema === true);
				if (!groupNormalization.ok) return { response: createSCIMErrorResponse("BAD_REQUEST", groupNormalization.detail, "invalidValue") };
				normalizedBody = groupNormalization.body;
			}
			if (isUserMutation) normalizedBody = normalizeSCIMUserEntraCompatibilityRequestBody(request.method, normalizedBody);
			if (normalizedBody === body) return;
			const headers = new Headers(request.headers);
			headers.delete("content-length");
			return { request: new Request(request.url, {
				method: request.method,
				headers,
				body: JSON.stringify(normalizedBody),
				signal: request.signal
			}) };
		},
		endpoints: {
			...createSCIMManagedConnectionEndpoints(options.managedConnections ? resolveManagedConnectionOptions(options.managedConnections) : void 0, projection, identity),
			decommissionSCIMConnection: createDecommissionSCIMConnectionEndpoint(projection, identity),
			reconcileSCIMProjection: createReconcileSCIMProjectionEndpoint(options, projection),
			createSCIMGroup: createSCIMGroup(connectionMiddleware, projection),
			deleteSCIMGroup: deleteSCIMGroup(connectionMiddleware, projection),
			getSCIMGroup: getSCIMGroup(connectionMiddleware),
			listSCIMGroups: listSCIMGroups(connectionMiddleware),
			patchSCIMGroup: patchSCIMGroup(connectionMiddleware, projection),
			replaceSCIMGroup: replaceSCIMGroup(connectionMiddleware, projection),
			createSCIMUser: createSCIMUser(connectionMiddleware, identity, projection),
			deleteSCIMUser: deleteSCIMUser(connectionMiddleware, identity, projection),
			getSCIMUser: getSCIMUser(connectionMiddleware),
			listSCIMUsers: listSCIMUsers(connectionMiddleware),
			patchSCIMUser: patchSCIMUser(connectionMiddleware, identity, projection),
			replaceSCIMUser: replaceSCIMUser(connectionMiddleware, identity, projection),
			getSCIMServiceProviderConfig,
			getSCIMSchemas,
			getSCIMSchema,
			getSCIMResourceTypes,
			getSCIMResourceType
		},
		async onResponse(response) {
			if (response.headers.get(SCIM_RESPONSE_MARKER) !== "1") return;
			const headers = new Headers(response.headers);
			headers.delete(SCIM_RESPONSE_MARKER);
			headers.set("content-type", SCIM_MEDIA_TYPE);
			return { response: new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers
			}) };
		},
		hooks: { after: [{
			matcher: (context) => context.path?.startsWith("/scim/v2") === true,
			handler: createAuthMiddleware(async (ctx) => {
				ctx.setHeader(SCIM_RESPONSE_MARKER, "1");
				const returned = ctx.context.returned;
				if (!isAPIErrorLike(returned) || isSCIMErrorBody(returned.body)) return;
				const body = returned.body;
				const detail = isRecord(body) && typeof body.message === "string" ? body.message : returned.message;
				const validationError = returned.statusCode === 400 && isRecord(body) && body.code === "VALIDATION_ERROR";
				throw createSCIMError(returned.status, {
					detail,
					...validationError ? { scimType: "invalidValue" } : {}
				});
			})
		}] },
		schema: {
			...options.managedConnections ? managedSCIMSchema : {},
			scimConnectionBinding: { fields: {
				connectionId: {
					type: "string",
					required: true,
					index: true
				},
				connectionKey: {
					type: "string",
					required: true,
					unique: true,
					returned: false
				},
				provisioningDomainId: {
					type: "string",
					required: true
				},
				createdAt: {
					type: "date",
					required: true
				},
				decommissionedAt: {
					type: "date",
					required: false
				},
				decommissionStatus: {
					type: "string",
					required: true,
					defaultValue: "active"
				},
				decommissionCursorUserId: {
					type: "string",
					required: false,
					returned: false
				},
				decommissionReconciledUserCount: {
					type: "number",
					required: true,
					defaultValue: 0
				},
				decommissionBatchCount: {
					type: "number",
					required: true,
					defaultValue: 0
				},
				decommissionRevision: {
					type: "number",
					required: true,
					defaultValue: 0,
					returned: false
				},
				decommissionCompletedAt: {
					type: "date",
					required: false
				},
				decommissionLeaseId: {
					type: "string",
					required: false,
					returned: false
				},
				decommissionLeaseExpiresAt: {
					type: "date",
					required: false,
					returned: false
				}
			} },
			scimIdentityTombstone: { fields: {
				connectionId: {
					type: "string",
					required: true,
					index: true
				},
				provisioningDomainId: {
					type: "string",
					required: true,
					index: true
				},
				externalId: {
					type: "string",
					required: true
				},
				externalIdKey: {
					type: "string",
					required: true,
					unique: true,
					returned: false
				},
				userId: {
					type: "string",
					required: true,
					index: true,
					references: {
						model: "user",
						field: "id"
					}
				},
				profile: {
					type: "string",
					required: true
				},
				deletedAt: {
					type: "date",
					required: true
				}
			} },
			scimSubject: { fields: {
				userId: {
					type: "string",
					required: true,
					unique: true,
					references: {
						model: "user",
						field: "id"
					}
				},
				profileSourceId: {
					type: "string",
					required: false,
					index: true
				},
				revision: {
					type: "number",
					required: true
				},
				createdAt: {
					type: "date",
					required: true
				},
				updatedAt: {
					type: "date",
					required: true
				}
			} },
			scimUser: { fields: {
				connectionId: {
					type: "string",
					required: true,
					index: true
				},
				provisioningDomainId: {
					type: "string",
					required: true,
					index: true
				},
				userId: {
					type: "string",
					required: true,
					index: true,
					references: {
						model: "user",
						field: "id"
					}
				},
				connectionUserKey: {
					type: "string",
					required: true,
					unique: true,
					returned: false
				},
				userName: {
					type: "string",
					required: true
				},
				userNameKey: {
					type: "string",
					required: true,
					unique: true,
					returned: false
				},
				primaryEmail: {
					type: "string",
					required: true
				},
				workEmailValueIndex: {
					type: "string",
					required: true,
					returned: false
				},
				emailValueIndex: {
					type: "string",
					required: true,
					returned: false
				},
				displayName: {
					type: "string",
					required: true
				},
				formattedName: {
					type: "string",
					required: true
				},
				givenName: {
					type: "string",
					required: false
				},
				familyName: {
					type: "string",
					required: false
				},
				serializedEmails: {
					type: "string",
					required: true,
					returned: false
				},
				serializedAttributes: {
					type: "string",
					required: false,
					returned: false
				},
				externalId: {
					type: "string",
					required: false
				},
				externalIdKey: {
					type: "string",
					required: false,
					unique: true,
					returned: false
				},
				active: {
					type: "boolean",
					required: true
				},
				orderKey: {
					type: "string",
					required: true,
					unique: true,
					returned: false
				},
				createdAt: {
					type: "date",
					required: true
				},
				updatedAt: {
					type: "date",
					required: true
				}
			} },
			scimProjectionGrant: { fields: {
				connectionId: {
					type: "string",
					required: true,
					index: true
				},
				provisioningDomainId: {
					type: "string",
					required: true,
					index: true
				},
				scimUserId: {
					type: "string",
					required: true,
					index: true,
					references: {
						model: "scimUser",
						field: "id"
					}
				},
				userId: {
					type: "string",
					required: true,
					index: true,
					references: {
						model: "user",
						field: "id"
					}
				},
				sourceKind: {
					type: "string",
					required: true
				},
				sourceId: {
					type: "string",
					required: true
				},
				sourceValue: {
					type: "string",
					required: false
				},
				role: {
					type: "string",
					required: true
				},
				grantKey: {
					type: "string",
					required: true,
					unique: true,
					returned: false
				},
				createdAt: {
					type: "date",
					required: true
				},
				updatedAt: {
					type: "date",
					required: true
				}
			} },
			scimGroup: { fields: {
				connectionId: {
					type: "string",
					required: true,
					index: true
				},
				provisioningDomainId: {
					type: "string",
					required: true,
					index: true
				},
				revision: {
					type: "number",
					required: true,
					defaultValue: 0,
					returned: false
				},
				displayName: {
					type: "string",
					required: true
				},
				displayNameKey: {
					type: "string",
					required: true,
					unique: true,
					returned: false
				},
				externalId: {
					type: "string",
					required: false
				},
				externalIdKey: {
					type: "string",
					required: false,
					unique: true,
					returned: false
				},
				orderKey: {
					type: "string",
					required: true,
					unique: true,
					returned: false
				},
				createdAt: {
					type: "date",
					required: true
				},
				updatedAt: {
					type: "date",
					required: true
				}
			} },
			scimGroupMember: { fields: {
				connectionId: {
					type: "string",
					required: true,
					index: true
				},
				groupId: {
					type: "string",
					required: true,
					index: true,
					references: {
						model: "scimGroup",
						field: "id"
					}
				},
				scimUserId: {
					type: "string",
					required: true,
					index: true,
					references: {
						model: "scimUser",
						field: "id"
					}
				},
				membershipKey: {
					type: "string",
					required: true,
					unique: true,
					returned: false
				},
				createdAt: {
					type: "date",
					required: true
				}
			} }
		},
		options
	};
}
/**
* Adds an inbound SCIM 2.0 service provider to Better Auth.
*
* Every configured connection owns an isolated set of SCIM resources. The
* plugin does not require the organization plugin and never represents a
* provisioned identity as an authentication account.
*/
function scim(options) {
	validateConnections(options);
	return createSCIMPlugin(options);
}
//#endregion
export { SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT, acquireActiveSCIMUserLink, scim };
