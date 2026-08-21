import type {
	BetterAuthPluginDBSchema,
	DBPrimitive,
} from "@better-auth/core/db";

/**
 * CapabilitySet is a JSON **array**. node-pg encodes a top-level JS array as a
 * Postgres array, not jsonb — so we stringify here instead of changing the
 * global adapter factory (which would also rewrite unrelated json fields).
 */
const jsonArrayField = {
	type: "json" as const,
	required: true as const,
	transform: {
		input(value: DBPrimitive) {
			return Array.isArray(value) ? JSON.stringify(value) : value;
		},
		output(value: DBPrimitive) {
			if (typeof value !== "string") {
				return value;
			}
			try {
				return JSON.parse(value) as DBPrimitive;
			} catch {
				return value;
			}
		},
	},
};

export const schema = {
	dpCatalogMeta: {
		fields: {
			serviceId: {
				type: "string",
				required: true,
				unique: true,
			},
			generation: {
				type: "number",
				required: true,
				defaultValue: 1,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpAction: {
		fields: {
			serviceId: {
				type: "string",
				required: true,
				index: true,
			},
			action: {
				type: "string",
				required: true,
			},
			description: {
				type: "string",
				required: false,
			},
			catalogGeneration: {
				type: "number",
				required: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpScopeDimension: {
		fields: {
			serviceId: {
				type: "string",
				required: true,
				index: true,
			},
			dimension: {
				type: "string",
				required: true,
			},
			algebra: {
				type: "string",
				required: true,
			},
			catalogGeneration: {
				type: "number",
				required: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpProfile: {
		fields: {
			serviceId: {
				type: "string",
				required: true,
				index: true,
			},
			profile: {
				type: "string",
				required: true,
			},
			permissions: jsonArrayField,
			catalogGeneration: {
				type: "number",
				required: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpPrincipalGrant: {
		fields: {
			userId: {
				type: "string",
				required: true,
				index: true,
				references: {
					model: "user",
					field: "id",
				},
			},
			entityId: {
				type: "string",
				required: false,
			},
			permissions: jsonArrayField,
			profile: {
				type: "string",
				required: false,
			},
			expiresAt: {
				type: "date",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpSessionGrant: {
		fields: {
			sessionId: {
				type: "string",
				required: true,
				unique: true,
				index: true,
				references: {
					model: "session",
					field: "id",
				},
			},
			userId: {
				type: "string",
				required: true,
				index: true,
				references: {
					model: "user",
					field: "id",
				},
			},
			permissions: jsonArrayField,
			expiresAt: {
				type: "date",
				required: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpEntity: {
		fields: {
			entityId: {
				type: "string",
				required: true,
				unique: true,
			},
			package: {
				type: "string",
				required: true,
			},
			rootSki: {
				type: "string",
				required: true,
			},
			caCertPem: {
				type: "string",
				required: false,
			},
			platformCaCertCosign: {
				type: "json",
				required: false,
			},
			ownerUserId: {
				type: "string",
				required: true,
				index: true,
				references: {
					model: "user",
					field: "id",
				},
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpCredential: {
		fields: {
			ski: {
				type: "string",
				required: true,
				unique: true,
			},
			entityId: {
				type: "string",
				required: true,
				index: true,
			},
			kind: {
				type: "string",
				required: true,
			},
			publicJwk: {
				type: "json",
				required: true,
			},
			credential: {
				type: "json",
				required: true,
			},
			zone: {
				type: "string",
				required: false,
			},
			host: {
				type: "string",
				required: false,
			},
			seatId: {
				type: "string",
				required: false,
			},
			status: {
				type: "string",
				required: true,
				defaultValue: "active",
			},
			revokedAt: {
				type: "date",
				required: false,
			},
			revokedReason: {
				type: "string",
				required: false,
			},
			renewedBySki: {
				type: "string",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpUserCredentialBind: {
		fields: {
			userId: {
				type: "string",
				required: true,
				index: true,
				references: {
					model: "user",
					field: "id",
				},
			},
			credentialSki: {
				type: "string",
				required: true,
				index: true,
			},
			entityId: {
				type: "string",
				required: true,
				index: true,
			},
			isPrimary: {
				type: "boolean",
				required: true,
				defaultValue: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpNameOccupancy: {
		fields: {
			entityId: {
				type: "string",
				required: true,
				index: true,
			},
			nameKey: {
				type: "string",
				required: true,
			},
			kind: {
				type: "string",
				required: true,
			},
			credentialSki: {
				type: "string",
				required: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpEnrollRequest: {
		fields: {
			entityId: {
				type: "string",
				required: true,
				index: true,
			},
			host: {
				type: "string",
				required: false,
			},
			zone: {
				type: "string",
				required: false,
			},
			role: {
				type: "string",
				required: true,
			},
			csrPem: {
				type: "string",
				required: true,
			},
			subjectSki: {
				type: "string",
				required: true,
				index: true,
			},
			publicJwk: {
				type: "json",
				required: true,
			},
			status: {
				type: "string",
				required: true,
				defaultValue: "pending",
			},
			pullToken: {
				type: "string",
				required: true,
				unique: true,
			},
			createdByUserId: {
				type: "string",
				required: false,
			},
			leafPem: {
				type: "string",
				required: false,
			},
			chainPem: {
				type: "string",
				required: false,
			},
			credential: {
				type: "json",
				required: false,
			},
			platformCertCosign: {
				type: "json",
				required: false,
			},
			seatId: {
				type: "string",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	dpEnrollInvite: {
		fields: {
			entityId: {
				type: "string",
				required: true,
				index: true,
			},
			host: {
				type: "string",
				required: false,
			},
			zone: {
				type: "string",
				required: false,
			},
			role: {
				type: "string",
				required: true,
			},
			inviteToken: {
				type: "string",
				required: true,
				unique: true,
			},
			expiresAt: {
				type: "date",
				required: true,
			},
			maxUses: {
				type: "number",
				required: true,
				defaultValue: 1,
			},
			usedCount: {
				type: "number",
				required: true,
				defaultValue: 0,
			},
			consumedAt: {
				type: "date",
				required: false,
			},
			createdByUserId: {
				type: "string",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
} satisfies BetterAuthPluginDBSchema;
