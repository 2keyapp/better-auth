import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

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
			permissions: {
				type: "json",
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
			permissions: {
				type: "json",
				required: true,
			},
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
			permissions: {
				type: "json",
				required: true,
			},
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
} satisfies BetterAuthPluginDBSchema;
