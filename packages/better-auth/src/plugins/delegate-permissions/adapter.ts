import type {
	BetterAuthOptions,
	GenericEndpointContext,
} from "@better-auth/core";
import type { DBAdapter } from "@better-auth/core/db/adapter";
import type {
	CapabilitySet,
	Catalog,
	ProfileDef,
	ScopeAlgebra,
} from "./capability/types";
import type { CatalogSeed } from "./seeds/idr";
import type {
	DpActionRow,
	DpCatalogMetaRow,
	DpPrincipalGrantRow,
	DpProfileRow,
	DpScopeDimensionRow,
	DpSessionGrantRow,
} from "./types";

function isScopeAlgebra(value: string): value is ScopeAlgebra {
	return value === "exact" || value === "dns_prefix" || value === "set";
}

export function getDelegatePermissionsAdapter(
	adapter: DBAdapter<BetterAuthOptions>,
	serviceId: string,
) {
	return {
		async getCatalogMeta(
			_ctx?: GenericEndpointContext,
		): Promise<DpCatalogMetaRow | null> {
			return adapter.findOne<DpCatalogMetaRow>({
				model: "dpCatalogMeta",
				where: [{ field: "serviceId", value: serviceId }],
			});
		},

		async loadCatalog(_ctx?: GenericEndpointContext): Promise<Catalog | null> {
			const meta = await adapter.findOne<DpCatalogMetaRow>({
				model: "dpCatalogMeta",
				where: [{ field: "serviceId", value: serviceId }],
			});
			if (!meta) {
				return null;
			}
			const actions = await adapter.findMany<DpActionRow>({
				model: "dpAction",
				where: [{ field: "serviceId", value: serviceId }],
			});
			const dims = await adapter.findMany<DpScopeDimensionRow>({
				model: "dpScopeDimension",
				where: [{ field: "serviceId", value: serviceId }],
			});
			if (actions.length === 0 || dims.length === 0) {
				return null;
			}
			return {
				serviceId,
				generation: meta.generation,
				actions: actions.map((a) => ({
					action: a.action,
					description: a.description ?? undefined,
				})),
				scopeDimensions: dims.map((d) => {
					if (!isScopeAlgebra(d.algebra)) {
						throw new Error(`invalid scope algebra: ${d.algebra}`);
					}
					return { dimension: d.dimension, algebra: d.algebra };
				}),
			};
		},

		async loadProfiles(
			_ctx?: GenericEndpointContext,
		): Promise<readonly ProfileDef[]> {
			const rows = await adapter.findMany<DpProfileRow>({
				model: "dpProfile",
				where: [{ field: "serviceId", value: serviceId }],
			});
			return rows.map((r) => ({
				profile: r.profile,
				permissions: r.permissions,
			}));
		},

		async seedCatalog(
			seed: CatalogSeed,
			_ctx?: GenericEndpointContext,
		): Promise<Catalog> {
			const now = new Date();
			const existing = await adapter.findOne<DpCatalogMetaRow>({
				model: "dpCatalogMeta",
				where: [{ field: "serviceId", value: seed.serviceId }],
			});
			const generation = existing ? existing.generation + 1 : 1;

			if (existing) {
				const oldActions = await adapter.findMany<DpActionRow>({
					model: "dpAction",
					where: [{ field: "serviceId", value: seed.serviceId }],
				});
				for (const row of oldActions) {
					await adapter.delete({
						model: "dpAction",
						where: [{ field: "id", value: row.id }],
					});
				}
				const oldDims = await adapter.findMany<DpScopeDimensionRow>({
					model: "dpScopeDimension",
					where: [{ field: "serviceId", value: seed.serviceId }],
				});
				for (const row of oldDims) {
					await adapter.delete({
						model: "dpScopeDimension",
						where: [{ field: "id", value: row.id }],
					});
				}
				const oldProfiles = await adapter.findMany<DpProfileRow>({
					model: "dpProfile",
					where: [{ field: "serviceId", value: seed.serviceId }],
				});
				for (const row of oldProfiles) {
					await adapter.delete({
						model: "dpProfile",
						where: [{ field: "id", value: row.id }],
					});
				}
				await adapter.update({
					model: "dpCatalogMeta",
					where: [{ field: "id", value: existing.id }],
					update: { generation, updatedAt: now },
				});
			} else {
				await adapter.create({
					model: "dpCatalogMeta",
					data: {
						serviceId: seed.serviceId,
						generation,
						updatedAt: now,
					},
				});
			}

			for (const action of seed.actions) {
				await adapter.create({
					model: "dpAction",
					data: {
						serviceId: seed.serviceId,
						action: action.action,
						description: action.description ?? null,
						catalogGeneration: generation,
						createdAt: now,
					},
				});
			}
			for (const dim of seed.scopeDimensions) {
				await adapter.create({
					model: "dpScopeDimension",
					data: {
						serviceId: seed.serviceId,
						dimension: dim.dimension,
						algebra: dim.algebra,
						catalogGeneration: generation,
						createdAt: now,
					},
				});
			}
			for (const profile of seed.profiles) {
				await adapter.create({
					model: "dpProfile",
					data: {
						serviceId: seed.serviceId,
						profile: profile.profile,
						permissions: profile.permissions,
						catalogGeneration: generation,
						createdAt: now,
					},
				});
			}

			const catalog = await this.loadCatalog();
			if (!catalog) {
				throw new Error("failed to load catalog after seed");
			}
			return catalog;
		},

		async getPrincipalGrant(
			userId: string,
			_ctx?: GenericEndpointContext,
		): Promise<DpPrincipalGrantRow | null> {
			return adapter.findOne<DpPrincipalGrantRow>({
				model: "dpPrincipalGrant",
				where: [{ field: "userId", value: userId }],
			});
		},

		async upsertPrincipalGrant(input: {
			userId: string;
			entityId?: string | null;
			permissions: CapabilitySet;
			profile?: string | null;
			expiresAt?: Date | null;
		}): Promise<DpPrincipalGrantRow> {
			const now = new Date();
			const existing = await adapter.findOne<DpPrincipalGrantRow>({
				model: "dpPrincipalGrant",
				where: [{ field: "userId", value: input.userId }],
			});
			if (existing) {
				const updated = await adapter.update<DpPrincipalGrantRow>({
					model: "dpPrincipalGrant",
					where: [{ field: "id", value: existing.id }],
					update: {
						entityId: input.entityId ?? null,
						permissions: input.permissions,
						profile: input.profile ?? null,
						expiresAt: input.expiresAt ?? null,
						updatedAt: now,
					},
				});
				return updated ?? { ...existing, ...input, updatedAt: now };
			}
			return adapter.create<
				Omit<DpPrincipalGrantRow, "id">,
				DpPrincipalGrantRow
			>({
				model: "dpPrincipalGrant",
				data: {
					userId: input.userId,
					entityId: input.entityId ?? null,
					permissions: input.permissions,
					profile: input.profile ?? null,
					expiresAt: input.expiresAt ?? null,
					createdAt: now,
					updatedAt: now,
				},
			});
		},

		async getSessionGrant(
			sessionId: string,
			_ctx?: GenericEndpointContext,
		): Promise<DpSessionGrantRow | null> {
			return adapter.findOne<DpSessionGrantRow>({
				model: "dpSessionGrant",
				where: [{ field: "sessionId", value: sessionId }],
			});
		},

		async upsertSessionGrant(input: {
			sessionId: string;
			userId: string;
			permissions: CapabilitySet;
			expiresAt: Date;
		}): Promise<DpSessionGrantRow> {
			const now = new Date();
			const existing = await adapter.findOne<DpSessionGrantRow>({
				model: "dpSessionGrant",
				where: [{ field: "sessionId", value: input.sessionId }],
			});
			if (existing) {
				const updated = await adapter.update<DpSessionGrantRow>({
					model: "dpSessionGrant",
					where: [{ field: "id", value: existing.id }],
					update: {
						permissions: input.permissions,
						expiresAt: input.expiresAt,
					},
				});
				return (
					updated ?? {
						...existing,
						permissions: input.permissions,
						expiresAt: input.expiresAt,
					}
				);
			}
			return adapter.create<Omit<DpSessionGrantRow, "id">, DpSessionGrantRow>({
				model: "dpSessionGrant",
				data: {
					sessionId: input.sessionId,
					userId: input.userId,
					permissions: input.permissions,
					expiresAt: input.expiresAt,
					createdAt: now,
				},
			});
		},
	};
}
