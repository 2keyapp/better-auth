//#region src/plugins/delegate-permissions/adapter.ts
function isScopeAlgebra(value) {
	return value === "exact" || value === "dns_prefix" || value === "set";
}
function getDelegatePermissionsAdapter(adapter, serviceId) {
	return {
		async getCatalogMeta(_ctx) {
			return adapter.findOne({
				model: "dpCatalogMeta",
				where: [{
					field: "serviceId",
					value: serviceId
				}]
			});
		},
		async loadCatalog(_ctx) {
			const meta = await adapter.findOne({
				model: "dpCatalogMeta",
				where: [{
					field: "serviceId",
					value: serviceId
				}]
			});
			if (!meta) return null;
			const actions = await adapter.findMany({
				model: "dpAction",
				where: [{
					field: "serviceId",
					value: serviceId
				}]
			});
			const dims = await adapter.findMany({
				model: "dpScopeDimension",
				where: [{
					field: "serviceId",
					value: serviceId
				}]
			});
			if (actions.length === 0 || dims.length === 0) return null;
			return {
				serviceId,
				generation: meta.generation,
				actions: actions.map((a) => ({
					action: a.action,
					description: a.description ?? void 0
				})),
				scopeDimensions: dims.map((d) => {
					if (!isScopeAlgebra(d.algebra)) throw new Error(`invalid scope algebra: ${d.algebra}`);
					return {
						dimension: d.dimension,
						algebra: d.algebra
					};
				})
			};
		},
		async loadProfiles(_ctx) {
			return (await adapter.findMany({
				model: "dpProfile",
				where: [{
					field: "serviceId",
					value: serviceId
				}]
			})).map((r) => ({
				profile: r.profile,
				permissions: r.permissions
			}));
		},
		async seedCatalog(seed, _ctx) {
			const now = /* @__PURE__ */ new Date();
			const existing = await adapter.findOne({
				model: "dpCatalogMeta",
				where: [{
					field: "serviceId",
					value: seed.serviceId
				}]
			});
			const generation = existing ? existing.generation + 1 : 1;
			if (existing) {
				const oldActions = await adapter.findMany({
					model: "dpAction",
					where: [{
						field: "serviceId",
						value: seed.serviceId
					}]
				});
				for (const row of oldActions) await adapter.delete({
					model: "dpAction",
					where: [{
						field: "id",
						value: row.id
					}]
				});
				const oldDims = await adapter.findMany({
					model: "dpScopeDimension",
					where: [{
						field: "serviceId",
						value: seed.serviceId
					}]
				});
				for (const row of oldDims) await adapter.delete({
					model: "dpScopeDimension",
					where: [{
						field: "id",
						value: row.id
					}]
				});
				const oldProfiles = await adapter.findMany({
					model: "dpProfile",
					where: [{
						field: "serviceId",
						value: seed.serviceId
					}]
				});
				for (const row of oldProfiles) await adapter.delete({
					model: "dpProfile",
					where: [{
						field: "id",
						value: row.id
					}]
				});
				await adapter.update({
					model: "dpCatalogMeta",
					where: [{
						field: "id",
						value: existing.id
					}],
					update: {
						generation,
						updatedAt: now
					}
				});
			} else await adapter.create({
				model: "dpCatalogMeta",
				data: {
					serviceId: seed.serviceId,
					generation,
					updatedAt: now
				}
			});
			for (const action of seed.actions) await adapter.create({
				model: "dpAction",
				data: {
					serviceId: seed.serviceId,
					action: action.action,
					description: action.description ?? null,
					catalogGeneration: generation,
					createdAt: now
				}
			});
			for (const dim of seed.scopeDimensions) await adapter.create({
				model: "dpScopeDimension",
				data: {
					serviceId: seed.serviceId,
					dimension: dim.dimension,
					algebra: dim.algebra,
					catalogGeneration: generation,
					createdAt: now
				}
			});
			for (const profile of seed.profiles) await adapter.create({
				model: "dpProfile",
				data: {
					serviceId: seed.serviceId,
					profile: profile.profile,
					permissions: profile.permissions,
					catalogGeneration: generation,
					createdAt: now
				}
			});
			const catalog = await this.loadCatalog();
			if (!catalog) throw new Error("failed to load catalog after seed");
			return catalog;
		},
		async getPrincipalGrant(userId, _ctx) {
			return adapter.findOne({
				model: "dpPrincipalGrant",
				where: [{
					field: "userId",
					value: userId
				}]
			});
		},
		async upsertPrincipalGrant(input) {
			const now = /* @__PURE__ */ new Date();
			const existing = await adapter.findOne({
				model: "dpPrincipalGrant",
				where: [{
					field: "userId",
					value: input.userId
				}]
			});
			if (existing) return await adapter.update({
				model: "dpPrincipalGrant",
				where: [{
					field: "id",
					value: existing.id
				}],
				update: {
					entityId: input.entityId ?? null,
					permissions: input.permissions,
					profile: input.profile ?? null,
					expiresAt: input.expiresAt ?? null,
					updatedAt: now
				}
			}) ?? {
				...existing,
				...input,
				updatedAt: now
			};
			return adapter.create({
				model: "dpPrincipalGrant",
				data: {
					userId: input.userId,
					entityId: input.entityId ?? null,
					permissions: input.permissions,
					profile: input.profile ?? null,
					expiresAt: input.expiresAt ?? null,
					createdAt: now,
					updatedAt: now
				}
			});
		},
		async getSessionGrant(sessionId, _ctx) {
			return adapter.findOne({
				model: "dpSessionGrant",
				where: [{
					field: "sessionId",
					value: sessionId
				}]
			});
		},
		async upsertSessionGrant(input) {
			const now = /* @__PURE__ */ new Date();
			const existing = await adapter.findOne({
				model: "dpSessionGrant",
				where: [{
					field: "sessionId",
					value: input.sessionId
				}]
			});
			if (existing) return await adapter.update({
				model: "dpSessionGrant",
				where: [{
					field: "id",
					value: existing.id
				}],
				update: {
					permissions: input.permissions,
					expiresAt: input.expiresAt
				}
			}) ?? {
				...existing,
				permissions: input.permissions,
				expiresAt: input.expiresAt
			};
			return adapter.create({
				model: "dpSessionGrant",
				data: {
					sessionId: input.sessionId,
					userId: input.userId,
					permissions: input.permissions,
					expiresAt: input.expiresAt,
					createdAt: now
				}
			});
		},
		async getEntity(entityId) {
			return adapter.findOne({
				model: "dpEntity",
				where: [{
					field: "entityId",
					value: entityId
				}]
			});
		},
		async createEntity(input) {
			const now = /* @__PURE__ */ new Date();
			return adapter.create({
				model: "dpEntity",
				data: {
					entityId: input.entityId,
					package: input.package,
					rootSki: input.rootSki,
					caCertPem: input.caCertPem ?? null,
					platformCaCertCosign: input.platformCaCertCosign ?? null,
					ownerUserId: input.ownerUserId,
					createdAt: now,
					updatedAt: now
				}
			});
		},
		async getCredential(ski) {
			return adapter.findOne({
				model: "dpCredential",
				where: [{
					field: "ski",
					value: ski
				}]
			});
		},
		async createCredential(input) {
			const c = input.credential;
			return adapter.create({
				model: "dpCredential",
				data: {
					ski: c.ski,
					entityId: c.entityId,
					kind: c.kind,
					publicJwk: c.publicJwk,
					credential: c,
					zone: c.zone ?? null,
					host: c.host ?? null,
					seatId: input.seatId ?? null,
					status: "active",
					revokedAt: null,
					revokedReason: null,
					renewedBySki: null,
					createdAt: /* @__PURE__ */ new Date()
				}
			});
		},
		async bindUserCredential(input) {
			return adapter.create({
				model: "dpUserCredentialBind",
				data: {
					userId: input.userId,
					credentialSki: input.credentialSki,
					entityId: input.entityId,
					isPrimary: input.isPrimary ?? true,
					createdAt: /* @__PURE__ */ new Date()
				}
			});
		},
		async getNameOccupancy(entityId, nameKey) {
			return (await adapter.findMany({
				model: "dpNameOccupancy",
				where: [{
					field: "entityId",
					value: entityId
				}, {
					field: "nameKey",
					value: nameKey
				}]
			}))[0] ?? null;
		},
		async claimName(input) {
			return adapter.create({
				model: "dpNameOccupancy",
				data: {
					entityId: input.entityId,
					nameKey: input.nameKey,
					kind: input.kind,
					credentialSki: input.credentialSki,
					createdAt: /* @__PURE__ */ new Date()
				}
			});
		},
		async updateCredentialStatus(ski, update) {
			return adapter.update({
				model: "dpCredential",
				where: [{
					field: "ski",
					value: ski
				}],
				update
			});
		},
		async listCredentials(entityId, status) {
			const where = [{
				field: "entityId",
				value: entityId
			}];
			if (status) where.push({
				field: "status",
				value: status
			});
			return adapter.findMany({
				model: "dpCredential",
				where
			});
		},
		async releaseNameBySki(entityId, credentialSki) {
			const rows = await adapter.findMany({
				model: "dpNameOccupancy",
				where: [{
					field: "entityId",
					value: entityId
				}, {
					field: "credentialSki",
					value: credentialSki
				}]
			});
			for (const row of rows) await adapter.delete({
				model: "dpNameOccupancy",
				where: [{
					field: "id",
					value: row.id
				}]
			});
		},
		async createEnrollRequest(input) {
			const now = /* @__PURE__ */ new Date();
			return adapter.create({
				model: "dpEnrollRequest",
				data: {
					entityId: input.entityId,
					host: input.host ?? "",
					zone: input.zone ?? null,
					role: input.role,
					csrPem: input.csrPem,
					subjectSki: input.subjectSki,
					publicJwk: input.publicJwk,
					status: input.status ?? "pending",
					pullToken: input.pullToken,
					createdByUserId: input.createdByUserId ?? null,
					leafPem: input.leafPem ?? null,
					chainPem: input.chainPem ?? null,
					credential: input.credential ?? null,
					platformCertCosign: input.platformCertCosign ?? null,
					seatId: input.seatId ?? null,
					createdAt: now,
					updatedAt: now
				}
			});
		},
		async getEnrollRequest(id) {
			return adapter.findOne({
				model: "dpEnrollRequest",
				where: [{
					field: "id",
					value: id
				}]
			});
		},
		async getEnrollByPullToken(pullToken) {
			return adapter.findOne({
				model: "dpEnrollRequest",
				where: [{
					field: "pullToken",
					value: pullToken
				}]
			});
		},
		async listEnrollRequests(entityId, status) {
			const where = [{
				field: "entityId",
				value: entityId
			}];
			if (status) where.push({
				field: "status",
				value: status
			});
			return adapter.findMany({
				model: "dpEnrollRequest",
				where
			});
		},
		async updateEnrollRequest(id, update) {
			return adapter.update({
				model: "dpEnrollRequest",
				where: [{
					field: "id",
					value: id
				}],
				update: {
					...update,
					updatedAt: /* @__PURE__ */ new Date()
				}
			});
		}
	};
}
//#endregion
export { getDelegatePermissionsAdapter };
