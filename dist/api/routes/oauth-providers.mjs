import { HIDE_METADATA } from "../../utils/hide-metadata.mjs";
import { createAuthEndpoint } from "@better-auth/core/api";
//#region src/api/routes/oauth-providers.ts
function getJwtPluginOptions(ctx) {
	const jwtPlugin = ctx.options.plugins?.find((plugin) => plugin.id === "jwt");
	if (!jwtPlugin || !("options" in jwtPlugin)) return;
	return jwtPlugin.options;
}
function resolveSocialProviderRedirectUri(ctx, providerId) {
	const configs = ctx.options.socialProviders;
	if (!configs) return `${ctx.baseURL}/callback/${providerId}`;
	for (const [key, originalConfig] of Object.entries(configs)) {
		if (key !== providerId) continue;
		const providerConfig = typeof originalConfig === "function" ? void 0 : originalConfig;
		if (providerConfig && typeof providerConfig === "object" && "redirectURI" in providerConfig && typeof providerConfig.redirectURI === "string" && providerConfig.redirectURI.length > 0) return providerConfig.redirectURI;
		break;
	}
	return `${ctx.baseURL}/callback/${providerId}`;
}
/** Builds login-method discovery payload from runtime Better Auth configuration. */
function buildOAuthProvidersResponse(ctx) {
	const providers = [];
	if (ctx.context.options.emailAndPassword?.enabled) providers.push({
		id: "email",
		enabled: true
	});
	for (const provider of ctx.context.socialProviders) providers.push({
		id: provider.id,
		enabled: true,
		redirectUri: resolveSocialProviderRedirectUri(ctx.context, provider.id)
	});
	return {
		issuer: getJwtPluginOptions(ctx.context)?.jwt?.issuer ?? ctx.context.baseURL,
		providers
	};
}
/** Public discovery for login UIs — which auth methods are enabled on this server. */
const getOAuthProviders = createAuthEndpoint("/.well-known/oauth-providers", {
	method: "GET",
	metadata: {
		...HIDE_METADATA,
		openapi: {
			description: "Lists enabled login methods (email/password and social providers) for client UI discovery.",
			responses: { "200": {
				description: "Enabled login methods",
				content: { "application/json": { schema: {
					type: "object",
					properties: {
						issuer: { type: "string" },
						providers: {
							type: "array",
							items: {
								type: "object",
								properties: {
									id: { type: "string" },
									enabled: { type: "boolean" },
									redirectUri: { type: "string" }
								},
								required: ["id", "enabled"]
							}
						}
					},
					required: ["issuer", "providers"]
				} } }
			} }
		}
	}
}, async (ctx) => {
	return ctx.json(buildOAuthProvidersResponse(ctx));
});
//#endregion
export { buildOAuthProvidersResponse, getOAuthProviders };
