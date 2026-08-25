import { createAuthMiddleware } from "@better-auth/core/api";
import { HIDE_METADATA } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import * as z from "zod";
//#region src/routes.ts
const flutterAuthorizationProxy = createAuthEndpoint("/flutter-authorization-proxy", {
	method: "GET",
	query: z.object({
		authorizationURL: z.string(),
		oauthState: z.string().optional()
	}),
	metadata: HIDE_METADATA
}, async (ctx) => {
	const { authorizationURL } = ctx.query;
	if (authorizationURL.includes("#")) throw new APIError("BAD_REQUEST", { message: "Invalid authorizationURL" });
	let url;
	try {
		url = new URL(authorizationURL);
	} catch {
		throw new APIError("BAD_REQUEST", { message: "Invalid authorizationURL" });
	}
	if (url.protocol !== "https:" || url.origin === new URL(ctx.context.baseURL).origin) throw new APIError("BAD_REQUEST", { message: "Invalid authorizationURL" });
	const { oauthState } = ctx.query;
	if (oauthState) {
		const oauthStateCookie = ctx.context.createAuthCookie("oauth_state", { maxAge: 600 });
		ctx.setCookie(oauthStateCookie.name, oauthState, oauthStateCookie.attributes);
		return ctx.redirect(authorizationURL);
	}
	const state = url.searchParams.get("state");
	if (!state) throw new APIError("BAD_REQUEST", { message: "Unexpected error" });
	const stateCookie = ctx.context.createAuthCookie("state", { maxAge: 300 });
	await ctx.setSignedCookie(stateCookie.name, state, ctx.context.secret, stateCookie.attributes);
	return ctx.redirect(ctx.query.authorizationURL);
});
//#endregion
//#region src/version.ts
const PACKAGE_VERSION = "1.6.23";
//#endregion
//#region src/index.ts
/**
* Better Auth server plugin for Flutter / Dart clients.
*
* Adds trusted-origin helpers for custom URL schemes, copies
* `flutter-origin` into the request origin header (so CSRF/origin
* checks work without a browser Origin), and attaches session cookies
* to deep-link redirects after OAuth / magic-link / email verification.
*/
const flutter = (options) => {
	return {
		id: "flutter",
		version: PACKAGE_VERSION,
		init: () => {
			return { options: { trustedOrigins: [] } };
		},
		async onRequest(request) {
			if (options?.disableOriginOverride || request.headers.get("origin")) return;
			/**
			* To bypass origin check from Flutter clients, set the origin
			* header from the flutter-origin header.
			*/
			const flutterOrigin = request.headers.get("flutter-origin");
			if (!flutterOrigin) return;
			try {
				request.headers.set("origin", flutterOrigin);
				return { request };
			} catch {
				const newHeaders = new Headers(request.headers);
				newHeaders.set("origin", flutterOrigin);
				return { request: new Request(request, { headers: newHeaders }) };
			}
		},
		hooks: { after: [{
			matcher(context) {
				return !!(context.path?.startsWith("/callback") || context.path?.startsWith("/oauth2/callback") || context.path?.startsWith("/magic-link/verify") || context.path?.startsWith("/verify-email"));
			},
			handler: createAuthMiddleware(async (ctx) => {
				const headers = ctx.context.responseHeaders;
				const location = headers?.get("location");
				if (!location) return;
				if (location.includes("/oauth-proxy-callback")) return;
				let redirectURL;
				try {
					redirectURL = new URL(location);
				} catch {
					return;
				}
				const isHttpRedirect = redirectURL.protocol === "http:" || redirectURL.protocol === "https:";
				const isLoopbackHttpRedirect = isHttpRedirect && (redirectURL.hostname === "localhost" || redirectURL.hostname === "127.0.0.1");
				if (isHttpRedirect && !isLoopbackHttpRedirect) return;
				if (!ctx.context.isTrustedOrigin(location)) return;
				const cookie = headers?.get("set-cookie");
				if (!cookie) return;
				redirectURL.searchParams.set("cookie", cookie);
				ctx.setHeader("location", redirectURL.toString());
			})
		}] },
		endpoints: { flutterAuthorizationProxy },
		options
	};
};
//#endregion
export { flutter };
