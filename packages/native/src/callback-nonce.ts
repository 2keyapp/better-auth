/** Query param the native client puts on `callbackURL` and requires on the `?cookie=` redirect. */
export const CALLBACK_NONCE_PARAM = "ba_nonce";

export function nativeRedirectHasCallbackNonce(redirectURL: URL): boolean {
	const nonce = redirectURL.searchParams.get(CALLBACK_NONCE_PARAM)?.trim();
	return Boolean(nonce);
}

/**
 * Attach a session Set-Cookie to a native / loopback callback Location.
 *
 * Returns `undefined` when the Location has no callback nonce — cookie-only
 * redirects are login CSRF (a copied URL completes an in-flight waiter).
 */
export function attachSessionCookieToCallback(
	location: string,
	setCookie: string,
): string | undefined {
	let redirectURL: URL;
	try {
		redirectURL = new URL(location);
	} catch {
		return undefined;
	}
	if (!nativeRedirectHasCallbackNonce(redirectURL)) {
		return undefined;
	}
	redirectURL.searchParams.set("cookie", setCookie);
	return redirectURL.toString();
}
