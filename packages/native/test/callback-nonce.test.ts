import { describe, expect, it } from "vitest";
import {
	attachSessionCookieToCallback,
	CALLBACK_NONCE_PARAM,
} from "../src/callback-nonce";

describe("attachSessionCookieToCallback", () => {
	const cookie = "better-auth.session_token=abc; Path=/";

	it("appends cookie and preserves the callback nonce", () => {
		const next = attachSessionCookieToCallback(
			`scomm://auth/callback?${CALLBACK_NONCE_PARAM}=n1`,
			cookie,
		);
		expect(next).toBeDefined();
		const url = new URL(next!);
		expect(url.searchParams.get(CALLBACK_NONCE_PARAM)).toBe("n1");
		expect(url.searchParams.get("cookie")).toBe(cookie);
	});

	it("does not attach cookie when the callback has no nonce", () => {
		expect(
			attachSessionCookieToCallback("scomm://auth/callback", cookie),
		).toBeUndefined();
		expect(
			attachSessionCookieToCallback(
				"http://127.0.0.1:8080/auth-callback",
				cookie,
			),
		).toBeUndefined();
	});

	it("rejects an empty nonce", () => {
		expect(
			attachSessionCookieToCallback(
				`myapp://auth/callback?${CALLBACK_NONCE_PARAM}=`,
				cookie,
			),
		).toBeUndefined();
	});
});
