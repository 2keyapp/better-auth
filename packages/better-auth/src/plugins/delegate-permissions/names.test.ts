import { describe, expect, it } from "vitest";
import { parseMachineHost } from "./names";

describe("parseMachineHost", () => {
	it("accepts logical host {path}--{entity}", () => {
		expect(
			parseMachineHost("laptop--user@example.com", "user@example.com"),
		).toEqual({ path: "laptop" });
	});

	it("rejects host that does not end with --{entity}", () => {
		expect(
			parseMachineHost("laptop--other@example.com", "user@example.com"),
		).toBeNull();
	});

	it("rejects empty or invalid path", () => {
		expect(
			parseMachineHost("--user@example.com", "user@example.com"),
		).toBeNull();
		expect(
			parseMachineHost("bad--path--user@example.com", "user@example.com"),
		).toBeNull();
	});
});
