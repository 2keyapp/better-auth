import * as z from "zod";
import type { Capability, CapabilitySet, ScopeMap } from "./capability/types";

const scopeMapSchema = z.record(
	z.string(),
	z.union([z.string(), z.array(z.string())]),
);

const capabilitySchema = z.object({
	action: z.string().min(1),
	scope: scopeMapSchema.default({}),
	delegable: z.boolean(),
});

export const capabilitySetSchema = z.array(capabilitySchema).min(1);

export function parseCapabilitySet(input: unknown): CapabilitySet {
	const parsed = capabilitySetSchema.parse(input);
	return parsed.map(
		(c): Capability => ({
			action: c.action,
			scope: c.scope as ScopeMap,
			delegable: c.delegable,
		}),
	);
}
