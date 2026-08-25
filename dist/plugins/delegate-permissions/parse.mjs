import * as z from "zod";
//#region src/plugins/delegate-permissions/parse.ts
const scopeMapSchema = z.record(z.string(), z.union([z.string(), z.array(z.string())]));
const capabilitySchema = z.object({
	action: z.string().min(1),
	scope: scopeMapSchema.default({}),
	delegable: z.boolean()
});
const capabilitySetSchema = z.array(capabilitySchema).min(1);
function parseCapabilitySet(input) {
	return capabilitySetSchema.parse(input).map((c) => ({
		action: c.action,
		scope: c.scope,
		delegable: c.delegable
	}));
}
//#endregion
export { capabilitySetSchema, parseCapabilitySet };
