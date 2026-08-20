//#region src/plugins/delegate-permissions/capability/expand.ts
/**
* Expand a named profile into a CapabilitySet using catalog profile defs.
*/
function expandProfile(profile, profiles, catalog) {
	const found = profiles.find((p) => p.profile === profile);
	if (!found) throw new Error(`profile "${profile}" not found for service "${catalog.serviceId}"`);
	return found.permissions;
}
//#endregion
export { expandProfile };
