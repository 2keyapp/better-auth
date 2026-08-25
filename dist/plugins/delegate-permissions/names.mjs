//#region src/plugins/delegate-permissions/names.ts
/**
* Host / zone naming helpers (no role markers in the host string).
* Machine host form: `{path}--{entityId}`.
*/
const SEPARATOR = "--";
function isValidHostPath(path) {
	if (!path || path.includes(SEPARATOR)) return false;
	for (const label of path.split(".")) if (!label || label.length > 63 || label.startsWith("-") || label.endsWith("-")) return false;
	return true;
}
/**
* Parse `{path}--{entity}` for `entityId`.
* Callers should strip any product-specific domain suffix before calling.
*/
function parseMachineHost(host, entityId) {
	let canonicalHost = host.trim().toLowerCase();
	const entity = entityId.trim().toLowerCase();
	if (!canonicalHost || !entity) return null;
	if (canonicalHost.endsWith(".")) canonicalHost = canonicalHost.slice(0, -1);
	const suffix = `${SEPARATOR}${entity}`;
	if (!canonicalHost.endsWith(suffix)) return null;
	const path = canonicalHost.slice(0, -suffix.length);
	if (!path || path.includes(SEPARATOR) || !isValidHostPath(path)) return null;
	return { path };
}
function zoneNameKey(zone) {
	return zone.trim().toLowerCase();
}
function machineNameKey(path) {
	return path.trim().toLowerCase();
}
/** Child zone must be a one-or-more-label extension under parent (dns_prefix). */
function zoneUnderParent(childZone, parentZone) {
	const child = zoneNameKey(childZone);
	const parent = zoneNameKey(parentZone);
	if (parent === "") return child !== "";
	return child !== parent && child.endsWith(`.${parent}`);
}
//#endregion
export { machineNameKey, parseMachineHost, zoneNameKey, zoneUnderParent };
