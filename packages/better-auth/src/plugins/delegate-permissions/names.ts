/* cspell:ignore FQHN */
/**
 * Host / zone naming helpers (no role markers in the host string).
 * Machine host form: `{path}--{entityId}` (logical) or `{path}--{entityId}.idr.to` (verified FQHN).
 */

const SEPARATOR = "--";
const IDR_TO_SUFFIX = ".idr.to";

function isValidHostPath(path: string): boolean {
	if (!path || path.includes(SEPARATOR)) return false;
	for (const label of path.split(".")) {
		if (
			!label ||
			label.length > 63 ||
			label.startsWith("-") ||
			label.endsWith("-")
		) {
			return false;
		}
	}
	return true;
}

/**
 * Parse `{path}--{entity}` for `entityId`.
 * Accepts optional trailing `.idr.to` (verified FQHN from billing / Presence).
 */
export function parseMachineHost(
	host: string,
	entityId: string,
): { path: string } | null {
	let canonicalHost = host.trim().toLowerCase();
	const entity = entityId.trim().toLowerCase();
	if (!canonicalHost || !entity) return null;
	if (canonicalHost.endsWith(".")) {
		canonicalHost = canonicalHost.slice(0, -1);
	}
	if (canonicalHost.endsWith(IDR_TO_SUFFIX)) {
		canonicalHost = canonicalHost.slice(0, -IDR_TO_SUFFIX.length);
	}

	const suffix = `${SEPARATOR}${entity}`;
	if (!canonicalHost.endsWith(suffix)) return null;
	const path = canonicalHost.slice(0, -suffix.length);
	if (!path || path.includes(SEPARATOR) || !isValidHostPath(path)) {
		return null;
	}
	return { path };
}

export function zoneNameKey(zone: string): string {
	return zone.trim().toLowerCase();
}

export function machineNameKey(path: string): string {
	return path.trim().toLowerCase();
}

/** Child zone must be a one-or-more-label extension under parent (dns_prefix). */
export function zoneUnderParent(
	childZone: string,
	parentZone: string,
): boolean {
	const child = zoneNameKey(childZone);
	const parent = zoneNameKey(parentZone);
	if (parent === "") {
		return child !== "";
	}
	return child !== parent && child.endsWith(`.${parent}`);
}
