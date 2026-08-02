/**
 * Host / zone naming helpers (no role markers in the host string).
 * Machine host form: `{path}--{entityId}`
 */

export function parseMachineHost(
	host: string,
	entityId: string,
): { path: string } | null {
	const canonicalHost = host.trim().toLowerCase();
	const entity = entityId.trim().toLowerCase();
	const suffix = `--${entity}`;
	if (!canonicalHost.endsWith(suffix)) {
		return null;
	}
	const path = canonicalHost.slice(0, -suffix.length);
	if (!path || path.includes("--")) {
		return null;
	}
	for (const label of path.split(".")) {
		if (
			!label ||
			label.length > 63 ||
			label.startsWith("-") ||
			label.endsWith("-")
		) {
			return null;
		}
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
