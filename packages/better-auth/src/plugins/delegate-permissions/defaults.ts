/** Shared optional-option defaults for `delegatePermissions()`. */

export const DAY_SEC = 24 * 60 * 60;

export const DEFAULT_SESSION_GRANT_EXPIRES_IN = 3600;
export const DEFAULT_INVITE_EXPIRES_IN = 7 * DAY_SEC;
export const DEFAULT_INVITE_MAX_EXPIRES_IN = 30 * DAY_SEC;
export const DEFAULT_INVITE_MAX_USES = 1;
export const DEFAULT_CREDENTIAL_EXPIRES_IN = 365 * DAY_SEC;
export const DEFAULT_CA_CERT_EXPIRES_IN = 3650 * DAY_SEC;
export const DEFAULT_LEAF_CERT_EXPIRES_IN = 365 * DAY_SEC;

export function secondsToDays(seconds: number): number {
	return seconds / DAY_SEC;
}
