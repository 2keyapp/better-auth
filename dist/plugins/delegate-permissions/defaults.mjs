//#region src/plugins/delegate-permissions/defaults.ts
/** Shared optional-option defaults for `delegatePermissions()`. */
const DAY_SEC = 1440 * 60;
const DEFAULT_SESSION_GRANT_EXPIRES_IN = 3600;
const DEFAULT_INVITE_EXPIRES_IN = 7 * DAY_SEC;
const DEFAULT_INVITE_MAX_EXPIRES_IN = 30 * DAY_SEC;
const DEFAULT_CREDENTIAL_EXPIRES_IN = 365 * DAY_SEC;
const DEFAULT_CA_CERT_EXPIRES_IN = 3650 * DAY_SEC;
const DEFAULT_LEAF_CERT_EXPIRES_IN = 365 * DAY_SEC;
function secondsToDays(seconds) {
	return seconds / DAY_SEC;
}
//#endregion
export { DEFAULT_CA_CERT_EXPIRES_IN, DEFAULT_CREDENTIAL_EXPIRES_IN, DEFAULT_INVITE_EXPIRES_IN, DEFAULT_INVITE_MAX_EXPIRES_IN, DEFAULT_LEAF_CERT_EXPIRES_IN, DEFAULT_SESSION_GRANT_EXPIRES_IN, secondsToDays };
