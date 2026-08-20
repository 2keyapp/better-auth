//#region src/plugins/delegate-permissions/capability/action.ts
/**
* Whether a granted action covers a requested action.
* Supports exact match and a single trailing `.*` wildcard (e.g. `cert.*` → `cert.issue`).
*/
function actionCovers(granted, requested) {
	if (granted === requested) return true;
	if (granted.endsWith(".*")) {
		const prefix = granted.slice(0, -2);
		if (prefix.length === 0) return false;
		return requested === prefix || requested.startsWith(`${prefix}.`);
	}
	return false;
}
//#endregion
export { actionCovers };
