//#region src/plugins/delegate-permissions/capability/action.d.ts
/**
 * Whether a granted action covers a requested action.
 * Supports exact match and a single trailing `.*` wildcard (e.g. `cert.*` → `cert.issue`).
 */
declare function actionCovers(granted: string, requested: string): boolean;
//#endregion
export { actionCovers };