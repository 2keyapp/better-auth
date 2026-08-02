import type { BetterAuthClientPlugin } from "@better-auth/core";
import { PACKAGE_VERSION } from "../../version";
import type { delegatePermissions } from ".";

export const delegatePermissionsClient = () => {
	return {
		id: "delegate-permissions",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof delegatePermissions>,
		pathMethods: {
			"/delegate-permissions/seed-catalog": "POST",
			"/delegate-permissions/catalog": "GET",
			"/delegate-permissions/principal-grant": "POST",
			"/delegate-permissions/issue-session-capabilities": "POST",
			"/delegate-permissions/authorize": "POST",
			"/delegate-permissions/assert-subset": "POST",
		},
	} satisfies BetterAuthClientPlugin;
};
