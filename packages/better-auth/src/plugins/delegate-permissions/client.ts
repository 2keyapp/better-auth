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
			"/delegate-permissions/kickstart-entity": "POST",
			"/delegate-permissions/issue-delegate": "POST",
			"/delegate-permissions/issue-machine": "POST",
			"/delegate-permissions/enroll-create": "POST",
			"/delegate-permissions/enroll-list": "GET",
			"/delegate-permissions/enroll-approve": "POST",
			"/delegate-permissions/enroll-reject": "POST",
			"/delegate-permissions/enroll-pull": "POST",
			"/delegate-permissions/enroll-instant": "POST",
			"/delegate-permissions/enroll-machine-permissions": "POST",
		},
	} satisfies BetterAuthClientPlugin;
};
