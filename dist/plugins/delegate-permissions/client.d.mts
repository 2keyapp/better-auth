import { delegatePermissions } from "./index.mjs";

//#region src/plugins/delegate-permissions/client.d.ts
declare const delegatePermissionsClient: () => {
  id: "delegate-permissions";
  version: string;
  $InferServerPlugin: ReturnType<typeof delegatePermissions>;
  pathMethods: {
    "/delegate-permissions/seed-catalog": "POST";
    "/delegate-permissions/catalog": "GET";
    "/delegate-permissions/principal-grant": "POST";
    "/delegate-permissions/issue-session-capabilities": "POST";
    "/delegate-permissions/authorize": "POST";
    "/delegate-permissions/assert-subset": "POST";
    "/delegate-permissions/kickstart-entity": "POST";
    "/delegate-permissions/entity": "GET";
    "/delegate-permissions/issue-delegate": "POST";
    "/delegate-permissions/issue-machine": "POST";
    "/delegate-permissions/enroll-create": "POST";
    "/delegate-permissions/enroll-invite": "POST";
    "/delegate-permissions/enroll-list": "GET";
    "/delegate-permissions/enroll-approve": "POST";
    "/delegate-permissions/enroll-reject": "POST";
    "/delegate-permissions/enroll-pull": "POST";
    "/delegate-permissions/enroll-instant": "POST";
    "/delegate-permissions/enroll-machine-permissions": "POST";
    "/delegate-permissions/platform-root": "GET";
    "/delegate-permissions/credential-revoke": "POST";
    "/delegate-permissions/credential-status": "GET";
    "/delegate-permissions/credential-list": "GET";
    "/delegate-permissions/machine-decommission": "POST";
    "/delegate-permissions/machine-renew": "POST";
  };
};
//#endregion
export { delegatePermissionsClient };