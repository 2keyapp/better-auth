import { scim } from "./index.mjs";

//#region src/client.d.ts
declare const scimClient: () => {
  id: "scim-client";
  version: string;
  $InferServerPlugin: ReturnType<typeof scim>;
};
//#endregion
export { scimClient };