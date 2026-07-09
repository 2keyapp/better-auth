import { t as PACKAGE_VERSION } from "./version-YIydhdrs.mjs";
//#region src/client.ts
const scimClient = () => {
	return {
		id: "scim-client",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {}
	};
};
//#endregion
export { scimClient };
