import { KeyPairMaterial } from "./types.mjs";

//#region src/plugins/delegate-permissions/pki/keys.d.ts
declare function generateEd25519KeyPair(): Promise<KeyPairMaterial>;
//#endregion
export { generateEd25519KeyPair };