import { CapabilitySet } from "../capability/types.mjs";
import { CapabilityCredential, CredentialKind, EntityPackage, KeyPairMaterial, PublicJwk } from "./types.mjs";

//#region src/plugins/delegate-permissions/pki/credential.d.ts
declare function verifyCredentialSignature(credential: CapabilityCredential, issuerPublicJwk: PublicJwk): Promise<boolean>;
declare function issueCredential(input: {
  kind: CredentialKind;
  entityId: string;
  subject: KeyPairMaterial;
  permissions: CapabilitySet;
  issuerSki: string;
  issuerPrivateJwk: Record<string, unknown>;
  zone?: string;
  host?: string;
  package?: EntityPackage;
  ttlSeconds?: number;
}): Promise<CapabilityCredential>;
/** Test/dev cosign: attach platformCosign with the platform authority key. */
declare function attachPlatformCosign(credential: CapabilityCredential, platformPrivateJwk: Record<string, unknown>, platformKid: string): Promise<CapabilityCredential>;
//#endregion
export { attachPlatformCosign, issueCredential, verifyCredentialSignature };