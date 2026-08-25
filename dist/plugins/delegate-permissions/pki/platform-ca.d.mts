import { KeyPairMaterial } from "./types.mjs";

//#region src/plugins/delegate-permissions/pki/platform-ca.d.ts
type PlatformCertIssue = {
  readonly platformCertPem: string;
  readonly platformRootPem: string;
};
type PlatformCaMaterial = {
  readonly key: KeyPairMaterial;
  readonly rootPem: string;
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
};
/** Build a self-signed CA PEM from an Ed25519 private JWK (Platform Root or Entity CA). */
declare function createSelfSignedCaPem(privateJwk: Record<string, unknown>, commonName: string, notAfterDays?: number): Promise<{
  rootPem: string;
  ski: string;
  publicJwk: Record<string, unknown>;
}>;
/** Build (or rebuild) a self-signed Platform Root CA PEM from an Ed25519 private JWK. */
declare function createPlatformRootPem(privateJwk: Record<string, unknown>, commonName?: string, notAfterDays?: number): Promise<{
  rootPem: string;
  ski: string;
  publicJwk: Record<string, unknown>;
}>;
/** Load Platform CA from private JWK + optional stored root PEM. */
declare function loadPlatformCaMaterial(input: {
  privateJwk: Record<string, unknown>;
  rootPem?: string;
  commonName?: string;
  notAfterDays?: number;
}): Promise<PlatformCaMaterial>;
/** Generate an ephemeral Platform CA (dev/test). */
declare function generateEphemeralPlatformCa(commonName?: string, notAfterDays?: number): Promise<PlatformCaMaterial>;
type IssueKind = "ca" | "leaf";
/**
 * Issue a Platform-signed endorsement certificate for the same SPKI as
 * `entityCertPem` (Entity CA or Entity-signed leaf).
 *
 * For `kind: "ca"`, the Entity CA must verify as self-signed.
 * For `kind: "leaf"`, pass `chainPem` (Entity CA, or leaf+EntityCA) to verify.
 */
declare function issuePlatformEndorsementCert(input: {
  platform: PlatformCaMaterial;
  entityCertPem: string;
  kind: IssueKind; /** Entity CA PEM, or leaf+CA chain (issuer = last cert). */
  chainPem?: string;
  subjectCn?: string;
  host?: string;
  notAfterDays?: number;
}): Promise<PlatformCertIssue>;
/**
 * HAProxy litmus: `platformCertPem` verifies against the single Platform Root
 * (`ca-file` / `ca-sign-file`).
 */
declare function verifyAgainstTrustAnchor(certPem: string, rootPem: string): Promise<boolean>;
//#endregion
export { PlatformCaMaterial, PlatformCertIssue, createPlatformRootPem, createSelfSignedCaPem, generateEphemeralPlatformCa, issuePlatformEndorsementCert, loadPlatformCaMaterial, verifyAgainstTrustAnchor };