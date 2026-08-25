import { KeyPairMaterial, PublicJwk } from "./types.mjs";

//#region src/plugins/delegate-permissions/pki/csr.d.ts
/**
 * Parse a PKCS#10 PEM, verify the CSR signature, and bind it to `publicJwk`
 * when that is supplied. Returns the canonical public JWK + SKI from the CSR.
 */
declare function bindCsrToPublicJwk(csrPem: string, publicJwk?: Record<string, unknown>): Promise<{
  ski: string;
  publicJwk: PublicJwk;
}>;
/** True when the leaf SPKI is the same public key as the enrollment CSR. */
declare function leafMatchesCsr(leafPem: string, csrPem: string): Promise<boolean>;
/**
 * Device `identity init`: Ed25519 keypair + PKCS#10 CSR.
 * Private key is returned once for the caller to store locally.
 */
declare function createDeviceCsr(input?: {
  commonName?: string;
}): Promise<{
  key: KeyPairMaterial;
  csrPem: string;
}>;
/**
 * Admin signs a pending CSR with the Entity CA (same host as `enroll-instant`).
 * `chainPem` is leaf + Entity CA so Platform can verify before endorsement.
 */
declare function signCsrWithCa(input: {
  csrPem: string;
  caCertPem: string;
  caPrivateJwk: Record<string, unknown>;
  host?: string;
  subjectCn?: string;
  notAfterDays?: number;
}): Promise<{
  leafPem: string;
  chainPem: string;
}>;
//#endregion
export { bindCsrToPublicJwk, createDeviceCsr, leafMatchesCsr, signCsrWithCa };