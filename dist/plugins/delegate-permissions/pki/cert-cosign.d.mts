//#region src/plugins/delegate-permissions/pki/cert-cosign.d.ts
type PlatformCertCosign = {
  readonly kid: string;
  readonly signedAt: string;
  readonly signature: string;
};
/**
 * Platform co-sign over an X.509 PEM (DER committed as base64).
 * Used for Entity CA roots and machine leaf certificates.
 */
declare function attachPlatformCertCosign(certPem: string, platformPrivateJwk: Record<string, unknown>, platformKid: string): Promise<PlatformCertCosign>;
declare function verifyPlatformCertCosign(certPem: string, cosign: PlatformCertCosign, platformPublicJwk: Record<string, unknown>): Promise<boolean>;
//#endregion
export { PlatformCertCosign, attachPlatformCertCosign, verifyPlatformCertCosign };