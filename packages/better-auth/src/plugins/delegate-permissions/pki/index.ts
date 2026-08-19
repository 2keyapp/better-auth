export type { PlatformCertCosign } from "./cert-cosign";
export {
	attachPlatformCertCosign,
	verifyPlatformCertCosign,
} from "./cert-cosign";
export {
	attachPlatformCosign,
	issueCredential,
	verifyCredentialSignature,
} from "./credential";
export {
	bindCsrToPublicJwk,
	createDeviceCsr,
	leafMatchesCsr,
	signCsrWithCa,
} from "./csr";
export { generateEd25519KeyPair } from "./keys";
export type { PlatformCaMaterial, PlatformCertIssue } from "./platform-ca";
export {
	createPlatformRootPem,
	createSelfSignedCaPem,
	generateEphemeralPlatformCa,
	issuePlatformEndorsementCert,
	loadPlatformCaMaterial,
	verifyAgainstTrustAnchor,
} from "./platform-ca";
export type {
	CapabilityCredential,
	CosignProvider,
	CredentialKind,
	EntityPackage,
	KeyPairMaterial,
	PublicJwk,
	SeatBinder,
} from "./types";
