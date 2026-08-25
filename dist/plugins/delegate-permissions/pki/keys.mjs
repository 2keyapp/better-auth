import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";
//#region src/plugins/delegate-permissions/pki/keys.ts
function toPublicJwk(jwk) {
	const { d: _d, ...rest } = jwk;
	return rest;
}
async function generateEd25519KeyPair() {
	const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
		crv: "Ed25519",
		extractable: true
	});
	const privateJwk = await exportJWK(privateKey);
	const publicJwk = toPublicJwk(await exportJWK(publicKey));
	const ski = await calculateJwkThumbprint(publicJwk, "sha256");
	return {
		ski,
		publicJwk: {
			...publicJwk,
			kid: ski,
			alg: "EdDSA"
		},
		privateJwk: {
			...privateJwk,
			kid: ski,
			alg: "EdDSA"
		}
	};
}
//#endregion
export { generateEd25519KeyPair };
