import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";
import type { KeyPairMaterial, PublicJwk } from "./types";

function toPublicJwk(jwk: Record<string, unknown>): PublicJwk {
	const { d: _d, ...rest } = jwk;
	return rest as PublicJwk;
}

export async function generateEd25519KeyPair(): Promise<KeyPairMaterial> {
	const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
		crv: "Ed25519",
		extractable: true,
	});
	const privateJwk = (await exportJWK(privateKey)) as Record<string, unknown>;
	const publicJwk = toPublicJwk(
		(await exportJWK(publicKey)) as Record<string, unknown>,
	);
	const ski = await calculateJwkThumbprint(publicJwk, "sha256");
	return {
		ski,
		publicJwk: { ...publicJwk, kid: ski, alg: "EdDSA" },
		privateJwk: { ...privateJwk, kid: ski, alg: "EdDSA" },
	};
}
