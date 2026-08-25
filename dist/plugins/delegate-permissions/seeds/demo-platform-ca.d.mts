//#region src/plugins/delegate-permissions/seeds/demo-platform-ca.d.ts
/**
 * Built-in Platform CA for `seed: "demo"` only.
 *
 * Private JWK is the public Ed25519 test vector from RFC 8037 Appendix A —
 * not a production secret. HAProxy can trust `GET /delegate-permissions/platform-root`
 * across process restarts because the key is fixed (root PEM serial may change).
 *
 * Production tenants must pass `platformCa` with their own key.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8037#appendix-A
 */
declare const DEMO_PLATFORM_CA: {
  readonly commonName: "Platform CA (demo)";
  readonly privateJwk: {
    readonly kty: "OKP";
    readonly crv: "Ed25519";
    readonly d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    readonly x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    readonly alg: "EdDSA";
  };
};
//#endregion
export { DEMO_PLATFORM_CA };