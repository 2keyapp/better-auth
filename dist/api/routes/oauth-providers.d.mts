import { GenericEndpointContext } from "@better-auth/core";
import * as better_call0 from "better-call";

//#region src/api/routes/oauth-providers.d.ts
interface OAuthProviderInfo {
  id: string;
  enabled: boolean;
  /** IdP-registered redirect URI for social providers (Better Auth callback). */
  redirectUri?: string;
}
interface OAuthProvidersResponse {
  issuer: string;
  providers: OAuthProviderInfo[];
}
/** Builds login-method discovery payload from runtime Better Auth configuration. */
declare function buildOAuthProvidersResponse(ctx: GenericEndpointContext): OAuthProvidersResponse;
/** Public discovery for login UIs — which auth methods are enabled on this server. */
declare const getOAuthProviders: better_call0.StrictEndpoint<"/.well-known/oauth-providers", {
  method: "GET";
  metadata: {
    openapi: {
      description: string;
      responses: {
        "200": {
          description: string;
          content: {
            "application/json": {
              schema: {
                type: "object";
                properties: {
                  issuer: {
                    type: string;
                  };
                  providers: {
                    type: string;
                    items: {
                      type: string;
                      properties: {
                        id: {
                          type: string;
                        };
                        enabled: {
                          type: string;
                        };
                        redirectUri: {
                          type: string;
                        };
                      };
                      required: string[];
                    };
                  };
                };
                required: string[];
              };
            };
          };
        };
      };
    };
    scope: "server";
  };
}, OAuthProvidersResponse>;
//#endregion
export { OAuthProviderInfo, OAuthProvidersResponse, buildOAuthProvidersResponse, getOAuthProviders };