import * as better_auth0 from "better-auth";
import * as zod from "zod";
import * as better_call0 from "better-call";
import * as zod_v4_core0 from "zod/v4/core";

//#region src/index.d.ts
interface FlutterOptions {
  /**
   * Disable origin override for Flutter API routes.
   * When set to true, the origin header will not be overridden from
   * the `flutter-origin` request header.
   */
  disableOriginOverride?: boolean | undefined;
}
declare module "@better-auth/core" {
  interface BetterAuthPluginRegistry<AuthOptions, Options> {
    flutter: {
      creator: typeof flutter;
    };
  }
}
/**
 * Better Auth server plugin for Flutter / Dart clients.
 *
 * Adds trusted-origin helpers for custom URL schemes, copies
 * `flutter-origin` into the request origin header (so CSRF/origin
 * checks work without a browser Origin), and attaches session cookies
 * to deep-link redirects after OAuth / magic-link / email verification.
 */
declare const flutter: (options?: FlutterOptions | undefined) => {
  id: "flutter";
  version: string;
  init: () => {
    options: {
      trustedOrigins: never[];
    };
  };
  onRequest(request: Request): Promise<{
    request: Request;
  } | undefined>;
  hooks: {
    after: {
      matcher(context: better_auth0.HookEndpointContext): boolean;
      handler: (inputContext: better_call0.MiddlewareInputContext<better_call0.MiddlewareOptions>) => Promise<void>;
    }[];
  };
  endpoints: {
    flutterAuthorizationProxy: better_call0.StrictEndpoint<"/flutter-authorization-proxy", {
      method: "GET";
      query: zod.ZodObject<{
        authorizationURL: zod.ZodString;
        oauthState: zod.ZodOptional<zod.ZodString>;
      }, zod_v4_core0.$strip>;
      metadata: {
        readonly scope: "server";
      };
    }, {
      status: ("OK" | "CREATED" | "ACCEPTED" | "NO_CONTENT" | "MULTIPLE_CHOICES" | "MOVED_PERMANENTLY" | "FOUND" | "SEE_OTHER" | "NOT_MODIFIED" | "TEMPORARY_REDIRECT" | "BAD_REQUEST" | "UNAUTHORIZED" | "PAYMENT_REQUIRED" | "FORBIDDEN" | "NOT_FOUND" | "METHOD_NOT_ALLOWED" | "NOT_ACCEPTABLE" | "PROXY_AUTHENTICATION_REQUIRED" | "REQUEST_TIMEOUT" | "CONFLICT" | "GONE" | "LENGTH_REQUIRED" | "PRECONDITION_FAILED" | "PAYLOAD_TOO_LARGE" | "URI_TOO_LONG" | "UNSUPPORTED_MEDIA_TYPE" | "RANGE_NOT_SATISFIABLE" | "EXPECTATION_FAILED" | "I'M_A_TEAPOT" | "MISDIRECTED_REQUEST" | "UNPROCESSABLE_ENTITY" | "LOCKED" | "FAILED_DEPENDENCY" | "TOO_EARLY" | "UPGRADE_REQUIRED" | "PRECONDITION_REQUIRED" | "TOO_MANY_REQUESTS" | "REQUEST_HEADER_FIELDS_TOO_LARGE" | "UNAVAILABLE_FOR_LEGAL_REASONS" | "INTERNAL_SERVER_ERROR" | "NOT_IMPLEMENTED" | "BAD_GATEWAY" | "SERVICE_UNAVAILABLE" | "GATEWAY_TIMEOUT" | "HTTP_VERSION_NOT_SUPPORTED" | "VARIANT_ALSO_NEGOTIATES" | "INSUFFICIENT_STORAGE" | "LOOP_DETECTED" | "NOT_EXTENDED" | "NETWORK_AUTHENTICATION_REQUIRED") | better_call0.Status;
      body: ({
        message?: string;
        code?: string;
        cause?: unknown;
      } & Record<string, any>) | undefined;
      headers: HeadersInit;
      statusCode: number;
      name: string;
      message: string;
      stack?: string;
      cause?: unknown;
    }>;
  };
  options: FlutterOptions | undefined;
};
//#endregion
export { FlutterOptions, flutter };