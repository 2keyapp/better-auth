# @2key/auth-native

Better Auth **server** plugin for native (Flutter / Dart) clients.

Formerly published as `@better-auth/flutter`.

The Dart client SDK lives at `packages/clients/dart` and is consumed via
GitHub (`path: packages/clients/dart`). This npm package is the TypeScript
server plugin (`@2key/auth-native`).

## Install (server / billing-auth-host)

```json
{
  "dependencies": {
    "@2key/auth-native": "github:2keyapp/better-auth#release-native"
  }
}
```

| Package | Release branch |
|---------|----------------|
| `@2key/auth-native` | `release-native` |
| `@better-auth/flutter` | **deprecated** — migrate to `@2key/auth-native` |

## Dart client

```yaml
better_auth:
  git:
    url: https://github.com/2keyapp/better-auth.git
    path: packages/clients/dart
    ref: <PINNED_SHA>
```

Host apps must **not** depend on this Dart package directly — use
`two_key_dart_sdk` from `2key-billing-sdks`.

## Usage

```ts
import { authNative } from "@2key/auth-native";
// deprecated alias still works:
// import { flutter } from "@2key/auth-native";

export const auth = betterAuth({
  plugins: [authNative()],
});
```
