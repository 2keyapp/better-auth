# Better Auth Flutter Plugin

Server-side Better Auth plugin for Flutter and Dart clients.

> The Dart client SDK lives at `packages/flutter/dart`
> (intended for [pub.dev](https://pub.dev) as `better_auth`).
> This npm package is the TypeScript server plugin only.

## Installation

```bash
pnpm add better-auth @better-auth/flutter
```

## Basic Usage

```ts
import { betterAuth } from "better-auth";
import { flutter } from "@better-auth/flutter";

export const auth = betterAuth({
  plugins: [flutter()],
  emailAndPassword: {
    enabled: true,
  },
  // Replace "myapp" with your Flutter deep-link scheme
  trustedOrigins: ["myapp://"],
});
```

The Dart client should send a `flutter-origin` header (e.g. `myapp://`) on
authenticated requests so the plugin can satisfy origin checks.

For **session handoff** (Flutter → web while already signed in), use the
[one-time-token](https://www.better-auth.com/docs/plugins/one-time-token)
plugin — see the [Flutter integration guide](https://www.better-auth.com/docs/integrations/flutter).

## Documentation

* **Flutter Integration Guide:** [Flutter Integration Guide](https://www.better-auth.com/docs/integrations/flutter)
* **Main Better Auth Installation:** [Installation Guide](https://www.better-auth.com/docs/installation)

## License

MIT
