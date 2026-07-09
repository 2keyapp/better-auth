# Better Auth Flutter Plugin

Server-side Better Auth plugin for Flutter and Dart clients.

The Dart client SDK lives at `packages/flutter/dart` and is consumed via
GitHub (`path: packages/flutter/dart`). This npm package is the TypeScript
server plugin (`@better-auth/flutter`).

## Installation

### Server (Node.js)

Install from GitHub release branches:

```json
{
  "dependencies": {
    "better-auth": "github:2keyapp/better-auth#release",
    "@better-auth/flutter": "github:2keyapp/better-auth#release-flutter"
  }
}
```

| Package | Release branch |
| --- | --- |
| `better-auth` | `release` |
| `@better-auth/flutter` | `release-flutter` |

### Client (Flutter / Dart)

```yaml
dependencies:
  better_auth:
    git:
      url: https://github.com/2keyapp/better-auth.git
      ref: main
      path: packages/flutter/dart
```

| Package | Git ref |
| --- | --- |
| `better_auth` | `main` (monorepo path; pin by commit in production) |

See the [Install from GitHub](https://www.better-auth.com/docs/guides/github-installation) guide for details.

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
* **Install from GitHub:** [Install from GitHub](https://www.better-auth.com/docs/guides/github-installation)
* **Main Better Auth Installation:** [Installation Guide](https://www.better-auth.com/docs/installation)

## License

MIT
