# Better Auth SCIM Plugin

`@better-auth/scim` adds an inbound System for Cross-domain Identity Management (SCIM) 2.0 service to [Better Auth](https://www.better-auth.com). Directory services can provision isolated Users, Groups, and direct Group memberships through bearer-authenticated connections.

The plugin supports a focused subset of the resource model in [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) and the protocol in [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644).

## Installation

This fork publishes packaged builds on GitHub release branches (not npm):

```json
{
  "dependencies": {
    "better-auth": "github:2keyapp/better-auth#release",
    "@better-auth/scim": "github:2keyapp/better-auth#release-scim"
  }
}
```

| Package | Release branch |
| --- | --- |
| `better-auth` | `release` |
| `@better-auth/scim` | `release-scim` |

See the [Install from GitHub](/docs/guides/github-installation) guide for details.

Upstream consumers can still install from npm when available:

```bash
pnpm add @better-auth/scim
```

## Documentation

For setup, Groups and custom roles, and the protocol reference, visit [better-auth.com/docs/plugins/scim](https://www.better-auth.com/docs/plugins/scim).

## License

MIT
