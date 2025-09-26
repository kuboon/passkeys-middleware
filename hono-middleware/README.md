# @passkeys-middleware/hono

A reusable [Hono](https://hono.dev/) middleware that adds [passkey / WebAuthn](https://passkeys.dev/) registration and authentication endpoints powered by [`@simplewebauthn/server`](https://github.com/MasterKale/SimpleWebAuthn).

The middleware exposes a ready-to-serve `client.js` bundle based on [`@simplewebauthn/client`](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/client) and a JSON API for bootstrapping and verifying passkey ceremonies. It is designed so the package can be published to both npm and [JSR](https://jsr.io/) as-is.

## Installation

```bash
npm install @passkeys-middleware/hono
```

or using the `npm:` specifier in Deno/JSR projects:

```ts
import { createPasskeyMiddleware } from 'jsr:@passkeys-middleware/hono';
```

## Usage

```ts
import { Hono } from 'hono';
import {
  InMemoryPasskeyStore,
  createPasskeyMiddleware,
} from '@passkeys-middleware/hono';

const app = new Hono();
const storage = new InMemoryPasskeyStore();

app.use(
  '/webauthn',
  createPasskeyMiddleware({
    rpID: 'example.com',
    rpName: 'Example Passkeys Demo',
    origin: 'https://example.com',
    storage,
    mountPath: '/webauthn',
  }),
);

app.get('/', (c) => c.text('Hello passkeys!'));
```

The middleware exposes the following endpoints relative to the mount path (e.g. `/webauthn`):

| Method | Path | Description |
| ------ | ---- | ----------- |
| `GET` | `/client.js` | Returns the pre-built `@simplewebauthn/client` bundle. |
| `GET` | `/credentials?username=<name>` | Lists stored credentials for the account. |
| `DELETE` | `/credentials/:credentialId?username=<name>` | Removes a stored credential (if the storage implementation supports deletion). |
| `POST` | `/register/options` | Generates registration options for the provided username (auto-provisions the account when needed). |
| `POST` | `/register/verify` | Verifies a registration ceremony and stores the resulting credential with the provided nickname. |
| `POST` | `/authenticate/options` | Generates authentication options for the stored credentials of the given user. |
| `POST` | `/authenticate/verify` | Verifies an authentication ceremony and updates the stored credential counter. |

All JSON endpoints return `4xx` errors when required parameters are missing or a credential/user cannot be resolved.

### Storage

`@passkeys-middleware/hono` ships with `InMemoryPasskeyStore` and `InMemoryChallengeStore` for quick experiments. For production use you should implement the `PasskeyStorage` and `PasskeyChallengeStore` interfaces with your own persistence layer and session handling.

### Client bundle caching

`client.js` is read from disk on first request and cached in-memory for subsequent responses. If you need custom caching headers you can wrap the middleware with your own handler.

## Building from source

```bash
npm install
npm run build -w hono-middleware
```

This compiles the TypeScript sources into `dist/` with type declarations so the package is ready for npm/JSR publication.
