# Passkeys Middleware Monorepo

This repository hosts two packages that demonstrate how to integrate passkey (WebAuthn) authentication with [Hono](https://hono.dev/):

- [`@passkeys-middleware/hono`](./hono-middleware) – a reusable middleware that exposes WebAuthn endpoints powered by [`@simplewebauthn/server`](https://github.com/MasterKale/SimpleWebAuthn) and serves the [`@simplewebauthn/client`](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/client) browser bundle.
- [`@passkeys-middleware/demo-server`](./server) – a Hono application that mounts the middleware at `/webauthn` and provides a small UI for registering and authenticating multiple passkeys per account with nicknames.

## Project structure

```
/
├─ hono-middleware/    # Source for the reusable middleware (npm + JSR ready)
└─ server/             # Demo server that consumes the middleware via app.use('/webauthn', ...)
```

## Development

```bash
npm install       # Install dependencies (requires network access to npm registry)
npm run build     # Build the middleware package (runs in the hono-middleware workspace)
```

The demo server can be launched with:

```bash
npm run dev -w server
```

By default it listens on <http://localhost:8787> and uses `localhost` as the relying party ID. You can override the relying party values using environment variables:

- `RP_ID`
- `RP_NAME`
- `RP_ORIGIN`
- `PORT`

## Publishing

- Publish the middleware to npm via `npm publish` from the `hono-middleware/` directory.
- Publish to [JSR](https://jsr.io/) with `npx jsr publish`.

The demo server is intended for local development and should not be published.
