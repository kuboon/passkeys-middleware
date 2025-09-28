/// <reference lib="deno.ns" />

import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  createPasskeyMiddleware,
  InMemoryChallengeStore,
  InMemoryPasskeyStore,
} from "@passkeys-middleware/hono";
import createEnv from "ventojs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const rpID = process.env.RP_ID ?? "localhost";
const rpName = process.env.RP_NAME ?? "Passkeys Middleware Demo";
const port = Number.parseInt(process.env.PORT ?? "8787", 10);
const defaultOrigin = process.env.RP_ORIGIN ??
  (rpID === "localhost" ? `http://localhost:${port}` : `https://${rpID}`);
const origin = process.env.RP_ORIGIN ?? defaultOrigin;

const app = new Hono();
const credentialStore = new InMemoryPasskeyStore();
const challengeStore = new InMemoryChallengeStore();

app.use(
  createPasskeyMiddleware({
    rpID,
    rpName,
    origin,
    storage: credentialStore,
    challengeStore,
  }),
);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const env = createEnv({ includes: __dirname, autoescape: true });

app.get("/", async (c) => {
  const result = await env.run("index.vto", { rpID, origin });
  return c.html(result.content);
});

app.onError((err, c) => {
  console.error(err);
  if (err instanceof HTTPException) {
    return err.getResponse();
  }
  return c.json({ message: "Internal Server Error" }, 500);
});

Deno.serve({ port }, app.fetch);

console.log(`Passkeys demo listening on http://localhost:${port}`);
