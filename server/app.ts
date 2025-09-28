/// <reference lib="deno.ns" />

import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  createPasskeyMiddleware,
  InMemoryChallengeStore,
  InMemoryPasskeyStore,
} from "@passkeys-middleware/hono";
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

app.get("/", async (c) => {
  const html = await fetch(import.meta.resolve("./static/index.html")).then(x=>x.text())
  return c.html(html);
});

app.onError((err, c) => {
  console.error(err);
  if (err instanceof HTTPException) {
    return err.getResponse();
  }
  return c.json({ message: "Internal Server Error" }, 500);
});

export { app }
