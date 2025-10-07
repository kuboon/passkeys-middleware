import { assert, assertEquals, assertFalse } from "@std/assert";
import {
  createDpopProof,
  generateDpopKeyPair,
  normalizeHtu,
  verifyDpopProof,
} from "./mod.ts";

const exampleUrl = "https://example.com/resource?foo=bar";

Deno.test("normalizeHtu removes fragments and preserves query", () => {
  assertEquals(
    normalizeHtu(`${exampleUrl}#fragment`),
    exampleUrl,
  );
});

Deno.test("create and verify DPoP proof", async () => {
  const keyPair = await generateDpopKeyPair();
  const proof = await createDpopProof({
    keyPair,
    method: "GET",
    url: `${exampleUrl}#section`,
    accessToken: "token-value",
    nonce: "abc123",
  });

  const result = await verifyDpopProof({
    proof,
    method: "GET",
    url: exampleUrl,
    accessToken: "token-value",
    nonce: "abc123",
  });

  assert(result.valid);
  assert(result.payload);
  assertEquals(result.payload.htm, "GET");
  assertEquals(result.payload.htu, exampleUrl);
  assert(result.payload.ath);
  assertEquals(result.payload.nonce, "abc123");
});

Deno.test("reject mismatched method", async () => {
  const keyPair = await generateDpopKeyPair();
  const proof = await createDpopProof({
    keyPair,
    method: "POST",
    url: exampleUrl,
  });

  const result = await verifyDpopProof({
    proof,
    method: "GET",
    url: exampleUrl,
  });

  assertFalse(result.valid);
  assertEquals(result.error, "method-mismatch");
});

Deno.test("reject mismatched access token hash", async () => {
  const keyPair = await generateDpopKeyPair();
  const proof = await createDpopProof({
    keyPair,
    method: "GET",
    url: exampleUrl,
    accessToken: "correct-token",
  });

  const result = await verifyDpopProof({
    proof,
    method: "GET",
    url: exampleUrl,
    accessToken: "wrong-token",
  });

  assertFalse(result.valid);
  assertEquals(result.error, "ath-mismatch");
});

Deno.test("reject stale proof", async () => {
  const keyPair = await generateDpopKeyPair();
  const now = Math.floor(Date.now() / 1000);
  const proof = await createDpopProof({
    keyPair,
    method: "GET",
    url: exampleUrl,
    iat: now - 1000,
  });

  const result = await verifyDpopProof({
    proof,
    method: "GET",
    url: exampleUrl,
    now,
    maxAgeSeconds: 300,
  });

  assertFalse(result.valid);
  assertEquals(result.error, "expired");
});

Deno.test("detect replay via custom checker", async () => {
  const seen = new Set<string>();
  const keyPair = await generateDpopKeyPair();
  const proof = await createDpopProof({
    keyPair,
    method: "GET",
    url: exampleUrl,
  });

  const first = await verifyDpopProof({
    proof,
    method: "GET",
    url: exampleUrl,
    checkReplay: (jti) => {
      if (seen.has(jti)) {
        return false;
      }
      seen.add(jti);
      return true;
    },
  });

  assert(first.valid);

  const second = await verifyDpopProof({
    proof,
    method: "GET",
    url: exampleUrl,
    checkReplay: (jti) => seen.has(jti) ? false : (seen.add(jti), true),
  });

  assertFalse(second.valid);
  assertEquals(second.error, "replay-detected");
});
