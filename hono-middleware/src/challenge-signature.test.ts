import {
  assertEquals,
  assertExists,
  assertNotEquals,
  assertStrictEquals,
} from "@std/assert";
import {
  CHALLENGE_COOKIE_NAME,
  challengeSignatureInternals,
  createSignedChallengeValue,
  verifySignedChallengeValue,
} from "./challenge-signature.ts";

Deno.test("creates and verifies signed challenge value", async () => {
  const kv = await Deno.openKv(":memory:");
  try {
    challengeSignatureInternals.setKvOverride(kv);
    const payload = {
      userId: "user-123",
      type: "registration" as const,
      value: { challenge: "test-challenge", origin: "https://example.com" },
    };
    const token = await createSignedChallengeValue(payload);
    const verified = await verifySignedChallengeValue(token, {
      userId: payload.userId,
      type: payload.type,
    });
    assertExists(verified);
    assertEquals(verified.challenge, payload.value.challenge);
    assertEquals(verified.origin, payload.value.origin);
    assertEquals(CHALLENGE_COOKIE_NAME, "passkey_challenge");
    const storedSecret = await kv.get<Uint8Array>(
      challengeSignatureInternals.getKvKey(),
    );
    assertExists(storedSecret.value);
    assertEquals(storedSecret.value.length, 32);
  } finally {
    challengeSignatureInternals.setKvOverride(null);
    kv.close();
  }
});

Deno.test("rejects mismatched identifiers", async () => {
  const kv = await Deno.openKv(":memory:");
  try {
    challengeSignatureInternals.setKvOverride(kv);
    const token = await createSignedChallengeValue({
      userId: "user-1",
      type: "authentication",
      value: { challenge: "c2", origin: "https://auth.example" },
    });
    const result = await verifySignedChallengeValue(token, {
      userId: "user-2",
      type: "authentication",
    });
    assertStrictEquals(result, null);
    const typeMismatch = await verifySignedChallengeValue(token, {
      userId: "user-1",
      type: "registration",
    });
    assertStrictEquals(typeMismatch, null);
  } finally {
    challengeSignatureInternals.setKvOverride(null);
    kv.close();
  }
});

Deno.test("detects tampered signatures", async () => {
  const kv = await Deno.openKv(":memory:");
  try {
    challengeSignatureInternals.setKvOverride(kv);
    const token = await createSignedChallengeValue({
      userId: "user-3",
      type: "authentication",
      value: { challenge: "orig", origin: "https://site" },
    });
    const parts = token.split(".");
    assertEquals(parts.length, 2);
    const tamperedSignature = (parts[1][0] === "A" ? "B" : "A") +
      parts[1].slice(1);
    assertNotEquals(parts[1], tamperedSignature);
    const tamperedToken = `${parts[0]}.${tamperedSignature}`;
    const verified = await verifySignedChallengeValue(tamperedToken, {
      userId: "user-3",
      type: "authentication",
    });
    assertStrictEquals(verified, null);
  } finally {
    challengeSignatureInternals.setKvOverride(null);
    kv.close();
  }
});
