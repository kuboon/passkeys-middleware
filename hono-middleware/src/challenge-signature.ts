import { base64 } from "@hexagon/base64";
import type { ChallengeType, PasskeyStoredChallenge } from "./types.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const SECRET_KV_KEY = ["passkey", "challenge_signature", "secret"] as const;
const SECRET_BYTE_LENGTH = 32;
export const CHALLENGE_COOKIE_NAME = "passkey_challenge";

let kvOverride: Deno.Kv | null = null;
let kvPromise: Promise<Deno.Kv> | undefined;
let secretPromise: Promise<Uint8Array> | undefined;
let hmacKeyPromise: Promise<CryptoKey> | undefined;

const toArrayBuffer = (input: Uint8Array | ArrayBuffer): ArrayBuffer => {
  if (input instanceof ArrayBuffer) {
    return input;
  }
  if (input.byteOffset === 0 && input.buffer instanceof ArrayBuffer) {
    return input.buffer;
  }
  return input.slice().buffer;
};

const base64UrlEncode = (input: Uint8Array | ArrayBuffer): string =>
  base64.fromArrayBuffer(toArrayBuffer(input), true);

const base64UrlDecode = (input: string): Uint8Array =>
  new Uint8Array(base64.toArrayBuffer(input, true));

const getKvInstance = (): Promise<Deno.Kv> => {
  if (kvOverride) {
    return Promise.resolve(kvOverride);
  }
  if (!kvPromise) {
    kvPromise = Deno.openKv();
  }
  return kvPromise;
};

const getSecretBytes = (): Promise<Uint8Array> => {
  if (!secretPromise) {
    secretPromise = (async () => {
      const kv = await getKvInstance();
      const current = await kv.get<Uint8Array>(SECRET_KV_KEY);
      const existing = current.value;
      if (
        existing instanceof Uint8Array && existing.length === SECRET_BYTE_LENGTH
      ) {
        return new Uint8Array(existing);
      }
      const generated = new Uint8Array(SECRET_BYTE_LENGTH);
      crypto.getRandomValues(generated);
      const atomic = kv.atomic();
      if (current.versionstamp) {
        atomic.check({
          key: SECRET_KV_KEY,
          versionstamp: current.versionstamp,
        });
      } else {
        atomic.check({ key: SECRET_KV_KEY, versionstamp: null });
      }
      const commit = await atomic.set(SECRET_KV_KEY, generated).commit();
      if (!commit.ok) {
        secretPromise = undefined;
        return getSecretBytes();
      }
      return generated;
    })();
  }
  return secretPromise;
};

const getHmacKey = (): Promise<CryptoKey> => {
  if (!hmacKeyPromise) {
    hmacKeyPromise = (async () => {
      const secret = await getSecretBytes();
      const rawKey = toArrayBuffer(secret);
      return crypto.subtle.importKey(
        "raw",
        rawKey,
        {
          name: "HMAC",
          hash: "SHA-256",
        },
        false,
        ["sign", "verify"],
      );
    })();
  }
  return hmacKeyPromise;
};

const encodePayload = (payload: ChallengeSignaturePayload): Uint8Array =>
  encoder.encode(JSON.stringify(payload));

const decodePayload = (payloadBytes: Uint8Array): ChallengeSignaturePayload => {
  const parsed = JSON.parse(decoder.decode(payloadBytes));
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Invalid payload structure");
  }
  const candidate = parsed as Record<string, unknown>;
  const userId = typeof candidate.userId === "string" ? candidate.userId : null;
  const type =
    candidate.type === "registration" || candidate.type === "authentication"
      ? candidate.type
      : null;
  const value = candidate.value;
  if (!userId || !type || typeof value !== "object" || value === null) {
    throw new Error("Invalid challenge payload");
  }
  const challenge = (value as Record<string, unknown>).challenge;
  const origin = (value as Record<string, unknown>).origin;
  if (typeof challenge !== "string" || typeof origin !== "string") {
    throw new Error("Invalid challenge value");
  }
  return {
    userId,
    type,
    value: { challenge, origin },
  } satisfies ChallengeSignaturePayload;
};

const signPayload = async (payloadBytes: Uint8Array): Promise<string> => {
  const key = await getHmacKey();
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    toArrayBuffer(payloadBytes),
  );
  return base64UrlEncode(signature);
};

const verifySignature = async (
  payloadBytes: Uint8Array,
  signature: string,
): Promise<boolean> => {
  try {
    const key = await getHmacKey();
    const signatureBytes = base64UrlDecode(signature);
    return await crypto.subtle.verify(
      "HMAC",
      key,
      toArrayBuffer(signatureBytes),
      toArrayBuffer(payloadBytes),
    );
  } catch {
    return false;
  }
};

export interface ChallengeSignaturePayload {
  userId: string;
  type: ChallengeType;
  value: PasskeyStoredChallenge;
}

export const createSignedChallengeValue = async (
  payload: ChallengeSignaturePayload,
): Promise<string> => {
  const payloadBytes = encodePayload(payload);
  const tokenPayload = base64UrlEncode(payloadBytes);
  const signature = await signPayload(payloadBytes);
  return `${tokenPayload}.${signature}`;
};

export const verifySignedChallengeValue = async (
  token: string | undefined,
  expected: { userId: string; type: ChallengeType },
): Promise<PasskeyStoredChallenge | null> => {
  if (!token) {
    return null;
  }
  const separatorIndex = token.lastIndexOf(".");
  if (separatorIndex <= 0 || separatorIndex === token.length - 1) {
    return null;
  }
  const payloadBase64 = token.slice(0, separatorIndex);
  const signature = token.slice(separatorIndex + 1);
  let payloadBytes: Uint8Array;
  try {
    payloadBytes = base64UrlDecode(payloadBase64);
  } catch {
    return null;
  }
  const signatureValid = await verifySignature(payloadBytes, signature);
  if (!signatureValid) {
    return null;
  }
  try {
    const payload = decodePayload(payloadBytes);
    if (payload.userId !== expected.userId || payload.type !== expected.type) {
      return null;
    }
    return payload.value;
  } catch {
    return null;
  }
};

export const challengeSignatureInternals = {
  setKvOverride: (kv: Deno.Kv | null) => {
    kvOverride = kv;
    if (!kvOverride) {
      kvPromise = undefined;
    }
    secretPromise = undefined;
    hmacKeyPromise = undefined;
  },
  getKvKey: () => SECRET_KV_KEY,
};
