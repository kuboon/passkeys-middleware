import { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const toUint8Array = (input: ArrayBuffer | Uint8Array): Uint8Array =>
  input instanceof Uint8Array ? input : new Uint8Array(input);

const base64UrlEncode = (input: ArrayBuffer | Uint8Array): string =>
  encodeBase64Url(toUint8Array(input));

const base64UrlDecode = (input: string): Uint8Array =>
  new Uint8Array(decodeBase64Url(input));

const sha256Base64Url = async (value: string): Promise<string> => {
  const data = textEncoder.encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(digest);
};

const normalizeMethod = (method: string): string => method.trim().toUpperCase();

export const normalizeHtu = (url: string): string => {
  const parsed = new URL(url);
  return `${parsed.origin}${parsed.pathname}${parsed.search}`;
};

export interface GenerateDpopKeyPairOptions {
  /**
   * Whether the generated keys should be extractable. Defaults to `true` so the
   * public key can be embedded in the DPoP proof header.
   */
  extractable?: boolean;
}

export const generateDpopKeyPair = (
  options: GenerateDpopKeyPairOptions = {},
): Promise<CryptoKeyPair> =>
  crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    options.extractable ?? true,
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>;

export interface DpopJwtPayload {
  readonly htm: string;
  readonly htu: string;
  readonly jti: string;
  readonly iat: number;
  readonly nonce?: string;
  readonly ath?: string;
}

export interface CreateDpopProofOptions {
  readonly keyPair: CryptoKeyPair;
  readonly method: string;
  readonly url: string;
  readonly accessToken?: string;
  readonly nonce?: string;
  readonly jti?: string;
  readonly iat?: number;
}

const stripPrivateFields = (jwk: JsonWebKey): JsonWebKey => {
  const { crv, kty, x, y } = jwk;
  return { crv, kty, x, y };
};

export const createDpopProof = async (
  options: CreateDpopProofOptions,
): Promise<string> => {
  const method = normalizeMethod(options.method);
  const htu = normalizeHtu(options.url);
  const iat = options.iat ?? Math.floor(Date.now() / 1000);
  const jti = options.jti ?? crypto.randomUUID();

  if (!method) {
    throw new TypeError("HTTP method is required to create a DPoP proof.");
  }

  const payload: DpopJwtPayload = {
    htm: method,
    htu,
    iat,
    jti,
    ...(options.nonce !== undefined ? { nonce: options.nonce } : {}),
    ...(options.accessToken
      ? { ath: await sha256Base64Url(options.accessToken) }
      : {}),
  };

  const publicJwk = await crypto.subtle.exportKey(
    "jwk",
    options.keyPair.publicKey,
  );

  const header = {
    alg: "ES256" as const,
    typ: "dpop+jwt" as const,
    jwk: stripPrivateFields(publicJwk),
  };

  const encodedHeader = base64UrlEncode(
    textEncoder.encode(JSON.stringify(header)),
  );
  const encodedPayload = base64UrlEncode(
    textEncoder.encode(JSON.stringify(payload)),
  );
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    options.keyPair.privateKey,
    textEncoder.encode(signingInput),
  );

  const encodedSignature = base64UrlEncode(signature);
  return `${signingInput}.${encodedSignature}`;
};

export interface VerifyDpopProofOptions {
  readonly proof: string;
  readonly method: string;
  readonly url: string;
  readonly accessToken?: string;
  readonly nonce?: string;
  /** Maximum allowed age (seconds) for the `iat` claim. Defaults to 300s. */
  readonly maxAgeSeconds?: number;
  /**
   * Allowed clock skew (seconds) when comparing the `iat` claim with the
   * current time. Defaults to 60s.
   */
  readonly clockSkewSeconds?: number;
  /** Optional hook to reject replayed `jti` values. */
  readonly checkReplay?: (jti: string) => boolean | Promise<boolean>;
  /**
   * Allows providing a custom timestamp (in seconds) for deterministic tests.
   * Defaults to `Math.floor(Date.now() / 1000)`.
   */
  readonly now?: number;
}

export interface VerifyDpopProofResult {
  readonly valid: boolean;
  readonly error?: string;
  readonly payload?: DpopJwtPayload;
  readonly jwk?: JsonWebKey;
}

const parseJwtSection = (segment: string) => {
  const bytes = base64UrlDecode(segment);
  const decoded = textDecoder.decode(bytes);
  return JSON.parse(decoded);
};

const isValidPublicJwk = (jwk: unknown): jwk is JsonWebKey => {
  if (!jwk || typeof jwk !== "object") {
    return false;
  }
  const record = jwk as Record<string, unknown>;
  return (
    record.kty === "EC" &&
    record.crv === "P-256" &&
    typeof record.x === "string" &&
    typeof record.y === "string"
  );
};

const timingSafeEqual = (a: string, b: string): boolean => {
  const aBytes = textEncoder.encode(a);
  const bBytes = textEncoder.encode(b);
  if (aBytes.length !== bBytes.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < aBytes.length; i += 1) {
    result |= aBytes[i]! ^ bBytes[i]!;
  }
  return result === 0;
};

export const verifyDpopProof = async (
  options: VerifyDpopProofOptions,
): Promise<VerifyDpopProofResult> => {
  const parts = options.proof.split(".");
  if (parts.length !== 3) {
    return { valid: false, error: "invalid-format" };
  }

  let header: { alg?: string; typ?: string; jwk?: unknown };
  let payload: DpopJwtPayload & Record<string, unknown>;
  try {
    header = parseJwtSection(parts[0]!) as typeof header;
    payload = parseJwtSection(parts[1]!) as typeof payload;
  } catch {
    return { valid: false, error: "invalid-json" };
  }

  if (header.typ?.toLowerCase() !== "dpop+jwt") {
    return { valid: false, error: "invalid-type" };
  }
  if (header.alg !== "ES256") {
    return { valid: false, error: "unsupported-algorithm" };
  }
  if (!isValidPublicJwk(header.jwk)) {
    return { valid: false, error: "invalid-jwk" };
  }

  const expectedMethod = normalizeMethod(options.method);
  if (payload.htm?.toUpperCase() !== expectedMethod) {
    return { valid: false, error: "method-mismatch" };
  }

  let expectedHtu: string;
  try {
    expectedHtu = normalizeHtu(options.url);
  } catch {
    return { valid: false, error: "invalid-url" };
  }
  if (payload.htu !== expectedHtu) {
    return { valid: false, error: "url-mismatch" };
  }

  if (typeof payload.jti !== "string" || !payload.jti) {
    return { valid: false, error: "invalid-jti" };
  }

  if (typeof payload.iat !== "number" || !Number.isFinite(payload.iat)) {
    return { valid: false, error: "invalid-iat" };
  }

  const maxAge = options.maxAgeSeconds ?? 300;
  const clockSkew = options.clockSkewSeconds ?? 60;
  const now = options.now ?? Math.floor(Date.now() / 1000);

  if (payload.iat > now + clockSkew) {
    return { valid: false, error: "future-iat" };
  }
  if (now - payload.iat > maxAge) {
    return { valid: false, error: "expired" };
  }

  if (options.nonce !== undefined) {
    if (payload.nonce !== options.nonce) {
      return { valid: false, error: "nonce-mismatch" };
    }
  }

  if (options.accessToken) {
    if (typeof payload.ath !== "string") {
      return { valid: false, error: "missing-ath" };
    }
    const expectedAth = await sha256Base64Url(options.accessToken);
    if (!timingSafeEqual(payload.ath, expectedAth)) {
      return { valid: false, error: "ath-mismatch" };
    }
  }

  if (options.checkReplay) {
    const ok = await options.checkReplay(payload.jti);
    if (!ok) {
      return { valid: false, error: "replay-detected" };
    }
  }

  let publicKey: CryptoKey;
  try {
    publicKey = await crypto.subtle.importKey(
      "jwk",
      header.jwk,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["verify"],
    );
  } catch {
    return { valid: false, error: "invalid-jwk" };
  }

  const decodedSignature = base64UrlDecode(parts[2]!);
  const signatureBytes = new Uint8Array(decodedSignature.length);
  signatureBytes.set(decodedSignature);
  const signingInput = textEncoder.encode(`${parts[0]!}.${parts[1]!}`);
  const signatureValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    signatureBytes,
    signingInput,
  );
  if (!signatureValid) {
    return { valid: false, error: "invalid-signature" };
  }

  return {
    valid: true,
    payload: {
      htm: payload.htm,
      htu: payload.htu,
      jti: payload.jti,
      iat: payload.iat,
      nonce: payload.nonce,
      ath: payload.ath,
    },
    jwk: header.jwk,
  };
};
