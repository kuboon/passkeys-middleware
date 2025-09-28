import { Hono } from "hono";
import type { Context, ExecutionContext } from "hono";
import { createMiddleware } from "hono/factory";
import { getCookie, setCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
} from "@simplewebauthn/server";
import {
  AuthenticationOptionsRequestBody,
  AuthenticationVerifyRequestBody,
  PasskeyCredential,
  PasskeyMiddlewareOptions,
  PasskeySessionState,
  PasskeyStorage,
  PasskeyUser,
  RegistrationOptionsRequestBody,
  RegistrationVerifyRequestBody,
} from "./types.ts";
import { InMemoryChallengeStore } from "./in-memory-challenge-store.ts";
import {
  cryptoRandomUUIDFallback,
  loadSimpleWebAuthnClient,
} from "./utils.ts";
import { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";

declare module "hono" {
  interface ContextVariableMap {
    passkey: PasskeySessionState;
  }
}

const randomUUID = () =>
  globalThis.crypto?.randomUUID() ?? cryptoRandomUUIDFallback();

const DEFAULT_MOUNT_PATH = "/webauthn";
const SESSION_COOKIE_NAME = "passkey_session";
const cookieBaseOptions = {
  httpOnly: true,
  sameSite: "Lax" as const,
  path: "/",
};

let clientBundlePromise: Promise<string> | undefined;

const loadClientBundle = () => {
  if (!clientBundlePromise) {
    clientBundlePromise = loadSimpleWebAuthnClient();
  }
  return clientBundlePromise;
};

const normalizeMountPath = (path: string) => {
  if (!path || path === "/") return "";
  const withLeadingSlash = path.startsWith("/") ? path : `/${path}`;
  return withLeadingSlash.endsWith("/")
    ? withLeadingSlash.slice(0, -1)
    : withLeadingSlash;
};

const normalizeNickname = (nickname: string | undefined) =>
  nickname?.trim() ?? "";

const jsonError = (status: ContentfulStatusCode, message: string) =>
  new HTTPException(status, { message });

const getErrorDetails = (
  error: unknown,
): { code?: string; message?: string } => {
  if (typeof error !== "object" || error === null) {
    return {};
  }
  const record = error as Record<string, unknown>;
  const code = typeof record.code === "string" ? record.code : undefined;
  const message = typeof record.message === "string"
    ? record.message
    : undefined;
  return { code, message };
};

const ensureUser = (
  storage: PasskeyStorage,
  username: string,
): Promise<PasskeyUser | null> => {
  const normalized = username.trim();
  if (!normalized) {
    return Promise.resolve(null);
  }
  return storage.getUserByUsername(normalized);
};

const respond = <T>(handler: () => Promise<T>) =>
  handler().catch((error: unknown) => {
    if (error instanceof HTTPException) {
      throw error;
    }
    if (error instanceof Error) {
      throw new HTTPException(500, { message: error.message, cause: error });
    }
    throw new HTTPException(500, { message: "Unexpected error", cause: error });
  });

const unauthenticatedState = (): PasskeySessionState => ({
  isAuthenticated: false,
  user: null,
  redirectTo: null,
});

const normalizeRedirectTarget = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    return null;
  }
  if (!trimmed.startsWith("/") || trimmed.startsWith("//")) {
    return null;
  }
  return trimmed.length > 1024 ? trimmed.slice(0, 1024) : trimmed;
};

const matchesMountPath = (path: string, mountPath: string) =>
  mountPath === "" || path === mountPath || path.startsWith(`${mountPath}/`);

const getExecutionContext = (c: Context): ExecutionContext | undefined => {
  try {
    return c.executionCtx;
  } catch {
    return undefined;
  }
};

export const createPasskeyMiddleware = (
  options: PasskeyMiddlewareOptions,
) => {
  const {
    rpID,
    rpName,
    origin,
    storage,
    registrationOptions,
    authenticationOptions,
    verifyRegistrationOptions,
    verifyAuthenticationOptions,
  } = options;
  const challengeStore = options.challengeStore ?? new InMemoryChallengeStore();
  const webauthn = {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    ...options.webauthn,
  };
  const mountPath = normalizeMountPath(
    options.path ?? options.mountPath ?? DEFAULT_MOUNT_PATH,
  );
  const router = new Hono();
  const pendingRedirects = new Map<string, string>();

  const loadSessionState = async (c: Context): Promise<PasskeySessionState> => {
    const sessionValue = getCookie(c, SESSION_COOKIE_NAME)?.trim();
    if (!sessionValue) {
      return unauthenticatedState();
    }
    try {
      const user = await storage.getUserById(sessionValue);
      if (!user) {
        return unauthenticatedState();
      }
      return { isAuthenticated: true, user, redirectTo: null };
    } catch {
      return unauthenticatedState();
    }
  };

  const updateSessionState = (c: Context, state: PasskeySessionState) => {
    c.set("passkey", state);
  };

  router.use("*", async (c, next) => {
    const state = await loadSessionState(c);
    updateSessionState(c, state);
    await next();
  });

  const routes = mountPath ? router.basePath(mountPath) : router;

  const ensureJsonBody = async <T>(c: Context) => {
    try {
      return (await c.req.json()) as T;
    } catch {
      throw jsonError(400, "Invalid JSON payload");
    }
  };

  const ensureUserOrThrow = async (username: string) => {
    const user = await ensureUser(storage, username);
    if (!user) {
      throw jsonError(404, "User not found");
    }
    return user;
  };

  const setNoStore = (c: Context) => {
    c.header("Cache-Control", "no-store");
  };

  routes.get("/client.js", (c) =>
    respond(async () => {
      setNoStore(c);
      const bundle = await loadClientBundle();
      c.header("Content-Type", "application/javascript; charset=utf-8");
      return c.body(bundle);
    }));

  routes.get("/credentials", (c) =>
    respond(async () => {
      setNoStore(c);
      const username = c.req.query("username")?.trim();
      if (!username) {
        throw jsonError(400, "Missing username query parameter");
      }
      const user = await ensureUser(storage, username);
      if (!user) {
        return c.json({ user: null, credentials: [] });
      }
      const credentials = await storage.getCredentialsByUserId(user.id);
      return c.json({ user, credentials });
    }));

  routes.delete("/credentials/:credentialId", (c) =>
    respond(async () => {
      setNoStore(c);
      if (!storage.deleteCredential) {
        throw jsonError(405, "Credential deletion not supported");
      }
      const credentialIdParam = c.req.param("credentialId");
      const credentialId = credentialIdParam
        ? decodeURIComponent(credentialIdParam)
        : "";
      const username = c.req.query("username")?.trim();
      if (!credentialId) {
        throw jsonError(400, "Missing credential identifier");
      }
      if (!username) {
        throw jsonError(400, "Missing username query parameter");
      }
      const user = await ensureUserOrThrow(username);
      const credential = await storage.getCredentialById(credentialId);
      if (!credential || credential.userId !== user.id) {
        throw jsonError(404, "Credential not found");
      }
      await storage.deleteCredential(credentialId);
      return c.json({ success: true });
    }));

  routes.post("/register/options", (c) =>
    respond(async () => {
      setNoStore(c);
      const body = await ensureJsonBody<RegistrationOptionsRequestBody>(c);
      const username = body.username?.trim();
      if (!username) {
        throw jsonError(400, "username is required");
      }
      let user = await ensureUser(storage, username);
      if (!user) {
        const displayName = body.displayName?.trim() || username;
        user = {
          id: randomUUID(),
          username,
          displayName,
        } satisfies PasskeyUser;
        try {
          await storage.createUser(user);
        } catch (error: unknown) {
          const { code, message } = getErrorDetails(error);
          if (code === "USER_EXISTS" || message?.includes("exists")) {
            user = await ensureUser(storage, username);
            if (!user) {
              throw jsonError(
                500,
                "Failed to fetch existing user after duplicate creation error",
              );
            }
          } else {
            throw error;
          }
        }
      }

      const existingCredentials = await storage.getCredentialsByUserId(user.id);
      const optionsInput: GenerateRegistrationOptionsOpts = {
        rpName,
        rpID,
        userName: user.username,
        userDisplayName: user.displayName,
        excludeCredentials: existingCredentials.map((credential) => ({
          id: credential.id,
          transports: credential.transports,
        })),
        ...registrationOptions,
      };

      const optionsResult = await webauthn.generateRegistrationOptions(
        optionsInput,
      );
      await challengeStore.setChallenge(
        user.id,
        "registration",
        optionsResult.challenge,
      );
      return c.json(optionsResult);
    }));

  routes.post("/register/verify", (c) =>
    respond(async () => {
      setNoStore(c);
      const body = await ensureJsonBody<RegistrationVerifyRequestBody>(c);
      const username = body.username?.trim();
      const nickname = normalizeNickname(body.nickname);
      if (!username) {
        throw jsonError(400, "username is required");
      }
      if (!nickname) {
        throw jsonError(400, "nickname is required");
      }
      const user = await ensureUserOrThrow(username);
      const expectedChallenge = await challengeStore.getChallenge(
        user.id,
        "registration",
      );
      if (!expectedChallenge) {
        throw jsonError(400, "No registration challenge for user");
      }

      const verification = await webauthn.verifyRegistrationResponse({
        response: body.credential,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        ...verifyRegistrationOptions,
      });

      const { registrationInfo } = verification;
      if (!registrationInfo) {
        throw jsonError(400, "Registration could not be verified");
      }

      const registrationCredential = registrationInfo.credential;
      const credentialId = registrationCredential.id;
      const credentialPublicKey = encodeBase64Url(
        registrationCredential.publicKey,
      );

      const now = Date.now();
      const storedCredential: PasskeyCredential = {
        id: credentialId,
        userId: user.id,
        nickname,
        publicKey: credentialPublicKey,
        counter: registrationCredential.counter,
        transports: registrationCredential.transports ??
          body.credential.response.transports,
        deviceType: registrationInfo.credentialDeviceType,
        backedUp: registrationInfo.credentialBackedUp,
        createdAt: now,
        updatedAt: now,
      };

      await storage.saveCredential(storedCredential);
      await challengeStore.clearChallenge(user.id, "registration");

      return c.json({
        verified: verification.verified,
        credential: storedCredential,
      });
    }));

  routes.post("/authenticate/options", (c) =>
    respond(async () => {
      setNoStore(c);
      const body = await ensureJsonBody<AuthenticationOptionsRequestBody>(c);
      const username = body.username?.trim();
      if (!username) {
        throw jsonError(400, "username is required");
      }
      const user = await ensureUserOrThrow(username);
      const credentials = await storage.getCredentialsByUserId(user.id);
      if (credentials.length === 0) {
        throw jsonError(404, "No registered credentials for user");
      }

      const redirectTarget = normalizeRedirectTarget(body.redirectTo);
      if (redirectTarget) {
        pendingRedirects.set(user.id, redirectTarget);
      } else {
        pendingRedirects.delete(user.id);
      }

      const optionsInput: GenerateAuthenticationOptionsOpts = {
        rpID,
        allowCredentials: credentials.map((credential) => ({
          id: credential.id,
          transports: credential.transports,
        })),
        userVerification: "preferred",
        ...authenticationOptions,
      };

      const optionsResult = await webauthn.generateAuthenticationOptions(
        optionsInput,
      );
      await challengeStore.setChallenge(
        user.id,
        "authentication",
        optionsResult.challenge,
      );
      return c.json(optionsResult);
    }));

  routes.post("/authenticate/verify", (c) =>
    respond(async () => {
      setNoStore(c);
      const body = await ensureJsonBody<AuthenticationVerifyRequestBody>(c);
      const username = body.username?.trim();
      if (!username) {
        throw jsonError(400, "username is required");
      }
      const user = await ensureUserOrThrow(username);
      const expectedChallenge = await challengeStore.getChallenge(
        user.id,
        "authentication",
      );
      if (!expectedChallenge) {
        throw jsonError(400, "No authentication challenge for user");
      }

      const credentialId = body.credential.id;
      const storedCredential = await storage.getCredentialById(credentialId);
      if (!storedCredential || storedCredential.userId !== user.id) {
        throw jsonError(404, "Credential not found");
      }

      const verification = await webauthn.verifyAuthenticationResponse({
        response: body.credential,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: storedCredential.id,
          publicKey: decodeBase64Url(storedCredential.publicKey) as Uint8Array<
            ArrayBuffer
          >,
          counter: storedCredential.counter,
          transports: storedCredential.transports,
        },
        ...verifyAuthenticationOptions,
      });

      const { authenticationInfo } = verification;
      if (!authenticationInfo) {
        throw jsonError(400, "Authentication could not be verified");
      }

      storedCredential.counter = authenticationInfo.newCounter;
      storedCredential.updatedAt = Date.now();
      storedCredential.backedUp = authenticationInfo.credentialBackedUp;
      storedCredential.deviceType = authenticationInfo.credentialDeviceType;
      await storage.updateCredential(storedCredential);
      await challengeStore.clearChallenge(user.id, "authentication");

      const redirectFromStore = pendingRedirects.get(user.id);
      pendingRedirects.delete(user.id);
      const redirectTarget = normalizeRedirectTarget(body.redirectTo) ??
        redirectFromStore ?? null;

      const secure = c.req.url.startsWith("https://");
      setCookie(c, SESSION_COOKIE_NAME, user.id, {
        ...cookieBaseOptions,
        secure,
      });
      const sessionState: PasskeySessionState = {
        isAuthenticated: true,
        user,
        redirectTo: redirectTarget,
      };
      updateSessionState(c, sessionState);

      return c.json({
        verified: verification.verified,
        credential: storedCredential,
        redirectTo: redirectTarget,
      });
    }));

  routes.all("*", () => {
    throw jsonError(404, "Endpoint not found");
  });

  return createMiddleware(async (c, next) => {
    const state = await loadSessionState(c);
    updateSessionState(c, state);

    if (matchesMountPath(c.req.path, mountPath)) {
      const executionCtx = getExecutionContext(c);
      return router.fetch(c.req.raw, c.env, executionCtx);
    }

    return next();
  });
};

export type PasskeyMiddleware = ReturnType<typeof createPasskeyMiddleware>;

export { InMemoryChallengeStore } from "./in-memory-challenge-store.ts";
export { InMemoryPasskeyStore } from "./in-memory-passkey-store.ts";
export * from "./types.ts";
