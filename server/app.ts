/// <reference lib="deno.ns" />

import { Hono } from "hono";
import type { Context } from "hono";
import { setCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";
import {
  createPasskeyMiddleware,
  type PasskeySessionState,
  type PasskeyUser,
} from "@passkeys-middleware/hono";
import { DenoKvPasskeyStore } from "./deno-kv-passkey-store.ts";
import {
  RemoteAuthService,
  type RemoteAuthSession,
  toRemoteAuthSessionView,
} from "./remote-auth-service.ts";
import process from "node:process";

const rpID = process.env.RP_ID ?? "localhost";
const rpName = process.env.RP_NAME ?? "Passkeys Middleware Demo";

const app = new Hono();
const credentialStore = await DenoKvPasskeyStore.create();
const pubsubBaseUrl = process.env.PUBSUB_BASE_URL?.trim() ||
  "https://pubsub.kbn.one/";
const remoteAuth = await RemoteAuthService.create({
  pubsubBaseUrl,
});

const SESSION_COOKIE_NAME = "passkey_session";
const baseCookieOptions = {
  httpOnly: true,
  sameSite: "Lax" as const,
  path: "/",
};

const isSecureRequest = (c: Context) => c.req.url.startsWith("https://");

const setNoStore = (c: Context) => {
  c.header("Cache-Control", "no-store");
};

const getSessionState = (c: Context): PasskeySessionState =>
  (c.get("passkey") as PasskeySessionState | undefined) ?? {
    isAuthenticated: false,
    user: null,
  };

const setSessionState = (c: Context, state: PasskeySessionState) => {
  c.set("passkey", state);
};

const clearSession = (c: Context) => {
  setCookie(c, SESSION_COOKIE_NAME, "", {
    ...baseCookieOptions,
    secure: isSecureRequest(c),
    maxAge: 0,
  });
  setSessionState(c, { isAuthenticated: false, user: null });
};

const sanitizeRemoteSession = toRemoteAuthSessionView;

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      case "'":
        return "&#39;";
      default:
        return char;
    }
  });

const ensureAuthenticatedUser = async (c: Context): Promise<PasskeyUser> => {
  const session = getSessionState(c);
  if (!session.isAuthenticated || !session.user) {
    throw new HTTPException(401, { message: "Sign-in required" });
  }
  const user = await credentialStore.getUserById(session.user.id);
  if (!user) {
    clearSession(c);
    throw new HTTPException(404, { message: "User not found" });
  }
  return user;
};

const updateSessionUser = (c: Context, user: PasskeyUser) => {
  setSessionState(c, { isAuthenticated: true, user });
};

app.use(
  createPasskeyMiddleware({
    rpID,
    rpName,
    storage: credentialStore,
  }),
);

app.get("/session", (c) => {
  setNoStore(c);
  return c.json(getSessionState(c));
});

app.post("/session/logout", (c) => {
  setNoStore(c);
  clearSession(c);
  return c.json({ success: true });
});

app.patch("/account", async (c) => {
  setNoStore(c);
  const currentUser = await ensureAuthenticatedUser(c);
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    throw new HTTPException(400, { message: "Invalid JSON payload" });
  }
  if (!body || typeof body !== "object") {
    throw new HTTPException(400, { message: "Invalid request body" });
  }

  const payload = body as {
    username?: unknown;
    displayName?: unknown;
  };

  const updatedUser: PasskeyUser = { ...currentUser };
  let changed = false;

  if ("username" in payload) {
    const username = typeof payload.username === "string"
      ? payload.username.trim()
      : "";
    if (!username) {
      throw new HTTPException(400, { message: "Username cannot be empty" });
    }
    if (username.toLowerCase() !== currentUser.username.toLowerCase()) {
      const existing = await credentialStore.getUserByUsername(username);
      if (existing && existing.id !== currentUser.id) {
        throw new HTTPException(409, {
          message: "That username is already taken.",
        });
      }
      updatedUser.username = username;
      changed = true;
    }
  }

  if ("displayName" in payload) {
    if (typeof payload.displayName === "string") {
      const displayName = payload.displayName.trim() || updatedUser.username;
      if (displayName !== currentUser.displayName) {
        updatedUser.displayName = displayName;
        changed = true;
      }
    } else if (payload.displayName === null) {
      if (currentUser.displayName !== updatedUser.username) {
        updatedUser.displayName = updatedUser.username;
        changed = true;
      }
    }
  }

  if (!changed) {
    return c.json({ user: currentUser });
  }

  await credentialStore.updateUser(updatedUser);
  updateSessionUser(c, updatedUser);
  return c.json({ user: updatedUser });
});

app.delete("/account", async (c) => {
  setNoStore(c);
  const user = await ensureAuthenticatedUser(c);
  if (typeof credentialStore.deleteUser !== "function") {
    throw new HTTPException(405, {
      message: "Account deletion is not supported by this storage adapter.",
    });
  }
  if (typeof credentialStore.deleteCredential === "function") {
    const credentials = await credentialStore.getCredentialsByUserId(user.id);
    for (const credential of credentials) {
      await credentialStore.deleteCredential(credential.id);
    }
  }
  await credentialStore.deleteUser(user.id);
  clearSession(c);
  return c.json({ success: true });
});

app.post("/remote-auth/session", async (c) => {
  setNoStore(c);
  const session = await remoteAuth.createSession();
  const requestUrl = new URL(c.req.url);
  const loginUrl = new URL("/", requestUrl);
  const hashParams = new URLSearchParams();
  hashParams.set("remote", session.joinToken);
  loginUrl.hash = hashParams.toString();
  return c.json({
    sessionId: session.id,
    pollToken: session.pollToken,
    channel: session.pollToken,
    loginUrl: loginUrl.toString(),
    expiresAt: session.expiresAt,
  });
});

app.get("/remote-auth/session", async (c) => {
  setNoStore(c);
  const token = c.req.query("token")?.trim();
  if (!token) {
    throw new HTTPException(400, { message: "token is required" });
  }
  const session = await remoteAuth.getSessionByJoinToken(token);
  if (!session) {
    throw new HTTPException(404, { message: "Remote session not found" });
  }
  return c.json(sanitizeRemoteSession(session));
});

app.get("/remote-auth/events", async (c) => {
  setNoStore(c);
  const sessionId = c.req.query("session")?.trim();
  const pollToken = c.req.query("token")?.trim();
  if (!sessionId || !pollToken) {
    throw new HTTPException(400, { message: "session and token are required" });
  }
  const session = await remoteAuth.getSessionForPoll(sessionId, pollToken);
  if (!session) {
    throw new HTTPException(404, { message: "Remote session not found" });
  }

  const encoder = new TextEncoder();
  let unsubscribe: (() => void) | null = null;

  const stream = new ReadableStream({
    start(controller) {
      const send = (value: RemoteAuthSession) => {
        const payload = JSON.stringify(sanitizeRemoteSession(value));
        controller.enqueue(
          encoder.encode(`event: update\ndata: ${payload}\n\n`),
        );
        if (value.status === "claimed" || value.status === "expired") {
          if (unsubscribe) {
            unsubscribe();
            unsubscribe = null;
          }
          controller.enqueue(encoder.encode(": closed\n\n"));
          controller.close();
        }
      };

      unsubscribe = remoteAuth.subscribe(sessionId, (value) => {
        send(value);
      });

      send(session);
      controller.enqueue(encoder.encode(": keep-alive\n\n"));
    },
    cancel() {
      if (unsubscribe) {
        unsubscribe();
        unsubscribe = null;
      }
    },
  });

  const headers = new Headers({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-store",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
  });

  return new Response(stream, { headers });
});

app.post("/remote-auth/authorize", async (c) => {
  setNoStore(c);
  const currentUser = await ensureAuthenticatedUser(c);
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    throw new HTTPException(400, { message: "Invalid JSON payload" });
  }
  if (!body || typeof body !== "object") {
    throw new HTTPException(400, { message: "Invalid request body" });
  }
  const token = (body as { token?: unknown }).token;
  if (typeof token !== "string" || !token.trim()) {
    throw new HTTPException(400, { message: "token is required" });
  }
  const session = await remoteAuth.authorizeSession(token.trim(), currentUser);
  return c.json(sanitizeRemoteSession(session));
});

app.post("/remote-auth/claim", async (c) => {
  setNoStore(c);
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    throw new HTTPException(400, { message: "Invalid JSON payload" });
  }
  if (!body || typeof body !== "object") {
    throw new HTTPException(400, { message: "Invalid request body" });
  }
  const payload = body as {
    sessionId?: unknown;
    pollToken?: unknown;
    claimToken?: unknown;
  };
  const sessionId = typeof payload.sessionId === "string"
    ? payload.sessionId.trim()
    : "";
  const pollToken = typeof payload.pollToken === "string"
    ? payload.pollToken.trim()
    : "";
  const claimToken = typeof payload.claimToken === "string"
    ? payload.claimToken.trim()
    : "";
  if (!sessionId || !pollToken || !claimToken) {
    throw new HTTPException(400, {
      message: "sessionId, pollToken, and claimToken are required",
    });
  }
  const session = await remoteAuth.claimSession({
    id: sessionId,
    pollToken,
    claimToken,
  });
  if (!session.user) {
    throw new HTTPException(500, { message: "Remote session user missing" });
  }
  setCookie(c, SESSION_COOKIE_NAME, session.user.id, {
    ...baseCookieOptions,
    secure: isSecureRequest(c),
  });
  setSessionState(c, { isAuthenticated: true, user: session.user });
  return c.json({ success: true, user: session.user });
});

app.get("/", async (c) => {
  const html = await fetch(import.meta.resolve("./static/index.html")).then(
    (x) => x.text(),
  );
  const rendered = html
    .replaceAll("__RP_ID__", escapeHtml(rpID))
    .replaceAll("__PUBSUB_BASE_JSON__", JSON.stringify(pubsubBaseUrl));
  return c.html(rendered);
});

app.get("/styles.css", async (c) => {
  const css = await fetch(import.meta.resolve("./static/styles.css")).then(
    (x) => x.text(),
  );
  c.header("Content-Type", "text/css; charset=utf-8");
  return c.body(css);
});

app.onError((err, c) => {
  console.error(err);
  if (err instanceof HTTPException) {
    return err.getResponse();
  }
  return c.json({ message: "Internal Server Error" }, 500);
});

export { app };
