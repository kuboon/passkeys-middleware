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
import { createOidcRouter } from "./oidc-router.ts";
import { loadEnv } from "./load-env.ts";

const {
  rpID,
  rpName,
  oidcIssuer,
  oidcClientId,
  oidcClientName,
  oidcClientRedirectUri,
  oidcCookieKeys,
} = loadEnv();

const app = new Hono();
const credentialStore = await DenoKvPasskeyStore.create();

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

const oidcRouter = createOidcRouter({
  issuer: oidcIssuer,
  client: {
    id: oidcClientId,
    name: oidcClientName,
    redirectUris: [oidcClientRedirectUri],
  },
  credentialStore,
  passkeySessionCookieName: SESSION_COOKIE_NAME,
  cookieKeys: oidcCookieKeys,
});

app.route("/oidc", oidcRouter);

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

app.get("/", async (c) => {
  const html = await fetch(import.meta.resolve("./static/index.html")).then(
    (x) => x.text(),
  );
  return c.html(html);
});

app.get("/demo", (c) => c.redirect("/demo.html"));

app.get("/demo.html", async (c) => {
  const html = await fetch(import.meta.resolve("./static/demo.html")).then(
    (x) => x.text(),
  );
  return c.html(html);
});

app.onError((err, c) => {
  console.error(err);
  if (err instanceof HTTPException) {
    return err.getResponse();
  }
  return c.json({ message: "Internal Server Error" }, 500);
});

export { app };
