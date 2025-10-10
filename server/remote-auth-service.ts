import type { PasskeyUser } from "@passkeys-middleware/hono";

const SESSION_PREFIX = ["passkeys_middleware", "remote", "session"] as const;
const JOIN_PREFIX = ["passkeys_middleware", "remote", "join"] as const;
const DEFAULT_PUBSUB_BASE_URL = "https://pubsub.kbn.one/";

export type RemoteAuthStatus =
  | "pending"
  | "authorized"
  | "claimed"
  | "expired";

export interface RemoteAuthSession {
  id: string;
  pollToken: string;
  joinToken: string;
  createdAt: number;
  expiresAt: number;
  status: RemoteAuthStatus;
  user: PasskeyUser | null;
  claimToken: string | null;
}

export interface RemoteAuthSessionView {
  id: string;
  status: RemoteAuthStatus;
  expiresAt: number;
  user: {
    id: string;
    username: string;
    displayName: string;
  } | null;
  claimToken: string | null;
}

export interface RemoteAuthServiceOptions {
  pubsubBaseUrl?: string | URL | null;
}

type SessionSubscriber = (session: RemoteAuthSession) => void;

const randomBytes = (size = 32): Uint8Array => {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return bytes;
};

const toBase64Url = (bytes: Uint8Array): string => {
  const text = Array.from(bytes)
    .map((byte) => String.fromCharCode(byte))
    .join("");
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const createToken = (size = 32) => toBase64Url(randomBytes(size));

const normalizeBaseUrl = (value: string | URL): string => {
  const source = value instanceof URL ? value.toString() : String(value);
  const trimmed = source.trim();
  if (!trimmed) {
    throw new Error("PubSub base URL cannot be empty");
  }
  const url = new URL(trimmed);
  url.search = "";
  url.hash = "";
  const path = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
  url.pathname = path;
  return url.toString();
};

export const toRemoteAuthSessionView = (
  session: RemoteAuthSession,
): RemoteAuthSessionView => ({
  id: session.id,
  status: session.status,
  expiresAt: session.expiresAt,
  user: session.user
    ? {
      id: session.user.id,
      username: session.user.username,
      displayName: session.user.displayName,
    }
    : null,
  claimToken: session.status === "authorized" ? session.claimToken : null,
});

const sessionKey = (id: string): Deno.KvKey =>
  [...SESSION_PREFIX, id] as Deno.KvKey;

const joinKey = (token: string): Deno.KvKey =>
  [...JOIN_PREFIX, token] as Deno.KvKey;

const getRemainingTtl = (session: RemoteAuthSession): number =>
  Math.max(session.expiresAt - Date.now(), 0);

export class RemoteAuthService {
  private readonly subscribers = new Map<string, Set<SessionSubscriber>>();
  private readonly expiryTimers = new Map<string, number>();

  private readonly pubsubBaseUrl: string | null;

  private constructor(
    private readonly kv: Deno.Kv,
    options: RemoteAuthServiceOptions = {},
  ) {
    const base = options.pubsubBaseUrl ?? DEFAULT_PUBSUB_BASE_URL;
    const normalized = typeof base === "string" ? base.trim() : base;
    this.pubsubBaseUrl = normalized ? normalizeBaseUrl(normalized) : null;
  }

  static async create(
    options: RemoteAuthServiceOptions = {},
  ): Promise<RemoteAuthService> {
    const kv = await Deno.openKv();
    return new RemoteAuthService(kv, options);
  }

  async createSession(ttlMs = 5 * 60 * 1000): Promise<RemoteAuthSession> {
    const now = Date.now();
    const session: RemoteAuthSession = {
      id: createToken(24),
      pollToken: createToken(32),
      joinToken: createToken(24),
      createdAt: now,
      expiresAt: now + ttlMs,
      status: "pending",
      user: null,
      claimToken: null,
    };

    const result = await this.kv.atomic()
      .check({ key: sessionKey(session.id), versionstamp: null })
      .set(sessionKey(session.id), session, { expireIn: ttlMs })
      .set(joinKey(session.joinToken), { sessionId: session.id }, {
        expireIn: ttlMs,
      })
      .commit();

    if (!result.ok) {
      throw new Error("Unable to create remote authentication session");
    }

    this.scheduleExpiry(session);
    this.publishSessionUpdate(session);

    return session;
  }

  async getSessionForPoll(
    id: string,
    pollToken: string,
  ): Promise<RemoteAuthSession | null> {
    const entry = await this.kv.get<RemoteAuthSession>(sessionKey(id));
    if (!entry.value) {
      return null;
    }
    const session = entry.value;
    if (session.pollToken !== pollToken) {
      return null;
    }
    if (session.status === "expired" || getRemainingTtl(session) <= 0) {
      await this.expireSession(entry);
      return { ...session, status: "expired" };
    }
    this.scheduleExpiry(session);
    return session;
  }

  async getSessionByJoinToken(
    token: string,
  ): Promise<RemoteAuthSession | null> {
    const mapping = await this.kv.get<{ sessionId: string }>(joinKey(token));
    if (!mapping.value) {
      return null;
    }
    const entry = await this.kv.get<RemoteAuthSession>(
      sessionKey(mapping.value.sessionId),
    );
    if (!entry.value) {
      return null;
    }
    const session = entry.value;
    if (session.joinToken !== token) {
      return null;
    }
    if (session.status === "expired" || getRemainingTtl(session) <= 0) {
      await this.expireSession(entry);
      return { ...session, status: "expired" };
    }
    this.scheduleExpiry(session);
    return session;
  }

  subscribe(id: string, callback: SessionSubscriber): () => void {
    const existing = this.subscribers.get(id) ?? new Set();
    existing.add(callback);
    this.subscribers.set(id, existing);
    return () => {
      const current = this.subscribers.get(id);
      if (!current) {
        return;
      }
      current.delete(callback);
      if (current.size === 0) {
        this.subscribers.delete(id);
      }
    };
  }

  private notify(session: RemoteAuthSession) {
    const listeners = this.subscribers.get(session.id);
    if (!listeners) {
      return;
    }
    for (const listener of listeners) {
      try {
        listener(session);
      } catch (error) {
        console.error("RemoteAuthService subscriber error", error);
      }
    }
    if (session.status === "claimed" || session.status === "expired") {
      this.subscribers.delete(session.id);
      this.clearExpiry(session.id);
    }
  }

  private clearExpiry(id: string) {
    const timer = this.expiryTimers.get(id);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.expiryTimers.delete(id);
    }
  }

  private scheduleExpiry(session: RemoteAuthSession) {
    this.clearExpiry(session.id);
    const remaining = getRemainingTtl(session);
    if (remaining <= 0) {
      return;
    }
    const timer = setTimeout(() => {
      this.handleExpiry(session.id).catch((error) => {
        console.error("Failed to expire remote auth session", error);
      });
    }, remaining);
    this.expiryTimers.set(session.id, timer as unknown as number);
  }

  private async handleExpiry(id: string) {
    const entry = await this.kv.get<RemoteAuthSession>(sessionKey(id));
    if (!entry.value) {
      this.clearExpiry(id);
      return;
    }
    await this.expireSession(entry);
  }

  private async expireSession(
    entry: Deno.KvEntryMaybe<RemoteAuthSession>,
  ) {
    if (!entry.value) {
      return;
    }
    const session = entry.value;
    if (session.status === "expired") {
      return;
    }
    const updated: RemoteAuthSession = { ...session, status: "expired" };
    await this.kv.atomic()
      .check(entry)
      .set(sessionKey(session.id), updated, { expireIn: 60_000 })
      .delete(joinKey(session.joinToken))
      .commit();
    this.notify(updated);
    this.publishSessionUpdate(updated);
  }

  async authorizeSession(
    token: string,
    user: PasskeyUser,
  ): Promise<RemoteAuthSession> {
    const mapping = await this.kv.get<{ sessionId: string }>(joinKey(token));
    if (!mapping.value) {
      throw new Error("Remote session not found");
    }
    const entry = await this.kv.get<RemoteAuthSession>(
      sessionKey(mapping.value.sessionId),
    );
    if (!entry.value) {
      throw new Error("Remote session not found");
    }
    const session = entry.value;
    if (session.joinToken !== token) {
      throw new Error("Remote session token mismatch");
    }
    if (session.status === "expired" || getRemainingTtl(session) <= 0) {
      await this.expireSession(entry);
      throw new Error("Remote session expired");
    }
    if (session.status === "claimed") {
      throw new Error("Remote session already completed");
    }

    const claimToken = session.claimToken ?? createToken(24);
    const updated: RemoteAuthSession = {
      ...session,
      status: "authorized",
      user,
      claimToken,
    };
    const remainingTtl = getRemainingTtl(updated) || 60_000;
    const result = await this.kv.atomic()
      .check(entry)
      .set(sessionKey(session.id), updated, { expireIn: remainingTtl })
      .set(joinKey(session.joinToken), { sessionId: session.id }, {
        expireIn: remainingTtl,
      })
      .commit();
    if (!result.ok) {
      throw new Error("Failed to authorise remote session");
    }
    this.scheduleExpiry(updated);
    this.notify(updated);
    this.publishSessionUpdate(updated);
    return updated;
  }

  async claimSession(params: {
    id: string;
    pollToken: string;
    claimToken: string;
  }): Promise<RemoteAuthSession> {
    const entry = await this.kv.get<RemoteAuthSession>(sessionKey(params.id));
    if (!entry.value) {
      throw new Error("Remote session not found");
    }
    const session = entry.value;
    if (session.pollToken !== params.pollToken) {
      throw new Error("Remote session token mismatch");
    }
    if (session.status === "expired" || getRemainingTtl(session) <= 0) {
      await this.expireSession(entry);
      throw new Error("Remote session expired");
    }
    if (session.status !== "authorized" || !session.claimToken) {
      throw new Error("Remote session is not ready");
    }
    if (session.claimToken !== params.claimToken) {
      throw new Error("Invalid claim token");
    }
    if (!session.user) {
      throw new Error("Remote session has no associated user");
    }

    const updated: RemoteAuthSession = {
      ...session,
      status: "claimed",
    };
    const result = await this.kv.atomic()
      .check(entry)
      .set(sessionKey(session.id), updated, { expireIn: 60_000 })
      .delete(joinKey(session.joinToken))
      .commit();
    if (!result.ok) {
      throw new Error("Failed to finalise remote session");
    }
    this.notify(updated);
    this.publishSessionUpdate(updated);
    return updated;
  }

  private publishSessionUpdate(session: RemoteAuthSession) {
    if (!this.pubsubBaseUrl) {
      return;
    }
    const payload = toRemoteAuthSessionView(session);
    queueMicrotask(async () => {
      try {
        const url = new URL(this.pubsubBaseUrl);
        url.pathname = `${url.pathname}${
          encodeURIComponent(session.pollToken)
        }`;
        const response = await fetch(url.toString(), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
          keepalive: true,
        });
        if (!response.ok) {
          const details = await response.text().catch(() => "");
          console.error(
            "Failed to publish remote auth update",
            response.status,
            details,
          );
        }
      } catch (error) {
        console.error("Failed to publish remote auth update", error);
      }
    });
  }
}
