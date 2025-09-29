import { Hono } from "hono";
import Provider from "oidc-provider";
import { createServerAdapter } from "@whatwg-node/server";
import type { PasskeyUser } from "@passkeys-middleware/hono";
import type { KoaContextWithOIDC } from "oidc-provider";

import type { DenoKvPasskeyStore } from "./deno-kv-passkey-store.ts";

export type OidcRouterOptions = {
  issuer: string;
  client: {
    id: string;
    redirectUris: string[];
    name?: string;
  };
  credentialStore: DenoKvPasskeyStore;
  passkeySessionCookieName: string;
  cookieKeys?: string[];
};

const html = (content: string) =>
  `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>OIDC Sign-in Required</title><style>body{font-family:system-ui, -apple-system, "Segoe UI", sans-serif;margin:0;padding:2rem;background:#f8fafc;color:#0f172a;}main{max-width:560px;margin:0 auto;background:#fff;padding:2rem;border-radius:16px;box-shadow:0 25px 45px rgba(15,23,42,0.12);}h1{font-size:1.6rem;margin-top:0;}p{line-height:1.6;}a.button{display:inline-flex;align-items:center;justify-content:center;padding:0.65rem 1.4rem;background:#2563eb;color:#fff;border-radius:999px;font-weight:600;text-decoration:none;margin-top:1rem;}a.button.secondary{background:#0f172a1a;color:#1e293b;}code{background:#f1f5f9;padding:0.15rem 0.35rem;border-radius:6px;font-size:0.95rem;}</style></head><body><main>${content}</main></body></html>`;

const createLoginRequiredPage = () =>
  html(
    `<h1>パスキーでサインインしてください</h1><p>この OpenID Connect のフローを続けるには、先にパスキーでサインインする必要があります。</p><p>別タブで <code>/</code> または <code>/demo.html</code> のページからサインインしてから、このページに戻ってください。</p><a class="button" href="/demo.html">デモページへ戻る</a><a class="button secondary" href="/">トップへ</a>`,
  );

const createAccountMissingPage = () =>
  html(
    `<h1>アカウントが見つかりません</h1><p>パスキーのセッションは存在しますが、対応するアカウントが見つかりませんでした。再度サインインしてください。</p><a class="button" href="/demo.html">サインインする</a>`,
  );

const createUnexpectedPromptPage = (prompt: string) =>
  html(
    `<h1>リクエストを続行できません</h1><p>対応していないプロンプト <code>${prompt}</code> が要求されました。</p><a class="button" href="/demo.html">デモページに戻る</a>`,
  );

export const createOidcRouter = (
  options: OidcRouterOptions,
): Hono => {
  const {
    issuer,
    client,
    credentialStore,
    passkeySessionCookieName,
    cookieKeys,
  } = options;

  const provider = new Provider(issuer, {
    cookies: {
      keys: cookieKeys && cookieKeys.length > 0
        ? cookieKeys
        : [crypto.randomUUID()],
    },
    clients: [
      {
        client_id: client.id,
        redirect_uris: client.redirectUris,
        response_types: ["id_token"],
        grant_types: ["implicit"],
        token_endpoint_auth_method: "none",
        client_name: client.name,
      },
    ],
    interactions: {
      url: (_ctx, interaction) => `/oidc/interactions/${interaction.uid}`,
    },
    features: {
      devInteractions: { enabled: false },
      rpInitiatedLogout: { enabled: true },
    },
    claims: {
      openid: ["sub"],
      profile: ["name", "preferred_username"],
    },
    findAccount: async (_ctx, id: string) => {
      const account = await credentialStore.getUserById(id);
      if (!account) return undefined;
      return {
        accountId: id,
        async claims(_use, scope) {
          const user = await credentialStore.getUserById(id);
          if (!user) return { sub: id };
          const result: Record<string, unknown> = {
            sub: id,
          };
          if (!scope || scope.includes("profile")) {
            result.name = user.displayName ?? user.username;
            result.preferred_username = user.username;
          }
          return result;
        },
      };
    },
  });

  provider.proxy = true;

  const readSessionId = (ctx: KoaContextWithOIDC): string | null =>
    ctx.cookies.get(passkeySessionCookieName)?.trim() ?? null;

  const clearPasskeySession = (ctx: KoaContextWithOIDC) => {
    ctx.cookies.set(passkeySessionCookieName, "", {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      secure: ctx.secure,
      maxAge: 0,
    });
  };

  const getPasskeyUser = async (
    sessionId: string,
  ): Promise<PasskeyUser | null> => {
    try {
      const user = await credentialStore.getUserById(sessionId);
      return user ?? null;
    } catch {
      return null;
    }
  };

  provider.use(async (ctx, next) => {
    if (!ctx.path.startsWith("/interactions/")) {
      return next();
    }

    const details = await provider.interactionDetails(ctx.req, ctx.res);
    if (details.prompt.name === "login") {
      const sessionId = readSessionId(ctx);
      if (!sessionId) {
        ctx.status = 401;
        ctx.body = createLoginRequiredPage();
        return;
      }
      const user = await getPasskeyUser(sessionId);
      if (!user) {
        clearPasskeySession(ctx);
        ctx.status = 401;
        ctx.body = createAccountMissingPage();
        return;
      }
      const result = {
        login: {
          accountId: user.id,
          ts: Math.floor(Date.now() / 1000),
          remember: true,
          amr: ["passkey"],
          acr: "urn:passkeys:assurance:basic",
        },
      };
      await provider.interactionFinished(ctx.req, ctx.res, result, {
        mergeWithLastSubmission: false,
      });
      return;
    }

    if (details.prompt.name === "consent") {
      const { Grant } = provider;
      const accountId = details.session?.accountId;
      if (!accountId) {
        ctx.status = 401;
        ctx.body = createLoginRequiredPage();
        return;
      }
      let grant = details.grantId
        ? await Grant.find(details.grantId)
        : undefined;
      if (!grant) {
        grant = new Grant({
          accountId,
          clientId: details.params.client_id as string,
        });
      }

      if (details.missingOIDCScope?.length) {
        grant.addOIDCScope(details.missingOIDCScope.join(" "));
      }

      if (details.missingOIDCClaims?.length) {
        grant.addOIDCClaims(details.missingOIDCClaims);
      }

      if (details.missingResourceScopes) {
        for (
          const [indicator, scopes] of Object.entries(
            details.missingResourceScopes,
          )
        ) {
          grant.addResourceScope(indicator, scopes.join(" "));
        }
      }

      const grantId = await grant.save();

      const consent = details.grantId
        ? { grantId }
        : { grantId, scope: details.params.scope };

      await provider.interactionFinished(ctx.req, ctx.res, { consent }, {
        mergeWithLastSubmission: true,
      });
      return;
    }

    ctx.status = 400;
    ctx.body = createUnexpectedPromptPage(details.prompt.name);
  });

  const adapter = createServerAdapter(provider.callback());
  const router = new Hono();

  router.use(async (c, next) => {
    c.header("Cache-Control", "no-store");
    await next();
  });

  router.all("*", async (c) => {
    const response = await adapter.fetch(c.req.raw);
    return response;
  });

  return router;
};
