import process from "node:process";

const trimOrUndefined = (value: string | undefined): string | undefined => {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

export interface EnvConfig {
  rpID: string;
  rpName: string;
  publicOrigin: string;
  oidcIssuer: string;
  oidcClientId: string;
  oidcClientName: string;
  oidcClientRedirectUri: string;
  oidcCookieKeys: string[];
}

export const loadEnv = (): EnvConfig => {
  const rpID = trimOrUndefined(process.env.RP_ID) ?? "localhost";
  const rpName = trimOrUndefined(process.env.RP_NAME) ??
    "Passkeys Middleware Demo";
  const defaultOrigin = trimOrUndefined(process.env.PUBLIC_ORIGIN) ??
    "http://localhost:8000";
  const publicOrigin = defaultOrigin.endsWith("/")
    ? defaultOrigin.slice(0, -1)
    : defaultOrigin;
  const oidcIssuer = trimOrUndefined(process.env.OIDC_ISSUER) ??
    `${publicOrigin}/oidc`;
  const oidcClientId = trimOrUndefined(process.env.OIDC_CLIENT_ID) ??
    "demo-client";
  const oidcClientName = trimOrUndefined(process.env.OIDC_CLIENT_NAME) ??
    "Passkeys Demo Client";
  const oidcClientRedirectUri =
    trimOrUndefined(process.env.OIDC_CLIENT_REDIRECT_URI) ??
      `${publicOrigin}/demo.html`;
  const oidcCookieKeys =
    trimOrUndefined(process.env.OIDC_COOKIE_KEYS)?.split(",")
      .map((key) => key.trim())
      .filter((key) => key.length > 0) ?? [];

  return {
    rpID,
    rpName,
    publicOrigin,
    oidcIssuer,
    oidcClientId,
    oidcClientName,
    oidcClientRedirectUri,
    oidcCookieKeys,
  };
};
