import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import {
  AuthenticationOptionsOverrides,
  AuthenticationOptionsRequestBody,
  AuthenticationVerifyRequestBody,
  PasskeyChallengeStore,
  PasskeyCredential,
  PasskeyMiddlewareOptions,
  PasskeyStorage,
  PasskeyUser,
  RegistrationOptionsOverrides,
  RegistrationOptionsRequestBody,
  RegistrationVerifyRequestBody,
  VerifyAuthenticationOverrides,
  VerifyRegistrationOverrides,
} from './types';
import { InMemoryChallengeStore } from './in-memory-challenge-store';
import {
  base64urlFromBuffer,
  bufferFromBase64url,
  cryptoRandomUUIDFallback,
  loadSimpleWebAuthnClient,
} from './utils';

const randomUUID = () => globalThis.crypto?.randomUUID() ?? cryptoRandomUUIDFallback();

let clientBundlePromise: Promise<string> | undefined;

const loadClientBundle = () => {
  if (!clientBundlePromise) {
    clientBundlePromise = loadSimpleWebAuthnClient();
  }
  return clientBundlePromise;
};

const normalizeMountPath = (path: string) => {
  if (!path || path === '/') return '';
  const withLeadingSlash = path.startsWith('/') ? path : `/${path}`;
  return withLeadingSlash.endsWith('/')
    ? withLeadingSlash.slice(0, -1)
    : withLeadingSlash;
};

const normalizeNickname = (nickname: string | undefined) => nickname?.trim() ?? '';

const jsonError = (status: number, message: string) =>
  new HTTPException(status, { message });

const ensureUser = async (
  storage: PasskeyStorage,
  username: string,
): Promise<PasskeyUser | null> => {
  const normalized = username.trim();
  if (!normalized) {
    return null;
  }
  return storage.getUserByUsername(normalized);
};

const respond = <T>(handler: () => Promise<T>) =>
  handler().catch((error: unknown) => {
    if (error instanceof HTTPException) {
      throw error;
    }
    if (error instanceof Error) {
      throw new HTTPException(500, { message: error.message });
    }
    throw new HTTPException(500, { message: 'Unexpected error' });
  });

export const createPasskeyMiddleware = (
  options: PasskeyMiddlewareOptions,
): MiddlewareHandler => {
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
  const mountPath = normalizeMountPath(options.mountPath ?? '');

  return async (c, next) => {
    const url = new URL(c.req.url);
    if (mountPath && !url.pathname.startsWith(mountPath)) {
      return next();
    }

    const relativePath = url.pathname.slice(mountPath.length) || '/';
    const method = c.req.method.toUpperCase();

    const ensureJsonBody = async <T>() => {
      try {
        return (await c.req.json()) as T;
      } catch {
        throw jsonError(400, 'Invalid JSON payload');
      }
    };

    const ensureUserOrThrow = async (username: string) => {
      const user = await respond(async () => ensureUser(storage, username));
      if (!user) {
        throw jsonError(404, 'User not found');
      }
      return user;
    };

    const setNoStore = () => {
      c.header('Cache-Control', 'no-store');
    };

    if (method === 'GET' && relativePath === '/client.js') {
      return respond(async () => {
        setNoStore();
        const bundle = await loadClientBundle();
        c.header('Content-Type', 'application/javascript; charset=utf-8');
        return c.body(bundle);
      });
    }

    if (method === 'GET' && relativePath === '/credentials') {
      return respond(async () => {
        setNoStore();
        const username = c.req.query('username')?.trim();
        if (!username) {
          throw jsonError(400, 'Missing username query parameter');
        }
        const user = await ensureUser(storage, username);
        if (!user) {
          return c.json({ user: null, credentials: [] });
        }
        const credentials = await storage.getCredentialsByUserId(user.id);
        return c.json({ user, credentials });
      });
    }

    if (method === 'DELETE' && relativePath.startsWith('/credentials/')) {
      return respond(async () => {
        setNoStore();
        if (!storage.deleteCredential) {
          throw jsonError(405, 'Credential deletion not supported');
        }
        const credentialId = decodeURIComponent(relativePath.replace('/credentials/', ''));
        const username = c.req.query('username')?.trim();
        if (!credentialId) {
          throw jsonError(400, 'Missing credential identifier');
        }
        if (!username) {
          throw jsonError(400, 'Missing username query parameter');
        }
        const user = await ensureUserOrThrow(username);
        const credential = await storage.getCredentialById(credentialId);
        if (!credential || credential.userId !== user.id) {
          throw jsonError(404, 'Credential not found');
        }
        await storage.deleteCredential(credentialId);
        return c.json({ success: true });
      });
    }

    if (method === 'POST' && relativePath === '/register/options') {
      return respond(async () => {
        setNoStore();
        const body = await ensureJsonBody<RegistrationOptionsRequestBody>();
        const username = body.username?.trim();
        if (!username) {
          throw jsonError(400, 'username is required');
        }
        let user = await ensureUser(storage, username);
        if (!user) {
          const displayName = body.displayName?.trim() || username;
          user = {
            id: randomUUID(),
            username,
            displayName,
          } satisfies PasskeyUser;
          await storage.createUser(user);
        }

        const existingCredentials = await storage.getCredentialsByUserId(user.id);
        const optionsInput: GenerateRegistrationOptionsOpts = {
          rpName,
          rpID,
          userID: user.id,
          userName: user.username,
          userDisplayName: user.displayName,
          excludeCredentials: existingCredentials.map((credential) => ({
            id: bufferFromBase64url(credential.id),
            type: 'public-key',
            transports: credential.transports,
          })),
          ...registrationOptions,
        };

        const optionsResult = await generateRegistrationOptions(optionsInput);
        await challengeStore.setChallenge(user.id, 'registration', optionsResult.challenge);
        return c.json(optionsResult);
      });
    }

    if (method === 'POST' && relativePath === '/register/verify') {
      return respond(async () => {
        setNoStore();
        const body = await ensureJsonBody<RegistrationVerifyRequestBody>();
        const username = body.username?.trim();
        const nickname = normalizeNickname(body.nickname);
        if (!username) {
          throw jsonError(400, 'username is required');
        }
        if (!nickname) {
          throw jsonError(400, 'nickname is required');
        }
        const user = await ensureUserOrThrow(username);
        const expectedChallenge = await challengeStore.getChallenge(user.id, 'registration');
        if (!expectedChallenge) {
          throw jsonError(400, 'No registration challenge for user');
        }

        const verification = await verifyRegistrationResponse({
          response: body.credential,
          expectedChallenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          ...verifyRegistrationOptions,
        });

        const { registrationInfo } = verification;
        if (!registrationInfo) {
          throw jsonError(400, 'Registration could not be verified');
        }

        const credentialId = base64urlFromBuffer(registrationInfo.credentialID);
        const credentialPublicKey = base64urlFromBuffer(
          registrationInfo.credentialPublicKey,
        );

        const now = Date.now();
        const storedCredential: PasskeyCredential = {
          id: credentialId,
          userId: user.id,
          nickname,
          publicKey: credentialPublicKey,
          counter: registrationInfo.counter,
          transports: body.credential.response.transports,
          deviceType: registrationInfo.credentialDeviceType,
          backedUp: registrationInfo.credentialBackedUp,
          createdAt: now,
          updatedAt: now,
        };

        await storage.saveCredential(storedCredential);
        await challengeStore.clearChallenge(user.id, 'registration');

        return c.json({
          verified: verification.verified,
          credential: storedCredential,
        });
      });
    }

    if (method === 'POST' && relativePath === '/authenticate/options') {
      return respond(async () => {
        setNoStore();
        const body = await ensureJsonBody<AuthenticationOptionsRequestBody>();
        const username = body.username?.trim();
        if (!username) {
          throw jsonError(400, 'username is required');
        }
        const user = await ensureUserOrThrow(username);
        const credentials = await storage.getCredentialsByUserId(user.id);
        if (credentials.length === 0) {
          throw jsonError(404, 'No registered credentials for user');
        }

        const optionsInput: GenerateAuthenticationOptionsOpts = {
          rpID,
          allowCredentials: credentials.map((credential) => ({
            id: bufferFromBase64url(credential.id),
            type: 'public-key',
            transports: credential.transports,
          })),
          userVerification: 'preferred',
          ...authenticationOptions,
        };

        const optionsResult = await generateAuthenticationOptions(optionsInput);
        await challengeStore.setChallenge(user.id, 'authentication', optionsResult.challenge);
        return c.json(optionsResult);
      });
    }

    if (method === 'POST' && relativePath === '/authenticate/verify') {
      return respond(async () => {
        setNoStore();
        const body = await ensureJsonBody<AuthenticationVerifyRequestBody>();
        const username = body.username?.trim();
        if (!username) {
          throw jsonError(400, 'username is required');
        }
        const user = await ensureUserOrThrow(username);
        const expectedChallenge = await challengeStore.getChallenge(user.id, 'authentication');
        if (!expectedChallenge) {
          throw jsonError(400, 'No authentication challenge for user');
        }

        const credentialId = body.credential.id;
        const storedCredential = await storage.getCredentialById(credentialId);
        if (!storedCredential || storedCredential.userId !== user.id) {
          throw jsonError(404, 'Credential not found');
        }

        const verification = await verifyAuthenticationResponse({
          response: body.credential,
          expectedChallenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          authenticator: {
            credentialPublicKey: bufferFromBase64url(storedCredential.publicKey),
            credentialID: bufferFromBase64url(storedCredential.id),
            counter: storedCredential.counter,
            transports: storedCredential.transports,
          },
          ...verifyAuthenticationOptions,
        });

        const { authenticationInfo } = verification;
        if (!authenticationInfo) {
          throw jsonError(400, 'Authentication could not be verified');
        }

        storedCredential.counter = authenticationInfo.newCounter;
        storedCredential.updatedAt = Date.now();
        storedCredential.backedUp = authenticationInfo.credentialBackedUp;
        storedCredential.deviceType = authenticationInfo.credentialDeviceType;
        await storage.updateCredential(storedCredential);
        await challengeStore.clearChallenge(user.id, 'authentication');

        return c.json({
          verified: verification.verified,
          credential: storedCredential,
        });
      });
    }

    if (relativePath === '/' || relativePath === '') {
      return next();
    }

    throw jsonError(404, 'Endpoint not found');
  };
};

export type PasskeyMiddleware = ReturnType<typeof createPasskeyMiddleware>;

export { InMemoryChallengeStore } from './in-memory-challenge-store';
export { InMemoryPasskeyStore } from './in-memory-passkey-store';
export * from './types';
