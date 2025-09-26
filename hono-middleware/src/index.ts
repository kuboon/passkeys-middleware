import { Hono } from 'hono';
import type { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
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
} from './types.ts';
import { InMemoryChallengeStore } from './in-memory-challenge-store.ts';
import {
  base64urlFromBuffer,
  bufferFromBase64url,
  cryptoRandomUUIDFallback,
  loadSimpleWebAuthnClient,
} from './utils.ts';

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

const jsonError = (status: ContentfulStatusCode, message: string) =>
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
      throw new HTTPException(500, { message: error.message, cause: error});
    }
    throw new HTTPException(500, { message: 'Unexpected error', cause: error });
  });

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
  const mountPath = normalizeMountPath(options.mountPath ?? '');
  const router = new Hono();
  const routes = mountPath ? router.basePath(mountPath) : router;

  const ensureJsonBody = async <T>(c: Context) => {
    try {
      return (await c.req.json()) as T;
    } catch {
      throw jsonError(400, 'Invalid JSON payload');
    }
  };

  const ensureUserOrThrow = async (username: string) => {
    const user = await ensureUser(storage, username);
    if (!user) {
      throw jsonError(404, 'User not found');
    }
    return user;
  };

  const setNoStore = (c: Context) => {
    c.header('Cache-Control', 'no-store');
  };

  routes.get('/client.js', (c) =>
    respond(async () => {
      setNoStore(c);
      const bundle = await loadClientBundle();
      c.header('Content-Type', 'application/javascript; charset=utf-8');
      return c.body(bundle);
    }),
  );

  routes.get('/credentials', (c) =>
    respond(async () => {
      setNoStore(c);
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
    }),
  );

  routes.delete('/credentials/:credentialId', (c) =>
    respond(async () => {
      setNoStore(c);
      if (!storage.deleteCredential) {
        throw jsonError(405, 'Credential deletion not supported');
      }
      const credentialIdParam = c.req.param('credentialId');
      const credentialId = credentialIdParam ? decodeURIComponent(credentialIdParam) : '';
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
    }),
  );

  routes.post('/register/options', (c) =>
    respond(async () => {
      setNoStore(c);
      const body = await ensureJsonBody<RegistrationOptionsRequestBody>(c);
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
        try {
          await storage.createUser(user);
        } catch (err: any) {
          // If user already exists due to race condition, fetch the existing user
          // You may need to adjust the error check depending on your storage implementation
          if (err && (err.code === 'USER_EXISTS' || err.message?.includes('exists'))) {
            user = await ensureUser(storage, username);
            if (!user) {
              throw jsonError(500, 'Failed to fetch existing user after duplicate creation error');
            }
          } else {
            throw err;
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

      const optionsResult = await generateRegistrationOptions(optionsInput);
      await challengeStore.setChallenge(user.id, 'registration', optionsResult.challenge);
      return c.json(optionsResult);
    }),
  );

  routes.post('/register/verify', (c) =>
    respond(async () => {
      setNoStore(c);
      const body = await ensureJsonBody<RegistrationVerifyRequestBody>(c);
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

      const registrationCredential = registrationInfo.credential;
      const credentialId = registrationCredential.id;
      const credentialPublicKey = base64urlFromBuffer(
        registrationCredential.publicKey,
      );

      const now = Date.now();
      const storedCredential: PasskeyCredential = {
        id: credentialId,
        userId: user.id,
        nickname,
        publicKey: credentialPublicKey,
        counter: registrationCredential.counter,
        transports:
          registrationCredential.transports ?? body.credential.response.transports,
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
    }),
  );

  routes.post('/authenticate/options', (c) =>
    respond(async () => {
      setNoStore(c);
      const body = await ensureJsonBody<AuthenticationOptionsRequestBody>(c);
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
          id: credential.id,
          transports: credential.transports,
        })),
        userVerification: 'preferred',
        ...authenticationOptions,
      };

      const optionsResult = await generateAuthenticationOptions(optionsInput);
      await challengeStore.setChallenge(user.id, 'authentication', optionsResult.challenge);
      return c.json(optionsResult);
    }),
  );

  routes.post('/authenticate/verify', (c) =>
    respond(async () => {
      setNoStore(c);
      const body = await ensureJsonBody<AuthenticationVerifyRequestBody>(c);
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
        credential: {
          id: storedCredential.id,
          publicKey: bufferFromBase64url(storedCredential.publicKey),
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
    }),
  );

  routes.all('*', () => {
    throw jsonError(404, 'Endpoint not found');
  });

  return router;
};

export type PasskeyRouter = ReturnType<typeof createPasskeyMiddleware>;
export type PasskeyMiddleware = PasskeyRouter;

export { InMemoryChallengeStore } from './in-memory-challenge-store.ts';
export { InMemoryPasskeyStore } from './in-memory-passkey-store.ts';
export * from './types.ts';
