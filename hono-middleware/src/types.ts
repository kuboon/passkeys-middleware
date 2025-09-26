import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  RegistrationResponseJSON,
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';

export interface PasskeyUser {
  id: string;
  username: string;
  displayName: string;
}

export interface PasskeyCredential {
  id: string;
  userId: string;
  nickname: string;
  publicKey: string;
  counter: number;
  transports?: AuthenticatorTransportFuture[];
  deviceType?: CredentialDeviceType;
  backedUp?: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface PasskeyStorage {
  getUserByUsername(username: string): Promise<PasskeyUser | null>;
  getUserById(userId: string): Promise<PasskeyUser | null>;
  createUser(user: PasskeyUser): Promise<void>;
  updateUser(user: PasskeyUser): Promise<void>;
  getCredentialById(credentialId: string): Promise<PasskeyCredential | null>;
  getCredentialsByUserId(userId: string): Promise<PasskeyCredential[]>;
  saveCredential(credential: PasskeyCredential): Promise<void>;
  updateCredential(credential: PasskeyCredential): Promise<void>;
  deleteCredential?(credentialId: string): Promise<void>;
}

export type ChallengeType = 'registration' | 'authentication';

export interface PasskeyChallengeStore {
  setChallenge(userId: string, type: ChallengeType, challenge: string): Promise<void>;
  getChallenge(userId: string, type: ChallengeType): Promise<string | null>;
  clearChallenge(userId: string, type: ChallengeType): Promise<void>;
}

export interface RegistrationOptionsRequestBody {
  username: string;
  displayName?: string;
}

export interface RegistrationVerifyRequestBody {
  username: string;
  nickname: string;
  credential: RegistrationResponseJSON;
}

export interface AuthenticationOptionsRequestBody {
  username: string;
}

export interface AuthenticationVerifyRequestBody {
  username: string;
  credential: AuthenticationResponseJSON;
}

export type RegistrationOptionsOverrides = Partial<
  Omit<
    GenerateRegistrationOptionsOpts,
    'rpID' | 'rpName' | 'userName' | 'userDisplayName' | 'excludeCredentials'
  >
>;

export type AuthenticationOptionsOverrides = Partial<
  Omit<GenerateAuthenticationOptionsOpts, 'rpID' | 'allowCredentials'>
>;

export type VerifyRegistrationOverrides = Partial<
  Omit<
    VerifyRegistrationResponseOpts,
    'response' | 'expectedChallenge' | 'expectedOrigin' | 'expectedRPID'
  >
>;

export type VerifyAuthenticationOverrides = Partial<
  Omit<
    VerifyAuthenticationResponseOpts,
    'response' | 'expectedChallenge' | 'expectedOrigin' | 'expectedRPID' | 'credential'
  >
>;

export interface PasskeyMiddlewareOptions {
  rpID: string;
  rpName: string;
  origin: string | string[];
  storage: PasskeyStorage;
  challengeStore?: PasskeyChallengeStore;
  mountPath?: string;
  registrationOptions?: RegistrationOptionsOverrides;
  authenticationOptions?: AuthenticationOptionsOverrides;
  verifyRegistrationOptions?: VerifyRegistrationOverrides;
  verifyAuthenticationOptions?: VerifyAuthenticationOverrides;
}
