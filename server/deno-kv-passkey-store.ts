import type {
  PasskeyCredential,
  PasskeyStorage,
  PasskeyUser,
} from "@passkeys-middleware/hono";

const USER_KEY_PREFIX = ["passkeys_middleware", "user"] as const;
const USERNAME_KEY_PREFIX = ["passkeys_middleware", "username"] as const;
const CREDENTIAL_KEY_PREFIX = ["passkeys_middleware", "credential"] as const;
const USER_CREDENTIAL_KEY_PREFIX = [
  "passkeys_middleware",
  "user_credentials",
] as const;

const normalizeUsername = (username: string): string =>
  username.trim().toLowerCase();

const userKey = (userId: string): Deno.KvKey =>
  [...USER_KEY_PREFIX, userId] as Deno.KvKey;

const usernameKey = (username: string): Deno.KvKey =>
  [...USERNAME_KEY_PREFIX, normalizeUsername(username)] as Deno.KvKey;

const credentialKey = (credentialId: string): Deno.KvKey =>
  [...CREDENTIAL_KEY_PREFIX, credentialId] as Deno.KvKey;

const userCredentialKey = (
  userId: string,
  credentialId: string,
): Deno.KvKey =>
  [...USER_CREDENTIAL_KEY_PREFIX, userId, credentialId] as Deno.KvKey;

const listUserCredentials = (
  kv: Deno.Kv,
  userId: string,
): Deno.KvListIterator<PasskeyCredential> =>
  kv.list<PasskeyCredential>({
    prefix: [...USER_CREDENTIAL_KEY_PREFIX, userId] as Deno.KvKey,
  });

export class DenoKvPasskeyStore implements PasskeyStorage {
  constructor(private readonly kv: Deno.Kv) {}

  static async create(): Promise<DenoKvPasskeyStore> {
    const kv = await Deno.openKv();
    return new DenoKvPasskeyStore(kv);
  }

  async getUserByUsername(username: string): Promise<PasskeyUser | null> {
    const normalized = normalizeUsername(username);
    if (!normalized) {
      return null;
    }
    const idEntry = await this.kv.get<string>(
      usernameKey(normalized),
    );
    return idEntry.value ? await this.getUserById(idEntry.value) : null;
  }

  async getUserById(userId: string): Promise<PasskeyUser | null> {
    const entry = await this.kv.get<PasskeyUser>(userKey(userId));
    return entry.value ?? null;
  }

  async createUser(user: PasskeyUser): Promise<void> {
    const normalized = normalizeUsername(user.username);
    if (!normalized) {
      throw new Error("Username is required");
    }
    const result = await this.kv.atomic()
      .check({ key: userKey(user.id), versionstamp: null })
      .check({ key: usernameKey(user.username), versionstamp: null })
      .set(userKey(user.id), user)
      .set(usernameKey(user.username), user.id)
      .commit();
    if (!result.ok) {
      throw new Error("User already exists");
    }
  }

  async updateUser(user: PasskeyUser): Promise<void> {
    const existing = await this.kv.get<PasskeyUser>(userKey(user.id));
    if (!existing.value) {
      throw new Error("User does not exist");
    }
    const normalized = normalizeUsername(user.username);
    if (!normalized) {
      throw new Error("Username is required");
    }
    const currentNormalized = normalizeUsername(existing.value.username);
    if (normalized !== currentNormalized) {
      const usernameOwner = await this.kv.get<string>(
        usernameKey(user.username),
      );
      if (usernameOwner.value && usernameOwner.value !== user.id) {
        throw new Error("Username already taken");
      }
    }
    const tx = this.kv.atomic().check(existing).set(userKey(user.id), user);
    if (normalized !== currentNormalized) {
      tx.delete(usernameKey(existing.value.username));
      tx.set(usernameKey(user.username), user.id);
    }
    const result = await tx.commit();
    if (!result.ok) {
      throw new Error("Unable to update user");
    }
  }

  async getCredentialById(
    credentialId: string,
  ): Promise<PasskeyCredential | null> {
    const entry = await this.kv.get<PasskeyCredential>(
      credentialKey(credentialId),
    );
    return entry.value ?? null;
  }

  async getCredentialsByUserId(userId: string): Promise<PasskeyCredential[]> {
    const credentials: PasskeyCredential[] = [];
    for await (const entry of listUserCredentials(this.kv, userId)) {
      if (entry.value) {
        credentials.push(entry.value);
      }
    }
    return credentials;
  }

  async saveCredential(credential: PasskeyCredential): Promise<void> {
    const userEntry = await this.kv.get<PasskeyUser>(
      userKey(credential.userId),
    );
    if (!userEntry.value) {
      throw new Error("User does not exist");
    }
    const tx = this.kv.atomic()
      .check(userEntry)
      .check({ key: credentialKey(credential.id), versionstamp: null })
      .check({
        key: userCredentialKey(credential.userId, credential.id),
        versionstamp: null,
      })
      .set(credentialKey(credential.id), credential)
      .set(userCredentialKey(credential.userId, credential.id), credential);
    const result = await tx.commit();
    if (!result.ok) {
      throw new Error("Credential already exists");
    }
  }

  async updateCredential(credential: PasskeyCredential): Promise<void> {
    const existing = await this.kv.get<PasskeyCredential>(
      credentialKey(credential.id),
    );
    if (!existing.value) {
      throw new Error("Credential does not exist");
    }
    const userEntry = await this.kv.get<PasskeyUser>(
      userKey(credential.userId),
    );
    if (!userEntry.value) {
      throw new Error("User does not exist");
    }
    const tx = this.kv.atomic()
      .check(existing)
      .check(userEntry)
      .set(credentialKey(credential.id), credential)
      .set(userCredentialKey(credential.userId, credential.id), credential);
    if (existing.value.userId !== credential.userId) {
      tx.delete(userCredentialKey(existing.value.userId, credential.id));
    }
    const result = await tx.commit();
    if (!result.ok) {
      throw new Error("Unable to update credential");
    }
  }

  async deleteCredential(credentialId: string): Promise<void> {
    const existing = await this.kv.get<PasskeyCredential>(
      credentialKey(credentialId),
    );
    if (!existing.value) {
      return;
    }
    const result = await this.kv.atomic()
      .check(existing)
      .delete(credentialKey(credentialId))
      .delete(userCredentialKey(existing.value.userId, credentialId))
      .commit();
    if (!result.ok) {
      throw new Error("Unable to delete credential");
    }
  }

  async deleteUser(userId: string): Promise<void> {
    const existing = await this.kv.get<PasskeyUser>(userKey(userId));
    if (!existing.value) {
      return;
    }
    const result = await this.kv.atomic()
      .check(existing)
      .delete(userKey(userId))
      .delete(usernameKey(existing.value.username))
      .commit();
    if (!result.ok) {
      throw new Error("Unable to delete user");
    }
    for await (const entry of listUserCredentials(this.kv, userId)) {
      if (!entry.value) {
        continue;
      }
      await this.kv.delete(entry.key);
      await this.kv.delete(credentialKey(entry.value.id));
    }
  }
}
