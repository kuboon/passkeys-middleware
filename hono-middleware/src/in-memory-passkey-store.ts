import type {
  PasskeyCredential,
  PasskeyStorage,
  PasskeyUser,
} from "./types.ts";

export class InMemoryPasskeyStore implements PasskeyStorage {
  private readonly users = new Map<string, PasskeyUser>();
  private readonly usersByUsername = new Map<string, string>();
  private readonly credentials = new Map<string, PasskeyCredential>();

  getUserByUsername(username: string): Promise<PasskeyUser | null> {
    const key = username.toLowerCase();
    const userId = this.usersByUsername.get(key);
    return userId ? this.getUserById(userId) : Promise.resolve(null);
  }

  getUserById(userId: string): Promise<PasskeyUser | null> {
    return Promise.resolve(this.users.get(userId) ?? null);
  }

  createUser(user: PasskeyUser): Promise<void> {
    this.users.set(user.id, { ...user });
    this.usersByUsername.set(user.username.toLowerCase(), user.id);
    return Promise.resolve();
  }

  updateUser(user: PasskeyUser): Promise<void> {
    if (!this.users.has(user.id)) {
      throw new Error("User does not exist");
    }
    this.users.set(user.id, { ...user });
    this.usersByUsername.set(user.username.toLowerCase(), user.id);
    return Promise.resolve();
  }

  getCredentialById(credentialId: string): Promise<PasskeyCredential | null> {
    return Promise.resolve(this.credentials.get(credentialId) ?? null);
  }

  getCredentialsByUserId(userId: string): Promise<PasskeyCredential[]> {
    return Promise.resolve(
      Array.from(this.credentials.values()).filter(
        (credential) => credential.userId === userId,
      ),
    );
  }

  saveCredential(credential: PasskeyCredential): Promise<void> {
    this.credentials.set(credential.id, { ...credential });
    return Promise.resolve();
  }

  updateCredential(credential: PasskeyCredential): Promise<void> {
    if (!this.credentials.has(credential.id)) {
      throw new Error("Credential does not exist");
    }
    this.credentials.set(credential.id, { ...credential });
    return Promise.resolve();
  }

  deleteCredential(credentialId: string): Promise<void> {
    this.credentials.delete(credentialId);
    return Promise.resolve();
  }

  deleteUser(userId: string): Promise<void> {
    const existing = this.users.get(userId);
    if (!existing) {
      return Promise.resolve();
    }
    this.users.delete(userId);
    this.usersByUsername.delete(existing.username.toLowerCase());
    for (const [id, credential] of this.credentials.entries()) {
      if (credential.userId === userId) {
        this.credentials.delete(id);
      }
    }
    return Promise.resolve();
  }
}
