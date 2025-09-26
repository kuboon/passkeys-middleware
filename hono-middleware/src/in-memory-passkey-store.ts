import type { PasskeyCredential, PasskeyStorage, PasskeyUser } from './types';

export class InMemoryPasskeyStore implements PasskeyStorage {
  private readonly users = new Map<string, PasskeyUser>();
  private readonly usersByUsername = new Map<string, string>();
  private readonly credentials = new Map<string, PasskeyCredential>();

  async getUserByUsername(username: string): Promise<PasskeyUser | null> {
    const key = username.toLowerCase();
    const userId = this.usersByUsername.get(key);
    return userId ? this.getUserById(userId) : null;
  }

  async getUserById(userId: string): Promise<PasskeyUser | null> {
    return this.users.get(userId) ?? null;
  }

  async createUser(user: PasskeyUser): Promise<void> {
    this.users.set(user.id, { ...user });
    this.usersByUsername.set(user.username.toLowerCase(), user.id);
  }

  async updateUser(user: PasskeyUser): Promise<void> {
    if (!this.users.has(user.id)) {
      throw new Error('User does not exist');
    }
    this.users.set(user.id, { ...user });
    this.usersByUsername.set(user.username.toLowerCase(), user.id);
  }

  async getCredentialById(credentialId: string): Promise<PasskeyCredential | null> {
    return this.credentials.get(credentialId) ?? null;
  }

  async getCredentialsByUserId(userId: string): Promise<PasskeyCredential[]> {
    return Array.from(this.credentials.values()).filter(
      (credential) => credential.userId === userId,
    );
  }

  async saveCredential(credential: PasskeyCredential): Promise<void> {
    this.credentials.set(credential.id, { ...credential });
  }

  async updateCredential(credential: PasskeyCredential): Promise<void> {
    if (!this.credentials.has(credential.id)) {
      throw new Error('Credential does not exist');
    }
    this.credentials.set(credential.id, { ...credential });
  }

  async deleteCredential(credentialId: string): Promise<void> {
    this.credentials.delete(credentialId);
  }
}
