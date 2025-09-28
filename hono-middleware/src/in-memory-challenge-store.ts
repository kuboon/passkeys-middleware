import type {
  ChallengeType,
  PasskeyChallengeStore,
  PasskeyStoredChallenge,
} from "./types.ts";

export class InMemoryChallengeStore implements PasskeyChallengeStore {
  private readonly challenges = new Map<
    string,
    Map<ChallengeType, PasskeyStoredChallenge>
  >();

  setChallenge(
    userId: string,
    type: ChallengeType,
    value: PasskeyStoredChallenge,
  ): Promise<void> {
    const userChallenges = this.challenges.get(userId) ?? new Map();
    userChallenges.set(type, value);
    this.challenges.set(userId, userChallenges);
    return Promise.resolve();
  }

  getChallenge(
    userId: string,
    type: ChallengeType,
  ): Promise<PasskeyStoredChallenge | null> {
    return Promise.resolve(this.challenges.get(userId)?.get(type) ?? null);
  }

  clearChallenge(userId: string, type: ChallengeType): Promise<void> {
    const userChallenges = this.challenges.get(userId);
    if (userChallenges) {
      userChallenges.delete(type);
      if (userChallenges.size === 0) {
        this.challenges.delete(userId);
      }
    }
    return Promise.resolve();
  }
}
