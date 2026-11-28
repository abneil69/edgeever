export type AutoBiometricGuardState = {
  lastMemoId: string | null;
  lastUnlocked: boolean;
  suppressedMemoId: string | null;
};

export const createAutoBiometricGuardState = (
  initialUnlocked = false,
): AutoBiometricGuardState => ({
  lastMemoId: null,
  lastUnlocked: initialUnlocked,
  suppressedMemoId: null,
});

/**
 * Pure transition that determines whether automatic biometric unlock prompting
 * should be suppressed for the currently displayed memo.
 *
 * Rule:
 * - Suppress ONLY when staying on the exact same memo while E2EE transitions
 *   from unlocked -> locked (manual lock, idle timeout, sleep, lock-screen).
 * - Clear suppression as soon as the user navigates to a different memo (or
 *   leaves the editor) or unlocks again, so switching to another note and
 *   returning to an encrypted note always auto-prompts biometric unlock.
 */
export const advanceAutoBiometricGuard = (
  prev: AutoBiometricGuardState,
  currentMemoId: string | null,
  unlocked: boolean,
): AutoBiometricGuardState => {
  let suppressedMemoId = prev.suppressedMemoId;
  if (currentMemoId !== prev.lastMemoId) {
    suppressedMemoId = null;
  } else if (prev.lastUnlocked && !unlocked && currentMemoId !== null) {
    suppressedMemoId = currentMemoId;
  } else if (unlocked) {
    suppressedMemoId = null;
  }
  return {
    lastMemoId: currentMemoId,
    lastUnlocked: unlocked,
    suppressedMemoId,
  };
};

export const shouldSuppressAutoBiometric = (
  state: AutoBiometricGuardState,
  memoId: string | null,
): boolean => Boolean(memoId && state.suppressedMemoId === memoId);
