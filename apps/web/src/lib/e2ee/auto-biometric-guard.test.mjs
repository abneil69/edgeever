import { describe, expect, test } from "bun:test";
import {
  advanceAutoBiometricGuard,
  createAutoBiometricGuardState,
  shouldSuppressAutoBiometric,
} from "./auto-biometric-guard.ts";

describe("auto-biometric prompt suppression state machine", () => {
  test("prompts on initial open, suppresses on in-place lock, and re-enables after navigating away and back", () => {
    let state = createAutoBiometricGuardState(false);

    // 1. Cold open locked encrypted note M1 -> should auto-prompt.
    state = advanceAutoBiometricGuard(state, "M1", false);
    expect(shouldSuppressAutoBiometric(state, "M1")).toBe(false);

    // StrictMode / extra re-render while still locked on M1 -> stays unsuppressed.
    state = advanceAutoBiometricGuard(state, "M1", false);
    expect(shouldSuppressAutoBiometric(state, "M1")).toBe(false);

    // 2. User unlocks M1 via Touch ID or passphrase.
    state = advanceAutoBiometricGuard(state, "M1", true);
    expect(shouldSuppressAutoBiometric(state, "M1")).toBe(false);

    // Intermediate renders while async lock flush is still running (unlocked still true).
    state = advanceAutoBiometricGuard(state, "M1", true);
    state = advanceAutoBiometricGuard(state, "M1", true);
    expect(shouldSuppressAutoBiometric(state, "M1")).toBe(false);

    // 3. Lock finishes: unlocked flips true -> false while still on M1 -> MUST suppress!
    state = advanceAutoBiometricGuard(state, "M1", false);
    expect(shouldSuppressAutoBiometric(state, "M1")).toBe(true);

    // Subsequent re-renders / StrictMode double-render while locked on M1 -> stays suppressed!
    state = advanceAutoBiometricGuard(state, "M1", false);
    state = advanceAutoBiometricGuard(state, "M1", false);
    expect(shouldSuppressAutoBiometric(state, "M1")).toBe(true);

    // 4. User switches to a normal note M2 -> suppression clears.
    state = advanceAutoBiometricGuard(state, "M2", false);
    expect(shouldSuppressAutoBiometric(state, "M2")).toBe(false);

    // 5. User switches back to encrypted note M1 -> MUST auto-prompt again!
    state = advanceAutoBiometricGuard(state, "M1", false);
    expect(shouldSuppressAutoBiometric(state, "M1")).toBe(false);

    // 6. User unlocks M1 again, then locks M1 again -> MUST suppress again!
    state = advanceAutoBiometricGuard(state, "M1", true);
    state = advanceAutoBiometricGuard(state, "M1", false);
    expect(shouldSuppressAutoBiometric(state, "M1")).toBe(true);

    // 7. User switches directly from locked M1 to another encrypted note M3 -> MUST auto-prompt!
    state = advanceAutoBiometricGuard(state, "M3", false);
    expect(shouldSuppressAutoBiometric(state, "M3")).toBe(false);
  });
});
