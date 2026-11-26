import { useCallback, useEffect, useState } from "react";
import { StyleSheet, Switch, View } from "react-native";
import { Fingerprint, KeyRound, LockKeyhole, LockOpen, ShieldCheck } from "../icons";
import { Pressable, Text } from "../LocalizedText";
import {
  mobileE2eeBiometricStore,
  mobileE2eeSession,
  useMobileE2eeSession,
  type MobileBiometricStatus,
  type MobileE2eeAutoLockMinutes,
} from "../../lib/e2ee";
import { getMobileCatalog, useMobileLocale } from "../../lib/mobile-locale";
import { resolveMobileThemeStyles, useMobileTheme, type MobileResolvedTheme } from "../../lib/mobile-theme";
import { useSession } from "../../lib/session";
import {
  MobileE2eeChangePassphraseModal,
  MobileE2eeSetupModal,
  MobileE2eeUnlockModal,
} from "./MobileE2eeModals";
import { getMobileBiometricCopy } from "./biometric-copy";

const AUTO_LOCK_OPTIONS: MobileE2eeAutoLockMinutes[] = [5, 15, 30];

export const MobileE2eeSettingsPanel = ({ active }: { active: boolean }) => {
  const { resolvedLocale } = useMobileLocale();
  const { resolvedTheme } = useMobileTheme();
  refreshStyles(resolvedTheme);
  const { client } = useSession();
  const e2ee = useMobileE2eeSession();
  const copy = getMobileCatalog(resolvedLocale).e2ee;
  const bioCopy = getMobileBiometricCopy(resolvedLocale);

  const [setupOpen, setSetupOpen] = useState(false);
  const [unlockOpen, setUnlockOpen] = useState(false);
  const [changePassphraseOpen, setChangePassphraseOpen] = useState(false);
  const [biometricStatus, setBiometricStatus] = useState<MobileBiometricStatus>({
    available: false,
    enabled: false,
    keyId: null,
  });
  const [biometricPending, setBiometricPending] = useState(false);
  const [feedback, setFeedback] = useState<{ kind: "success" | "error"; message: string } | null>(null);

  const refreshBiometricStatus = useCallback(async () => {
    const status = await mobileE2eeBiometricStore.status(e2ee.scope).catch(() => ({
      available: false,
      enabled: false,
      keyId: null,
    }));
    setBiometricStatus(status);
  }, [e2ee.scope]);

  useEffect(() => {
    if (!active) return;
    setFeedback(null);
    if (client) {
      void mobileE2eeSession.refreshKeyring(() => client.getE2eeKeyring()).catch(() => undefined);
    }
    void refreshBiometricStatus();
  }, [active, client, refreshBiometricStatus]);

  const handleToggleBiometric = async (nextEnabled: boolean) => {
    if (biometricPending) return;
    setBiometricPending(true);
    setFeedback(null);
    try {
      if (nextEnabled) {
        if (!e2ee.unlocked) {
          setUnlockOpen(true);
          return;
        }
        const exported = mobileE2eeSession.exportMasterKeyBase64ForBiometric();
        await mobileE2eeBiometricStore.enable(
          e2ee.scope,
          exported.keyId,
          exported.masterKeyBase64,
          bioCopy.promptReason,
        );
        setFeedback({ kind: "success", message: bioCopy.enabled });
      } else {
        await mobileE2eeBiometricStore.disable(e2ee.scope);
        setFeedback({ kind: "success", message: bioCopy.disabled });
      }
      await refreshBiometricStatus();
    } catch (err) {
      setFeedback({
        kind: "error",
        message: err instanceof Error ? err.message : bioCopy.failed,
      });
    } finally {
      setBiometricPending(false);
    }
  };

  const statusLabel = !e2ee.configured
    ? copy.statusNotConfigured
    : e2ee.unlocked
      ? copy.statusConfiguredUnlocked
      : copy.statusConfiguredLocked;

  const autoLockLabel = (minutes: MobileE2eeAutoLockMinutes) =>
    minutes === 5 ? copy.autoLock5 : minutes === 15 ? copy.autoLock15 : copy.autoLock30;

  return (
    <View style={styles.content}>
      <View style={styles.hero}>
        <ShieldCheck color="#15803d" size={22} />
        <View style={styles.flex}>
          <View style={styles.titleRow}>
            <Text style={styles.cardTitle}>{copy.title}</Text>
            <View
              style={[
                styles.statusBadge,
                e2ee.unlocked
                  ? styles.statusBadgeUnlocked
                  : e2ee.configured
                    ? styles.statusBadgeLocked
                    : styles.statusBadgeUnconfigured,
              ]}
            >
              <Text
                style={[
                  styles.statusBadgeText,
                  e2ee.unlocked
                    ? styles.statusBadgeTextUnlocked
                    : e2ee.configured
                      ? styles.statusBadgeTextLocked
                      : styles.statusBadgeTextUnconfigured,
                ]}
              >
                {statusLabel}
              </Text>
            </View>
          </View>
          <Text style={styles.help}>{copy.description}</Text>
        </View>
      </View>

      {!e2ee.configured ? (
        <Pressable
          accessibilityRole="button"
          disabled={!client}
          onPress={() => setSetupOpen(true)}
          style={[styles.primaryButton, !client && styles.disabled]}
        >
          <LockKeyhole color="#ffffff" size={16} />
          <Text style={styles.primaryButtonText}>{copy.setupButton}</Text>
        </Pressable>
      ) : (
        <View style={styles.actionsStack}>
          <View style={styles.actionRow}>
            {e2ee.unlocked ? (
              <Pressable
                accessibilityRole="button"
                onPress={() => void mobileE2eeSession.lock("manual")}
                style={styles.secondaryButton}
              >
                <LockKeyhole color="#0f172a" size={16} />
                <Text style={styles.secondaryButtonText}>{copy.lockNowButton}</Text>
              </Pressable>
            ) : (
              <Pressable
                accessibilityRole="button"
                onPress={() => setUnlockOpen(true)}
                style={styles.primaryButtonFlex}
              >
                <LockOpen color="#ffffff" size={16} />
                <Text style={styles.primaryButtonText}>{copy.unlockButton}</Text>
              </Pressable>
            )}
            <Pressable
              accessibilityRole="button"
              disabled={!client}
              onPress={() => setChangePassphraseOpen(true)}
              style={[styles.secondaryButton, !client && styles.disabled]}
            >
              <KeyRound color="#0f172a" size={16} />
              <Text style={styles.secondaryButtonText}>{copy.changePassphraseButton}</Text>
            </Pressable>
          </View>

          <View style={styles.sectionBox}>
            <Text style={styles.sectionLabel}>{copy.autoLockLabel}</Text>
            <View style={styles.timeoutRow}>
              {AUTO_LOCK_OPTIONS.map((minutes) => {
                const selected = e2ee.autoLockMinutes === minutes;
                return (
                  <Pressable
                    key={minutes}
                    accessibilityRole="radio"
                    accessibilityState={{ checked: selected }}
                    onPress={() => void mobileE2eeSession.setAutoLockMinutes(minutes)}
                    style={[styles.timeoutChip, selected && styles.timeoutChipSelected]}
                  >
                    <Text style={[styles.timeoutChipText, selected && styles.timeoutChipTextSelected]}>
                      {autoLockLabel(minutes)}
                    </Text>
                  </Pressable>
                );
              })}
            </View>
          </View>

          {biometricStatus.available ? (
            <View style={styles.biometricRow}>
              <Fingerprint color="#047857" size={20} />
              <View style={styles.flex}>
                <Text style={styles.biometricTitle}>{bioCopy.label}</Text>
                <Text style={styles.help}>{bioCopy.description}</Text>
              </View>
              <Switch
                accessibilityLabel={bioCopy.label}
                disabled={biometricPending}
                onValueChange={(value) => void handleToggleBiometric(value)}
                value={biometricStatus.enabled && (!e2ee.keyId || biometricStatus.keyId === e2ee.keyId)}
              />
            </View>
          ) : null}
        </View>
      )}

      {feedback ? (
        <Text
          accessibilityLiveRegion="polite"
          style={feedback.kind === "error" ? styles.error : styles.success}
        >
          {feedback.message}
        </Text>
      ) : null}

      <MobileE2eeSetupModal
        client={client}
        onClose={() => setSetupOpen(false)}
        onConfigured={() => {
          setFeedback({ kind: "success", message: copy.setupSuccess });
          void refreshBiometricStatus();
        }}
        visible={setupOpen}
      />
      <MobileE2eeUnlockModal
        onClose={() => setUnlockOpen(false)}
        onUnlocked={() => {
          setFeedback({ kind: "success", message: copy.statusConfiguredUnlocked });
          void refreshBiometricStatus();
        }}
        visible={unlockOpen}
      />
      <MobileE2eeChangePassphraseModal
        client={client}
        onClose={() => setChangePassphraseOpen(false)}
        onRotated={() => {
          setFeedback({ kind: "success", message: copy.changePassphraseSuccess });
        }}
        visible={changePassphraseOpen}
      />
    </View>
  );
};

const baseStyles = StyleSheet.create({
  content: { gap: 14, padding: 16, paddingBottom: 24 },
  hero: { alignItems: "flex-start", flexDirection: "row", gap: 10 },
  flex: { flex: 1 },
  titleRow: { alignItems: "center", flexDirection: "row", flexWrap: "wrap", gap: 8 },
  cardTitle: { color: "#17211a", fontSize: 16, fontWeight: "800" },
  help: { color: "#64748b", fontSize: 12, lineHeight: 18, marginTop: 3 },
  statusBadge: { borderRadius: 999, paddingHorizontal: 8, paddingVertical: 2 },
  statusBadgeUnlocked: { backgroundColor: "#dcfce7" },
  statusBadgeLocked: { backgroundColor: "#fef3c7" },
  statusBadgeUnconfigured: { backgroundColor: "#f1f5f9" },
  statusBadgeText: { fontSize: 11, fontWeight: "700" },
  statusBadgeTextUnlocked: { color: "#15803d" },
  statusBadgeTextLocked: { color: "#b45309" },
  statusBadgeTextUnconfigured: { color: "#475569" },
  actionsStack: { gap: 12 },
  actionRow: { flexDirection: "row", flexWrap: "wrap", gap: 10 },
  primaryButton: {
    alignItems: "center",
    backgroundColor: "#15803d",
    borderRadius: 10,
    flexDirection: "row",
    gap: 8,
    justifyContent: "center",
    minHeight: 46,
    paddingHorizontal: 16,
  },
  primaryButtonFlex: {
    alignItems: "center",
    backgroundColor: "#15803d",
    borderRadius: 10,
    flex: 1,
    flexDirection: "row",
    gap: 8,
    justifyContent: "center",
    minHeight: 44,
    paddingHorizontal: 14,
  },
  primaryButtonText: { color: "#ffffff", fontSize: 14, fontWeight: "800" },
  secondaryButton: {
    alignItems: "center",
    backgroundColor: "#f8fafc",
    borderColor: "#cbd5e1",
    borderRadius: 10,
    borderWidth: 1,
    flex: 1,
    flexDirection: "row",
    gap: 8,
    justifyContent: "center",
    minHeight: 44,
    paddingHorizontal: 14,
  },
  secondaryButtonText: { color: "#0f172a", fontSize: 13, fontWeight: "700" },
  sectionBox: { gap: 8 },
  sectionLabel: { color: "#334155", fontSize: 13, fontWeight: "700" },
  timeoutRow: { flexDirection: "row", gap: 8 },
  timeoutChip: {
    alignItems: "center",
    backgroundColor: "#f8fafc",
    borderColor: "#cbd5e1",
    borderRadius: 8,
    borderWidth: 1,
    flex: 1,
    paddingVertical: 9,
  },
  timeoutChipSelected: { backgroundColor: "#ecfdf5", borderColor: "#047857" },
  timeoutChipText: { color: "#475569", fontSize: 13, fontWeight: "600" },
  timeoutChipTextSelected: { color: "#047857", fontWeight: "800" },
  biometricRow: {
    alignItems: "center",
    backgroundColor: "#f8fafc",
    borderColor: "#e2e8f0",
    borderRadius: 10,
    borderWidth: 1,
    flexDirection: "row",
    gap: 10,
    padding: 12,
  },
  biometricTitle: { color: "#0f172a", fontSize: 13, fontWeight: "700" },
  disabled: { opacity: 0.45 },
  error: { color: "#be123c", fontSize: 13, lineHeight: 19 },
  success: { color: "#15803d", fontSize: 13, fontWeight: "700", lineHeight: 19 },
});

let styles = baseStyles;
let currentTheme: MobileResolvedTheme = "light";

const refreshStyles = (theme: MobileResolvedTheme) => {
  if (currentTheme !== theme) {
    styles = resolveMobileThemeStyles(baseStyles, theme);
    currentTheme = theme;
  }
};
