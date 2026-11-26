import { useEffect, useState } from "react";
import type { MemoDetail } from "@edgeever/shared";
import { ScrollView, StyleSheet, View } from "react-native";
import { ActivityIndicator, Fingerprint, LockKeyhole, RotateCcw } from "../icons";
import { Pressable, Text, TextInput } from "../LocalizedText";
import {
  mobileE2eeBiometricStore,
  mobileE2eeSession,
  useMobileE2eeSession,
  type MobileBiometricStatus,
} from "../../lib/e2ee";
import { getMobileCatalog, localizeUntitledMemoTitle, useMobileLocale } from "../../lib/mobile-locale";
import { resolveMobileThemeStyles, useMobileTheme, type MobileResolvedTheme } from "../../lib/mobile-theme";
import { getMobileBiometricCopy } from "./biometric-copy";

export const MobileEncryptedNoteLockView = ({
  decryptError,
  decrypting,
  memo,
  onRetryDecrypt,
}: {
  decryptError: string | null;
  decrypting: boolean;
  memo: MemoDetail;
  onRetryDecrypt: () => void;
}) => {
  const { resolvedLocale } = useMobileLocale();
  const { resolvedTheme } = useMobileTheme();
  refreshStyles(resolvedTheme);
  const e2ee = useMobileE2eeSession();
  const catalog = getMobileCatalog(resolvedLocale);
  const copy = catalog.e2ee;
  const bioCopy = getMobileBiometricCopy(resolvedLocale);
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [biometricStatus, setBiometricStatus] = useState<MobileBiometricStatus>({
    available: false,
    enabled: false,
    keyId: null,
  });

  useEffect(() => {
    setPassphrase("");
    setError(null);
    let active = true;
    void mobileE2eeBiometricStore.status(e2ee.scope).then((status) => {
      if (active) setBiometricStatus(status);
    });
    return () => { active = false; };
  }, [e2ee.scope, memo.id]);

  const canUseBiometric = biometricStatus.available
    && biometricStatus.enabled
    && (!e2ee.keyId || biometricStatus.keyId === e2ee.keyId);

  const handlePassphraseUnlock = async () => {
    if (!passphrase) {
      setError(copy.wrongPassphrase);
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await mobileE2eeSession.unlockWithPassphrase(passphrase);
      setPassphrase("");
    } catch {
      setError(copy.wrongPassphrase);
    } finally {
      setSubmitting(false);
    }
  };

  const handleBiometricUnlock = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const result = await mobileE2eeBiometricStore.unlock(e2ee.scope, e2ee.keyId, bioCopy.promptReason);
      await mobileE2eeSession.unlockWithMasterKeyBase64(result.keyId, result.masterKeyBase64);
    } catch (err) {
      setError(err instanceof Error ? err.message : bioCopy.failed);
      const nextStatus = await mobileE2eeBiometricStore.status(e2ee.scope).catch(() => null);
      if (nextStatus) setBiometricStatus(nextStatus);
    } finally {
      setSubmitting(false);
    }
  };

  const displayTitle = localizeUntitledMemoTitle(memo.title, resolvedLocale);

  return (
    <ScrollView contentContainerStyle={styles.container} keyboardShouldPersistTaps="handled">
      <View style={styles.card}>
        <View style={styles.iconCircle}>
          <LockKeyhole color="#b45309" size={28} />
        </View>
        <Text numberOfLines={2} style={styles.noteTitle}>{displayTitle}</Text>
        {memo.tags.length > 0 ? (
          <View style={styles.tagsRow}>
            {memo.tags.slice(0, 6).map((tag) => (
              <Text key={tag} style={styles.tagChip}>#{tag}</Text>
            ))}
          </View>
        ) : null}
        <Text style={styles.lockTitle}>{copy.lockedScreenTitle}</Text>
        <Text style={styles.lockDescription}>{copy.lockedScreenDescription}</Text>

        {decrypting ? (
          <View style={styles.loadingRow}>
            <ActivityIndicator color="#047857" size="small" />
            <Text style={styles.loadingText}>{copy.decrypting}</Text>
          </View>
        ) : decryptError ? (
          <View style={styles.errorBlock}>
            <Text accessibilityRole="alert" style={styles.errorText}>{decryptError}</Text>
            <Pressable accessibilityRole="button" onPress={onRetryDecrypt} style={styles.primaryBtn}>
              <RotateCcw color="#ffffff" size={16} />
              <Text style={styles.primaryBtnText}>{catalog.fontLoad.retry}</Text>
            </Pressable>
          </View>
        ) : (
          <View style={styles.form}>
            {canUseBiometric ? (
              <Pressable
                accessibilityRole="button"
                disabled={submitting}
                onPress={() => void handleBiometricUnlock()}
                style={[styles.biometricBtn, submitting && styles.disabled]}
              >
                <Fingerprint color="#047857" size={20} />
                <Text style={styles.biometricBtnText}>{bioCopy.unlockButton}</Text>
              </Pressable>
            ) : null}
            <TextInput
              accessibilityLabel={copy.passphraseLabel}
              autoCapitalize="none"
              autoCorrect={false}
              onChangeText={setPassphrase}
              onSubmitEditing={() => void handlePassphraseUnlock()}
              placeholder={copy.passphrasePlaceholder}
              placeholderTextColor="#94a3b8"
              returnKeyType="done"
              secureTextEntry
              style={styles.input}
              value={passphrase}
            />
            {error ? <Text accessibilityRole="alert" style={styles.errorText}>{error}</Text> : null}
            <Pressable
              accessibilityRole="button"
              disabled={submitting}
              onPress={() => void handlePassphraseUnlock()}
              style={[styles.primaryBtn, submitting && styles.disabled]}
            >
              {submitting ? <ActivityIndicator color="#ffffff" size="small" /> : null}
              <Text style={styles.primaryBtnText}>{submitting ? copy.saving : copy.unlockButton}</Text>
            </Pressable>
          </View>
        )}
      </View>
    </ScrollView>
  );
};

const baseStyles = StyleSheet.create({
  container: {
    alignItems: "center",
    flexGrow: 1,
    justifyContent: "center",
    padding: 20,
  },
  card: {
    alignItems: "center",
    backgroundColor: "#ffffff",
    borderColor: "#e2e8f0",
    borderRadius: 16,
    borderWidth: 1,
    gap: 12,
    maxWidth: 400,
    padding: 24,
    width: "100%",
  },
  iconCircle: {
    alignItems: "center",
    backgroundColor: "#fef3c7",
    borderRadius: 28,
    height: 56,
    justifyContent: "center",
    width: 56,
  },
  noteTitle: {
    color: "#0f172a",
    fontSize: 18,
    fontWeight: "800",
    textAlign: "center",
  },
  tagsRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 6,
    justifyContent: "center",
  },
  tagChip: {
    backgroundColor: "#f1f5f9",
    borderRadius: 999,
    color: "#475569",
    fontSize: 12,
    overflow: "hidden",
    paddingHorizontal: 8,
    paddingVertical: 3,
  },
  lockTitle: {
    color: "#1e293b",
    fontSize: 15,
    fontWeight: "700",
    marginTop: 4,
    textAlign: "center",
  },
  lockDescription: {
    color: "#64748b",
    fontSize: 13,
    lineHeight: 19,
    textAlign: "center",
  },
  loadingRow: {
    alignItems: "center",
    flexDirection: "row",
    gap: 8,
    marginTop: 8,
  },
  loadingText: { color: "#475569", fontSize: 13 },
  errorBlock: { alignItems: "center", gap: 12, marginTop: 8, width: "100%" },
  form: { gap: 12, marginTop: 8, width: "100%" },
  biometricBtn: {
    alignItems: "center",
    backgroundColor: "#ecfdf5",
    borderColor: "#a7f3d0",
    borderRadius: 10,
    borderWidth: 1,
    flexDirection: "row",
    gap: 8,
    justifyContent: "center",
    minHeight: 46,
    paddingHorizontal: 14,
  },
  biometricBtnText: { color: "#047857", fontSize: 14, fontWeight: "700" },
  input: {
    backgroundColor: "#ffffff",
    borderColor: "#cbd5e1",
    borderRadius: 10,
    borderWidth: 1,
    color: "#0f172a",
    fontSize: 15,
    minHeight: 46,
    paddingHorizontal: 12,
    width: "100%",
  },
  primaryBtn: {
    alignItems: "center",
    backgroundColor: "#047857",
    borderRadius: 10,
    flexDirection: "row",
    gap: 8,
    justifyContent: "center",
    minHeight: 46,
    paddingHorizontal: 18,
    width: "100%",
  },
  primaryBtnText: { color: "#ffffff", fontSize: 14, fontWeight: "800" },
  errorText: { color: "#be123c", fontSize: 13, lineHeight: 18, textAlign: "center" },
  disabled: { opacity: 0.5 },
});

let styles = baseStyles;
let currentTheme: MobileResolvedTheme = "light";

const refreshStyles = (theme: MobileResolvedTheme) => {
  if (currentTheme !== theme) {
    styles = resolveMobileThemeStyles(baseStyles, theme);
    currentTheme = theme;
  }
};
