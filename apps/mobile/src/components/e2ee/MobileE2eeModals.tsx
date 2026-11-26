import { useEffect, useState } from "react";
import type { createEdgeEverClient } from "@edgeever/client";
import { KeyboardAvoidingView, Modal, Platform, ScrollView, StyleSheet, View } from "react-native";
import { ActivityIndicator, Check, Fingerprint, KeyRound, LockKeyhole, ShieldCheck, X } from "../icons";
import { Pressable, Text, TextInput } from "../LocalizedText";
import {
  mobileE2eeBiometricStore,
  mobileE2eeSession,
  useMobileE2eeSession,
  type MobileBiometricStatus,
} from "../../lib/e2ee";
import { getMobileCatalog, useMobileLocale } from "../../lib/mobile-locale";
import { resolveMobileThemeStyles, useMobileTheme, type MobileResolvedTheme } from "../../lib/mobile-theme";
import { getMobileBiometricCopy } from "./biometric-copy";

type MobileClient = ReturnType<typeof createEdgeEverClient>;

export const MobileE2eeSetupModal = ({
  client,
  onClose,
  onConfigured,
  visible,
}: {
  client: MobileClient | null;
  onClose: () => void;
  onConfigured?: () => void;
  visible: boolean;
}) => {
  const { resolvedLocale } = useMobileLocale();
  const { resolvedTheme } = useMobileTheme();
  refreshStyles(resolvedTheme);
  const catalog = getMobileCatalog(resolvedLocale);
  const copy = catalog.e2ee;
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [riskAccepted, setRiskAccepted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!visible) {
      setPassphrase("");
      setConfirmPassphrase("");
      setRiskAccepted(false);
      setError(null);
      setSubmitting(false);
    }
  }, [visible]);

  const handleSubmit = async () => {
    if (!client) {
      setError(copy.offlineCreateBlocked);
      return;
    }
    if (passphrase.length < 8) {
      setError(copy.passphraseTooShort);
      return;
    }
    if (passphrase !== confirmPassphrase) {
      setError(copy.passphraseMismatch);
      return;
    }
    if (!riskAccepted) {
      setError(copy.mustAcknowledge);
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await mobileE2eeSession.initializePassphrase(passphrase, (payload) =>
        client.putE2eeKeyring(payload),
      );
      onClose();
      onConfigured?.();
    } catch (err) {
      const code = (err as { code?: string } | null)?.code;
      if (code === "keyring_already_exists") {
        void mobileE2eeSession.refreshKeyring(() => client.getE2eeKeyring()).catch(() => undefined);
      }
      setError(err instanceof Error ? err.message : copy.decryptFailed);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal animationType="fade" onRequestClose={submitting ? undefined : onClose} transparent visible={visible}>
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={styles.backdrop}>
        <View style={styles.card}>
          <View style={styles.header}>
            <View style={styles.headerTitleRow}>
              <ShieldCheck color="#047857" size={20} />
              <Text style={styles.title}>{copy.setupDialogTitle}</Text>
            </View>
            <Pressable accessibilityLabel={catalog.common.cancel} accessibilityRole="button" disabled={submitting} onPress={onClose} style={styles.closeBtn}>
              <X color="#475569" size={18} />
            </Pressable>
          </View>
          <ScrollView contentContainerStyle={styles.body} keyboardShouldPersistTaps="handled">
            <Text style={styles.description}>{copy.setupDialogDescription}</Text>
            <View style={styles.warningBox}>
              <Text style={styles.warningText}>{copy.noRecoveryWarning}</Text>
            </View>
            <View style={styles.field}>
              <Text style={styles.label}>{copy.passphraseLabel}</Text>
              <TextInput
                autoCapitalize="none"
                autoCorrect={false}
                onChangeText={setPassphrase}
                placeholder={copy.passphrasePlaceholder}
                placeholderTextColor="#94a3b8"
                secureTextEntry
                style={styles.input}
                value={passphrase}
              />
            </View>
            <View style={styles.field}>
              <Text style={styles.label}>{copy.confirmPassphraseLabel}</Text>
              <TextInput
                autoCapitalize="none"
                autoCorrect={false}
                onChangeText={setConfirmPassphrase}
                placeholder={copy.confirmPassphrasePlaceholder}
                placeholderTextColor="#94a3b8"
                secureTextEntry
                style={styles.input}
                value={confirmPassphrase}
              />
            </View>
            <Pressable
              accessibilityRole="checkbox"
              accessibilityState={{ checked: riskAccepted }}
              onPress={() => setRiskAccepted((prev) => !prev)}
              style={styles.checkboxRow}
            >
              <View style={[styles.checkboxBox, riskAccepted && styles.checkboxBoxChecked]}>
                {riskAccepted ? <Check color="#ffffff" size={13} /> : null}
              </View>
              <Text style={styles.checkboxLabel}>{copy.acknowledgeNoRecovery}</Text>
            </Pressable>
            {error ? <Text accessibilityRole="alert" style={styles.error}>{error}</Text> : null}
            <View style={styles.footer}>
              <Pressable accessibilityRole="button" disabled={submitting} onPress={onClose} style={styles.secondaryBtn}>
                <Text style={styles.secondaryBtnText}>{catalog.common.cancel}</Text>
              </Pressable>
              <Pressable
                accessibilityRole="button"
                disabled={submitting}
                onPress={() => void handleSubmit()}
                style={[styles.primaryBtn, submitting && styles.disabled]}
              >
                {submitting ? <ActivityIndicator color="#ffffff" size="small" /> : null}
                <Text style={styles.primaryBtnText}>{submitting ? copy.saving : copy.submit}</Text>
              </Pressable>
            </View>
          </ScrollView>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
};

export const MobileE2eeUnlockModal = ({
  onClose,
  onUnlocked,
  visible,
}: {
  onClose: () => void;
  onUnlocked?: () => void;
  visible: boolean;
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
    if (!visible) {
      setPassphrase("");
      setError(null);
      setSubmitting(false);
      return;
    }
    let active = true;
    void mobileE2eeBiometricStore.status(e2ee.scope).then((status) => {
      if (active) setBiometricStatus(status);
    });
    return () => { active = false; };
  }, [e2ee.scope, visible]);

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
      onClose();
      onUnlocked?.();
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
      onClose();
      onUnlocked?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : bioCopy.failed);
      const nextStatus = await mobileE2eeBiometricStore.status(e2ee.scope).catch(() => null);
      if (nextStatus) setBiometricStatus(nextStatus);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal animationType="fade" onRequestClose={submitting ? undefined : onClose} transparent visible={visible}>
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={styles.backdrop}>
        <View style={styles.card}>
          <View style={styles.header}>
            <View style={styles.headerTitleRow}>
              <LockKeyhole color="#047857" size={20} />
              <Text style={styles.title}>{copy.unlockDialogTitle}</Text>
            </View>
            <Pressable accessibilityLabel={catalog.common.cancel} accessibilityRole="button" disabled={submitting} onPress={onClose} style={styles.closeBtn}>
              <X color="#475569" size={18} />
            </Pressable>
          </View>
          <View style={styles.body}>
            <Text style={styles.description}>{copy.unlockDialogDescription}</Text>
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
            <View style={styles.field}>
              <Text style={styles.label}>{copy.passphraseLabel}</Text>
              <TextInput
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
            </View>
            {error ? <Text accessibilityRole="alert" style={styles.error}>{error}</Text> : null}
            <View style={styles.footer}>
              <Pressable accessibilityRole="button" disabled={submitting} onPress={onClose} style={styles.secondaryBtn}>
                <Text style={styles.secondaryBtnText}>{catalog.common.cancel}</Text>
              </Pressable>
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
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
};

export const MobileE2eeChangePassphraseModal = ({
  client,
  onClose,
  onRotated,
  visible,
}: {
  client: MobileClient | null;
  onClose: () => void;
  onRotated?: () => void;
  visible: boolean;
}) => {
  const { resolvedLocale } = useMobileLocale();
  const { resolvedTheme } = useMobileTheme();
  refreshStyles(resolvedTheme);
  const catalog = getMobileCatalog(resolvedLocale);
  const copy = catalog.e2ee;
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!visible) {
      setCurrentPassphrase("");
      setNewPassphrase("");
      setConfirmPassphrase("");
      setError(null);
      setSubmitting(false);
    }
  }, [visible]);

  const handleSubmit = async () => {
    if (!client) {
      setError(copy.offlineCreateBlocked);
      return;
    }
    if (!currentPassphrase) {
      setError(copy.wrongPassphrase);
      return;
    }
    if (newPassphrase.length < 8) {
      setError(copy.passphraseTooShort);
      return;
    }
    if (newPassphrase !== confirmPassphrase) {
      setError(copy.passphraseMismatch);
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await mobileE2eeSession.rotatePassphrase(currentPassphrase, newPassphrase, (payload) =>
        client.putE2eeKeyring(payload),
      );
      onClose();
      onRotated?.();
    } catch (err) {
      const code = (err as { code?: string } | null)?.code;
      if (code === "keyring_revision_conflict") {
        void mobileE2eeSession.refreshKeyring(() => client.getE2eeKeyring()).catch(() => undefined);
      }
      setError(err instanceof Error ? err.message : copy.wrongPassphrase);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal animationType="fade" onRequestClose={submitting ? undefined : onClose} transparent visible={visible}>
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={styles.backdrop}>
        <View style={styles.card}>
          <View style={styles.header}>
            <View style={styles.headerTitleRow}>
              <KeyRound color="#047857" size={20} />
              <Text style={styles.title}>{copy.changePassphraseTitle}</Text>
            </View>
            <Pressable accessibilityLabel={catalog.common.cancel} accessibilityRole="button" disabled={submitting} onPress={onClose} style={styles.closeBtn}>
              <X color="#475569" size={18} />
            </Pressable>
          </View>
          <ScrollView contentContainerStyle={styles.body} keyboardShouldPersistTaps="handled">
            <Text style={styles.description}>{copy.changePassphraseDescription}</Text>
            <View style={styles.field}>
              <Text style={styles.label}>{copy.currentPassphraseLabel}</Text>
              <TextInput
                autoCapitalize="none"
                autoCorrect={false}
                onChangeText={setCurrentPassphrase}
                placeholder={copy.passphrasePlaceholder}
                placeholderTextColor="#94a3b8"
                secureTextEntry
                style={styles.input}
                value={currentPassphrase}
              />
            </View>
            <View style={styles.field}>
              <Text style={styles.label}>{copy.newPassphraseLabel}</Text>
              <TextInput
                autoCapitalize="none"
                autoCorrect={false}
                onChangeText={setNewPassphrase}
                placeholder={copy.passphrasePlaceholder}
                placeholderTextColor="#94a3b8"
                secureTextEntry
                style={styles.input}
                value={newPassphrase}
              />
            </View>
            <View style={styles.field}>
              <Text style={styles.label}>{copy.confirmPassphraseLabel}</Text>
              <TextInput
                autoCapitalize="none"
                autoCorrect={false}
                onChangeText={setConfirmPassphrase}
                placeholder={copy.confirmPassphrasePlaceholder}
                placeholderTextColor="#94a3b8"
                secureTextEntry
                style={styles.input}
                value={confirmPassphrase}
              />
            </View>
            {error ? <Text accessibilityRole="alert" style={styles.error}>{error}</Text> : null}
            <View style={styles.footer}>
              <Pressable accessibilityRole="button" disabled={submitting} onPress={onClose} style={styles.secondaryBtn}>
                <Text style={styles.secondaryBtnText}>{catalog.common.cancel}</Text>
              </Pressable>
              <Pressable
                accessibilityRole="button"
                disabled={submitting}
                onPress={() => void handleSubmit()}
                style={[styles.primaryBtn, submitting && styles.disabled]}
              >
                {submitting ? <ActivityIndicator color="#ffffff" size="small" /> : null}
                <Text style={styles.primaryBtnText}>{submitting ? copy.saving : copy.submit}</Text>
              </Pressable>
            </View>
          </ScrollView>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
};

const baseStyles = StyleSheet.create({
  backdrop: {
    alignItems: "center",
    backgroundColor: "rgba(15, 23, 42, 0.55)",
    flex: 1,
    justifyContent: "center",
    padding: 18,
  },
  card: {
    backgroundColor: "#ffffff",
    borderColor: "#dbe7de",
    borderRadius: 16,
    borderWidth: 1,
    maxHeight: "88%",
    maxWidth: 440,
    overflow: "hidden",
    width: "100%",
  },
  header: {
    alignItems: "center",
    borderBottomColor: "#e2e8f0",
    borderBottomWidth: StyleSheet.hairlineWidth,
    flexDirection: "row",
    justifyContent: "space-between",
    paddingHorizontal: 16,
    paddingVertical: 14,
  },
  headerTitleRow: { alignItems: "center", flex: 1, flexDirection: "row", gap: 8 },
  title: { color: "#0f172a", fontSize: 16, fontWeight: "800" },
  closeBtn: { alignItems: "center", height: 32, justifyContent: "center", width: 32 },
  body: { gap: 14, padding: 16 },
  description: { color: "#475569", fontSize: 13, lineHeight: 19 },
  warningBox: {
    backgroundColor: "#fffbeb",
    borderColor: "#fde68a",
    borderRadius: 10,
    borderWidth: 1,
    padding: 11,
  },
  warningText: { color: "#92400e", fontSize: 12, lineHeight: 18 },
  field: { gap: 6 },
  label: { color: "#334155", fontSize: 13, fontWeight: "700" },
  input: {
    backgroundColor: "#ffffff",
    borderColor: "#cbd5e1",
    borderRadius: 10,
    borderWidth: 1,
    color: "#0f172a",
    fontSize: 15,
    minHeight: 46,
    paddingHorizontal: 12,
  },
  checkboxRow: { alignItems: "flex-start", flexDirection: "row", gap: 10 },
  checkboxBox: {
    alignItems: "center",
    borderColor: "#94a3b8",
    borderRadius: 5,
    borderWidth: 1.5,
    height: 20,
    justifyContent: "center",
    marginTop: 1,
    width: 20,
  },
  checkboxBoxChecked: { backgroundColor: "#047857", borderColor: "#047857" },
  checkboxLabel: { color: "#334155", flex: 1, fontSize: 13, lineHeight: 19 },
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
  error: { color: "#be123c", fontSize: 13, lineHeight: 18 },
  footer: { flexDirection: "row", gap: 10, justifyContent: "flex-end", marginTop: 4 },
  secondaryBtn: {
    alignItems: "center",
    borderColor: "#cbd5e1",
    borderRadius: 10,
    borderWidth: 1,
    justifyContent: "center",
    minHeight: 44,
    paddingHorizontal: 16,
  },
  secondaryBtnText: { color: "#334155", fontSize: 14, fontWeight: "700" },
  primaryBtn: {
    alignItems: "center",
    backgroundColor: "#047857",
    borderRadius: 10,
    flexDirection: "row",
    gap: 8,
    justifyContent: "center",
    minHeight: 44,
    paddingHorizontal: 18,
  },
  primaryBtnText: { color: "#ffffff", fontSize: 14, fontWeight: "800" },
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
