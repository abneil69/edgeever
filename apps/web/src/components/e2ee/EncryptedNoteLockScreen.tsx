import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { ChevronLeft, Fingerprint, Loader2, Lock } from "lucide-react";
import { useTranslation } from "react-i18next";
import { getMemoDisplayTitle, type MemoDetail } from "@edgeever/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { e2eeSession, useE2eeSession } from "@/lib/e2ee";

export const EncryptedNoteLockScreen = ({
  memo,
  decrypting = false,
  decryptError = null,
  suppressAutoBiometric = false,
  onBackToList,
  onRetryDecrypt,
}: {
  memo: MemoDetail;
  decrypting?: boolean;
  decryptError?: string | null;
  suppressAutoBiometric?: boolean;
  onBackToList?: () => void;
  onRetryDecrypt?: () => void;
}) => {
  const { t } = useTranslation();
  const e2ee = useE2eeSession();
  const [passphrase, setPassphrase] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const autoPromptedKeyRef = useRef<string | null>(null);
  const onRetryDecryptRef = useRef(onRetryDecrypt);
  onRetryDecryptRef.current = onRetryDecrypt;
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const displayTitle = getMemoDisplayTitle(memo.title, t("common.untitledMemo"));

  const runBiometricUnlock = useCallback(async () => {
    if (!window.edgeeverDesktop?.e2eeBiometricUnlock) return;
    setError(null);
    setSubmitting(true);
    try {
      const unlocked = await window.edgeeverDesktop.e2eeBiometricUnlock({
        expectedKeyId: e2ee.keyring?.keyId,
        reason: t("e2ee.touchIdReasonUnlock"),
      });
      e2eeSession.unlockWithMasterKeyBase64(unlocked.keyId, unlocked.masterKeyBase64);
      onRetryDecryptRef.current?.();
    } catch (err) {
      if (!mountedRef.current) return;
      const code = (err as { code?: string } | null)?.code;
      if (code === "e2ee_biometric_cancelled") {
        // User cancelled or dismissed Touch ID; stay quietly on the passphrase form.
        return;
      }
      if (code === "e2ee_biometric_key_mismatch" || code === "e2ee_biometric_stale") {
        setBiometricAvailable(false);
        setError(t("e2ee.touchIdMismatch"));
      } else {
        setError(t("e2ee.touchIdFailed"));
      }
    } finally {
      if (mountedRef.current) {
        setSubmitting(false);
      }
    }
  }, [e2ee.keyring?.keyId, t]);

  useEffect(() => {
    setPassphrase("");
    setError(null);
    let cancelled = false;
    void window.edgeeverDesktop?.e2eeBiometricStatus?.()
      .then((status) => {
        if (cancelled) return;
        const available = Boolean(
          status.available
          && status.enabled
          && (!e2ee.keyring?.keyId || status.keyId === e2ee.keyring.keyId),
        );
        setBiometricAvailable(available);
        const promptKey = `${memo.id}:${e2ee.keyring?.keyId ?? ""}`;
        const windowFocused = typeof document === "undefined"
          || (document.visibilityState === "visible" && (typeof document.hasFocus !== "function" || document.hasFocus()));
        if (
          available
          && !decrypting
          && !e2ee.unlocked
          && windowFocused
          && !suppressAutoBiometric
          && autoPromptedKeyRef.current !== promptKey
        ) {
          autoPromptedKeyRef.current = promptKey;
          void runBiometricUnlock();
        }
      })
      .catch(() => {
        if (!cancelled) setBiometricAvailable(false);
      });
    return () => { cancelled = true; };
  }, [decrypting, e2ee.keyring?.keyId, e2ee.unlocked, memo.id, runBiometricUnlock, suppressAutoBiometric]);

  const handleBiometricUnlock = () => runBiometricUnlock();

  const handleUnlockSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!passphrase) return;
    setError(null);
    setSubmitting(true);
    try {
      await e2eeSession.unlockWithPassphrase(passphrase);
      setPassphrase("");
      onRetryDecrypt?.();
    } catch {
      setError(t("e2ee.wrongPassphrase"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section
      data-encrypted-note-lock-screen
      className="flex h-full min-h-0 flex-col bg-background"
    >
      <header className="flex h-14 shrink-0 items-center justify-between border-b border-slate-200 px-4">
        <div className="flex min-w-0 items-center gap-2">
          {onBackToList ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  aria-label={t("common.back")}
                  onClick={onBackToList}
                  className="h-8 w-8 lg:hidden"
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>{t("common.back")}</TooltipContent>
            </Tooltip>
          ) : null}
          <Lock className="h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
          <h1 className="truncate text-sm font-semibold text-slate-900">{displayTitle}</h1>
        </div>
        <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 text-xs font-medium text-slate-600">
          <Lock className="h-3 w-3" aria-hidden="true" />
          {t("e2ee.encryptedBadge")}
        </span>
      </header>

      <div className="flex flex-1 flex-col items-center justify-center px-6 py-10">
        <div className="w-full max-w-sm rounded-2xl border border-slate-200 bg-card p-6 shadow-sm">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 text-slate-700">
            {decrypting ? <Loader2 className="h-5 w-5 animate-spin" /> : <Lock className="h-5 w-5" />}
          </div>
          <h2 className="text-center text-base font-semibold text-slate-950">
            {decrypting ? t("e2ee.decrypting") : t("e2ee.lockedScreenTitle")}
          </h2>
          <p className="mt-2 text-center text-xs leading-5 text-slate-500">
            {t("e2ee.lockedScreenDescription")}
          </p>

          {memo.tags.length > 0 ? (
            <div className="mt-3 flex flex-wrap items-center justify-center gap-1.5">
              {memo.tags.map((tag) => (
                <span key={tag} className="rounded-md bg-slate-100 px-2 py-0.5 text-xs text-slate-600">
                  #{tag}
                </span>
              ))}
            </div>
          ) : null}

          {!decrypting ? (
            <form onSubmit={(event) => void handleUnlockSubmit(event)} className="mt-5 grid gap-3">
              {biometricAvailable ? (
                <Button
                  type="button"
                  variant="outline"
                  disabled={submitting}
                  onClick={() => void handleBiometricUnlock()}
                  className="w-full justify-center gap-2"
                >
                  <Fingerprint className="h-4 w-4" />
                  {t("e2ee.touchIdUnlockButton")}
                </Button>
              ) : null}

              <Input
                type="password"
                autoComplete="current-password"
                value={passphrase}
                placeholder={t("e2ee.passphrasePlaceholder")}
                disabled={submitting}
                onChange={(event) => setPassphrase(event.target.value)}
              />

              {(error || decryptError) ? (
                <p role="alert" className="text-xs leading-5 text-rose-600">
                  {error ?? decryptError}
                </p>
              ) : null}

              <Button type="submit" disabled={submitting || !passphrase} className="w-full justify-center">
                {submitting ? t("e2ee.saving") : t("e2ee.unlock")}
              </Button>
            </form>
          ) : null}
        </div>
      </div>
    </section>
  );
};
