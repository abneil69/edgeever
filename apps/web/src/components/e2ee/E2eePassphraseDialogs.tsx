import { useEffect, useState, type FormEvent } from "react";
import { AlertTriangle, Fingerprint, KeyRound, Lock, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { e2eeSession, useE2eeSession } from "@/lib/e2ee";

const MIN_PASSPHRASE_LENGTH = 8;

export const E2eeSetupDialog = ({
  open,
  onOpenChange,
  onConfigured,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfigured?: () => void;
}) => {
  const { t } = useTranslation();
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setPassphrase("");
      setConfirmPassphrase("");
      setAcknowledged(false);
      setError(null);
      setSubmitting(false);
    }
  }, [open]);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
      setError(t("e2ee.passphraseTooShort"));
      return;
    }
    if (passphrase !== confirmPassphrase) {
      setError(t("e2ee.passphraseMismatch"));
      return;
    }
    if (!acknowledged) {
      setError(t("e2ee.mustAcknowledge"));
      return;
    }
    setSubmitting(true);
    try {
      await e2eeSession.initializePassphrase(passphrase, api.putE2eeKeyring);
      onOpenChange(false);
      onConfigured?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("e2ee.wrongPassphrase"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(next) => { if (!submitting) onOpenChange(next); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-slate-700" />
            {t("e2ee.setupDialogTitle")}
          </DialogTitle>
          <DialogDescription>{t("e2ee.setupDialogDescription")}</DialogDescription>
        </DialogHeader>
        <form onSubmit={(event) => void handleSubmit(event)} className="grid gap-4">
          <div className="flex items-start gap-2.5 rounded-lg border border-amber-200 bg-amber-50/80 p-3 text-xs leading-5 text-amber-900 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-200">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{t("e2ee.noRecoveryWarning")}</span>
          </div>
          <label className="grid gap-1.5 text-xs font-medium text-slate-700">
            {t("e2ee.passphraseLabel")}
            <Input
              type="password"
              autoComplete="new-password"
              value={passphrase}
              placeholder={t("e2ee.passphrasePlaceholder")}
              disabled={submitting}
              onChange={(event) => setPassphrase(event.target.value)}
            />
          </label>
          <label className="grid gap-1.5 text-xs font-medium text-slate-700">
            {t("e2ee.confirmPassphraseLabel")}
            <Input
              type="password"
              autoComplete="new-password"
              value={confirmPassphrase}
              placeholder={t("e2ee.confirmPassphrasePlaceholder")}
              disabled={submitting}
              onChange={(event) => setConfirmPassphrase(event.target.value)}
            />
          </label>
          <label className="flex items-start gap-2 text-xs leading-5 text-slate-700">
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 shrink-0 accent-[var(--checkbox-on)]"
              checked={acknowledged}
              disabled={submitting}
              onChange={(event) => setAcknowledged(event.target.checked)}
            />
            <span>{t("e2ee.acknowledgeNoRecovery")}</span>
          </label>
          {error ? <p role="alert" className="text-xs text-rose-600">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={submitting} onClick={() => onOpenChange(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={submitting}>
              {submitting ? t("e2ee.saving") : t("e2ee.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export const E2eeUnlockDialog = ({
  open,
  onOpenChange,
  onUnlocked,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUnlocked?: () => void;
}) => {
  const { t } = useTranslation();
  const e2ee = useE2eeSession();
  const [passphrase, setPassphrase] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setPassphrase("");
      setError(null);
      setSubmitting(false);
      return;
    }
    let cancelled = false;
    void window.edgeeverDesktop?.e2eeBiometricStatus?.()
      .then((status) => {
        if (cancelled) return;
        const matches = Boolean(
          status.available
          && status.enabled
          && (!e2ee.keyring?.keyId || status.keyId === e2ee.keyring.keyId),
        );
        setBiometricAvailable(matches);
      })
      .catch(() => {
        if (!cancelled) setBiometricAvailable(false);
      });
    return () => { cancelled = true; };
  }, [e2ee.keyring?.keyId, open]);

  const handleBiometricUnlock = async () => {
    if (!window.edgeeverDesktop?.e2eeBiometricUnlock) return;
    setError(null);
    setSubmitting(true);
    try {
      const unlocked = await window.edgeeverDesktop.e2eeBiometricUnlock({
        expectedKeyId: e2ee.keyring?.keyId,
        reason: t("e2ee.touchIdReasonUnlock"),
      });
      e2eeSession.unlockWithMasterKeyBase64(unlocked.keyId, unlocked.masterKeyBase64);
      onOpenChange(false);
      onUnlocked?.();
    } catch (err) {
      const code = (err as { code?: string } | null)?.code;
      if (code === "e2ee_biometric_key_mismatch" || code === "e2ee_biometric_stale") {
        setBiometricAvailable(false);
        setError(t("e2ee.touchIdMismatch"));
      } else {
        setError(t("e2ee.touchIdFailed"));
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!passphrase) return;
    setError(null);
    setSubmitting(true);
    try {
      await e2eeSession.unlockWithPassphrase(passphrase);
      onOpenChange(false);
      onUnlocked?.();
    } catch {
      setError(t("e2ee.wrongPassphrase"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(next) => { if (!submitting) onOpenChange(next); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-slate-700" />
            {t("e2ee.unlockDialogTitle")}
          </DialogTitle>
          <DialogDescription>{t("e2ee.unlockDialogDescription")}</DialogDescription>
        </DialogHeader>
        <form onSubmit={(event) => void handleSubmit(event)} className="grid gap-4">
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
          <label className="grid gap-1.5 text-xs font-medium text-slate-700">
            {t("e2ee.passphraseLabel")}
            <Input
              type="password"
              autoFocus={!biometricAvailable}
              autoComplete="current-password"
              value={passphrase}
              placeholder={t("e2ee.passphrasePlaceholder")}
              disabled={submitting}
              onChange={(event) => setPassphrase(event.target.value)}
            />
          </label>
          {error ? <p role="alert" className="text-xs text-rose-600">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={submitting} onClick={() => onOpenChange(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={submitting || !passphrase}>
              {submitting ? t("e2ee.saving") : t("e2ee.unlock")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export const E2eeChangePassphraseDialog = ({
  open,
  onOpenChange,
  onChanged,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onChanged?: () => void;
}) => {
  const { t } = useTranslation();
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setCurrentPassphrase("");
      setNewPassphrase("");
      setConfirmPassphrase("");
      setError(null);
      setSubmitting(false);
    }
  }, [open]);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (newPassphrase.length < MIN_PASSPHRASE_LENGTH) {
      setError(t("e2ee.passphraseTooShort"));
      return;
    }
    if (newPassphrase !== confirmPassphrase) {
      setError(t("e2ee.passphraseMismatch"));
      return;
    }
    setSubmitting(true);
    try {
      await e2eeSession.rotatePassphrase(currentPassphrase, newPassphrase, api.putE2eeKeyring);
      onOpenChange(false);
      onChanged?.();
    } catch {
      setError(t("e2ee.wrongPassphrase"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(next) => { if (!submitting) onOpenChange(next); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-slate-700" />
            {t("e2ee.changePassphraseTitle")}
          </DialogTitle>
          <DialogDescription>{t("e2ee.changePassphraseDescription")}</DialogDescription>
        </DialogHeader>
        <form onSubmit={(event) => void handleSubmit(event)} className="grid gap-4">
          <label className="grid gap-1.5 text-xs font-medium text-slate-700">
            {t("e2ee.currentPassphraseLabel")}
            <Input
              type="password"
              autoComplete="current-password"
              value={currentPassphrase}
              disabled={submitting}
              onChange={(event) => setCurrentPassphrase(event.target.value)}
            />
          </label>
          <label className="grid gap-1.5 text-xs font-medium text-slate-700">
            {t("e2ee.newPassphraseLabel")}
            <Input
              type="password"
              autoComplete="new-password"
              value={newPassphrase}
              placeholder={t("e2ee.passphrasePlaceholder")}
              disabled={submitting}
              onChange={(event) => setNewPassphrase(event.target.value)}
            />
          </label>
          <label className="grid gap-1.5 text-xs font-medium text-slate-700">
            {t("e2ee.confirmNewPassphraseLabel")}
            <Input
              type="password"
              autoComplete="new-password"
              value={confirmPassphrase}
              placeholder={t("e2ee.confirmPassphrasePlaceholder")}
              disabled={submitting}
              onChange={(event) => setConfirmPassphrase(event.target.value)}
            />
          </label>
          {error ? <p role="alert" className="text-xs text-rose-600">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={submitting} onClick={() => onOpenChange(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" disabled={submitting || !currentPassphrase || !newPassphrase}>
              {submitting ? t("e2ee.saving") : t("e2ee.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};
