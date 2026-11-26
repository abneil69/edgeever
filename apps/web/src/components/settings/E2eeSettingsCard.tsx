import { useEffect, useState } from "react";
import { CheckCircle2, Fingerprint, KeyRound, Lock, LockOpen, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import { e2eeSession, useE2eeSession, type E2eeAutoLockMinutes } from "@/lib/e2ee";
import {
  E2eeChangePassphraseDialog,
  E2eeSetupDialog,
  E2eeUnlockDialog,
} from "@/components/e2ee/E2eePassphraseDialogs";
import {
  SETTINGS_CARD_DESCRIPTION_CLASSNAME,
  SETTINGS_CARD_HEADER_CLASSNAME,
  SETTINGS_CARD_ICON_CLASSNAME,
  SETTINGS_CARD_TITLE_CLASSNAME,
} from "./settings-ui";

export const E2eeSettingsCard = ({ demoMode }: { demoMode: boolean }) => {
  const { t } = useTranslation();
  const e2ee = useE2eeSession();
  const [setupOpen, setSetupOpen] = useState(false);
  const [unlockOpen, setUnlockOpen] = useState(false);
  const [changeOpen, setChangeOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [biometricStatus, setBiometricStatus] = useState<{ available: boolean; enabled: boolean; keyId: string | null }>({
    available: false,
    enabled: false,
    keyId: null,
  });
  const [biometricBusy, setBiometricBusy] = useState(false);

  const loadBiometricStatus = async () => {
    try {
      const status = await window.edgeeverDesktop?.e2eeBiometricStatus?.();
      if (status) setBiometricStatus(status);
    } catch {
      setBiometricStatus({ available: false, enabled: false, keyId: null });
    }
  };

  useEffect(() => {
    if (!demoMode) {
      void e2eeSession.refreshKeyring(api.getE2eeKeyring).catch(() => undefined);
    }
    void loadBiometricStatus();
  }, [demoMode]);

  const handleToggleBiometric = async () => {
    setNotice(null);
    setError(null);
    if (!window.edgeeverDesktop?.e2eeBiometricEnable || !window.edgeeverDesktop?.e2eeBiometricDisable) return;
    setBiometricBusy(true);
    try {
      if (biometricStatus.enabled) {
        const next = await window.edgeeverDesktop.e2eeBiometricDisable();
        setBiometricStatus((current) => ({ ...current, enabled: next.enabled, keyId: next.keyId }));
        setNotice(t("e2ee.touchIdDisabled"));
      } else {
        if (!e2ee.unlocked) {
          setError(t("e2ee.touchIdNeedUnlockFirst"));
          setUnlockOpen(true);
          return;
        }
        const exported = e2eeSession.exportMasterKeyBase64ForBiometric();
        const next = await window.edgeeverDesktop.e2eeBiometricEnable({
          keyId: exported.keyId,
          masterKeyBase64: exported.masterKeyBase64,
          reason: t("e2ee.touchIdReasonEnable"),
        });
        setBiometricStatus((current) => ({ ...current, enabled: next.enabled, keyId: next.keyId }));
        setNotice(t("e2ee.touchIdEnabled"));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t("e2ee.touchIdFailed"));
    } finally {
      setBiometricBusy(false);
    }
  };

  const statusBadge = !e2ee.configured
    ? { label: t("e2ee.statusNotConfigured"), className: "border-slate-200 bg-slate-50 text-slate-600" }
    : e2ee.unlocked
      ? { label: t("e2ee.statusConfiguredUnlocked"), className: "border-emerald-200 bg-emerald-50 text-emerald-700" }
      : { label: t("e2ee.statusConfiguredLocked"), className: "border-amber-200 bg-amber-50 text-amber-800" };

  return (
    <>
      <Card className="w-full min-w-0 overflow-hidden shadow-none">
        <CardHeader className={SETTINGS_CARD_HEADER_CLASSNAME}>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0 space-y-1">
              <CardTitle className={SETTINGS_CARD_TITLE_CLASSNAME}>
                <ShieldCheck className={SETTINGS_CARD_ICON_CLASSNAME} />
                <span>{t("e2ee.title")}</span>
                <span className={`ml-1 inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${statusBadge.className}`}>
                  {statusBadge.label}
                </span>
              </CardTitle>
              <CardDescription className={SETTINGS_CARD_DESCRIPTION_CLASSNAME}>
                {demoMode ? t("e2ee.demoUnsupported") : t("e2ee.description")}
              </CardDescription>
            </div>
            {!demoMode ? (
              <div className="flex shrink-0 flex-wrap items-center gap-2">
                {!e2ee.configured ? (
                  <Button size="sm" variant="outline" className="text-xs font-normal" type="button" onClick={() => setSetupOpen(true)}>
                    <Lock className="h-4 w-4" />
                    {t("e2ee.setupButton")}
                  </Button>
                ) : (
                  <>
                    {e2ee.unlocked ? (
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-xs font-normal"
                        type="button"
                        onClick={() => void e2eeSession.lock("manual")}
                      >
                        <Lock className="h-4 w-4" />
                        {t("e2ee.lockNowButton")}
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-xs font-normal"
                        type="button"
                        onClick={() => setUnlockOpen(true)}
                      >
                        <LockOpen className="h-4 w-4" />
                        {t("e2ee.unlockButton")}
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-xs font-normal"
                      type="button"
                      onClick={() => setChangeOpen(true)}
                    >
                      <KeyRound className="h-4 w-4" />
                      {t("e2ee.changePassphraseButton")}
                    </Button>
                  </>
                )}
              </div>
            ) : null}
          </div>
        </CardHeader>

        {!demoMode && e2ee.configured ? (
          <CardContent className="grid gap-4 p-4 pt-0 sm:px-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <span className="text-xs font-medium text-slate-700">{t("e2ee.autoLockLabel")}</span>
              <Select
                value={String(e2ee.autoLockMinutes)}
                onValueChange={(value) => e2eeSession.setAutoLockMinutes(Number(value) as E2eeAutoLockMinutes)}
              >
                <SelectTrigger className="h-8 w-40 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="5">{t("e2ee.autoLock5")}</SelectItem>
                  <SelectItem value="15">{t("e2ee.autoLock15")}</SelectItem>
                  <SelectItem value="30">{t("e2ee.autoLock30")}</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {biometricStatus.available ? (
              <div className="flex flex-col gap-2 border-t border-slate-100 pt-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0 space-y-0.5">
                  <div className="flex items-center gap-1.5 text-xs font-medium text-slate-800">
                    <Fingerprint className="h-4 w-4 text-slate-500" />
                    <span>{t("e2ee.touchIdLabel")}</span>
                  </div>
                  <p className="text-xs leading-5 text-slate-500">{t("e2ee.touchIdDescription")}</p>
                </div>
                <Button
                  size="sm"
                  variant={biometricStatus.enabled ? "soft" : "outline"}
                  type="button"
                  disabled={biometricBusy}
                  onClick={() => void handleToggleBiometric()}
                  className="shrink-0 text-xs font-normal"
                >
                  {biometricStatus.enabled ? t("common.disable") : t("common.enable")}
                </Button>
              </div>
            ) : null}

            {notice ? (
              <p className="flex items-center gap-1.5 text-xs text-emerald-700">
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                {notice}
              </p>
            ) : null}
            {error ? (
              <p role="alert" className="text-xs text-rose-600">
                {error}
              </p>
            ) : null}
          </CardContent>
        ) : null}
      </Card>

      <E2eeSetupDialog
        open={setupOpen}
        onOpenChange={setSetupOpen}
        onConfigured={() => {
          setNotice(t("e2ee.setupSuccess"));
          setError(null);
        }}
      />
      <E2eeUnlockDialog
        open={unlockOpen}
        onOpenChange={setUnlockOpen}
        onUnlocked={() => {
          setError(null);
        }}
      />
      <E2eeChangePassphraseDialog
        open={changeOpen}
        onOpenChange={setChangeOpen}
        onChanged={() => {
          setNotice(t("e2ee.changePassphraseSuccess"));
          setError(null);
        }}
      />
    </>
  );
};
