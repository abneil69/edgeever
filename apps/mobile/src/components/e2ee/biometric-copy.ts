export type MobileBiometricCopy = {
  label: string;
  description: string;
  unlockButton: string;
  promptReason: string;
  enabled: string;
  disabled: string;
  failed: string;
};

export const getMobileBiometricCopy = (locale: string): MobileBiometricCopy => {
  if (locale === "zh-TW") {
    return {
      label: "使用生物辨識快速解鎖",
      description: "將工作區主金鑰加密儲存在裝置安全區中，每次解鎖仍需通過生物辨識驗證。",
      unlockButton: "使用生物辨識解鎖",
      promptReason: "驗證身份以解鎖 EdgeEver 加密筆記",
      enabled: "已開啟生物辨識快速解鎖。",
      disabled: "已關閉生物辨識快速解鎖。",
      failed: "生物辨識驗證未通過，請改用主密碼解鎖。",
    };
  }
  if (locale.startsWith("zh")) {
    return {
      label: "使用生物识别快捷解锁",
      description: "将工作区主密钥加密保存在系统安全存储中，每次解锁仍需通过指纹或面容验证。",
      unlockButton: "使用生物识别解锁",
      promptReason: "验证身份以解锁 EdgeEver 加密笔记",
      enabled: "已开启生物识别快捷解锁。",
      disabled: "已关闭生物识别快捷解锁。",
      failed: "生物识别验证未通过，请改用主密码解锁。",
    };
  }
  return {
    label: "Unlock with Biometrics",
    description: "Store the workspace master key in system secure storage. Biometric authentication is required on every unlock.",
    unlockButton: "Unlock with Biometrics",
    promptReason: "Authenticate to unlock EdgeEver encrypted notes",
    enabled: "Biometric unlock enabled.",
    disabled: "Biometric unlock disabled.",
    failed: "Biometric verification failed. Please unlock with your master passphrase.",
  };
};
