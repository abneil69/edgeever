import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { createReadStream, createWriteStream } from "node:fs";
import { access, chmod, constants, mkdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { spawn } from "node:child_process";

const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA256_DIGEST_PATTERN = /^sha256:([0-9a-f]{64})$/i;
const FORK_VERSION_PATTERN = /^v?(\d+)\.(\d+)\.(\d+)(?:-([a-z0-9-]+?)(?:\.(\d+))?)?$/i;

export const parseForkVersion = (raw) => {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  const match = trimmed.match(FORK_VERSION_PATTERN);
  if (!match) return null;
  const [, major, minor, patch, channel = "", revision = ""] = match;
  return {
    raw: trimmed,
    normalized: trimmed.replace(/^v/i, ""),
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch),
    channel: channel.toLowerCase(),
    revision: revision ? Number(revision) : (channel ? 1 : 0),
  };
};

export const isNewerForkVersion = (candidateRaw, currentRaw) => {
  const candidate = parseForkVersion(candidateRaw);
  const current = parseForkVersion(currentRaw);
  if (!candidate || !current) return false;
  if (candidate.major !== current.major) return candidate.major > current.major;
  if (candidate.minor !== current.minor) return candidate.minor > current.minor;
  if (candidate.patch !== current.patch) return candidate.patch > current.patch;
  if (candidate.revision !== current.revision) return candidate.revision > current.revision;
  return false;
};

export const selectMacDmgAsset = (release, { repo, arch }) => {
  if (!release || typeof release !== "object" || !Array.isArray(release.assets)) return null;
  const suffix = arch === "x64" ? "-mac-x64.dmg" : "-mac-arm64.dmg";
  const prefix = `https://github.com/${repo}/releases/download/`;
  for (const asset of release.assets) {
    if (!asset || typeof asset !== "object") continue;
    if (typeof asset.name !== "string" || !asset.name.toLowerCase().endsWith(suffix)) continue;
    if (typeof asset.browser_download_url !== "string" || !asset.browser_download_url.startsWith(prefix)) continue;
    const digestMatch = typeof asset.digest === "string" ? asset.digest.trim().match(SHA256_DIGEST_PATTERN) : null;
    if (!digestMatch) {
      throw new Error(`Release asset ${asset.name} is missing a SHA-256 digest`);
    }
    return {
      name: asset.name,
      size: typeof asset.size === "number" && Number.isFinite(asset.size) ? asset.size : 0,
      downloadUrl: asset.browser_download_url,
      sha256: digestMatch[1].toLowerCase(),
    };
  }
  return null;
};

export const resolveMacAppBundlePath = (execPath) => {
  if (typeof execPath !== "string") return null;
  const marker = ".app/Contents/MacOS/";
  const index = execPath.indexOf(marker);
  if (index <= 0) return null;
  return execPath.slice(0, index + 4);
};

export const validateMacAppBundleForUpdate = async (appBundlePath) => {
  if (!appBundlePath || !appBundlePath.endsWith(".app")) {
    throw new Error("Unable to locate the running EdgeEver.app bundle for self-update");
  }
  if (appBundlePath.startsWith("/Volumes/") || appBundlePath.includes("/AppTranslocation/")) {
    throw new Error("Move EdgeEver.app to /Applications before installing updates");
  }
  const details = await stat(appBundlePath).catch(() => null);
  if (!details?.isDirectory()) {
    throw new Error("Running EdgeEver.app bundle path does not exist");
  }
  await access(dirname(appBundlePath), constants.W_OK).catch(() => {
    throw new Error(`No write permission to update ${appBundlePath}`);
  });
  return appBundlePath;
};

export const computeFileSha256 = (filePath) => new Promise((resolve, reject) => {
  const hash = createHash("sha256");
  const stream = createReadStream(filePath);
  stream.on("data", (chunk) => hash.update(chunk));
  stream.on("error", reject);
  stream.on("end", () => resolve(hash.digest("hex")));
});

const MAC_INSTALLER_SCRIPT = `#!/bin/sh
set -eu

PID="$1"
DMG_PATH="$2"
TARGET_APP="$3"
RELAUNCH="$4"
SCRIPT_PATH="$5"

# Wait for the running Electron app to exit cleanly.
i=0
while [ "$i" -lt 60 ]; do
  if ! kill -0 "$PID" 2>/dev/null; then
    break
  fi
  sleep 0.5
  i=$((i + 1))
done

MOUNT_DIR="$(mktemp -d /tmp/edgeever-update-XXXXXX)"
NEW_APP="\${TARGET_APP}.updating"
BACKUP_APP="\${TARGET_APP}.previous"

cleanup() {
  if [ -d "$MOUNT_DIR" ]; then
    hdiutil detach "$MOUNT_DIR" -force >/dev/null 2>&1 || true
    rmdir "$MOUNT_DIR" >/dev/null 2>&1 || true
  fi
  rm -rf "$NEW_APP" >/dev/null 2>&1 || true
  rm -f "$SCRIPT_PATH" >/dev/null 2>&1 || true
}
trap cleanup EXIT

hdiutil attach "$DMG_PATH" -nobrowse -readonly -mountpoint "$MOUNT_DIR" >/dev/null

APP_NAME="$(basename "$TARGET_APP")"
SRC_APP="$MOUNT_DIR/$APP_NAME"
if [ ! -d "$SRC_APP" ]; then
  SRC_APP="$(find "$MOUNT_DIR" -maxdepth 1 -name '*.app' -print -quit)"
fi
if [ -z "$SRC_APP" ] || [ ! -x "$SRC_APP/Contents/MacOS/EdgeEver" ]; then
  exit 1
fi

rm -rf "$NEW_APP" "$BACKUP_APP"
ditto "$SRC_APP" "$NEW_APP"
xattr -dr com.apple.quarantine "$NEW_APP" >/dev/null 2>&1 || true

mv "$TARGET_APP" "$BACKUP_APP"
if mv "$NEW_APP" "$TARGET_APP"; then
  rm -rf "$BACKUP_APP"
else
  mv "$BACKUP_APP" "$TARGET_APP" >/dev/null 2>&1 || true
  exit 1
fi

hdiutil detach "$MOUNT_DIR" -force >/dev/null 2>&1 || true
rmdir "$MOUNT_DIR" >/dev/null 2>&1 || true

if [ "$RELAUNCH" = "1" ]; then
  open -n "$TARGET_APP" >/dev/null 2>&1 || open "$TARGET_APP" >/dev/null 2>&1 || true
fi
`;

export const spawnMacDmgInstaller = async ({
  pid = process.pid,
  dmgPath,
  targetAppPath,
  relaunch = true,
  spawnImpl = spawn,
  tempDir = tmpdir(),
}) => {
  const scriptPath = join(tempDir, `edgeever-install-${Date.now()}-${Math.random().toString(16).slice(2, 10)}.sh`);
  await writeFile(scriptPath, MAC_INSTALLER_SCRIPT, { encoding: "utf8", mode: 0o700 });
  await chmod(scriptPath, 0o700);
  const child = spawnImpl("/bin/sh", [
    scriptPath,
    String(pid),
    dmgPath,
    targetAppPath,
    relaunch ? "1" : "0",
    scriptPath,
  ], {
    detached: true,
    stdio: "ignore",
  });
  child.unref?.();
  return { scriptPath };
};

export const createForkMacUpdater = ({
  repo,
  currentVersion,
  arch = process.arch,
  cacheDir,
  execPath = process.execPath,
  fetchImpl,
  quitApplication = () => {},
  installDmg = spawnMacDmgInstaller,
  userAgent = "EdgeEver-Desktop-Updater",
}) => {
  if (typeof repo !== "string" || !REPO_PATTERN.test(repo)) {
    throw new Error(`Invalid GitHub repository for fork updater: ${repo}`);
  }

  const updater = new EventEmitter();
  updater.autoDownload = false;
  updater.autoInstallOnAppQuit = false;
  updater.autoRunAppAfterInstall = true;
  updater.downloadedUpdateHelper = null;

  const nativeUpdater = new EventEmitter();
  let selectedRelease = null;
  let stagedFilePath = null;
  let stagedSha256 = null;
  let validatedTargetAppPath = null;

  updater.checkForUpdates = async () => {
    const apiUrl = `https://api.github.com/repos/${repo}/releases/latest`;
    const response = await fetchImpl(apiUrl, {
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": userAgent,
      },
    });
    if (!response.ok) {
      throw new Error(`Failed to check fork releases (HTTP ${response.status})`);
    }
    const release = await response.json();
    const tagName = typeof release?.tag_name === "string" ? release.tag_name.trim() : "";
    if (!tagName) {
      return { isUpdateAvailable: false, updateInfo: null };
    }
    const normalizedVersion = tagName.replace(/^v/i, "");
    if (!isNewerForkVersion(tagName, currentVersion)) {
      selectedRelease = null;
      return { isUpdateAvailable: false, updateInfo: { version: normalizedVersion } };
    }
    const asset = selectMacDmgAsset(release, { repo, arch });
    if (!asset) {
      selectedRelease = null;
      return { isUpdateAvailable: false, updateInfo: { version: normalizedVersion } };
    }
    selectedRelease = {
      tagName,
      version: normalizedVersion,
      asset,
    };
    return {
      isUpdateAvailable: true,
      updateInfo: {
        version: normalizedVersion,
        tagName,
        sha256: asset.sha256,
        assetName: asset.name,
        size: asset.size,
      },
    };
  };

  updater.downloadUpdate = async () => {
    const candidate = selectedRelease;
    if (!candidate) {
      throw new Error("No fork update release selected for download");
    }
    const updatesDir = join(cacheDir, "fork-updates");
    await mkdir(updatesDir, { recursive: true, mode: 0o700 });
    const safeName = basename(candidate.asset.name).replace(/[^A-Za-z0-9._-]/g, "_");
    const finalPath = join(updatesDir, `${candidate.tagName.replace(/[^A-Za-z0-9._-]/g, "_")}-${safeName}`);
    const partPath = `${finalPath}.part`;

    // Reuse an already-downloaded DMG if its SHA-256 matches the release digest.
    const existingStats = await stat(finalPath).catch(() => null);
    if (existingStats?.isFile()) {
      const existingHash = await computeFileSha256(finalPath).catch(() => null);
      if (existingHash === candidate.asset.sha256) {
        stagedFilePath = finalPath;
        stagedSha256 = candidate.asset.sha256;
        updater.downloadedUpdateHelper = { file: finalPath };
        updater.emit("update-downloaded", {
          version: candidate.version,
          downloadedFile: finalPath,
        });
        return [finalPath];
      }
      await unlink(finalPath).catch(() => undefined);
    }

    const response = await fetchImpl(candidate.asset.downloadUrl, {
      headers: { "User-Agent": userAgent },
    });
    if (!response.ok || !response.body) {
      throw new Error(`Failed to download update DMG (HTTP ${response.status})`);
    }

    const headerLength = Number(response.headers?.get?.("content-length") ?? 0);
    const total = Number.isFinite(headerLength) && headerLength > 0 ? headerLength : candidate.asset.size;
    const hash = createHash("sha256");
    const writer = createWriteStream(partPath, { mode: 0o600 });
    let transferred = 0;
    const startedAt = Date.now();
    let lastEmitAt = 0;

    try {
      const reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        const chunk = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
        hash.update(chunk);
        if (!writer.write(chunk)) {
          await new Promise((resolve, reject) => {
            writer.once("drain", resolve);
            writer.once("error", reject);
          });
        }
        transferred += chunk.byteLength;
        const now = Date.now();
        if (now - lastEmitAt >= 150) {
          lastEmitAt = now;
          const elapsedSec = Math.max(0.001, (now - startedAt) / 1000);
          const rawPercent = total > 0 ? Math.floor((transferred / total) * 100) : 0;
          updater.emit("download-progress", {
            percent: Math.min(99, rawPercent),
            transferred,
            total: total || transferred,
            bytesPerSecond: Math.round(transferred / elapsedSec),
          });
        }
      }
      await new Promise((resolve, reject) => {
        writer.once("finish", resolve);
        writer.once("error", reject);
        writer.end();
      });

      const elapsedSec = Math.max(0.001, (Date.now() - startedAt) / 1000);
      updater.emit("download-progress", {
        percent: 100,
        transferred,
        total: total || transferred,
        bytesPerSecond: Math.round(transferred / elapsedSec),
      });

      const actualSha256 = hash.digest("hex");
      if (actualSha256 !== candidate.asset.sha256) {
        throw new Error(`Downloaded DMG SHA-256 mismatch: expected ${candidate.asset.sha256}, got ${actualSha256}`);
      }
      await rename(partPath, finalPath);
      stagedFilePath = finalPath;
      stagedSha256 = actualSha256;
      updater.downloadedUpdateHelper = { file: finalPath };
      updater.emit("update-downloaded", {
        version: candidate.version,
        downloadedFile: finalPath,
      });
      return [finalPath];
    } catch (error) {
      writer.destroy();
      await unlink(partPath).catch(() => undefined);
      throw error;
    }
  };

  nativeUpdater.getFeedURL = () => (stagedFilePath ? `file://${stagedFilePath}` : "");

  nativeUpdater.checkForUpdates = () => {
    void (async () => {
      try {
        if (!stagedFilePath || !stagedSha256) {
          throw new Error("No verified DMG update is staged for installation");
        }
        const actualHash = await computeFileSha256(stagedFilePath);
        if (actualHash !== stagedSha256) {
          throw new Error("Staged update DMG failed integrity verification before install");
        }
        const appPath = resolveMacAppBundlePath(execPath);
        validatedTargetAppPath = await validateMacAppBundleForUpdate(appPath);
        nativeUpdater.emit("update-downloaded");
      } catch (error) {
        nativeUpdater.emit("error", error instanceof Error ? error : new Error(String(error)));
      }
    })();
  };

  nativeUpdater.quitAndInstall = () => {
    if (!stagedFilePath || !validatedTargetAppPath) {
      nativeUpdater.emit("error", new Error("Update installer was not prepared"));
      return;
    }
    void installDmg({
      pid: process.pid,
      dmgPath: stagedFilePath,
      targetAppPath: validatedTargetAppPath,
      relaunch: updater.autoRunAppAfterInstall !== false,
    }).then(() => {
      quitApplication();
    }).catch((error) => {
      nativeUpdater.emit("error", error instanceof Error ? error : new Error(String(error)));
    });
  };

  return { updater, nativeUpdater };
};
