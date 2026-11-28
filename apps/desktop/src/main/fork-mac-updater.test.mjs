import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { createDesktopUpdateController } from "./desktop-update-controller.mjs";
import {
  createForkMacUpdater,
  isNewerForkVersion,
  parseForkVersion,
  resolveMacAppBundlePath,
  selectMacDmgAsset,
  validateMacAppBundleForUpdate,
} from "./fork-mac-updater.mjs";

const streamFromBytes = (bytes) => new ReadableStream({
  start(controller) {
    controller.enqueue(bytes);
    controller.close();
  },
});

const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

describe("fork macOS updater", () => {
  test("compares custom fork release tags and upstream semver versions accurately", () => {
    expect(parseForkVersion("v2.34.0-e2ee.2")).toMatchObject({
      major: 2,
      minor: 34,
      patch: 0,
      channel: "e2ee",
      revision: 2,
    });
    expect(isNewerForkVersion("v2.34.0-e2ee.2", "v2.34.0-e2ee.1")).toBe(true);
    expect(isNewerForkVersion("v2.34.0-e2ee.10", "v2.34.0-e2ee.2")).toBe(true);
    expect(isNewerForkVersion("v2.34.0-e2ee.2", "2.34.0")).toBe(true);
    expect(isNewerForkVersion("v2.35.0-e2ee.1", "v2.34.0-e2ee.9")).toBe(true);
    expect(isNewerForkVersion("v2.34.0-e2ee.2", "v2.34.0-e2ee.2")).toBe(false);
    expect(isNewerForkVersion("v2.34.0-e2ee.1", "v2.34.0-e2ee.2")).toBe(false);
    expect(isNewerForkVersion("v2.33.0-e2ee.5", "v2.34.0-e2ee.1")).toBe(false);
  });

  test("selects matching arch DMG asset and requires SHA-256 digest", () => {
    const digest = `sha256:${"a".repeat(64)}`;
    const release = {
      tag_name: "v2.34.0-e2ee.3",
      assets: [
        {
          name: "edgeever-android-v2.34.0-arm64-v8a.apk",
          size: 100,
          digest,
          browser_download_url: "https://github.com/abneil69/edgeever/releases/download/v2.34.0-e2ee.3/edgeever-android-v2.34.0-arm64-v8a.apk",
        },
        {
          name: "EdgeEver-2.34.0-mac-arm64.dmg",
          size: 200,
          digest,
          browser_download_url: "https://github.com/abneil69/edgeever/releases/download/v2.34.0-e2ee.3/EdgeEver-2.34.0-mac-arm64.dmg",
        },
      ],
    };
    expect(selectMacDmgAsset(release, { repo: "abneil69/edgeever", arch: "arm64" })).toMatchObject({
      name: "EdgeEver-2.34.0-mac-arm64.dmg",
      sha256: "a".repeat(64),
    });
    expect(selectMacDmgAsset(release, { repo: "abneil69/edgeever", arch: "x64" })).toBeNull();

    const missingDigest = {
      ...release,
      assets: [{ ...release.assets[1], digest: null }],
    };
    expect(() => selectMacDmgAsset(missingDigest, { repo: "abneil69/edgeever", arch: "arm64" }))
      .toThrow(/SHA-256 digest/);
  });

  test("resolves and validates macOS .app bundle paths and rejects mounted volumes", async () => {
    expect(resolveMacAppBundlePath("/Applications/EdgeEver.app/Contents/MacOS/EdgeEver"))
      .toBe("/Applications/EdgeEver.app");
    expect(resolveMacAppBundlePath("/usr/local/bin/node")).toBeNull();
    await expect(validateMacAppBundleForUpdate("/Volumes/EdgeEver/EdgeEver.app"))
      .rejects.toThrow(/Move EdgeEver\.app to \/Applications/);
  });

  test("integrates with createDesktopUpdateController to check, download, verify SHA-256, and install", async () => {
    const workDir = await mkdtemp(join(tmpdir(), "edgeever-fork-updater-"));
    try {
      const fakeApp = join(workDir, "EdgeEver.app");
      await mkdir(join(fakeApp, "Contents", "MacOS"), { recursive: true });
      const fakeExec = join(fakeApp, "Contents", "MacOS", "EdgeEver");
      await writeFile(fakeExec, "");

      const dmgBytes = Buffer.from("fake-dmg-payload-v2.34.0-e2ee.3");
      const dmgSha256 = sha256Hex(dmgBytes);
      const releasePayload = {
        tag_name: "v2.34.0-e2ee.3",
        assets: [
          {
            name: "EdgeEver-2.34.0-mac-arm64.dmg",
            size: dmgBytes.byteLength,
            digest: `sha256:${dmgSha256}`,
            browser_download_url: "https://github.com/abneil69/edgeever/releases/download/v2.34.0-e2ee.3/EdgeEver-2.34.0-mac-arm64.dmg",
          },
        ],
      };

      const fetchImpl = async (url) => {
        if (url === "https://api.github.com/repos/abneil69/edgeever/releases/latest") {
          return new Response(JSON.stringify(releasePayload), { status: 200 });
        }
        if (url === releasePayload.assets[0].browser_download_url) {
          return new Response(streamFromBytes(dmgBytes), {
            status: 200,
            headers: { "content-length": String(dmgBytes.byteLength) },
          });
        }
        return new Response("not found", { status: 404 });
      };

      let installedArgs = null;
      let quitCalled = false;
      const statuses = [];
      const errors = [];

      const { updater, nativeUpdater } = createForkMacUpdater({
        repo: "abneil69/edgeever",
        currentVersion: "v2.34.0-e2ee.2",
        arch: "arm64",
        cacheDir: join(workDir, "cache"),
        execPath: fakeExec,
        fetchImpl,
        quitApplication: () => { quitCalled = true; },
        installDmg: async (args) => { installedArgs = args; },
      });

      let downloadedVersion = null;
      const controller = createDesktopUpdateController({
        updater,
        platform: "darwin",
        nativeUpdater,
        quitApplication: () => { quitCalled = true; },
        onStatus: (s) => statuses.push(s),
        onError: (e, stage) => errors.push({ message: e.message, stage }),
        onDownloaded: (v) => { downloadedVersion = v; },
        beforeInstall: () => {},
      });

      await controller.check("manual");
      // Wait for automatic download triggered by controller.check().
      for (let i = 0; i < 40 && !downloadedVersion; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }

      expect(errors).toEqual([]);
      expect(downloadedVersion).toBe("2.34.0-e2ee.3");
      expect(statuses.at(-1)).toMatchObject({ state: "downloaded", version: "2.34.0-e2ee.3" });

      const installResult = await controller.install("2.34.0-e2ee.3");
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(installResult).toEqual({ started: true });
      expect(installedArgs).toMatchObject({
        targetAppPath: fakeApp,
        relaunch: true,
      });
      expect(quitCalled).toBe(true);
    } finally {
      await rm(workDir, { recursive: true, force: true });
    }
  });

  test("rejects tampered DMG whose SHA-256 does not match the release digest", async () => {
    const workDir = await mkdtemp(join(tmpdir(), "edgeever-fork-updater-bad-"));
    try {
      const releasePayload = {
        tag_name: "v2.34.0-e2ee.3",
        assets: [
          {
            name: "EdgeEver-2.34.0-mac-arm64.dmg",
            size: 16,
            digest: `sha256:${"f".repeat(64)}`,
            browser_download_url: "https://github.com/abneil69/edgeever/releases/download/v2.34.0-e2ee.3/EdgeEver-2.34.0-mac-arm64.dmg",
          },
        ],
      };
      const { updater } = createForkMacUpdater({
        repo: "abneil69/edgeever",
        currentVersion: "v2.34.0-e2ee.2",
        arch: "arm64",
        cacheDir: join(workDir, "cache"),
        fetchImpl: async (url) => {
          if (url.endsWith("/releases/latest")) {
            return new Response(JSON.stringify(releasePayload), { status: 200 });
          }
          return new Response(streamFromBytes(Buffer.from("tampered-payload")), { status: 200 });
        },
      });
      const check = await updater.checkForUpdates();
      expect(check.isUpdateAvailable).toBe(true);
      await expect(updater.downloadUpdate()).rejects.toThrow(/SHA-256 mismatch/);
    } finally {
      await rm(workDir, { recursive: true, force: true });
    }
  });
});
