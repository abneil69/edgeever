import { describe, expect, test } from "bun:test";
import { createEdgeEverClient } from "./index.ts";
import { encodeBase64 } from "@edgeever/shared";

describe("EdgeEverClient E2EE keyring SDK", () => {
  test("getE2eeKeyring, putE2eeKeyring, getBackupE2eeKeyring, and restoreJsonE2eeKeyring call expected endpoints", async () => {
    const calls = [];
    const payload = {
      keyId: "ek_0123456789abcdef",
      kdfAlgorithm: "PBKDF2-SHA256",
      kdfSalt: encodeBase64(new Uint8Array(16).fill(1)),
      kdfIterations: 600_000,
      wrappedMasterKey: encodeBase64(new Uint8Array(48).fill(2)),
      masterKeyIv: encodeBase64(new Uint8Array(12).fill(3)),
    };
    const keyring = {
      ...payload,
      revision: 1,
      createdAt: "2026-11-26T00:00:00.000Z",
      updatedAt: "2026-11-26T00:00:00.000Z",
    };
    const stored = { configured: true, keyring };

    const client = createEdgeEverClient({
      baseUrl: "https://notes.example.test",
      fetch: async (url, init) => {
        const href = String(url);
        const method = init?.method ?? "GET";
        calls.push({ url: href, method, body: init?.body });
        if (href.endsWith("/api/v1/e2ee/keyring") && method === "GET") {
          return Response.json({ configured: false, keyring: null });
        }
        if (href.endsWith("/api/v1/e2ee/keyring") && method === "PUT") {
          return Response.json(stored, { status: 201 });
        }
        if (href.includes("/api/v1/backups/data?")) {
          return Response.json({ e2eeKeyring: keyring, nextCursor: null });
        }
        if (href.endsWith("/api/v1/restores/json/e2ee-keyring")) {
          return Response.json({ ok: true, e2eeKeyring: keyring });
        }
        throw new Error(`Unexpected fetch: ${method} ${href}`);
      },
    });

    expect(await client.getE2eeKeyring()).toEqual({ configured: false, keyring: null });
    expect(await client.putE2eeKeyring(payload)).toEqual(stored);
    expect(await client.getBackupE2eeKeyring({ identity: "2026-11-26T00:00:00.000Z", revision: "42" })).toEqual({
      e2eeKeyring: keyring,
      nextCursor: null,
    });
    expect(await client.restoreJsonE2eeKeyring(keyring)).toEqual({ ok: true, e2eeKeyring: keyring });

    expect(calls).toEqual([
      { url: "https://notes.example.test/api/v1/e2ee/keyring", method: "GET", body: undefined },
      { url: "https://notes.example.test/api/v1/e2ee/keyring", method: "PUT", body: JSON.stringify(payload) },
      {
        url: "https://notes.example.test/api/v1/backups/data?kind=e2ee-keyring&identity=2026-11-26T00%3A00%3A00.000Z&revision=42",
        method: "GET",
        body: undefined,
      },
      {
        url: "https://notes.example.test/api/v1/restores/json/e2ee-keyring",
        method: "POST",
        body: JSON.stringify({ e2eeKeyring: keyring }),
      },
    ]);
  });
});
