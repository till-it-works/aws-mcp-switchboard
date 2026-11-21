/**
 * KMS envelope sealing for all client/browser-held state.
 *
 * blob = "asb1." + b64url(edk) + "." + b64url(iv12) + "." + b64url(ciphertext || tag16)
 * AES-256-GCM, AAD = typ + "|" + aud. One data key per container, rotated after 1 h or 10k seals.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { DecryptCommand, GenerateDataKeyCommand, type KMSClient } from "@aws-sdk/client-kms";
import { LruCache } from "./cache.js";

export type BlobType = "cl" | "pd" | "ac" | "at" | "rt" | "tk";

export interface Sealer {
  seal(typ: BlobType, aud: string, payload: object): Promise<string>;
  /** Returns the payload, or null for any failure (malformed, wrong typ/aud, tampered, expired, KMS error). */
  unseal<T extends object = Record<string, unknown>>(typ: BlobType, aud: string, blob: string): Promise<T | null>;
}

const PREFIX = "asb1";
const ENCRYPTION_CONTEXT = { app: "aws-mcp-switchboard" };
const KEY_MAX_AGE_MS = 3_600_000;
const KEY_MAX_SEALS = 10_000;

interface DataKey {
  plain: Buffer;
  edk: Buffer;
  createdAt: number;
  seals: number;
}

const b64u = (b: Buffer) => b.toString("base64url");
const keyId = (edk: Buffer) => createHash("sha256").update(edk).digest("base64url");

export function emitUnsealFailure(typ: BlobType): void {
  console.log(
    JSON.stringify({
      _aws: {
        Timestamp: Date.now(),
        CloudWatchMetrics: [
          { Namespace: "AwsMcpSwitchboard", Dimensions: [["typ"]], Metrics: [{ Name: "UnsealFailure", Unit: "Count" }] },
        ],
      },
      typ,
      UnsealFailure: 1,
    }),
  );
}

export function createSealer(opts: { kms: KMSClient; keyArn: string; now?: () => number }): Sealer {
  const now = opts.now ?? Date.now;
  const plainKeys = new LruCache<Buffer>({ max: 1000, ttlMs: KEY_MAX_AGE_MS, now });
  let current: DataKey | undefined;
  let pending: Promise<DataKey> | undefined;

  async function dataKey(): Promise<DataKey> {
    if (current && current.seals < KEY_MAX_SEALS && now() - current.createdAt < KEY_MAX_AGE_MS) return current;
    pending ??= (async () => {
      const r = await opts.kms.send(
        new GenerateDataKeyCommand({ KeyId: opts.keyArn, KeySpec: "AES_256", EncryptionContext: ENCRYPTION_CONTEXT }),
      );
      const k: DataKey = { plain: Buffer.from(r.Plaintext!), edk: Buffer.from(r.CiphertextBlob!), createdAt: now(), seals: 0 };
      plainKeys.set(keyId(k.edk), k.plain);
      current = k;
      return k;
    })().finally(() => {
      pending = undefined;
    });
    return pending;
  }

  async function plainKeyFor(edk: Buffer): Promise<Buffer> {
    const id = keyId(edk);
    const hit = plainKeys.get(id);
    if (hit) return hit;
    const r = await opts.kms.send(
      new DecryptCommand({ CiphertextBlob: edk, KeyId: opts.keyArn, EncryptionContext: ENCRYPTION_CONTEXT }),
    );
    const plain = Buffer.from(r.Plaintext!);
    plainKeys.set(id, plain);
    return plain;
  }

  return {
    async seal(typ, aud, payload) {
      const k = await dataKey();
      k.seals++;
      const iv = randomBytes(12);
      const c = createCipheriv("aes-256-gcm", k.plain, iv);
      c.setAAD(Buffer.from(`${typ}|${aud}`));
      const ct = Buffer.concat([c.update(JSON.stringify(payload), "utf8"), c.final(), c.getAuthTag()]);
      return `${PREFIX}.${b64u(k.edk)}.${b64u(iv)}.${b64u(ct)}`;
    },

    async unseal<T extends object>(typ: BlobType, aud: string, blob: string): Promise<T | null> {
      try {
        const parts = blob.split(".");
        if (parts.length !== 4 || parts[0] !== PREFIX) throw new Error("format");
        const edk = Buffer.from(parts[1]!, "base64url");
        const iv = Buffer.from(parts[2]!, "base64url");
        const ct = Buffer.from(parts[3]!, "base64url");
        if (edk.length === 0 || iv.length !== 12 || ct.length < 17) throw new Error("format");
        const key = await plainKeyFor(edk);
        const d = createDecipheriv("aes-256-gcm", key, iv);
        d.setAAD(Buffer.from(`${typ}|${aud}`));
        d.setAuthTag(ct.subarray(ct.length - 16));
        const json = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString("utf8");
        const payload = JSON.parse(json) as unknown;
        if (typeof payload !== "object" || payload === null || Array.isArray(payload)) throw new Error("payload");
        const exp = (payload as { exp?: unknown }).exp;
        if (typeof exp === "number" && exp * 1000 <= now()) throw new Error("expired");
        return payload as T;
      } catch {
        emitUnsealFailure(typ);
        return null;
      }
    },
  };
}
