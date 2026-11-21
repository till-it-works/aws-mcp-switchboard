import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { createSealer, type BlobType } from "../lambda/seal.js";

const KEY_ARN = "arn:aws:kms:eu-central-1:111122223333:key/test";
const AUD = "https://example.lambda-url.eu-central-1.on.aws/mcp";

// Fake KMS: "encrypts" a data key by prefixing a marker; Decrypt reverses it.
const kmsMock = mockClient(KMSClient);
function installFakeKms() {
  kmsMock.reset();
  kmsMock.on(GenerateDataKeyCommand).callsFake((input) => {
    expect(input.EncryptionContext).toEqual({ app: "aws-mcp-switchboard" });
    const plain = randomBytes(32);
    return { Plaintext: new Uint8Array(plain), CiphertextBlob: new Uint8Array(Buffer.concat([Buffer.from("EDK:"), plain])) };
  });
  kmsMock.on(DecryptCommand).callsFake((input) => {
    expect(input.EncryptionContext).toEqual({ app: "aws-mcp-switchboard" });
    const blob = Buffer.from(input.CiphertextBlob as Uint8Array);
    if (!blob.subarray(0, 4).equals(Buffer.from("EDK:"))) throw Object.assign(new Error("bad"), { name: "InvalidCiphertextException" });
    return { Plaintext: new Uint8Array(blob.subarray(4)) };
  });
}

let nowMs = Date.UTC(2026, 10, 20);
const now = () => nowMs;
const mk = () => createSealer({ kms: new KMSClient({ region: "eu-central-1" }), keyArn: KEY_ARN, now });

beforeEach(() => {
  installFakeKms();
  nowMs = Date.UTC(2026, 10, 20);
});
afterEach(() => vi.restoreAllMocks());

const TYPES: BlobType[] = ["cl", "pd", "ac", "at", "rt", "tk"];

describe("seal / unseal", () => {
  it.each(TYPES)("roundtrips typ=%s", async (typ) => {
    const s = mk();
    const payload = { a: 1, b: "x", exp: nowMs / 1000 + 60 };
    const blob = await s.seal(typ, AUD, payload);
    expect(blob).toMatch(/^asb1\.[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(await s.unseal(typ, AUD, blob)).toEqual(payload);
  });

  it("rejects a blob presented as another type", async () => {
    const s = mk();
    const blob = await s.seal("rt", AUD, { x: 1 });
    expect(await s.unseal("at", AUD, blob)).toBeNull();
  });

  it("rejects a blob for another deployment (aud)", async () => {
    const s = mk();
    const blob = await s.seal("at", AUD, { x: 1 });
    expect(await s.unseal("at", "https://other.example/mcp", blob)).toBeNull();
  });

  it("rejects tampered ciphertext, iv and edk", async () => {
    const s = mk();
    const blob = await s.seal("at", AUD, { x: 1 });
    const [p, edk, iv, ct] = blob.split(".") as [string, string, string, string];
    const flip = (b64: string) => {
      const buf = Buffer.from(b64, "base64url");
      buf[buf.length - 1]! ^= 1;
      return buf.toString("base64url");
    };
    expect(await s.unseal("at", AUD, [p, edk, iv, flip(ct)].join("."))).toBeNull();
    expect(await s.unseal("at", AUD, [p, edk, flip(iv), ct].join("."))).toBeNull();
    expect(await mk().unseal("at", AUD, [p, flip(edk), iv, ct].join("."))).toBeNull();
  });

  it("rejects expired payloads", async () => {
    const s = mk();
    const blob = await s.seal("ac", AUD, { exp: Math.floor(nowMs / 1000) + 60 });
    nowMs += 61_000;
    expect(await s.unseal("ac", AUD, blob)).toBeNull();
  });

  it.each(["", "asb1.x", "asb2.a.b.c", "asb1.a.b.c", "asb1..."])("returns null for malformed %j", async (bad) => {
    expect(await mk().unseal("at", AUD, bad)).toBeNull();
  });

  it("reuses one data key across seals", async () => {
    const s = mk();
    await s.seal("at", AUD, { x: 1 });
    await s.seal("rt", AUD, { x: 2 });
    expect(kmsMock.commandCalls(GenerateDataKeyCommand)).toHaveLength(1);
  });

  it("rotates the data key after 10 000 seals", async () => {
    const s = mk();
    for (let i = 0; i < 10_001; i++) await s.seal("at", AUD, { i });
    expect(kmsMock.commandCalls(GenerateDataKeyCommand)).toHaveLength(2);
  });

  it("rotates the data key after 1 h", async () => {
    const s = mk();
    await s.seal("at", AUD, { x: 1 });
    nowMs += 3_600_001;
    await s.seal("at", AUD, { x: 2 });
    expect(kmsMock.commandCalls(GenerateDataKeyCommand)).toHaveLength(2);
  });

  it("decrypts each data key once per container (fresh sealer)", async () => {
    const a = mk();
    const b1 = await a.seal("at", AUD, { x: 1 });
    const b2 = await a.seal("at", AUD, { x: 2 });
    const fresh = mk();
    expect(await fresh.unseal("at", AUD, b1)).toEqual({ x: 1 });
    expect(await fresh.unseal("at", AUD, b2)).toEqual({ x: 2 });
    expect(kmsMock.commandCalls(DecryptCommand)).toHaveLength(1);
  });

  it("never reuses an IV", async () => {
    const s = mk();
    const ivs = new Set<string>();
    for (let i = 0; i < 1000; i++) ivs.add((await s.seal("at", AUD, { i })).split(".")[2]!);
    expect(ivs.size).toBe(1000);
  });

  it("emits an EMF UnsealFailure metric without details", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await mk().unseal("rt", AUD, "asb1.garbage.x.y");
    const line = JSON.parse(log.mock.calls[0]![0] as string);
    expect(line).toMatchObject({ typ: "rt", UnsealFailure: 1 });
    expect(line._aws.CloudWatchMetrics[0]).toMatchObject({
      Namespace: "AwsMcpSwitchboard",
      Dimensions: [["typ"]],
      Metrics: [{ Name: "UnsealFailure", Unit: "Count" }],
    });
    expect(JSON.stringify(line)).not.toContain("garbage");
  });

  it("does not leak KMS errors to the caller", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    kmsMock.on(DecryptCommand).rejects(new Error("AccessDenied"));
    const blob = await mk().seal("at", AUD, { x: 1 });
    expect(await mk().unseal("at", AUD, blob)).toBeNull();
  });
});
