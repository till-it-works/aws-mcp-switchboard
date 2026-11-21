import { createHash, randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { createSealer } from "../lambda/seal.js";
import { loadConfig } from "../lambda/config.js";
import { IdcError, type Idc } from "../lambda/idc.js";
import { createOAuth } from "../lambda/oauth.js";
import { readRequest, type Res } from "../lambda/http.js";
import { BASE, evt } from "./helpers.js";

const kmsMock = mockClient(KMSClient);
let now = Date.UTC(2026, 10, 20);
const AUD = `${BASE}/mcp`;
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";

const idc = {
  startDeviceAuthorization: vi.fn(),
  pollDeviceToken: vi.fn(),
  refresh: vi.fn(),
};
const sealer = createSealer({ kms: new KMSClient({ region: "eu-central-1" }), keyArn: "arn:key", now: () => now });
const oauth = createOAuth({ cfg: loadConfig({ ACCESS_TTL_SECONDS: "3600" }), sealer, idc: idc as unknown as Idc, now: () => now });

const b64u = (b: Buffer) => b.toString("base64url");
const challenge = (v: string) => b64u(createHash("sha256").update(v).digest());
const body = (r: Res) => JSON.parse(r.body ?? "null");
const VERIFIER = "v".repeat(43);

let logs: string[] = [];
beforeEach(() => {
  now = Date.UTC(2026, 10, 20);
  kmsMock.reset();
  kmsMock.on(GenerateDataKeyCommand).callsFake(() => {
    const k = randomBytes(32);
    return { Plaintext: new Uint8Array(k), CiphertextBlob: new Uint8Array(Buffer.concat([Buffer.from("EDK:"), k])) };
  });
  kmsMock.on(DecryptCommand).callsFake((i) => ({ Plaintext: new Uint8Array(Buffer.from(i.CiphertextBlob as Uint8Array).subarray(4)) }));
  idc.startDeviceAuthorization.mockReset().mockResolvedValue({
    deviceCode: "DEVICECODE",
    userCode: "ABCD-EFGH",
    verificationUri: "https://idc/verify",
    verificationUriComplete: "https://idc/verify?code=ABCD-EFGH",
    interval: 1,
    expiresIn: 600,
    clientId: "oidc-1",
  });
  idc.pollDeviceToken.mockReset();
  idc.refresh.mockReset();
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...a) => void logs.push(a.map(String).join(" ")));
  vi.spyOn(console, "warn").mockImplementation((...a) => void logs.push(a.map(String).join(" ")));
});
afterEach(() => vi.restoreAllMocks());

async function register(redirect_uris: unknown = [REDIRECT]) {
  return oauth.register(readRequest(evt("POST", "/register", { body: { redirect_uris, client_name: "Claude" }, headers: { "content-type": "application/json" } })));
}
async function clientId() {
  return body(await register()).client_id as string;
}
function authorizeQuery(cid: string, over: Record<string, string | undefined> = {}) {
  const q = new URLSearchParams();
  const all: Record<string, string | undefined> = {
    client_id: cid,
    redirect_uri: REDIRECT,
    response_type: "code",
    code_challenge: challenge(VERIFIER),
    code_challenge_method: "S256",
    state: "st-1",
    resource: AUD,
    ...over,
  };
  for (const [k, v] of Object.entries(all)) if (v !== undefined) q.set(k, v);
  return q.toString();
}
const authorize = (query: string) => oauth.authorize(readRequest(evt("GET", "/authorize", { query })));
const pendingOf = (r: Res) => /const PENDING = "([^"]+)"/.exec(r.body ?? "")![1]!;
const nonceOf = (r: Res) => /sb_nonce=([^;]+)/.exec(r.cookies![0]!)![1]!;
const poll = (pending: string, cookie?: string) =>
  oauth.poll(readRequest(evt("POST", "/poll", { body: { pending }, headers: { "content-type": "application/json" }, cookies: cookie ? [`sb_nonce=${cookie}`] : [] })));
const token = (params: Record<string, string>) =>
  oauth.token(readRequest(evt("POST", "/token", { body: new URLSearchParams(params).toString(), headers: { "content-type": "application/x-www-form-urlencoded" } })));

/** Full login up to the auth code. */
async function login() {
  const cid = await clientId();
  const page = await authorize(authorizeQuery(cid));
  idc.pollDeviceToken.mockResolvedValueOnce({ accessToken: "IDC_AT", refreshToken: "IDC_RT", expiresAt: now / 1000 + 3600, clientId: "oidc-1" });
  const ok = body(await poll(pendingOf(page), nonceOf(page)));
  const code = new URL(ok.redirect).searchParams.get("code")!;
  return { cid, code };
}

describe("/register", () => {
  it("returns a sealed client_id for a public client", async () => {
    const r = await register();
    expect(r.status).toBe(201);
    const b = body(r);
    expect(b.client_id).toMatch(/^asb1\./);
    expect(b).toMatchObject({ token_endpoint_auth_method: "none", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] });
    expect(b.client_secret).toBeUndefined();
  });

  it("rejects a disallowed redirect URI and logs it", async () => {
    const r = await register(["https://evil.example/cb"]);
    expect(r.status).toBe(400);
    expect(body(r).error).toBe("invalid_redirect_uri");
    expect(logs.join("\n")).toContain("https://evil.example/cb");
  });

  it.each([[[]], ["x"], [[1]]])("rejects malformed redirect_uris %j", async (v) => {
    expect(body(await register(v)).error).toBe("invalid_client_metadata");
  });
});

describe("/authorize", () => {
  it("re-checks the redirect URI against the current allowlist (client registered before it was narrowed)", async () => {
    const cid = await clientId();
    const narrowed = createOAuth({ cfg: loadConfig({ ACCESS_TTL_SECONDS: "3600", ALLOWED_REDIRECT_URIS: "http://localhost:*" }), sealer, idc: idc as unknown as Idc, now: () => now });
    const r = await narrowed.authorize(readRequest(evt("GET", "/authorize", { query: authorizeQuery(cid) })));
    expect(r.status).toBe(400);
    expect(r.headers?.location).toBeUndefined();
    expect(idc.startDeviceAuthorization).not.toHaveBeenCalled();
    expect(logs.join("\n")).toContain("redirect_uri_not_allowed");
  });

  it("renders the device page with user code, pending blob and nonce cookie", async () => {
    const r = await authorize(authorizeQuery(await clientId()));
    expect(r.status).toBe(200);
    expect(r.headers?.["content-type"]).toContain("text/html");
    expect(r.headers?.["content-security-policy"]).toMatch(/default-src 'none'.*script-src 'nonce-/);
    expect(r.headers?.["content-security-policy"]).toContain("font-src 'self'");
    expect(r.body).toContain("^(ReadOnlyAccess|ViewOnlyAccess)$");
    expect(r.headers?.["cache-control"]).toBe("no-store");
    expect(r.body).toContain("ABCD-EFGH");
    expect(r.body).toContain("https://idc/verify?code=ABCD-EFGH");
    expect(pendingOf(r)).toMatch(/^asb1\./);
    expect(r.cookies?.[0]).toMatch(/^sb_nonce=[\w-]{43}; HttpOnly; Secure; SameSite=Lax; Path=\/poll; Max-Age=600$/);
  });

  it("accepts resource with trailing slash and missing resource", async () => {
    const cid = await clientId();
    expect((await authorize(authorizeQuery(cid, { resource: `${AUD}/` }))).status).toBe(200);
    expect((await authorize(authorizeQuery(cid, { resource: undefined }))).status).toBe(200);
  });

  it.each([
    ["unknown client", { client_id: "asb1.x.y.z" }],
    ["unregistered redirect_uri", { redirect_uri: "http://localhost:1234/cb" }],
  ])("%s → 400 without redirect", async (_l, over) => {
    const r = await authorize(authorizeQuery(await clientId(), over));
    expect(r.status).toBe(400);
    expect(r.headers?.location).toBeUndefined();
    expect(idc.startDeviceAuthorization).not.toHaveBeenCalled();
  });

  it.each([
    ["wrong response_type", { response_type: "token" }, "unsupported_response_type"],
    ["missing PKCE", { code_challenge: undefined }, "invalid_request"],
    ["plain PKCE", { code_challenge_method: "plain" }, "invalid_request"],
    ["wrong resource", { resource: "https://other/mcp" }, "invalid_target"],
  ])("%s → redirect with error", async (_l, over, error) => {
    const r = await authorize(authorizeQuery(await clientId(), over));
    expect(r.status).toBe(302);
    const loc = new URL(r.headers!.location!);
    expect(`${loc.origin}${loc.pathname}`).toBe(REDIRECT);
    expect(loc.searchParams.get("error")).toBe(error);
    expect(loc.searchParams.get("state")).toBe("st-1");
  });
});

describe("/poll", () => {
  it("success: redirects with code + state and clears the cookie", async () => {
    const page = await authorize(authorizeQuery(await clientId()));
    idc.pollDeviceToken.mockResolvedValueOnce({ accessToken: "IDC_AT", refreshToken: "IDC_RT", expiresAt: now / 1000 + 3600, clientId: "oidc-1" });
    const r = await poll(pendingOf(page), nonceOf(page));
    expect(idc.pollDeviceToken).toHaveBeenCalledWith(expect.objectContaining({ r: "eu-central-1" }), "DEVICECODE");
    const b = body(r);
    expect(b.status).toBe("ok");
    const u = new URL(b.redirect);
    expect(`${u.origin}${u.pathname}`).toBe(REDIRECT);
    expect(u.searchParams.get("state")).toBe("st-1");
    expect(u.searchParams.get("code")).toMatch(/^asb1\./);
    expect(r.cookies?.[0]).toMatch(/^sb_nonce=; .*Max-Age=0/);
  });

  it("missing or wrong nonce cookie → 403, IdC not called", async () => {
    const page = await authorize(authorizeQuery(await clientId()));
    expect((await poll(pendingOf(page))).status).toBe(403);
    expect((await poll(pendingOf(page), "wrong")).status).toBe(403);
    expect(idc.pollDeviceToken).not.toHaveBeenCalled();
  });

  it("pending and slow_down", async () => {
    const page = await authorize(authorizeQuery(await clientId()));
    idc.pollDeviceToken.mockRejectedValueOnce(new IdcError("pending")).mockRejectedValueOnce(new IdcError("slow_down"));
    expect(body(await poll(pendingOf(page), nonceOf(page)))).toEqual({ status: "pending" });
    expect(body(await poll(pendingOf(page), nonceOf(page)))).toEqual({ status: "pending", interval: 6 });
  });

  it.each(["expired", "denied", "invalid_grant"] as const)("%s → failed", async (kind) => {
    const page = await authorize(authorizeQuery(await clientId()));
    idc.pollDeviceToken.mockRejectedValueOnce(new IdcError(kind));
    expect(body(await poll(pendingOf(page), nonceOf(page)))).toEqual({ status: "failed" });
  });

  it("expired pending blob → failed", async () => {
    const page = await authorize(authorizeQuery(await clientId()));
    now += 601_000;
    expect(body(await poll(pendingOf(page), nonceOf(page)))).toEqual({ status: "failed" });
  });
});

describe("/token authorization_code", () => {
  it("exchanges code for access + refresh blobs", async () => {
    const { cid, code } = await login();
    const r = await token({ grant_type: "authorization_code", code, client_id: cid, redirect_uri: REDIRECT, code_verifier: VERIFIER });
    expect(r.status).toBe(200);
    expect(r.headers?.["cache-control"]).toBe("no-store");
    const b = body(r);
    expect(b).toMatchObject({ token_type: "Bearer", expires_in: 3600 });
    expect(b.access_token).toMatch(/^asb1\./);
    expect(b.refresh_token).toMatch(/^asb1\./);
    const at = await sealer.unseal("at", AUD, b.access_token);
    expect(at).toMatchObject({ at: "IDC_AT", ie: now / 1000 + 3600 });
    const rt = await sealer.unseal("rt", AUD, b.refresh_token);
    expect(rt).toMatchObject({ rt: "IDC_RT", oc: "oidc-1", sid: (at as { sid: string }).sid });
  });

  it.each([
    ["wrong verifier", { code_verifier: "w".repeat(43) }],
    ["wrong client", { client_id: "asb1.other" }],
    ["wrong redirect_uri", { redirect_uri: "http://localhost:1/cb" }],
  ])("%s → invalid_grant", async (_l, over) => {
    const { cid, code } = await login();
    const r = await token({ grant_type: "authorization_code", code, client_id: cid, redirect_uri: REDIRECT, code_verifier: VERIFIER, ...over });
    expect(r.status).toBe(400);
    expect(body(r).error).toBe("invalid_grant");
  });

  it("missing client_id → invalid_request", async () => {
    const { code } = await login();
    expect(body(await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER })).error).toBe("invalid_request");
  });

  it("code still valid after 5 min (user reads the approved page before finishing)", async () => {
    const { cid, code } = await login();
    now += 5 * 60_000;
    expect((await token({ grant_type: "authorization_code", code, client_id: cid, redirect_uri: REDIRECT, code_verifier: VERIFIER })).status).toBe(200);
  });

  it("expired code (> 10 min) → invalid_grant", async () => {
    const { cid, code } = await login();
    now += 10 * 60_000 + 1000;
    expect(body(await token({ grant_type: "authorization_code", code, client_id: cid, redirect_uri: REDIRECT, code_verifier: VERIFIER })).error).toBe("invalid_grant");
  });

  it("reused code (same container) → invalid_grant", async () => {
    const { cid, code } = await login();
    const p = { grant_type: "authorization_code", code, client_id: cid, redirect_uri: REDIRECT, code_verifier: VERIFIER };
    expect((await token(p)).status).toBe(200);
    expect(body(await token(p)).error).toBe("invalid_grant");
  });

  it("refresh blob presented as code → invalid_grant", async () => {
    const { cid, code } = await login();
    const b = body(await token({ grant_type: "authorization_code", code, client_id: cid, redirect_uri: REDIRECT, code_verifier: VERIFIER }));
    expect(body(await token({ grant_type: "authorization_code", code: b.refresh_token, client_id: cid, redirect_uri: REDIRECT, code_verifier: VERIFIER })).error).toBe("invalid_grant");
  });

  it("unsupported grant type", async () => {
    expect(body(await token({ grant_type: "password" })).error).toBe("unsupported_grant_type");
  });

  it("never logs codes, verifiers, tokens or blobs", async () => {
    const { cid, code } = await login();
    await token({ grant_type: "authorization_code", code, client_id: cid, redirect_uri: REDIRECT, code_verifier: VERIFIER });
    const all = logs.join("\n");
    for (const secret of [code, VERIFIER, "IDC_AT", "IDC_RT", "DEVICECODE", "asb1."]) expect(all).not.toContain(secret);
  });
});

describe("/token refresh_token", () => {
  async function pair() {
    const { cid, code } = await login();
    const b = body(await token({ grant_type: "authorization_code", code, client_id: cid, redirect_uri: REDIRECT, code_verifier: VERIFIER }));
    return { cid, rt: b.refresh_token as string, at: b.access_token as string };
  }

  it("returns a new pair, keeping sid, storing the rotated IdC refresh token", async () => {
    const { cid, rt, at } = await pair();
    idc.refresh.mockResolvedValueOnce({ accessToken: "IDC_AT2", refreshToken: "IDC_RT2", expiresAt: now / 1000 + 3600, clientId: "oidc-1" });
    const r = await token({ grant_type: "refresh_token", refresh_token: rt, client_id: cid });
    expect(r.status).toBe(200);
    expect(idc.refresh).toHaveBeenCalledWith(expect.objectContaining({ r: "eu-central-1" }), "IDC_RT", "oidc-1");
    const b = body(r);
    const newRt = await sealer.unseal<{ rt: string; sid: string }>("rt", AUD, b.refresh_token);
    const oldAt = await sealer.unseal<{ sid: string }>("at", AUD, at);
    expect(newRt?.rt).toBe("IDC_RT2");
    expect(newRt?.sid).toBe(oldAt?.sid);
    expect((await sealer.unseal("at", AUD, b.access_token))).toMatchObject({ at: "IDC_AT2" });
  });

  it("IdC failure → invalid_grant", async () => {
    const { cid, rt } = await pair();
    idc.refresh.mockRejectedValueOnce(new IdcError("invalid_grant"));
    expect(body(await token({ grant_type: "refresh_token", refresh_token: rt, client_id: cid })).error).toBe("invalid_grant");
  });

  it("other client's refresh token → invalid_grant without IdC call", async () => {
    const { rt } = await pair();
    const other = await clientId();
    expect(body(await token({ grant_type: "refresh_token", refresh_token: rt, client_id: other })).error).toBe("invalid_grant");
    expect(idc.refresh).not.toHaveBeenCalled();
  });

  it("access blob presented as refresh token → invalid_grant", async () => {
    const { cid, at } = await pair();
    expect(body(await token({ grant_type: "refresh_token", refresh_token: at, client_id: cid })).error).toBe("invalid_grant");
  });

  it("access token lifetime is capped by ACCESS_TTL_SECONDS and IdC expiry", async () => {
    const short = createOAuth({ cfg: loadConfig({ ACCESS_TTL_SECONDS: "120" }), sealer, idc: idc as unknown as Idc, now: () => now });
    const { cid, rt } = await pair();
    idc.refresh.mockResolvedValueOnce({ accessToken: "A", refreshToken: "R", expiresAt: now / 1000 + 3600, clientId: "oidc-1" });
    const r = await short.token(readRequest(evt("POST", "/token", { body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: cid }).toString() })));
    expect(body(r).expires_in).toBe(120);
  });
});

describe("tenants (managed mode)", () => {
  const managed = createOAuth({ cfg: loadConfig({ SWITCHBOARD_MODE: "managed", ACCESS_TTL_SECONDS: "3600" }), sealer, idc: idc as unknown as Idc, now: () => now });
  const TENANT_AUD = `${BASE}/mcp/d-1234567890/eu-west-1`;
  const auth = (query: string, cookies: string[] = []) => managed.authorize(readRequest(evt("GET", "/authorize", { query, cookies })));
  const mPoll = (pending: string, cookie: string) =>
    managed.poll(readRequest(evt("POST", "/poll", { body: { pending }, headers: { "content-type": "application/json" }, cookies: [`sb_nonce=${cookie}`] })));
  const mToken = (params: Record<string, string>) =>
    managed.token(readRequest(evt("POST", "/token", { body: new URLSearchParams(params).toString(), headers: { "content-type": "application/x-www-form-urlencoded" } })));
  const mClient = async () =>
    body(await managed.register(readRequest(evt("POST", "/register", { body: { redirect_uris: [REDIRECT] }, headers: { "content-type": "application/json" } }))))
      .client_id as string;

  async function mLogin(over: Record<string, string | undefined>) {
    const cid = await mClient();
    const page = await auth(authorizeQuery(cid, over));
    idc.pollDeviceToken.mockResolvedValueOnce({ accessToken: "IDC_AT", refreshToken: "IDC_RT", expiresAt: now / 1000 + 3600, clientId: "oidc-1" });
    const ok = body(await mPoll(pendingOf(page), nonceOf(page)));
    const code = new URL(ok.redirect).searchParams.get("code")!;
    const b = body(await mToken({ grant_type: "authorization_code", code, code_verifier: VERIFIER, client_id: cid, redirect_uri: REDIRECT }));
    return { cid, b };
  }

  it("/mcp without a chosen Identity Center renders the chooser form (no device flow yet)", async () => {
    const r = await auth(authorizeQuery(await mClient()));
    expect(r.status).toBe(200);
    expect(r.body).toContain('action="/authorize"');
    expect(r.body).toContain('name="idc_d"');
    expect(r.body).toMatch(/<option value="eu-central-1" selected>/);
    expect(r.body).toContain('name="client_id"');
    expect(r.body).toContain('name="code_challenge"');
    expect(r.headers?.["content-security-policy"]).toContain("form-action 'self'");
    expect(idc.startDeviceAuthorization).not.toHaveBeenCalled();
  });

  it("HOSTED_NOTICE=on: the chooser and the sign-in page carry the exploration-only notice; off by default", async () => {
    const hosted = createOAuth({ cfg: loadConfig({ SWITCHBOARD_MODE: "managed", ACCESS_TTL_SECONDS: "3600", HOSTED_NOTICE: "on" }), sealer, idc: idc as unknown as Idc, now: () => now });
    const cid = await mClient();
    const choose = await hosted.authorize(readRequest(evt("GET", "/authorize", { query: authorizeQuery(cid) })));
    expect(choose.body).toMatch(/class="notice[\s\S]*Exploration only/);
    const sign = await hosted.authorize(readRequest(evt("GET", "/authorize", { query: authorizeQuery(cid, { idc_d: "d-1234567890", idc_r: "eu-central-1" }) })));
    expect(sign.body).toContain('class="code"');
    expect(sign.body).toMatch(/class="notice[\s\S]*Exploration only/);
    expect((await auth(authorizeQuery(cid))).body).not.toContain('class="notice');
  });

  it("chooser is prefilled from the last choice (cookie)", async () => {
    const r = await auth(authorizeQuery(await mClient()), ["sb_idc=my-corp/us-east-1"]);
    expect(r.body).toContain('value="my-corp"');
    expect(r.body).toMatch(/<option value="us-east-1" selected>/);
  });

  it("chosen Identity Center (pasted sign-in link) starts the device flow and is remembered", async () => {
    const r = await auth(authorizeQuery(await mClient(), { idc_d: "https://my-corp.awsapps.com/start", idc_r: "us-east-1" }));
    expect(r.status).toBe(200);
    expect(idc.startDeviceAuthorization).toHaveBeenCalledWith({ d: "my-corp", r: "us-east-1" });
    expect(r.body).toContain("<b>my-corp</b>.awsapps.com/start");
    expect(r.cookies).toContainEqual(expect.stringMatching(/^sb_idc=my-corp\/us-east-1; HttpOnly; Secure; SameSite=Lax; Path=\/authorize; Max-Age=\d+$/));
  });

  it.each([
    ["bad directory", { idc_d: "evil.com", idc_r: "us-east-1" }],
    ["bad region", { idc_d: "my-corp", idc_r: "mars-1" }],
  ])("%s → chooser again with an error, no device flow", async (_l, over) => {
    const r = await auth(authorizeQuery(await mClient(), over));
    expect(r.status).toBe(200);
    expect(r.body).toContain('name="idc_d"');
    expect(r.body).toContain('class="err"');
    expect(idc.startDeviceAuthorization).not.toHaveBeenCalled();
  });

  it("tenant resource /mcp/<d>/<r> skips the chooser", async () => {
    const r = await auth(authorizeQuery(await mClient(), { resource: TENANT_AUD }));
    expect(r.status).toBe(200);
    expect(idc.startDeviceAuthorization).toHaveBeenCalledWith({ d: "d-1234567890", r: "eu-west-1" });
  });

  it("tenant tokens: access token only valid at its own resource URL; tenant sealed in; refresh uses it", async () => {
    const { cid, b } = await mLogin({ resource: TENANT_AUD });
    expect(await sealer.unseal("at", AUD, b.access_token)).toBeNull();
    expect(await sealer.unseal("at", TENANT_AUD, b.access_token)).toMatchObject({ t: { d: "d-1234567890", r: "eu-west-1" } });
    idc.refresh.mockResolvedValueOnce({ accessToken: "IDC_AT2", refreshToken: "IDC_RT2", expiresAt: now / 1000 + 3600, clientId: "oidc-1" });
    const r = body(await mToken({ grant_type: "refresh_token", refresh_token: b.refresh_token, client_id: cid }));
    expect(idc.refresh).toHaveBeenCalledWith({ d: "d-1234567890", r: "eu-west-1" }, "IDC_RT", "oidc-1");
    expect(await sealer.unseal("at", TENANT_AUD, r.access_token)).toMatchObject({ at: "IDC_AT2" });
  });

  it("shared /mcp tokens carry the chosen tenant", async () => {
    const { b } = await mLogin({ idc_d: "my-corp", idc_r: "us-east-1" });
    expect(await sealer.unseal("at", AUD, b.access_token)).toMatchObject({ t: { d: "my-corp", r: "us-east-1" } });
  });

  it("/token resource that differs from the authorized one → invalid_target", async () => {
    const { cid, b } = await mLogin({ resource: TENANT_AUD });
    const r = await mToken({ grant_type: "refresh_token", refresh_token: b.refresh_token, client_id: cid, resource: AUD });
    expect(body(r).error).toBe("invalid_target");
  });

  it.each(["https://other/mcp", `${BASE}/mcp/evil.com/eu-west-1`, `${BASE}/mcpx`])("bad resource %s → invalid_target", async (resource) => {
    const r = await auth(authorizeQuery(await mClient(), { resource }));
    expect(new URL(r.headers!.location!).searchParams.get("error")).toBe("invalid_target");
  });
});

describe("tenants (single mode)", () => {
  it("rejects tenant resource URLs", async () => {
    const r = await authorize(authorizeQuery(await clientId(), { resource: `${BASE}/mcp/d-1234567890/eu-west-1` }));
    expect(new URL(r.headers!.location!).searchParams.get("error")).toBe("invalid_target");
  });

  it("seals the configured Identity Center into the access token", async () => {
    const { cid, code } = await login();
    const b = body(await token({ grant_type: "authorization_code", code, code_verifier: VERIFIER, client_id: cid, redirect_uri: REDIRECT }));
    expect(await sealer.unseal("at", AUD, b.access_token)).toMatchObject({ t: { r: "eu-central-1" } });
  });
});
