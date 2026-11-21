/**
 * E2E helper: performs the full OAuth login against a deployed Switchboard like an MCP client would
 * (discovery → DCR → /authorize device page in the browser → loopback callback → /token) and stores
 * the token pair in .e2e/tokens.json (mode 600, never printed).
 *
 *   npx tsx scripts/e2e-login.ts <BASE_URL>          # login
 *   npx tsx scripts/e2e-login.ts <BASE_URL> refresh  # refresh grant
 *   npx tsx scripts/e2e-login.ts <BASE_URL> rpc '<json-rpc body>'
 */
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const [base = "", cmd = "login", arg = ""] = process.argv.slice(2).map((s, i) => (i === 0 ? s.replace(/\/+$/, "") : s));
const FILE = ".e2e/tokens.json";
const PORT = 33418;
const REDIRECT = `http://localhost:${PORT}/cb`;

interface Saved {
  clientId: string;
  accessToken: string;
  refreshToken: string;
}
const save = (s: Saved) => {
  mkdirSync(".e2e", { recursive: true, mode: 0o700 });
  writeFileSync(FILE, JSON.stringify(s));
  chmodSync(FILE, 0o600);
};
const load = () => JSON.parse(readFileSync(FILE, "utf8")) as Saved;

async function token(params: Record<string, string>) {
  const r = await fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(params) });
  const b = (await r.json()) as Record<string, unknown>;
  if (!r.ok) throw new Error(`/token ${r.status} ${JSON.stringify(b)}`);
  console.log(`/token ${r.status}: expires_in=${b.expires_in}, access ${String(b.access_token).length} B, refresh ${String(b.refresh_token).length} B`);
  return b as { access_token: string; refresh_token: string };
}

async function login() {
  const probe = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  console.log(`POST /mcp unauthenticated → ${probe.status}; www-authenticate present: ${probe.headers.has("www-authenticate")}`);
  const prm = (await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json()) as { authorization_servers: string[]; resource: string };
  const asm = (await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json()) as Record<string, string>;
  console.log(`discovery: resource=${prm.resource} issuer=${asm.issuer}`);
  const reg = (await (await fetch(asm.registration_endpoint!, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: "switchboard-e2e" }) })).json()) as { client_id: string };
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(8).toString("hex");
  const u = new URL(asm.authorization_endpoint!);
  u.search = new URLSearchParams({
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    response_type: "code",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state,
    resource: prm.resource,
  }).toString();

  const code = await new Promise<string>((resolve, reject) => {
    const srv = createServer((req, res) => {
      const q = new URL(req.url ?? "/", REDIRECT).searchParams;
      res.end(q.get("code") ? "Login complete - you can close this tab." : `Error: ${q.get("error")}`);
      srv.close();
      if (q.get("state") !== state) return reject(new Error("state mismatch"));
      const c = q.get("code");
      if (c) resolve(c);
      else reject(new Error(`authorize error ${q.get("error")}`));
    }).listen(PORT, () => {
      console.log("Opening browser for IAM Identity Center approval…");
      execFile("open", [u.toString()]);
    });
    setTimeout(() => reject(new Error("timeout")), 600_000).unref();
  });
  console.log("callback received code + matching state");
  const t = await token({ grant_type: "authorization_code", code, client_id: reg.client_id, redirect_uri: REDIRECT, code_verifier: verifier });
  save({ clientId: reg.client_id, accessToken: t.access_token, refreshToken: t.refresh_token });
}

async function refresh() {
  const s = load();
  const t = await token({ grant_type: "refresh_token", refresh_token: s.refreshToken, client_id: s.clientId });
  save({ clientId: s.clientId, accessToken: t.access_token, refreshToken: t.refresh_token });
}

async function rpc() {
  const started = Date.now();
  const r = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${load().accessToken}` },
    body: arg,
  });
  console.log(`HTTP ${r.status} in ${Date.now() - started} ms`);
  console.log(await r.text());
}

await ({ login, refresh, rpc } as Record<string, () => Promise<void>>)[cmd]!();
