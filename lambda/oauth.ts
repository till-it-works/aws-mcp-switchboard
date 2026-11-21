/**
 * OAuth 2.1 facade for MCP clients, backed by the IdC device flow.
 * Fully stateless: client registrations, pending logins, codes and tokens are sealed blobs.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { LruCache } from "./cache.js";
import { redirectUriAllowed, type Config } from "./config.js";
import { IdcError, type Idc } from "./idc.js";
import { jsonRes, type Req, type Res } from "./http.js";
import type { Sealer } from "./seal.js";
import { configuredIdc, DEFAULT_REGION, isIdcRegion, parseDirectory, parseMcpPath, type Idc as Tenant } from "./tenant.js";
import { choosePage, devicePage, errorPage, htmlRes, siteInfo } from "./pages.js";

// ---- sealed payloads (short keys keep blobs small) ----

/** typ=cl — DCR client registration. */
export interface ClPayload {
  ru: string[];
  cn: string;
  iat: number;
}
/** typ=pd — pending device login. */
interface PdPayload {
  dc: string; // IdC device code
  iv: number; // poll interval (s)
  cih: string;
  ru: string;
  st?: string;
  cc: string;
  nh: string; // sha256(browser nonce)
  t: Tenant;
  res: string; // resource path: /mcp or /mcp/<d>/<r>
  exp: number;
}
/** typ=ac — authorization code. */
interface AcPayload {
  at: string; // IdC access token
  rt: string; // IdC refresh token
  ie: number; // IdC access token expiry (epoch s)
  oc: string; // IdC OIDC client id
  sid: string;
  cih: string;
  ru: string;
  cc: string;
  t: Tenant;
  res: string;
  exp: number;
}
/** typ=at — access token presented on /mcp. */
export interface AtPayload {
  sid: string;
  cih: string;
  at: string;
  ie: number;
  /** Identity Center the IdC tokens belong to; absent in blobs from before tenants (single mode). */
  t?: Tenant;
  iat: number;
  exp: number;
}
/** typ=rt — refresh token, /token only. */
interface RtPayload {
  sid: string;
  cih: string;
  oc: string;
  rt: string;
  t?: Tenant;
  res?: string;
  iat: number;
  exp: number;
}

/** Long enough to read the approved page before tapping "Finish" (OAuth recommends at most 10 min); PKCE-bound. */
const CODE_TTL_S = 600;
const REFRESH_CEILING_S = 90 * 86_400;

const sha256 = (s: string) => createHash("sha256").update(s).digest();
const b64u = (b: Buffer) => b.toString("base64url");
export const clientIdHash = (clientId: string) => b64u(sha256(clientId).subarray(0, 16));
const safeEq = (a: string, b: string) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

const NO_STORE = { "cache-control": "no-store", pragma: "no-cache" };
const oauthError = (error: string, status = 400) => jsonRes(status, { error }, NO_STORE);

function withParams(uri: string, params: Record<string, string | undefined>): string {
  const u = new URL(uri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  return u.toString();
}

const htmlError = (status: number, message: string): Res => htmlRes(status, errorPage(message));

export function createOAuth(deps: { cfg: Config; sealer: Sealer; idc: Idc; now?: () => number }) {
  const { cfg, sealer, idc } = deps;
  /** Single mode: the one configured Identity Center. Managed: none — it comes from the URL or the login form. */
  const single = cfg.mode === "single" ? configuredIdc(cfg.idcStartUrl, cfg.idcRegion) : undefined;
  const hosted = cfg.hostedNotice ? cfg.repoUrl : undefined;
  const nowS = () => Math.floor((deps.now ?? Date.now)() / 1000);
  const seenCodes = new LruCache<true>({ max: 10_000, ttlMs: (CODE_TTL_S + 5) * 1000, now: deps.now });
  /** Audience of the authorization server's own blobs (cl, pd, ac, rt). Access tokens use the resource URL instead. */
  const aud = (req: Req) => `${req.baseUrl}/mcp`;
  const resourceUrl = (req: Req, res: string) => `${req.baseUrl}${res}`;

  /** `resource` → path + the tenant it fixes (if any); null = not one of ours (invalid_target). */
  function resolveResource(req: Req, resource: string | null): { res: string; tenant?: Tenant } | null {
    let path = "/mcp";
    if (resource !== null) {
      const r = resource.replace(/\/+$/, "");
      if (!r.startsWith(`${req.baseUrl}/`)) return null;
      path = r.slice(req.baseUrl.length);
    }
    const target = parseMcpPath(path);
    if (!target) return null;
    if (target.kind === "tenant") return cfg.mode === "managed" ? { res: path, tenant: target.idc } : null;
    return { res: path, tenant: single };
  }

  const resourceMatches = (req: Req, given: string | null, res: string) => given === null || given.replace(/\/+$/, "") === resourceUrl(req, res);

  async function mintPair(req: Req, p: { sid: string; cih: string; oc: string; at: string; rt: string; ie: number; t: Tenant; res: string }): Promise<Res> {
    const iat = nowS();
    const exp = Math.min(iat + cfg.accessTtlSeconds, p.ie);
    const access: AtPayload = { sid: p.sid, cih: p.cih, at: p.at, ie: p.ie, t: p.t, iat, exp };
    const refresh: RtPayload = { sid: p.sid, cih: p.cih, oc: p.oc, rt: p.rt, t: p.t, res: p.res, iat, exp: iat + REFRESH_CEILING_S };
    return {
      ...jsonRes(
        200,
        {
          access_token: await sealer.seal("at", resourceUrl(req, p.res), access),
          token_type: "Bearer",
          expires_in: Math.max(0, exp - iat),
          refresh_token: await sealer.seal("rt", aud(req), refresh),
        },
        NO_STORE,
      ),
      sid: p.sid,
    };
  }

  return {
    /** POST /register — RFC 7591, public clients only, client_id = sealed registration. */
    async register(req: Req): Promise<Res> {
      let meta: { redirect_uris?: unknown; client_name?: unknown };
      try {
        meta = JSON.parse(req.body) as typeof meta;
      } catch {
        return oauthError("invalid_client_metadata");
      }
      const uris = meta.redirect_uris;
      if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u) => typeof u === "string")) {
        return oauthError("invalid_client_metadata");
      }
      const rejected = (uris as string[]).filter((u) => !redirectUriAllowed(u, cfg.allowedRedirectUris));
      if (rejected.length) {
        console.warn(JSON.stringify({ msg: "redirect_uri_rejected", uris: rejected.map((u) => u.slice(0, 200)) }));
        return oauthError("invalid_redirect_uri");
      }
      const cn = typeof meta.client_name === "string" ? meta.client_name.slice(0, 100) : "";
      const iat = nowS();
      const cl: ClPayload = { ru: uris as string[], cn, iat };
      return jsonRes(
        201,
        {
          client_id: await sealer.seal("cl", aud(req), cl),
          client_id_issued_at: iat,
          client_name: cn,
          redirect_uris: uris,
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
        },
        NO_STORE,
      );
    },

    /** GET /authorize — validates the MCP client request, starts IdC device authorization, renders the device page. */
    async authorize(req: Req): Promise<Res> {
      const q = req.query;
      const clientId = q.get("client_id") ?? "";
      const cl = clientId ? await sealer.unseal<ClPayload>("cl", aud(req), clientId) : null;
      if (!cl) return htmlError(400, "Unknown client. Remove and re-add the connector.");
      const redirectUri = q.get("redirect_uri") ?? (cl.ru.length === 1 ? cl.ru[0]! : "");
      if (!cl.ru.includes(redirectUri)) {
        console.warn(JSON.stringify({ msg: "authorize_rejected", reason: "redirect_uri_mismatch" }));
        return htmlError(400, "redirect_uri does not match the registered client.");
      }
      // Client blobs outlive config changes: enforce the current allowlist, not only the one at registration.
      if (!redirectUriAllowed(redirectUri, cfg.allowedRedirectUris)) {
        console.warn(JSON.stringify({ msg: "authorize_rejected", reason: "redirect_uri_not_allowed" }));
        return htmlError(400, "This client's redirect_uri is no longer allowed. Remove and re-add the connector.");
      }
      const state = q.get("state") ?? undefined;
      const fail = (error: string): Res => {
        console.warn(JSON.stringify({ msg: "authorize_rejected", reason: error }));
        return { status: 302, headers: { location: withParams(redirectUri, { error, state }), ...NO_STORE } };
      };
      if (q.get("response_type") !== "code") return fail("unsupported_response_type");
      const cc = q.get("code_challenge") ?? "";
      if (!/^[\w-]{43}$/.test(cc) || q.get("code_challenge_method") !== "S256") return fail("invalid_request");
      const target = resolveResource(req, q.get("resource"));
      if (!target) return fail("invalid_target");

      let tenant = target.tenant;
      const cookies: string[] = [];
      if (!tenant) {
        // Managed /mcp: ask which Identity Center, then come back here with idc_d / idc_r.
        const params = [...q.entries()].filter(([k]) => k !== "idc_d" && k !== "idc_r");
        const d = q.get("idc_d");
        const r = q.get("idc_r") ?? DEFAULT_REGION;
        if (d === null) {
          const last = parseMcpPath(`/mcp/${req.cookies.sb_idc ?? ""}`);
          const prev = last?.kind === "tenant" ? last.idc : undefined;
          return htmlRes(200, choosePage({ params, directory: prev?.d ?? "", region: prev?.r ?? DEFAULT_REGION, hosted, links: cfg.legal.links }), { form: true });
        }
        const dir = parseDirectory(d);
        if (!dir || !isIdcRegion(r)) {
          const error = "Enter your directory ID (d-…) or access portal link, and pick the region your Identity Center runs in.";
          return htmlRes(200, choosePage({ params, directory: d, region: isIdcRegion(r) ? r : DEFAULT_REGION, error, hosted, links: cfg.legal.links }), { form: true });
        }
        tenant = { d: dir, r };
        cookies.push(`sb_idc=${dir}/${r}; HttpOnly; Secure; SameSite=Lax; Path=/authorize; Max-Age=31536000`);
      }

      let da;
      try {
        da = await idc.startDeviceAuthorization(tenant);
      } catch (e) {
        console.error(JSON.stringify({ msg: "start_device_authorization_failed", error: (e as Error).name }));
        return fail("server_error");
      }
      const nonce = b64u(randomBytes(32));
      const pd: PdPayload = {
        dc: da.deviceCode,
        iv: da.interval,
        cih: clientIdHash(clientId),
        ru: redirectUri,
        st: state,
        cc,
        nh: b64u(sha256(nonce)),
        t: tenant,
        res: target.res,
        exp: nowS() + da.expiresIn,
      };
      const pending = await sealer.seal("pd", aud(req), pd);
      const scriptNonce = b64u(randomBytes(16));
      return htmlRes(
        200,
        devicePage({ userCode: da.userCode, verifyUrl: da.verificationUriComplete, pending, interval: da.interval, expiresIn: da.expiresIn, scriptNonce, site: siteInfo(cfg, tenant), branding: cfg.branding, hosted, links: cfg.legal.links }),
        { scriptNonce, cookies: [`sb_nonce=${nonce}; HttpOnly; Secure; SameSite=Lax; Path=/poll; Max-Age=${da.expiresIn}`, ...cookies] },
      );
    },

    /** POST /poll — browser-bound device-token polling; mints the auth code on approval. */
    async poll(req: Req): Promise<Res> {
      let pendingBlob = "";
      try {
        pendingBlob = String((JSON.parse(req.body) as { pending?: unknown }).pending ?? "");
      } catch {
        /* handled below */
      }
      const pd = pendingBlob ? await sealer.unseal<PdPayload>("pd", aud(req), pendingBlob) : null;
      if (!pd) return jsonRes(200, { status: "failed" }, NO_STORE);
      const cookie = req.cookies.sb_nonce ?? "";
      if (!cookie || !safeEq(b64u(sha256(cookie)), pd.nh)) return jsonRes(403, { status: "failed" }, NO_STORE);

      let tok;
      try {
        tok = await idc.pollDeviceToken(pd.t, pd.dc);
      } catch (e) {
        const kind = e instanceof IdcError ? e.kind : "invalid_grant";
        if (kind === "pending") return jsonRes(200, { status: "pending" }, NO_STORE);
        if (kind === "slow_down") return jsonRes(200, { status: "pending", interval: pd.iv + 5 }, NO_STORE);
        if (!(e instanceof IdcError)) console.error(JSON.stringify({ msg: "device_poll_failed", error: (e as Error).name }));
        return jsonRes(200, { status: "failed" }, NO_STORE);
      }
      if (!tok.refreshToken) {
        console.error(JSON.stringify({ msg: "device_poll_failed", error: "no_refresh_token" }));
        return jsonRes(200, { status: "failed" }, NO_STORE);
      }
      const sid = b64u(randomBytes(16));
      const ac: AcPayload = {
        at: tok.accessToken,
        rt: tok.refreshToken,
        ie: tok.expiresAt,
        oc: tok.clientId,
        sid,
        cih: pd.cih,
        ru: pd.ru,
        cc: pd.cc,
        t: pd.t,
        res: pd.res,
        exp: nowS() + CODE_TTL_S,
      };
      const code = await sealer.seal("ac", aud(req), ac);
      console.log(JSON.stringify({ msg: "login_approved", sid }));
      return {
        ...jsonRes(200, { status: "ok", redirect: withParams(pd.ru, { code, state: pd.st }) }, NO_STORE),
        cookies: ["sb_nonce=; HttpOnly; Secure; SameSite=Lax; Path=/poll; Max-Age=0"],
        sid,
      };
    },

    /** POST /token — authorization_code (PKCE S256) and refresh_token grants. */
    async token(req: Req): Promise<Res> {
      const f = req.form();
      const grant = f.get("grant_type");
      const clientId = f.get("client_id") ?? "";

      if (grant === "authorization_code") {
        const code = f.get("code") ?? "";
        const verifier = f.get("code_verifier") ?? "";
        const redirectUri = f.get("redirect_uri") ?? "";
        if (!code || !verifier || !clientId) return oauthError("invalid_request");
        const ac = await sealer.unseal<AcPayload>("ac", aud(req), code);
        if (!ac) return oauthError("invalid_grant");
        if (!safeEq(clientIdHash(clientId), ac.cih)) return oauthError("invalid_grant");
        if (redirectUri !== ac.ru) return oauthError("invalid_grant");
        if (!safeEq(b64u(sha256(verifier)), ac.cc)) return oauthError("invalid_grant");
        if (!resourceMatches(req, f.get("resource"), ac.res)) return oauthError("invalid_target");
        const codeKey = b64u(sha256(code));
        if (seenCodes.get(codeKey)) return oauthError("invalid_grant");
        seenCodes.set(codeKey, true);
        return mintPair(req, { sid: ac.sid, cih: ac.cih, oc: ac.oc, at: ac.at, rt: ac.rt, ie: ac.ie, t: ac.t, res: ac.res });
      }

      if (grant === "refresh_token") {
        const blob = f.get("refresh_token") ?? "";
        if (!blob || !clientId) return oauthError("invalid_request");
        const rt = await sealer.unseal<RtPayload>("rt", aud(req), blob);
        if (!rt || !safeEq(clientIdHash(clientId), rt.cih)) return oauthError("invalid_grant");
        const t = rt.t ?? single; // blobs from before tenants belong to the configured Identity Center
        const res = rt.res ?? "/mcp";
        if (!t) return oauthError("invalid_grant");
        if (!resourceMatches(req, f.get("resource"), res)) return oauthError("invalid_target");
        let tok;
        try {
          tok = await idc.refresh(t, rt.rt, rt.oc);
        } catch (e) {
          if (!(e instanceof IdcError)) console.error(JSON.stringify({ msg: "refresh_failed", error: (e as Error).name }));
          return { ...oauthError("invalid_grant"), sid: rt.sid };
        }
        return mintPair(req, { sid: rt.sid, cih: rt.cih, oc: tok.clientId, at: tok.accessToken, rt: tok.refreshToken ?? rt.rt, ie: tok.expiresAt, t, res });
      }

      return oauthError("unsupported_grant_type");
    },
  };
}

export type OAuth = ReturnType<typeof createOAuth>;
