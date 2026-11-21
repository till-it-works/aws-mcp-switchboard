/** Lambda Function URL entry point: routing, CORS, access log, error mapping. */
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { LambdaFunctionURLEvent, LambdaFunctionURLResult } from "aws-lambda";
import { jsonRes, readRequest, type Req, type Res } from "./http.js";
import { getDeps } from "./deps.js";
import { fontAsset, htmlRes, landingPage, legalPage, siteInfo } from "./pages.js";
import { parseMcpPath } from "./tenant.js";

const CORS_BASE = { "access-control-allow-origin": "*" };
const CORS_MCP = { ...CORS_BASE, "access-control-expose-headers": "WWW-Authenticate, Mcp-Session-Id" };
const CORS_PREFLIGHT = {
  "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, mcp-session-id, mcp-protocol-version",
  "access-control-max-age": "86400",
};

const PRM = "/.well-known/oauth-protected-resource";
const isCorsPath = (p: string) => p.startsWith("/.well-known/") || p === "/register" || p === "/token" || parseMcpPath(p) !== null;
const managed = () => getDeps().cfg.mode === "managed";

/** MCP resource path this request addresses: /mcp always, /mcp/<d>/<r> in managed mode only. */
function mcpResource(path: string): string | null {
  const t = parseMcpPath(path);
  if (!t) return null;
  return t.kind === "shared" || managed() ? path : null;
}

function protectedResource(req: Req, res: string): Res {
  return jsonRes(200, { resource: `${req.baseUrl}${res}`, authorization_servers: [req.baseUrl] });
}

function landing(req: Req): Res {
  const { cfg } = getDeps();
  const scriptNonce = randomBytes(16).toString("base64url");
  const page = landingPage({
    baseUrl: req.baseUrl,
    rolePattern: cfg.allowedRolePattern.source,
    scriptNonce,
    repoUrl: cfg.repoUrl,
    branding: cfg.branding,
    hosted: cfg.hostedNotice ? cfg.repoUrl : undefined,
    links: cfg.legal.links,
    single: cfg.mode === "single" ? siteInfo(cfg) : undefined,
  });
  return htmlRes(200, page, { scriptNonce });
}

function authorizationServer(req: Req): Res {
  const b = req.baseUrl;
  return jsonRes(200, {
    issuer: b,
    authorization_endpoint: `${b}/authorize`,
    token_endpoint: `${b}/token`,
    registration_endpoint: `${b}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [],
  });
}

async function route(req: Req): Promise<Res> {
  const { method, path } = req;
  if (method === "OPTIONS" && isCorsPath(path)) return { status: 204, headers: { ...CORS_PREFLIGHT } };

  if (method === "GET") {
    if (path === PRM) return protectedResource(req, "/mcp");
    if (path.startsWith(`${PRM}/`)) {
      const res = mcpResource(path.slice(PRM.length));
      if (res) return protectedResource(req, res);
    }
    if (
      path === "/.well-known/oauth-authorization-server" ||
      path === "/.well-known/oauth-authorization-server/mcp" ||
      path === "/.well-known/openid-configuration" ||
      path === "/.well-known/openid-configuration/mcp"
    ) {
      return authorizationServer(req);
    }
    const asset = fontAsset(path);
    if (asset) return asset;
  }

  const only = (m: string, fn: () => Promise<Res>) => (method === m ? fn() : Promise.resolve(jsonRes(405, { error: "method_not_allowed" }, { allow: m })));
  if (path === "/register") return only("POST", () => getDeps().oauth.register(req));
  if (path === "/") return only("GET", async () => landing(req));
  if (path === "/authorize") return only("GET", () => getDeps().oauth.authorize(req));
  if (path === "/poll") return only("POST", () => getDeps().oauth.poll(req));
  if (path === "/token") return only("POST", () => getDeps().oauth.token(req));

  if (mcpResource(path)) {
    if (method === "POST") return getDeps().mcp.handle(req);
    if (method === "DELETE") return { status: 200 };
    return jsonRes(405, { error: "method_not_allowed" }, { allow: "POST, DELETE" });
  }

  if (method === "GET") {
    const { cfg } = getDeps();
    const page = cfg.legal.pages.find((p) => path === `/${p.slug}`);
    if (page) return htmlRes(200, legalPage({ page, links: cfg.legal.links, branding: cfg.branding }));
  }
  return jsonRes(404, { error: "not_found" });
}

/** Behind CloudFront: only requests carrying the origin secret header are served (direct Function URL calls get 403). */
function fromOrigin(req: Req): boolean {
  const secret = process.env.ORIGIN_SECRET;
  if (!secret) return true;
  const a = Buffer.from(req.headers["x-origin-verify"] ?? "");
  const b = Buffer.from(secret);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function handler(event: LambdaFunctionURLEvent): Promise<LambdaFunctionURLResult> {
  const started = Date.now();
  const req = readRequest(event);
  let res: Res;
  try {
    res = fromOrigin(req) ? await route(req) : jsonRes(403, { error: "forbidden" });
  } catch (e) {
    console.error(JSON.stringify({ msg: "unhandled", path: req.path, error: (e as Error).name }));
    res = jsonRes(500, { error: "server_error" });
  }
  if (isCorsPath(req.path)) res.headers = { ...(parseMcpPath(req.path) ? CORS_MCP : CORS_BASE), ...res.headers };
  console.log(
    JSON.stringify({ msg: "access", method: req.method, path: req.path, status: res.status, ms: Date.now() - started, ...(res.sid ? { sid: res.sid } : {}) }),
  );
  return { statusCode: res.status, headers: res.headers, body: res.body, cookies: res.cookies, isBase64Encoded: res.isBase64Encoded };
}
