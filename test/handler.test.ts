import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { handler } from "../lambda/handler.js";
import { setDeps, type Deps } from "../lambda/deps.js";
import { readRequest } from "../lambda/http.js";
import { loadConfig, redirectUriAllowed } from "../lambda/config.js";
import { FONT_PATHS } from "../lambda/pages.js";
import { BASE, evt, json, type Result } from "./helpers.js";

const call = async (...a: Parameters<typeof evt>) => (await handler(evt(...a))) as Result;

let logSpy: { mock: { calls: unknown[][] } };
beforeEach(() => {
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

describe("discovery metadata", () => {
  it.each(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"])("%s", async (path) => {
    const r = await call("GET", path);
    expect(r.statusCode).toBe(200);
    expect(json(r)).toEqual({ resource: `${BASE}/mcp`, authorization_servers: [BASE] });
    expect(r.headers?.["access-control-allow-origin"]).toBe("*");
  });

  it.each([
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp",
    "/.well-known/openid-configuration",
    "/.well-known/openid-configuration/mcp",
  ])("%s", async (path) => {
    const r = await call("GET", path);
    expect(r.statusCode).toBe(200);
    expect(json(r)).toEqual({
      issuer: BASE,
      authorization_endpoint: `${BASE}/authorize`,
      token_endpoint: `${BASE}/token`,
      registration_endpoint: `${BASE}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [],
    });
  });

  it("uses BASE_URL override when set", async () => {
    vi.stubEnv("BASE_URL", "https://switchboard.example.com");
    const r = await call("GET", "/.well-known/oauth-protected-resource");
    expect(json(r).resource).toBe("https://switchboard.example.com/mcp");
    vi.unstubAllEnvs();
  });
});

describe("CORS", () => {
  it.each(["/.well-known/oauth-authorization-server", "/register", "/token", "/mcp"])("OPTIONS %s → 204", async (path) => {
    const r = await call("OPTIONS", path);
    expect(r.statusCode).toBe(204);
    expect(r.headers).toMatchObject({
      "access-control-allow-origin": "*",
      "access-control-allow-methods": expect.stringContaining("POST"),
      "access-control-allow-headers": expect.stringContaining("authorization"),
    });
  });

  it("exposes WWW-Authenticate and Mcp-Session-Id on /mcp", async () => {
    const r = await call("POST", "/mcp", { body: { jsonrpc: "2.0", id: 1, method: "ping" } });
    expect(r.headers?.["access-control-expose-headers"]).toBe("WWW-Authenticate, Mcp-Session-Id");
  });
});

describe("/mcp transport", () => {
  it("POST without bearer → 401 with resource metadata pointer", async () => {
    const r = await call("POST", "/mcp", { body: { jsonrpc: "2.0", id: 1, method: "initialize" } });
    expect(r.statusCode).toBe(401);
    expect(r.headers?.["www-authenticate"]).toBe(
      `Bearer error="invalid_token", resource_metadata="${BASE}/.well-known/oauth-protected-resource"`,
    );
  });

  it("GET → 405", async () => {
    expect((await call("GET", "/mcp")).statusCode).toBe(405);
  });

  it("DELETE → 200", async () => {
    expect((await call("DELETE", "/mcp")).statusCode).toBe(200);
  });

  it("unknown path → 404", async () => {
    expect((await call("GET", "/nope")).statusCode).toBe(404);
  });
});

describe("request parsing", () => {
  it("decodes base64 form bodies and cookies", () => {
    const req = readRequest(
      evt("POST", "/token", {
        body: "grant_type=refresh_token&refresh_token=abc",
        base64: true,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        cookies: ["sb_nonce=n1", "other=x=y"],
      }),
    );
    expect(req.form().get("grant_type")).toBe("refresh_token");
    expect(req.cookies).toEqual({ sb_nonce: "n1", other: "x=y" });
    expect(req.baseUrl).toBe(BASE);
  });

  it("parses JSON bodies as form-equivalent params", () => {
    const req = readRequest(evt("POST", "/token", { body: { grant_type: "authorization_code", code: "c" }, headers: { "content-type": "application/json" } }));
    expect(req.form().get("code")).toBe("c");
  });
});

describe("access log", () => {
  it("logs one line per request without query, headers or body", async () => {
    await call("GET", "/.well-known/oauth-authorization-server", { query: "code=SECRETCODE", headers: { authorization: "Bearer SECRETTOKEN" } });
    const lines = logSpy.mock.calls.map((c) => String(c[0]));
    const access = lines.filter((l) => l.includes('"access"'));
    expect(access).toHaveLength(1);
    expect(JSON.parse(access[0]!)).toMatchObject({ msg: "access", method: "GET", path: "/.well-known/oauth-authorization-server", status: 200 });
    expect(lines.join("\n")).not.toMatch(/SECRETCODE|SECRETTOKEN/);
  });
});

describe("redirectUriAllowed", () => {
  const patterns = loadConfig({}).allowedRedirectUris;
  it.each([
    "http://localhost:6274/oauth/callback",
    "http://127.0.0.1:33418/callback",
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
  ])("accepts %s", (uri) => expect(redirectUriAllowed(uri, patterns)).toBe(true));

  it.each([
    "https://evil.example/cb",
    "http://localhost.evil.com/cb",
    "http://localhost:1@evil.com/cb",
    "https://localhost:6274/cb",
    "http://user@localhost:6274/cb",
    "https://claude.ai/api/mcp/auth_callback/../x",
    "https://claude.ai/api/mcp/auth_callback?x=1",
    "not a url",
  ])("rejects %s", (uri) => expect(redirectUriAllowed(uri, patterns)).toBe(false));
});

describe("loadConfig", () => {
  it("applies the defaults", () => {
    const c = loadConfig({});
    expect(c.awsMcpEndpoint).toBe("https://aws-mcp.eu-central-1.api.aws/mcp");
    expect(c.awsMcpRegion).toBe("eu-central-1");
    expect(c.allowedRolePattern.test("ReadOnlyAccess")).toBe(true);
    expect(c.allowedRolePattern.test("ViewOnlyAccess")).toBe(true);
    expect(c.allowedRolePattern.test("AdministratorAccess")).toBe(false);
    expect(c.allowedRolePattern.test("XReadOnlyAccess")).toBe(false);
    expect([...c.docsTools].sort()).toEqual([
      "aws___get_regional_availability",
      "aws___list_regions",
      "aws___read_documentation",
      "aws___retrieve_skill",
      "aws___search_documentation",
    ]);
    expect(c.accessTtlSeconds).toBe(3600);
  });

  it("reads overrides", () => {
    const c = loadConfig({ ALLOWED_ROLE_PATTERN: "^Foo$", DOCS_TOOLS: "a, b", ACCESS_TTL_SECONDS: "120", ALLOWED_REDIRECT_URIS: "https://x.example/cb" });
    expect(c.allowedRolePattern.test("Foo")).toBe(true);
    expect([...c.docsTools]).toEqual(["a", "b"]);
    expect(c.accessTtlSeconds).toBe(120);
    expect(c.allowedRedirectUris).toEqual(["https://x.example/cb"]);
  });
});

describe("OAuth routing", () => {
  const oauth = {
    register: vi.fn(async () => ({ status: 201, body: "reg" })),
    authorize: vi.fn(async () => ({ status: 200, body: "page", cookies: ["sb_nonce=x"] })),
    poll: vi.fn(async () => ({ status: 200, body: "poll", sid: "S1" })),
    token: vi.fn(async () => ({ status: 200, body: "tok" })),
  };
  beforeEach(() => setDeps({ oauth } as unknown as Deps));
  afterEach(() => setDeps(undefined));

  it.each([
    ["POST", "/register", "reg", "register"],
    ["GET", "/authorize", "page", "authorize"],
    ["POST", "/poll", "poll", "poll"],
    ["POST", "/token", "tok", "token"],
  ] as const)("%s %s dispatches to oauth.%s", async (method, path, body, fn) => {
    const r = await call(method, path);
    expect(r.body).toBe(body);
    expect(oauth[fn]).toHaveBeenCalled();
  });

  it("passes cookies through and logs sid", async () => {
    expect((await call("GET", "/authorize")).cookies).toEqual(["sb_nonce=x"]);
    await call("POST", "/poll");
    expect(String(logSpy.mock.calls.at(-1)?.[0])).toContain('"sid":"S1"');
  });

  it("CORS on /register and /token, not on /authorize or /poll", async () => {
    expect((await call("POST", "/register")).headers?.["access-control-allow-origin"]).toBe("*");
    expect((await call("POST", "/token")).headers?.["access-control-allow-origin"]).toBe("*");
    expect((await call("GET", "/authorize")).headers?.["access-control-allow-origin"]).toBeUndefined();
    expect((await call("POST", "/poll")).headers?.["access-control-allow-origin"]).toBeUndefined();
  });

  it("wrong methods → 405", async () => {
    expect((await call("GET", "/token")).statusCode).toBe(405);
    expect((await call("POST", "/authorize")).statusCode).toBe(405);
  });
});

describe("static assets", () => {
  it("serves fonts base64-encoded with immutable caching, no CORS", async () => {
    const r = await call("GET", FONT_PATHS[0]!);
    expect(r.statusCode).toBe(200);
    expect(r.isBase64Encoded).toBe(true);
    expect(r.headers?.["content-type"]).toBe("font/woff2");
    expect(r.headers?.["cache-control"]).toContain("immutable");
    expect(r.headers?.["access-control-allow-origin"]).toBeUndefined();
  });

  it("unknown asset → 404", async () => {
    expect((await call("GET", "/assets/x.woff2")).statusCode).toBe(404);
  });
});

describe("tenant routes", () => {
  const TP = "/mcp/d-1234567890/eu-west-1";
  const managed = () => {
    vi.stubEnv("SWITCHBOARD_MODE", "managed");
    setDeps(undefined);
  };
  afterEach(() => {
    vi.unstubAllEnvs();
    setDeps(undefined);
  });

  it("managed: path-inserted protected-resource metadata names the tenant URL", async () => {
    managed();
    const r = await call("GET", `/.well-known/oauth-protected-resource${TP}`);
    expect(r.statusCode).toBe(200);
    expect(json(r)).toEqual({ resource: `${BASE}${TP}`, authorization_servers: [BASE] });
  });

  it("managed: OPTIONS on a tenant MCP URL → 204", async () => {
    managed();
    expect((await call("OPTIONS", TP)).statusCode).toBe(204);
  });

  it.each(["/mcp/evil.com", "/mcp/d-1234567890/mars-1", "/.well-known/oauth-protected-resource/mcp/evil.com"])("managed: %s → 404", async (path) => {
    managed();
    expect((await call("GET", path)).statusCode).toBe(404);
  });

  it.each([TP, `/.well-known/oauth-protected-resource${TP}`])("single mode: %s → 404", async (path) => {
    setDeps(undefined);
    expect((await call("GET", path)).statusCode).toBe(404);
  });
});

describe("origin secret (behind CloudFront)", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("ORIGIN_SECRET set: requests without the matching x-origin-verify header → 403, before any work", async () => {
    vi.stubEnv("ORIGIN_SECRET", "s3cret-value");
    for (const headers of [{}, { "x-origin-verify": "wrong" }, { "x-origin-verify": "s3cret-valu" }] as Record<string, string>[]) {
      const r = await call("GET", "/.well-known/oauth-protected-resource", { headers });
      expect(r.statusCode).toBe(403);
    }
  });

  it("ORIGIN_SECRET set: matching header passes", async () => {
    vi.stubEnv("ORIGIN_SECRET", "s3cret-value");
    const r = await call("GET", "/.well-known/oauth-protected-resource", { headers: { "x-origin-verify": "s3cret-value" } });
    expect(r.statusCode).toBe(200);
  });

  it("ORIGIN_SECRET unset: no check (plain Function URL deployments)", async () => {
    expect((await call("GET", "/.well-known/oauth-protected-resource")).statusCode).toBe(200);
  });
});

describe("landing page", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    setDeps(undefined);
  });

  it("GET / → HTML with a nonce'd script and the shared connector URL", async () => {
    setDeps(undefined);
    const r = await call("GET", "/");
    expect(r.statusCode).toBe(200);
    expect(r.headers?.["content-type"]).toContain("text/html");
    const nonce = /script-src 'nonce-([^']+)'/.exec(r.headers?.["content-security-policy"] ?? "")?.[1];
    expect(nonce).toBeTruthy();
    expect(r.body).toContain(`<script nonce="${nonce}">`);
    expect(r.body).toContain(`${BASE}/mcp<`);
  });

  it("managed shows the builder; BRANDING=off drops till-it-works links; REPO_URL overrides the repo link", async () => {
    vi.stubEnv("SWITCHBOARD_MODE", "managed");
    vi.stubEnv("BRANDING", "off");
    vi.stubEnv("REPO_URL", "https://git.example/fork");
    setDeps(undefined);
    const r = await call("GET", "/");
    expect(r.body).toContain('id="d"');
    expect(r.body).toContain('href="https://git.example/fork"');
    expect(r.body).not.toContain("costpulse");
  });

  it("HOSTED_NOTICE=on shows the exploration-only notice linking the repo; off by default", async () => {
    setDeps(undefined);
    expect((await call("GET", "/")).body).not.toContain('class="notice');
    vi.stubEnv("HOSTED_NOTICE", "on");
    setDeps(undefined);
    const b = (await call("GET", "/")).body!;
    expect(b).toMatch(/class="notice[\s\S]*Exploration only[\s\S]*npm i github:till-it-works\/aws-mcp-switchboard/);
  });

  it("serves operator legal pages at /<slug> (GET only) and puts the links in the footer", async () => {
    vi.stubEnv("SWITCHBOARD_LEGAL", JSON.stringify({ pages: [{ slug: "terms", title: "Terms", html: "<p>hello</p>" }], links: [{ label: "Terms", href: "/terms" }] }));
    setDeps(undefined);
    const r = await call("GET", "/terms");
    expect(r.statusCode).toBe(200);
    expect(r.body).toContain('<article class="doc"><p>hello</p></article>');
    expect((await call("GET", "/")).body).toContain('<a href="/terms">Terms</a>');
    expect((await call("GET", "/privacy")).statusCode).toBe(404);
    expect((await call("POST", "/terms")).statusCode).toBe(404);
  });

  it("POST / → 405", async () => {
    expect((await call("POST", "/")).statusCode).toBe(405);
  });
});
