import { describe, expect, it } from "vitest";
import { edgeAuthCode } from "../cdk/lib/edge-auth.js";
import { parseMcpPath } from "../lambda/tenant.js";

const BASE = "https://sb.example.com";
type Ev = { request: { method: string; uri: string; headers: Record<string, { value: string }> } };
type Out = { statusCode?: number; headers?: Record<string, { value: string }>; body?: { encoding: string; data: string } };

const load = (managed: boolean) =>
  new Function(`${edgeAuthCode({ baseUrl: BASE, managed })}; return handler;`)() as (e: Ev) => Out;
const ev = (uri: string, method = "POST", headers: Record<string, { value: string }> = {}): Ev => ({ request: { method, uri, headers } });

describe("edge auth (CloudFront viewer-request function)", () => {
  const managed = load(true);
  const single = load(false);

  it("answers a token-less POST to /mcp with 401 + WWW-Authenticate pointing at the root PRM", () => {
    const r = managed(ev("/mcp"));
    expect(r.statusCode).toBe(401);
    expect(r.headers!["www-authenticate"]!.value).toBe(`Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource"`);
    expect(r.headers!["access-control-allow-origin"]!.value).toBe("*");
    expect(r.headers!["access-control-expose-headers"]!.value).toContain("WWW-Authenticate");
    expect(r.headers!["content-type"]!.value).toBe("application/json");
    expect(JSON.parse(r.body!.data)).toEqual({ error: "invalid_token" });
  });

  it("tenant paths (managed) point at the path-inserted PRM", () => {
    for (const uri of ["/mcp/d-1234567890/eu-central-1", "/mcp/my-org", "/mcp/my-org/us-east-1"]) {
      expect(managed(ev(uri)).headers!["www-authenticate"]!.value).toBe(`Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource${uri}"`);
    }
  });

  it("matches exactly the tenant paths the Lambda accepts; everything else goes to the origin", () => {
    const paths = ["/mcp/d-1234567890/eu-central-1", "/mcp/D-123", "/mcp/a.b", "/mcp/x/mars-1", "/mcp/x/y/z", "/mcp/", "/mcpx", "/mcp/-x", "/mcp/x/eu-central-1/"];
    for (const p of paths) expect(managed(ev(p)).statusCode === 401, p).toBe(parseMcpPath(p) !== null);
  });

  it("single mode only answers /mcp", () => {
    expect(single(ev("/mcp")).statusCode).toBe(401);
    expect(single(ev("/mcp/d-1234567890/eu-central-1")).statusCode).toBeUndefined();
  });

  it("passes requests with a Bearer token, other methods and other paths through unchanged", () => {
    const withToken = ev("/mcp", "POST", { authorization: { value: "Bearer abc" } });
    expect(managed(withToken)).toBe(withToken.request);
    for (const e of [ev("/mcp", "OPTIONS"), ev("/mcp", "GET"), ev("/", "POST"), ev("/token", "POST")]) expect(managed(e)).toBe(e.request);
  });

  it("a non-Bearer Authorization header still gets the 401", () => {
    expect(managed(ev("/mcp", "POST", { authorization: { value: "Basic Zm9vOmJhcg==" } })).statusCode).toBe(401);
  });

  it("is ES5 (no arrow functions, let/const or template literals) and under the 10 KB limit", () => {
    const code = edgeAuthCode({ baseUrl: BASE, managed: true });
    expect(code).not.toMatch(/=>|\blet\b|\bconst\b|`/);
    expect(code.length).toBeLessThan(10_000);
  });
});
