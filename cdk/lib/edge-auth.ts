import { IDC_REGIONS } from "../../lambda/tenant.js";

/**
 * CloudFront Function (viewer-request) that answers token-less MCP requests itself.
 *
 * Function URLs rename the origin's `WWW-Authenticate` to `x-amzn-Remapped-WWW-Authenticate`, and
 * CloudFront never runs viewer-response functions on origin responses >= 400. So the discovery 401
 * (the first request every MCP client sends) is produced at the edge, where the header survives.
 * Requests that carry a Bearer token go to the origin unchanged.
 *
 * Paths mirror `parseMcpPath`: `/mcp`, plus `/mcp/<directory>[/<region>]` in managed mode.
 * Plain ES5: the cloudfront-js runtime is not a full modern engine.
 */
export function edgeAuthCode({ baseUrl, managed }: { baseUrl: string; managed: boolean }): string {
  const label = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
  const tenant = managed ? `(?:\\/${label}(?:\\/(?:${IDC_REGIONS.join("|").replace(/-/g, "\\-")}))?)?` : "";
  const prm = `${baseUrl}/.well-known/oauth-protected-resource`;
  return [
    `var PATH = /^\\/mcp${tenant}$/;`,
    `var PRM = ${JSON.stringify(prm)};`,
    "function handler(event) {",
    "  var r = event.request;",
    "  if (r.method !== 'POST' || !PATH.test(r.uri)) return r;",
    "  var a = r.headers.authorization;",
    "  if (a && /^bearer\\s+\\S/i.test(a.value)) return r;",
    "  var meta = PRM + (r.uri === '/mcp' ? '' : r.uri);",
    "  return {",
    "    statusCode: 401,",
    "    statusDescription: 'Unauthorized',",
    "    headers: {",
    "      'www-authenticate': { value: 'Bearer resource_metadata=\"' + meta + '\"' },",
    "      'content-type': { value: 'application/json' },",
    "      'cache-control': { value: 'no-store' },",
    "      'access-control-allow-origin': { value: '*' },",
    "      'access-control-expose-headers': { value: 'WWW-Authenticate, Mcp-Session-Id' }",
    "    },",
    "    body: { encoding: 'text', data: '{\"error\":\"invalid_token\"}' }",
    "  };",
    "}",
  ].join("\n");
}
