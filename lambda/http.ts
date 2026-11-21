/** Normalised request/response shapes over Lambda Function URL events. */
import type { LambdaFunctionURLEvent } from "aws-lambda";

export interface Req {
  method: string;
  path: string;
  query: URLSearchParams;
  /** Lower-cased header names. */
  headers: Record<string, string>;
  cookies: Record<string, string>;
  body: string;
  /** `<scheme>://<host>` of this deployment, no trailing slash. */
  baseUrl: string;
  /** Body as form params (urlencoded, or a flat JSON object). */
  form(): URLSearchParams;
}

export interface Res {
  status: number;
  headers?: Record<string, string>;
  body?: string;
  cookies?: string[];
  /** Body is base64 (binary assets). */
  isBase64Encoded?: boolean;
  /** Login id for the access log only. */
  sid?: string;
}

export function baseUrlFrom(event: LambdaFunctionURLEvent): string {
  const override = process.env.BASE_URL?.trim();
  if (override) return override.replace(/\/+$/, "");
  return `https://${event.requestContext.domainName}`;
}

export function readRequest(event: LambdaFunctionURLEvent): Req {
  const raw = event.body ?? "";
  const body = event.isBase64Encoded ? Buffer.from(raw, "base64").toString("utf8") : raw;
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(event.headers ?? {})) if (v !== undefined) headers[k.toLowerCase()] = v;
  const cookies: Record<string, string> = {};
  for (const c of event.cookies ?? []) {
    const i = c.indexOf("=");
    if (i > 0) cookies[c.slice(0, i).trim()] = c.slice(i + 1).trim();
  }
  return {
    method: event.requestContext.http.method.toUpperCase(),
    path: event.rawPath,
    query: new URLSearchParams(event.rawQueryString ?? ""),
    headers,
    cookies,
    body,
    baseUrl: baseUrlFrom(event),
    form() {
      if ((headers["content-type"] ?? "").includes("application/json")) {
        const out = new URLSearchParams();
        try {
          const obj = JSON.parse(body) as unknown;
          if (obj && typeof obj === "object" && !Array.isArray(obj)) {
            for (const [k, v] of Object.entries(obj)) if (typeof v === "string") out.set(k, v);
          }
        } catch {
          /* invalid JSON → empty params */
        }
        return out;
      }
      return new URLSearchParams(body);
    },
  };
}

export const jsonRes = (status: number, body: unknown, headers: Record<string, string> = {}): Res => ({
  status,
  headers: { "content-type": "application/json", ...headers },
  body: JSON.stringify(body),
});

/** Points at the protected-resource metadata of the MCP URL that was called (path-inserted for tenant URLs, RFC 9728). */
export const wwwAuthenticate = (baseUrl: string, resourcePath = "/mcp") =>
  `Bearer error="invalid_token", resource_metadata="${baseUrl}/.well-known/oauth-protected-resource${resourcePath === "/mcp" ? "" : resourcePath}"`;

export const unauthorized = (baseUrl: string, resourcePath?: string): Res =>
  jsonRes(401, { error: "invalid_token" }, { "www-authenticate": wwwAuthenticate(baseUrl, resourcePath) });
