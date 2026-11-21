import type { LambdaFunctionURLEvent } from "aws-lambda";

export const DOMAIN = "abc123.lambda-url.eu-central-1.on.aws";
export const BASE = `https://${DOMAIN}`;

/** Build a Function URL event. `body` objects are JSON-encoded; strings are passed as-is. */
export function evt(
  method: string,
  path: string,
  opts: {
    query?: string;
    headers?: Record<string, string>;
    body?: string | object;
    base64?: boolean;
    cookies?: string[];
  } = {},
): LambdaFunctionURLEvent {
  let body = typeof opts.body === "object" ? JSON.stringify(opts.body) : opts.body;
  if (body !== undefined && opts.base64) body = Buffer.from(body).toString("base64");
  return {
    version: "2.0",
    routeKey: "$default",
    rawPath: path,
    rawQueryString: opts.query ?? "",
    cookies: opts.cookies,
    headers: { host: DOMAIN, ...(opts.headers ?? {}) },
    queryStringParameters: opts.query ? Object.fromEntries(new URLSearchParams(opts.query)) : undefined,
    requestContext: {
      accountId: "anonymous",
      apiId: "abc123",
      domainName: DOMAIN,
      domainPrefix: "abc123",
      http: { method, path, protocol: "HTTP/1.1", sourceIp: "203.0.113.1", userAgent: "test" },
      requestId: "req-1",
      routeKey: "$default",
      stage: "$default",
      time: "20/Nov/2026:00:00:00 +0000",
      timeEpoch: 0,
    },
    body,
    isBase64Encoded: opts.base64 ?? false,
  };
}

export type Result = { statusCode: number; headers?: Record<string, string>; body?: string; cookies?: string[]; isBase64Encoded?: boolean };
export const json = (r: Result) => JSON.parse(r.body ?? "null") as Record<string, unknown>;
