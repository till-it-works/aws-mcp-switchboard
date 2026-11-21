/** Environment configuration and redirect-URI policy. */
import { parseLegal, type Legal } from "./legal.js";

export type Mode = "single" | "managed";

export interface Config {
  /** single: one Identity Center fixed at deploy time. managed: any Identity Center, chosen per connector URL or at login. */
  mode: Mode;
  idcRegion: string;
  idcStartUrl: string;
  awsMcpEndpoint: string;
  awsMcpRegion: string;
  /** SSM parameter path prefix for the IdC OIDC client registrations (`<prefix>/<region>`). */
  oidcParamPrefix: string;
  kmsKeyArn: string;
  allowedRedirectUris: string[];
  allowedRolePattern: RegExp;
  docsTools: Set<string>;
  accessTtlSeconds: number;
  /** till-it-works branding on the pages (BRANDING=off removes it). */
  branding: boolean;
  /** Source repo linked from the landing page ("deploy in your own account"). */
  repoUrl: string;
  /** Operator-hosted demo (HOSTED_NOTICE=on): pages say "exploration only, rate-limited, self-host". */
  hostedNotice: boolean;
  /** Operator legal pages + footer links (inlined into the bundle by the stack). */
  legal: Legal;
}

export const DEFAULT_REPO_URL = "https://github.com/till-it-works/aws-mcp-switchboard";

export const DEFAULT_REDIRECT_URIS = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
  "https://chatgpt.com/connector_platform_oauth_redirect",
  "https://vscode.dev/redirect",
  "http://localhost:*",
  "http://127.0.0.1:*",
];

/** Upstream tools that never act on a user's behalf (verified against the AWS MCP Server). */
export const DEFAULT_DOCS_TOOLS = [
  "aws___search_documentation",
  "aws___read_documentation",
  "aws___retrieve_skill",
  "aws___list_regions",
  "aws___get_regional_availability",
];

const list = (v: string | undefined, dflt: string[]) =>
  v === undefined || v.trim() === "" ? dflt : v.split(",").map((s) => s.trim()).filter(Boolean);

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const mode = env.SWITCHBOARD_MODE ?? "single";
  if (mode !== "single" && mode !== "managed") throw new Error(`SWITCHBOARD_MODE must be "single" or "managed", got ${JSON.stringify(mode)}`);
  const oidcParamPrefix = (env.OIDC_PARAM_PREFIX ?? "/mcp-switchboard/oidc").replace(/\/+$/, "");
  // SSM reserves names starting with "aws" or "ssm" (case-insensitive, leading slash or not): GetParameter fails with AccessDeniedException.
  if (/^\/?(aws|ssm)/i.test(oidcParamPrefix)) throw new Error(`OIDC_PARAM_PREFIX must not start with "aws" or "ssm" (reserved by SSM), got ${JSON.stringify(oidcParamPrefix)}`);
  return {
    mode,
    idcRegion: env.IDC_REGION ?? "eu-central-1",
    idcStartUrl: env.IDC_START_URL ?? "",
    awsMcpEndpoint: env.AWS_MCP_ENDPOINT ?? "https://aws-mcp.eu-central-1.api.aws/mcp",
    awsMcpRegion: env.AWS_MCP_REGION ?? "eu-central-1",
    oidcParamPrefix,
    kmsKeyArn: env.KMS_KEY_ARN ?? "",
    allowedRedirectUris: list(env.ALLOWED_REDIRECT_URIS, DEFAULT_REDIRECT_URIS),
    allowedRolePattern: new RegExp(env.ALLOWED_ROLE_PATTERN ?? "^(ReadOnlyAccess|ViewOnlyAccess)$"),
    docsTools: new Set(list(env.DOCS_TOOLS, DEFAULT_DOCS_TOOLS)),
    accessTtlSeconds: Number(env.ACCESS_TTL_SECONDS ?? 3600) || 3600,
    branding: env.BRANDING !== "off",
    repoUrl: env.REPO_URL || DEFAULT_REPO_URL,
    hostedNotice: env.HOSTED_NOTICE === "on",
    // esbuild `define` replaces process.env.SWITCHBOARD_LEGAL with the operator JSON at bundle time.
    legal: parseLegal(env.SWITCHBOARD_LEGAL ?? process.env.SWITCHBOARD_LEGAL),
  };
}

/**
 * `scheme://host:*` entries match that exact scheme + hostname with any explicit port and no userinfo;
 * every other entry must match the URI string exactly.
 */
export function redirectUriAllowed(uri: string, patterns: string[]): boolean {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  return patterns.some((p) => {
    if (!p.endsWith(":*")) return uri === p;
    let base: URL;
    try {
      base = new URL(p.slice(0, -2));
    } catch {
      return false;
    }
    return (
      u.protocol === base.protocol &&
      u.hostname === base.hostname &&
      u.port !== "" &&
      u.username === "" &&
      u.password === "" &&
      uri.startsWith(`${base.protocol}//${base.hostname}:${u.port}`)
    );
  });
}
