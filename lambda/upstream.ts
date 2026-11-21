/**
 * Stateless client for the AWS MCP Server. Every request is SigV4-signed (service `aws-mcp`).
 * Credentials are chosen in exactly one place — selectCredentials — so only DOCS_TOOLS (+ tools/list)
 * can ever run with the Lambda role's credentials.
 */
import { SignatureV4 } from "@smithy/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";
import type { Config } from "./config.js";

export interface Creds {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface Target {
  creds: Creds;
}

export type Purpose = { kind: "tools/list" } | { kind: "call"; tool: string; target?: Target };

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface UpstreamResult {
  result?: Record<string, unknown>;
  error?: JsonRpcError;
  sessionId?: string;
}

export interface Tool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
  [k: string]: unknown;
}

export class TargetRequiredError extends Error {
  constructor(readonly tool: string) {
    super(`${tool} requires account_id and role_name`);
    this.name = "TargetRequiredError";
  }
}

export class UpstreamError extends Error {
  constructor(readonly status: number) {
    super(`upstream HTTP ${status}`);
    this.name = "UpstreamError";
  }
}

export class UpstreamForbiddenError extends UpstreamError {
  constructor() {
    super(403);
    this.name = "UpstreamForbiddenError";
  }
}

const PROTOCOL_VERSION = "2025-06-18";
const SIGNING_SERVICE = "aws-mcp";
/** Upstream holds slow calls ~96 s; stay below the 300 s Lambda timeout. */
const REQUEST_TIMEOUT_MS = 270_000;

/** Returns the JSON-RPC message with the given id from an SSE body (events separated by blank lines). */
export function parseSse(text: string, id: number): Record<string, unknown> | undefined {
  for (const event of text.split(/\r?\n\r?\n/)) {
    const data = event
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(l.startsWith("data: ") ? 6 : 5))
      .join("\n");
    if (!data) continue;
    try {
      const m = JSON.parse(data) as Record<string, unknown>;
      if (m.id === id) return m;
    } catch {
      /* non-JSON event */
    }
  }
  return undefined;
}

export function lambdaCredsFromEnv(env: Record<string, string | undefined> = process.env): Promise<Creds> {
  return Promise.resolve({
    accessKeyId: env.AWS_ACCESS_KEY_ID ?? "",
    secretAccessKey: env.AWS_SECRET_ACCESS_KEY ?? "",
    sessionToken: env.AWS_SESSION_TOKEN,
  });
}

export function createUpstream(deps: { cfg: Config; fetch?: typeof fetch; lambdaCreds?: () => Promise<Creds> }) {
  const { cfg } = deps;
  const doFetch = deps.fetch ?? fetch;
  const lambdaCreds = deps.lambdaCreds ?? (() => lambdaCredsFromEnv());
  const endpoint = new URL(cfg.awsMcpEndpoint);
  let toolList: Promise<Tool[]> | undefined;

  /** The single place that decides which credentials an upstream session uses. */
  async function selectCredentials(purpose: Purpose): Promise<Creds> {
    if (purpose.kind === "call" && purpose.target) return purpose.target.creds;
    if (purpose.kind === "tools/list" || cfg.docsTools.has(purpose.tool)) return lambdaCreds();
    throw new TargetRequiredError(purpose.tool);
  }

  /** One upstream session: all requests share the credentials and Mcp-Session-Id. */
  function session(creds: Creds, sessionId?: string) {
    let nextId = 1;
    const signer = new SignatureV4({ credentials: creds, service: SIGNING_SERVICE, region: cfg.awsMcpRegion, sha256: Sha256 });

    async function send(method: string, params: Record<string, unknown> | undefined, notification = false): Promise<Record<string, unknown> | undefined> {
      const id = notification ? undefined : nextId++;
      const p: Record<string, unknown> = { ...(params ?? {}) };
      p._meta = { ...((p._meta as Record<string, unknown> | undefined) ?? {}), AWS_REGION: cfg.awsMcpRegion };
      const body = JSON.stringify({ jsonrpc: "2.0", ...(id !== undefined ? { id } : {}), method, params: p });
      const headers: Record<string, string> = {
        host: endpoint.host,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      };
      if (sessionId) headers["mcp-session-id"] = sessionId;
      if (method !== "initialize") headers["mcp-protocol-version"] = PROTOCOL_VERSION;
      const signed = await signer.sign({
        method: "POST",
        protocol: endpoint.protocol,
        hostname: endpoint.hostname,
        path: endpoint.pathname,
        headers,
        body,
      });
      const res = await doFetch(endpoint, {
        method: "POST",
        headers: signed.headers as Record<string, string>,
        body,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      const sid = res.headers.get("mcp-session-id");
      if (sid) sessionId = sid;
      const text = await res.text();
      if (res.status === 403) throw new UpstreamForbiddenError();
      if (res.status < 200 || res.status >= 300) {
        console.error(JSON.stringify({ msg: "upstream_http_error", method, status: res.status, ...(res.status === 401 ? { hint: "signing" } : {}) }));
        throw new UpstreamError(res.status);
      }
      if (notification || id === undefined) return undefined;
      let message: Record<string, unknown> | undefined;
      try {
        message = (res.headers.get("content-type") ?? "").includes("text/event-stream")
          ? parseSse(text, id)
          : (JSON.parse(text) as Record<string, unknown>);
      } catch {
        message = undefined;
      }
      if (!message) throw new UpstreamError(502);
      return message;
    }

    async function initialize(): Promise<void> {
      const m = await send("initialize", {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "aws-mcp-switchboard", version: "1.0.0" },
      });
      if (m?.error) {
        console.error(JSON.stringify({ msg: "upstream_initialize_error", code: (m.error as JsonRpcError).code }));
        throw new UpstreamError(502);
      }
      await send("notifications/initialized", undefined, true);
    }

    async function request(method: string, params: Record<string, unknown>): Promise<UpstreamResult> {
      const m = await send(method, params);
      return { result: m?.result as Record<string, unknown> | undefined, error: m?.error as JsonRpcError | undefined, sessionId };
    }

    return { initialize, request };
  }

  return {
    selectCredentials,

    /**
     * tools/call against a fresh upstream session, or — with `sessionId` — against an existing one
     * (task polling: tasks are bound to the upstream session).
     */
    async callTool(
      tool: string,
      args: Record<string, unknown>,
      opts: { target?: Target; sessionId?: string; meta?: Record<string, unknown> } = {},
    ): Promise<UpstreamResult> {
      const creds = await selectCredentials({ kind: "call", tool, target: opts.target });
      const s = session(creds, opts.sessionId);
      if (!opts.sessionId) await s.initialize();
      const r = await s.request("tools/call", { name: tool, arguments: args, ...(opts.meta ? { _meta: opts.meta } : {}) });
      const { result, error, sessionId } = r;
      return error ? { error, sessionId } : { result, sessionId };
    },

    /** Upstream tool list (Lambda creds), cached per container; follows nextCursor. */
    getToolList(): Promise<Tool[]> {
      toolList ??= (async () => {
        const s = session(await selectCredentials({ kind: "tools/list" }));
        await s.initialize();
        const tools: Tool[] = [];
        let cursor: string | undefined;
        do {
          const r = await s.request("tools/list", cursor ? { cursor } : {});
          if (r.error) throw new UpstreamError(502);
          tools.push(...((r.result?.tools as Tool[] | undefined) ?? []));
          cursor = r.result?.nextCursor as string | undefined;
        } while (cursor);
        return tools;
      })();
      toolList.catch(() => (toolList = undefined));
      return toolList;
    },
  };
}

export type Upstream = ReturnType<typeof createUpstream>;
