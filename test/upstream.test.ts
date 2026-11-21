import { beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../lambda/config.js";
import {
  createUpstream,
  TargetRequiredError,
  UpstreamError,
  UpstreamForbiddenError,
  type Creds,
} from "../lambda/upstream.js";

const cfg = loadConfig({ AWS_MCP_ENDPOINT: "https://aws-mcp.eu-central-1.api.aws/mcp", AWS_MCP_REGION: "eu-central-1" });
const LAMBDA: Creds = { accessKeyId: "AKIALAMBDA", secretAccessKey: "s1", sessionToken: "tok-lambda" };
const ROLE: Creds = { accessKeyId: "ASIAROLE", secretAccessKey: "s2", sessionToken: "tok-role" };

interface Sent {
  headers: Record<string, string>;
  body: { jsonrpc: string; id?: number; method: string; params?: Record<string, unknown> & { _meta?: Record<string, unknown> } };
}
let sent: Sent[];
let responder: (b: Sent["body"], i: number) => Response;

const jsonResp = (o: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json", ...headers } });
const ok = (id: number | undefined, result: unknown, headers?: Record<string, string>) => jsonResp({ jsonrpc: "2.0", id, result }, headers);

/** Default upstream: initialize → session S1, notification → 202, everything else echoes the method. */
function defaultResponder(b: Sent["body"]): Response {
  if (b.method === "initialize") return ok(b.id, { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "x" } }, { "mcp-session-id": "S1" });
  if (b.method === "notifications/initialized") return new Response(null, { status: 202 });
  return ok(b.id, { echo: b.method });
}

const fetchMock = vi.fn(async (_url: string | URL, init?: RequestInit) => {
  const headers = Object.fromEntries(Object.entries(init!.headers as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]));
  const body = JSON.parse(String(init!.body)) as Sent["body"];
  sent.push({ headers, body });
  return responder(body, sent.length - 1);
});

const mk = () => createUpstream({ cfg, fetch: fetchMock as unknown as typeof fetch, lambdaCreds: async () => LAMBDA });

beforeEach(() => {
  sent = [];
  responder = defaultResponder;
  fetchMock.mockClear();
});

describe("selectCredentials", () => {
  it("uses Lambda creds for tools/list and docs tools", async () => {
    const u = mk();
    expect(await u.selectCredentials({ kind: "tools/list" })).toBe(LAMBDA);
    expect(await u.selectCredentials({ kind: "call", tool: "aws___search_documentation" })).toBe(LAMBDA);
  });

  it("requires Target creds for every other tool, even if a target is absent", async () => {
    const u = mk();
    await expect(u.selectCredentials({ kind: "call", tool: "aws___run_script" })).rejects.toBeInstanceOf(TargetRequiredError);
    await expect(u.selectCredentials({ kind: "call", tool: "aws___get_tasks" })).rejects.toBeInstanceOf(TargetRequiredError);
    expect(await u.selectCredentials({ kind: "call", tool: "aws___run_script", target: { creds: ROLE } })).toBe(ROLE);
  });

  it("prefers Target creds for a docs tool when a target is supplied", async () => {
    expect(await mk().selectCredentials({ kind: "call", tool: "aws___search_documentation", target: { creds: ROLE } })).toBe(ROLE);
  });
});

describe("callTool session", () => {
  it("signs initialize, initialized and call with the role creds only", async () => {
    const r = await mk().callTool("aws___run_script", { code: "1" }, { target: { creds: ROLE } });
    expect(r).toEqual({ result: { echo: "tools/call" }, sessionId: "S1" });
    expect(sent.map((s) => s.body.method)).toEqual(["initialize", "notifications/initialized", "tools/call"]);
    for (const s of sent) {
      expect(s.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=ASIAROLE\/\d{8}\/eu-central-1\/aws-mcp\/aws4_request/);
      expect(s.headers["x-amz-security-token"]).toBe("tok-role");
      expect(s.headers["x-amz-date"]).toMatch(/^\d{8}T\d{6}Z$/);
      expect(s.headers.accept).toBe("application/json, text/event-stream");
      expect(s.body.params?._meta?.AWS_REGION).toBe("eu-central-1");
    }
    expect(sent[0]!.headers["mcp-session-id"]).toBeUndefined();
    expect(sent[1]!.headers["mcp-session-id"]).toBe("S1");
    expect(sent[2]!.headers["mcp-session-id"]).toBe("S1");
    expect(sent[2]!.body.params).toMatchObject({ name: "aws___run_script", arguments: { code: "1" } });
    expect(sent[1]!.body.id).toBeUndefined();
  });

  it("merges client _meta with AWS_REGION", async () => {
    await mk().callTool("aws___list_regions", {}, { meta: { progressToken: 7 } });
    expect(sent[2]!.body.params?._meta).toEqual({ progressToken: 7, AWS_REGION: "eu-central-1" });
  });

  it("with an existing session id skips initialize (task polling)", async () => {
    const r = await mk().callTool("aws___get_tasks", { task_ids: ["t"] }, { target: { creds: ROLE }, sessionId: "OLD" });
    expect(sent.map((s) => s.body.method)).toEqual(["tools/call"]);
    expect(sent[0]!.headers["mcp-session-id"]).toBe("OLD");
    expect(r.sessionId).toBe("OLD");
  });

  it("passes JSON-RPC errors through", async () => {
    responder = (b) => (b.method === "tools/call" ? jsonResp({ jsonrpc: "2.0", id: b.id, error: { code: -32602, message: "Unknown tool" } }) : defaultResponder(b));
    expect(await mk().callTool("aws___list_regions", {})).toMatchObject({ error: { code: -32602, message: "Unknown tool" } });
  });

  it("parses SSE with interleaved notifications and multi-line data", async () => {
    responder = (b) => {
      if (b.method !== "tools/call") return defaultResponder(b);
      const sse = [
        `event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}\n`,
        `data: {"jsonrpc":"2.0","id":999,"result":{"wrong":true}}\n`,
        `data: {"jsonrpc":"2.0","id":${b.id},\ndata: "result":{"ok":1}}\n`,
        "",
      ].join("\n");
      return new Response(sse, { status: 200, headers: { "content-type": "text/event-stream" } });
    };
    expect((await mk().callTool("aws___list_regions", {})).result).toEqual({ ok: 1 });
  });

  it("403 → UpstreamForbiddenError, 401 → UpstreamError(401)", async () => {
    responder = (b) => (b.method === "tools/call" ? new Response("denied", { status: 403 }) : defaultResponder(b));
    await expect(mk().callTool("aws___run_script", {}, { target: { creds: ROLE } })).rejects.toBeInstanceOf(UpstreamForbiddenError);
    responder = () => new Response("", { status: 401 });
    await expect(mk().callTool("aws___list_regions", {})).rejects.toMatchObject({ name: "UpstreamError", status: 401 });
    await expect(mk().callTool("aws___list_regions", {})).rejects.toBeInstanceOf(UpstreamError);
  });

  it("refuses a non-docs tool without target before any network call", async () => {
    await expect(mk().callTool("aws___run_script", {})).rejects.toBeInstanceOf(TargetRequiredError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("getToolList", () => {
  it("follows nextCursor, uses Lambda creds and caches per container", async () => {
    responder = (b) => {
      if (b.method !== "tools/list") return defaultResponder(b);
      return b.params?.cursor ? ok(b.id, { tools: [{ name: "b" }] }) : ok(b.id, { tools: [{ name: "a" }], nextCursor: "c1" });
    };
    const u = mk();
    expect((await u.getToolList()).map((t) => t.name)).toEqual(["a", "b"]);
    expect(sent.filter((s) => s.body.method === "tools/list").map((s) => s.body.params?.cursor)).toEqual([undefined, "c1"]);
    expect(sent.every((s) => s.headers.authorization!.includes("Credential=AKIALAMBDA/"))).toBe(true);
    const n = sent.length;
    await u.getToolList();
    expect(sent.length).toBe(n);
  });

  it("does not cache failures", async () => {
    responder = () => new Response("", { status: 500 });
    const u = mk();
    await expect(u.getToolList()).rejects.toBeInstanceOf(UpstreamError);
    responder = (b) => (b.method === "tools/list" ? ok(b.id, { tools: [{ name: "a" }] }) : defaultResponder(b));
    expect(await u.getToolList()).toHaveLength(1);
  });
});
