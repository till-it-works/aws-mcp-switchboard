import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { createSealer } from "../lambda/seal.js";
import { loadConfig } from "../lambda/config.js";
import { IdcError, type Idc } from "../lambda/idc.js";
import { UpstreamError, UpstreamForbiddenError, type Upstream } from "../lambda/upstream.js";
import { createMcp } from "../lambda/mcp.js";
import { readRequest, type Res } from "../lambda/http.js";
import type { AtPayload } from "../lambda/oauth.js";
import { BASE, evt } from "./helpers.js";

const kmsMock = mockClient(KMSClient);
let now = Date.UTC(2026, 10, 20);
const nowS = () => Math.floor(now / 1000);
const AUD = `${BASE}/mcp`;
const cfg = loadConfig({ ALLOWED_ROLE_PATTERN: "^(ReadOnlyAccess|ViewOnlyAccess)$" });
const sealer = createSealer({ kms: new KMSClient({ region: "eu-central-1" }), keyArn: "arn:key", now: () => now });

const ROLE_CREDS = { accessKeyId: "ASIAROLE", secretAccessKey: "s", sessionToken: "t", expiration: now + 3_600_000 };
const UPSTREAM_TOOLS = [
  {
    name: "aws___run_script",
    description: "Run a script.",
    inputSchema: { type: "object", properties: { code: { type: "string" } }, required: ["code"] },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  { name: "aws___search_documentation", description: "Search docs.", inputSchema: { type: "object", properties: { search_phrase: { type: "string" } } }, annotations: { readOnlyHint: true } },
];

const idc = { listAccounts: vi.fn(), listAccountRoles: vi.fn(), getRoleCredentials: vi.fn() };
const upstream = { getToolList: vi.fn(), callTool: vi.fn() };
let mcp: ReturnType<typeof createMcp>;

let logs: string[] = [];
beforeEach(() => {
  now = Date.UTC(2026, 10, 20);
  kmsMock.reset();
  kmsMock.on(GenerateDataKeyCommand).callsFake(() => {
    const k = randomBytes(32);
    return { Plaintext: new Uint8Array(k), CiphertextBlob: new Uint8Array(Buffer.concat([Buffer.from("EDK:"), k])) };
  });
  kmsMock.on(DecryptCommand).callsFake((i) => ({ Plaintext: new Uint8Array(Buffer.from(i.CiphertextBlob as Uint8Array).subarray(4)) }));
  idc.listAccounts.mockReset().mockResolvedValue([
    { accountId: "111111111111", accountName: "prod-payments" },
    { accountId: "222222222222", accountName: "dev-sandbox" },
  ]);
  idc.listAccountRoles.mockReset().mockImplementation(async (_t: unknown, _at: string, id: string) =>
    id === "111111111111" ? ["ReadOnlyAccess", "AdministratorAccess"] : ["ViewOnlyAccess"],
  );
  idc.getRoleCredentials.mockReset().mockResolvedValue(ROLE_CREDS);
  upstream.getToolList.mockReset().mockResolvedValue(UPSTREAM_TOOLS);
  upstream.callTool.mockReset().mockResolvedValue({ result: { content: [{ type: "text", text: "ok" }] }, sessionId: "S1" });
  mcp = createMcp({ cfg, sealer, idc: idc as unknown as Idc, upstream: upstream as unknown as Upstream, now: () => now });
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...a) => void logs.push(a.map(String).join(" ")));
  vi.spyOn(console, "warn").mockImplementation((...a) => void logs.push(a.map(String).join(" ")));
});
afterEach(() => vi.restoreAllMocks());

async function bearer(over: Partial<AtPayload> = {}) {
  const p: AtPayload = { sid: "SID1", cih: "c", at: "IDC_AT", ie: nowS() + 3600, iat: nowS(), exp: nowS() + 3600, ...over };
  return sealer.seal("at", AUD, p);
}
async function rpc(body: string | object, token?: string): Promise<Res> {
  const t = token ?? (await bearer());
  return mcp.handle(readRequest(evt("POST", "/mcp", { body, headers: { "content-type": "application/json", authorization: `Bearer ${t}` } })));
}
const parsed = (r: Res) => JSON.parse(r.body!) as { result?: Record<string, unknown> & { content?: { text: string }[]; isError?: boolean }; error?: { code: number; message: string } };
const call = (name: string, args: Record<string, unknown>, id = 1, token?: string) => rpc({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }, token);

describe("bearer validation", () => {
  it("missing, garbage or wrong-type bearer → 401 with WWW-Authenticate", async () => {
    const noAuth = await mcp.handle(readRequest(evt("POST", "/mcp", { body: { jsonrpc: "2.0", id: 1, method: "ping" } })));
    expect(noAuth.status).toBe(401);
    expect(noAuth.headers?.["www-authenticate"]).toContain("resource_metadata=");
    expect((await rpc({ jsonrpc: "2.0", id: 1, method: "ping" }, "asb1.x.y.z")).status).toBe(401);
    const rt = await sealer.seal("rt", AUD, { exp: nowS() + 3600 });
    expect((await rpc({ jsonrpc: "2.0", id: 1, method: "ping" }, rt)).status).toBe(401);
  });

  it("expired access blob → 401", async () => {
    const t = await bearer({ exp: nowS() - 1 });
    expect((await rpc({ jsonrpc: "2.0", id: 1, method: "ping" }, t)).status).toBe(401);
  });

  it("cached bearer whose IdC token nears expiry → 401", async () => {
    const t = await bearer({ ie: nowS() + 100, exp: nowS() + 3600 });
    expect((await rpc({ jsonrpc: "2.0", id: 1, method: "ping" }, t)).status).toBe(200);
    now += 75_000;
    expect((await rpc({ jsonrpc: "2.0", id: 1, method: "ping" }, t)).status).toBe(401);
  });

  it("valid bearer is unsealed once per container", async () => {
    const t = await bearer();
    kmsMock.resetHistory();
    await rpc({ jsonrpc: "2.0", id: 1, method: "ping" }, t);
    await rpc({ jsonrpc: "2.0", id: 2, method: "ping" }, t);
    expect(kmsMock.commandCalls(DecryptCommand).length).toBeLessThanOrEqual(1);
  });
});

describe("JSON-RPC basics", () => {
  it("ping → {}", async () => {
    const r = await rpc({ jsonrpc: "2.0", id: 7, method: "ping" });
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body!)).toEqual({ jsonrpc: "2.0", id: 7, result: {} });
    expect(r.sid).toBe("SID1");
  });

  it("notifications → 202 empty", async () => {
    for (const method of ["notifications/initialized", "notifications/cancelled"]) {
      const r = await rpc({ jsonrpc: "2.0", method, params: {} });
      expect(r.status).toBe(202);
      expect(r.body ?? "").toBe("");
    }
  });

  it.each([
    ["2025-03-26", "2025-03-26"],
    ["2025-11-25", "2025-11-25"],
    ["2099-01-01", "2025-06-18"],
  ])("initialize echoes %s → %s", async (asked, got) => {
    const r = parsed(await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: asked, capabilities: {}, clientInfo: { name: "x" } } }));
    expect(r.result).toMatchObject({ protocolVersion: got, capabilities: { tools: {} }, serverInfo: { name: "aws-mcp-switchboard" } });
  });

  it("unknown method → -32601; malformed body → -32700/-32600", async () => {
    expect(parsed(await rpc({ jsonrpc: "2.0", id: 1, method: "resources/list" })).error?.code).toBe(-32601);
    expect(parsed(await rpc("not json{")).error?.code).toBe(-32700);
    expect(parsed(await rpc([{ jsonrpc: "2.0", id: 1, method: "ping" }])).error?.code).toBe(-32600);
  });
});

describe("tools/list", () => {
  it("adds list_accounts, rewrites credentialed tools, leaves docs tools untouched", async () => {
    const tools = parsed(await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" })).result!.tools as Record<string, unknown>[];
    const byName = Object.fromEntries(tools.map((t) => [t.name, t])) as Record<string, { inputSchema: { required: string[]; properties: Record<string, { type: string }> }; description: string; annotations: unknown }>;
    expect(Object.keys(byName).sort()).toEqual(["aws___run_script", "aws___search_documentation", "list_accounts"]);
    const rs = byName.aws___run_script!;
    expect(rs.inputSchema.required).toEqual(["code", "account_id", "role_name"]);
    expect(rs.inputSchema.properties.account_id).toMatchObject({ type: "string", pattern: "^\\d{12}$" });
    expect(rs.inputSchema.properties.role_name?.type).toBe("string");
    expect(rs.description).toMatch(/^Runs in the given AWS account\/role\. Call list_accounts first\. Run a script\.$/);
    expect(rs.annotations).toEqual({ readOnlyHint: false, destructiveHint: true });
    expect(byName.aws___search_documentation).toEqual(UPSTREAM_TOOLS[1]);
    expect(byName.list_accounts!.annotations).toMatchObject({ readOnlyHint: true });
    expect(byName.list_accounts!.description).toContain("name_filter");
    expect(UPSTREAM_TOOLS[0]!.inputSchema.required).toEqual(["code"]); // upstream cache not mutated
  });

  it("upstream failure → JSON-RPC error", async () => {
    upstream.getToolList.mockRejectedValueOnce(new UpstreamError(500));
    expect(parsed(await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" })).error?.code).toBe(-32603);
  });
});

describe("list_accounts", () => {
  const content = (r: Res) => {
    const p = parsed(r).result!;
    const fromText = JSON.parse(p.content![0]!.text);
    expect(p.structuredContent).toEqual(fromText);
    return fromText as { allowedRolePattern: string; note: string; accounts: { accountId: string; accountName: string; roles: string[] }[] };
  };

  it("returns the pattern, a note and accounts with allowed roles only", async () => {
    const c = content(await call("list_accounts", {}));
    expect(c.allowedRolePattern).toBe("^(ReadOnlyAccess|ViewOnlyAccess)$");
    expect(c.note).toMatch(/allowedRolePattern/);
    expect(c.accounts).toEqual([
      { accountId: "111111111111", accountName: "prod-payments", roles: ["ReadOnlyAccess"] },
      { accountId: "222222222222", accountName: "dev-sandbox", roles: ["ViewOnlyAccess"] },
    ]);
    expect(idc.listAccounts).toHaveBeenCalledWith(expect.objectContaining({ r: "eu-central-1" }), "IDC_AT");
  });

  it("name_filter matches name substring (case-insensitive) or exact id; roles fetched only for matches", async () => {
    expect(content(await call("list_accounts", { name_filter: "PAYMENTS" })).accounts.map((a) => a.accountId)).toEqual(["111111111111"]);
    expect(idc.listAccountRoles).toHaveBeenCalledTimes(1);
    expect(content(await call("list_accounts", { name_filter: "222222222222" })).accounts.map((a) => a.accountId)).toEqual(["222222222222"]);
  });

  it("caches accounts and roles per sid", async () => {
    await call("list_accounts", {});
    await call("list_accounts", {});
    expect(idc.listAccounts).toHaveBeenCalledTimes(1);
    expect(idc.listAccountRoles).toHaveBeenCalledTimes(2);
    now += 11 * 60_000;
    await call("list_accounts", {}, 3);
    expect(idc.listAccounts).toHaveBeenCalledTimes(2);
  });

  it("expired IdC token on the portal → HTTP 401", async () => {
    idc.listAccounts.mockRejectedValueOnce(new IdcError("token_expired"));
    expect((await call("list_accounts", {})).status).toBe(401);
  });
});

describe("proxied tools/call", () => {
  const args = { code: "print(1)", account_id: "111111111111", role_name: "ReadOnlyAccess" };

  it("strips account_id/role_name and calls upstream with role creds", async () => {
    const r = parsed(await call("aws___run_script", args));
    expect(r.result).toEqual({ content: [{ type: "text", text: "ok" }] });
    expect(idc.getRoleCredentials).toHaveBeenCalledWith(expect.objectContaining({ r: "eu-central-1" }), "IDC_AT", "111111111111", "ReadOnlyAccess");
    const [tool, upArgs, opts] = upstream.callTool.mock.calls[0]!;
    expect(tool).toBe("aws___run_script");
    expect(upArgs).toEqual({ code: "print(1)" });
    expect(opts.target.creds).toBe(ROLE_CREDS);
  });

  it("caches role creds per sid#account#role until 5 min before expiry", async () => {
    await call("aws___run_script", args);
    await call("aws___run_script", args, 2);
    expect(idc.getRoleCredentials).toHaveBeenCalledTimes(1);
    now += 56 * 60_000;
    await call("aws___run_script", args, 3);
    expect(idc.getRoleCredentials).toHaveBeenCalledTimes(2);
  });

  it("disallowed role → tool error naming the pattern, no GetRoleCredentials", async () => {
    const r = parsed(await call("aws___run_script", { ...args, role_name: "AdministratorAccess" })).result!;
    expect(r.isError).toBe(true);
    expect(r.content![0]!.text).toContain("^(ReadOnlyAccess|ViewOnlyAccess)$");
    expect(idc.getRoleCredentials).not.toHaveBeenCalled();
  });

  it.each([
    [{ code: "x", role_name: "ReadOnlyAccess" }],
    [{ code: "x", account_id: "12345", role_name: "ReadOnlyAccess" }],
    [{ code: "x", account_id: "111111111111" }],
  ])("missing/invalid target %j → tool error", async (a) => {
    const r = parsed(await call("aws___run_script", a)).result!;
    expect(r.isError).toBe(true);
    expect(upstream.callTool).not.toHaveBeenCalled();
  });

  it("unassigned account → No access to role …", async () => {
    idc.getRoleCredentials.mockRejectedValueOnce(new IdcError("no_access"));
    const r = parsed(await call("aws___run_script", args)).result!;
    expect(r.isError).toBe(true);
    expect(r.content![0]!.text).toBe("No access to role ReadOnlyAccess in 111111111111");
  });

  it("portal token expired → HTTP 401", async () => {
    idc.getRoleCredentials.mockRejectedValueOnce(new IdcError("token_expired"));
    expect((await call("aws___run_script", args)).status).toBe(401);
  });

  it("upstream 403 → permissions tool error; other upstream HTTP errors → tool error", async () => {
    upstream.callTool.mockRejectedValueOnce(new UpstreamForbiddenError());
    expect(parsed(await call("aws___run_script", args)).result!.content![0]!.text).toBe(
      "Role ReadOnlyAccess in 111111111111 lacks permissions for this call (or for AWS MCP Server).",
    );
    upstream.callTool.mockRejectedValueOnce(new UpstreamError(502));
    const r = parsed(await call("aws___run_script", args, 2)).result!;
    expect(r.isError).toBe(true);
  });

  it("upstream JSON-RPC error passes through", async () => {
    upstream.callTool.mockResolvedValueOnce({ error: { code: -32602, message: "bad args" } });
    expect(parsed(await call("aws___run_script", args)).error).toEqual({ code: -32602, message: "bad args" });
  });

  it("docs tool uses Lambda creds (no target) and passes arguments as-is", async () => {
    await call("aws___search_documentation", { search_phrase: "s3" });
    const [, upArgs, opts] = upstream.callTool.mock.calls[0]!;
    expect(upArgs).toEqual({ search_phrase: "s3" });
    expect(opts.target).toBeUndefined();
    expect(idc.getRoleCredentials).not.toHaveBeenCalled();
  });

  it("every tools/call reply is a bare JSON-RPC response (strict clients drop extra keys like sessionId)", async () => {
    upstream.callTool.mockResolvedValue({ result: { content: [{ type: "text", text: "ok" }] }, sessionId: "UPSTREAM_SID" });
    for (const [name, a] of [["aws___search_documentation", { search_phrase: "s3" }], ["aws___run_script", args]] as const) {
      const r = await call(name, a, 7);
      expect(Object.keys(JSON.parse(r.body!)).sort()).toEqual(["id", "jsonrpc", "result"]);
      expect(r.body).not.toContain("UPSTREAM_SID");
    }
    upstream.callTool.mockResolvedValue({ error: { code: -32602, message: "bad args" }, sessionId: "UPSTREAM_SID" });
    const e = await call("aws___search_documentation", { search_phrase: "s3" }, 8);
    expect(Object.keys(JSON.parse(e.body!)).sort()).toEqual(["error", "id", "jsonrpc"]);
  });

  it("unknown tool → -32602", async () => {
    expect(parsed(await call("aws___nope", {})).error?.code).toBe(-32602);
  });

  it("logs sid, tool, account and role but never creds or tokens", async () => {
    await call("aws___run_script", args);
    const all = logs.join("\n");
    expect(all).toContain('"tool":"aws___run_script"');
    expect(all).toContain('"account":"111111111111"');
    for (const secret of ["ASIAROLE", "IDC_AT", "asb1."]) expect(all).not.toContain(secret);
  });
});

describe("Task Handles", () => {
  const target = { account_id: "111111111111", role_name: "ReadOnlyAccess" };
  const TASK = "0b7c1f7e-1111-2222-3333-444455556666";
  const working = { content: [{ type: "text", text: JSON.stringify({ task_id: TASK, status: "working", message: "Use get_tasks" }) }] };
  const tasksResult = (status: string) => {
    const sc = { tasks: [{ task_id: TASK, status }] };
    return { content: [{ type: "text", text: JSON.stringify(sc) }], structuredContent: sc };
  };
  const GET_TASKS = {
    name: "aws___get_tasks",
    description: "Poll tasks.",
    inputSchema: { type: "object", properties: { task_ids: { type: "array", items: { type: "string" }, description: "ids" }, poll_iteration: { type: "integer" } }, required: ["task_ids"] },
    annotations: { readOnlyHint: true },
  };
  beforeEach(() => upstream.getToolList.mockResolvedValue([...UPSTREAM_TOOLS, GET_TASKS]));

  async function startTask(sid = "SID1") {
    upstream.callTool.mockResolvedValueOnce({ result: working, sessionId: "UPSESSION" });
    const r = parsed(await rpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "aws___run_script", arguments: { code: "x", ...target } } }, await bearer({ sid })));
    return JSON.parse(r.result!.content![0]!.text).task_id as string;
  }

  it("replaces the raw task id in run_script results with a sealed handle", async () => {
    const handle = await startTask();
    expect(handle).toMatch(/^asb1\./);
    expect(handle).not.toContain(TASK);
    expect(await sealer.unseal("tk", AUD, handle)).toMatchObject({ sid: "SID1", a: "111111111111", r: "ReadOnlyAccess", t: TASK, s: "UPSESSION" });
  });

  it("get_tasks schema takes handles and no account_id/role_name", async () => {
    const tools = parsed(await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" })).result!.tools as { name: string; inputSchema: { required: string[]; properties: Record<string, { description?: string }> } }[];
    const gt = tools.find((t) => t.name === "aws___get_tasks")!;
    expect(gt.inputSchema.required).toEqual(["task_ids"]);
    expect(gt.inputSchema.properties.account_id).toBeUndefined();
    expect(gt.inputSchema.properties.task_ids!.description).toMatch(/Task Handles/);
  });

  it("get_tasks unseals handles, polls the bound Target + upstream session, and re-wraps ids", async () => {
    const handle = await startTask();
    upstream.callTool.mockClear();
    idc.getRoleCredentials.mockClear();
    upstream.callTool.mockResolvedValueOnce({ result: tasksResult("completed"), sessionId: "UPSESSION" });
    const r = parsed(await call("aws___get_tasks", { task_ids: [handle], poll_iteration: 1 }, 2)).result!;
    const [tool, upArgs, opts] = upstream.callTool.mock.calls[0]!;
    expect(tool).toBe("aws___get_tasks");
    expect(upArgs).toEqual({ task_ids: [TASK], poll_iteration: 1 });
    expect(opts.sessionId).toBe("UPSESSION");
    expect(opts.target.creds).toBe(ROLE_CREDS);
    const out = JSON.stringify(r);
    expect(out).not.toContain(TASK);
    expect((r.structuredContent as { tasks: { task_id: string }[] }).tasks[0]!.task_id).toBe(handle);
  });

  it("foreign-sid or garbage handle → tool error, no upstream call", async () => {
    const foreign = await startTask("OTHER");
    upstream.callTool.mockClear();
    for (const h of [foreign, "asb1.x.y.z", "raw-task-id"]) {
      const r = parsed(await call("aws___get_tasks", { task_ids: [h] }, 2)).result!;
      expect(r.isError).toBe(true);
      expect(r.content![0]!.text).toBe("Unknown or expired Task Handle");
    }
    expect(upstream.callTool).not.toHaveBeenCalled();
  });

  it("handles from different Targets → tool error", async () => {
    const h1 = await startTask();
    upstream.callTool.mockResolvedValueOnce({ result: working, sessionId: "UPSESSION" });
    const r2 = parsed(await call("aws___run_script", { code: "x", account_id: "222222222222", role_name: "ViewOnlyAccess" }, 3)).result!;
    const h2 = JSON.parse(r2.content![0]!.text).task_id as string;
    upstream.callTool.mockClear();
    const r = parsed(await call("aws___get_tasks", { task_ids: [h1, h2] }, 4)).result!;
    expect(r.content![0]!.text).toBe("Task Handles from different accounts must be polled separately");
    expect(upstream.callTool).not.toHaveBeenCalled();
  });

  it("results without task ids pass through unchanged", async () => {
    const plain = { content: [{ type: "text", text: "{\"status\":\"success\"}" }], structuredContent: { status: "success" } };
    upstream.callTool.mockResolvedValueOnce({ result: plain, sessionId: "S" });
    expect(parsed(await call("aws___run_script", { code: "x", ...target })).result).toEqual(plain);
  });

  it("handles expire after 1 h", async () => {
    const handle = await startTask();
    now += 3601_000;
    const r = parsed(await call("aws___get_tasks", { task_ids: [handle] }, 2, await bearer())).result!;
    expect(r.content![0]!.text).toBe("Unknown or expired Task Handle");
  });
});

describe("tenants", () => {
  const TP = "/mcp/d-1234567890/eu-west-1";
  const T = { d: "d-1234567890", r: "eu-west-1" };
  const managedCfg = loadConfig({ SWITCHBOARD_MODE: "managed" });
  const at = (aud: string, over: Partial<AtPayload> = {}) =>
    sealer.seal("at", aud, { sid: "SID1", cih: "c", at: "IDC_AT", ie: nowS() + 3600, iat: nowS(), exp: nowS() + 3600, t: T, ...over } as AtPayload);
  const call = (m: ReturnType<typeof createMcp>, path: string, token: string) =>
    m.handle(
      readRequest(
        evt("POST", path, {
          body: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_accounts", arguments: {} } },
          headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        }),
      ),
    );
  const managedMcp = () => createMcp({ cfg: managedCfg, sealer, idc: idc as unknown as Idc, upstream: upstream as unknown as Upstream, now: () => now });

  it("portal calls use the tenant sealed in the access token", async () => {
    const r = await call(managedMcp(), TP, await at(`${BASE}${TP}`));
    expect(r.status).toBe(200);
    expect(idc.listAccounts).toHaveBeenCalledWith(T, "IDC_AT");
  });

  it("a token is only valid at its own resource URL — also after it was cached", async () => {
    const m = managedMcp();
    const tok = await at(`${BASE}${TP}`);
    expect((await call(m, TP, tok)).status).toBe(200);
    expect((await call(m, "/mcp", tok)).status).toBe(401);
    expect((await call(m, "/mcp/d-1234567890/us-east-1", tok)).status).toBe(401);
  });

  it("401 on a tenant URL points to that tenant's protected-resource metadata", async () => {
    const r = await call(managedMcp(), TP, "garbage");
    expect(r.status).toBe(401);
    expect(r.headers?.["www-authenticate"]).toContain(`resource_metadata="${BASE}/.well-known/oauth-protected-resource${TP}"`);
  });

  it("managed: token without a tenant → 401", async () => {
    expect((await call(managedMcp(), "/mcp", await at(AUD, { t: undefined }))).status).toBe(401);
  });

  it("single: token without a tenant uses the configured Identity Center", async () => {
    const r = await call(mcp, "/mcp", await at(AUD, { t: undefined }));
    expect(r.status).toBe(200);
    expect(idc.listAccounts).toHaveBeenCalledWith(expect.objectContaining({ r: "eu-central-1" }), "IDC_AT");
  });
});
