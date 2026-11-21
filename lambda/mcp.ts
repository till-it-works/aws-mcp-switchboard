/**
 * POST /mcp — bearer validation, minimal JSON-RPC, own `list_accounts`
 * and proxied AWS MCP Server tools with per-call Target selection.
 */
import { createHash } from "node:crypto";
import { LruCache } from "./cache.js";
import type { Config } from "./config.js";
import { IdcError, mapLimit, type Account, type Idc, type RoleCredentials } from "./idc.js";
import { jsonRes, unauthorized, type Req, type Res } from "./http.js";
import type { AtPayload } from "./oauth.js";
import type { Sealer } from "./seal.js";
import { configuredIdc, type Idc as Tenant } from "./tenant.js";
import { UpstreamError, UpstreamForbiddenError, type Tool, type Upstream } from "./upstream.js";

const SUPPORTED_VERSIONS = new Set(["2025-03-26", "2025-06-18", "2025-11-25"]);
const DEFAULT_VERSION = "2025-06-18";
const SERVER_VERSION = "1.0.0";
const IDC_SKEW_S = 30;
const PORTAL_TTL_MS = 10 * 60_000;
const CREDS_MARGIN_MS = 5 * 60_000;
const TARGET_PREFIX = "Runs in the given AWS account/role. Call list_accounts first. ";
const ACCOUNT_ID = /^\d{12}$/;
const GET_TASKS = "aws___get_tasks";
const TASK_HANDLE_TTL_S = 3600;
const BAD_HANDLE = "Unknown or expired Task Handle";
const NOTE = "Only permission sets matching allowedRolePattern are listed and usable; others are hidden by the Switchboard configuration.";

const LIST_ACCOUNTS_TOOL: Tool = {
  name: "list_accounts",
  description:
    "Lists the AWS accounts and permission sets (roles) you can use with the other tools (account_id, role_name). " +
    "In large organizations pass name_filter (case-insensitive substring of the account name, or an exact 12-digit account id). " +
    "allowedRolePattern shows which permission sets this Switchboard permits.",
  inputSchema: {
    type: "object",
    properties: { name_filter: { type: "string", description: "Account name substring or exact account id" } },
  },
  annotations: { readOnlyHint: true, openWorldHint: false },
};

interface RpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

type ToolResult = Record<string, unknown>;

/** typ=tk — Task Handle binding an upstream task id to caller, Target and upstream session. */
interface TkPayload {
  sid: string;
  a: string; // account id
  r: string; // role name
  t: string; // upstream task id
  s?: string; // upstream Mcp-Session-Id (tasks are session-bound)
  exp: number;
}

/**
 * Applies `fn` to task ids at the positions the AWS MCP Server uses: top-level `task_id` (run_script)
 * and `tasks[].task_id` (get_tasks), in `structuredContent` and in JSON `content[].text`.
 * Returns a new result plus the number of ids replaced.
 */
async function mapTaskIds(result: ToolResult, fn: (id: string) => Promise<string>): Promise<{ result: ToolResult; n: number }> {
  let n = 0;
  const walk = async (o: unknown): Promise<unknown> => {
    if (!o || typeof o !== "object" || Array.isArray(o)) return o;
    const copy = { ...(o as Record<string, unknown>) };
    if (typeof copy.task_id === "string") {
      copy.task_id = await fn(copy.task_id);
      n++;
    }
    if (Array.isArray(copy.tasks)) {
      copy.tasks = await Promise.all(
        copy.tasks.map(async (t) => {
          if (!t || typeof t !== "object" || typeof (t as { task_id?: unknown }).task_id !== "string") return t;
          n++;
          return { ...(t as object), task_id: await fn((t as { task_id: string }).task_id) };
        }),
      );
    }
    return copy;
  };
  const out: ToolResult = { ...result };
  if (result.structuredContent) out.structuredContent = await walk(result.structuredContent);
  if (Array.isArray(result.content)) {
    out.content = await Promise.all(
      result.content.map(async (c: { type?: string; text?: string }) => {
        if (c?.type !== "text" || typeof c.text !== "string" || !c.text.trimStart().startsWith("{")) return c;
        let parsed: unknown;
        try {
          parsed = JSON.parse(c.text);
        } catch {
          return c;
        }
        const before = n;
        const w = await walk(parsed);
        return n === before ? c : { ...c, text: JSON.stringify(w) };
      }),
    );
  }
  return { result: n ? out : result, n };
}

/** Authenticated caller: access-token payload + the resource URL it was presented at + its Identity Center. */
type Caller = AtPayload & { aud: string; tenant: Tenant };

/** Thrown inside a request to turn it into HTTP 401 (expired IdC session). */
class Reauth extends Error {}

const sha256 = (s: string) => createHash("sha256").update(s).digest("base64url");
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: "text", text: t }], ...(isError ? { isError: true } : {}) });

export function rewriteTool(t: Tool, docsTools: Set<string>): Tool {
  if (docsTools.has(t.name)) return t;
  const schema = (t.inputSchema ?? { type: "object" }) as { properties?: Record<string, unknown>; required?: string[] };
  if (t.name === GET_TASKS) {
    const ids = (schema.properties?.task_ids ?? { type: "array", items: { type: "string" } }) as Record<string, unknown>;
    return {
      ...t,
      inputSchema: {
        ...schema,
        properties: { ...(schema.properties ?? {}), task_ids: { ...ids, description: "Task Handles returned by previous tool calls (opaque strings, pass them unchanged)" } },
      },
    };
  }
  return {
    ...t,
    description: TARGET_PREFIX + (t.description ?? ""),
    inputSchema: {
      ...schema,
      type: "object",
      properties: {
        ...(schema.properties ?? {}),
        account_id: { type: "string", pattern: "^\\d{12}$", description: "12-digit AWS account id (see list_accounts)" },
        role_name: { type: "string", description: "Permission set name in that account (see list_accounts)" },
      },
      required: [...new Set([...(schema.required ?? []), "account_id", "role_name"])],
    },
  };
}

export function createMcp(deps: { cfg: Config; sealer: Sealer; idc: Idc; upstream: Upstream; now?: () => number }) {
  const { cfg, sealer, idc, upstream } = deps;
  /** Single mode: tokens from before tenants belong to the configured Identity Center. */
  const single = cfg.mode === "single" ? configuredIdc(cfg.idcStartUrl, cfg.idcRegion) : undefined;
  const now = deps.now ?? Date.now;
  const bearers = new LruCache<AtPayload>({ max: 1000, ttlMs: 3_600_000, now });
  const accountsCache = new LruCache<Account[]>({ max: 1000, ttlMs: PORTAL_TTL_MS, now });
  const rolesCache = new LruCache<string[]>({ max: 10_000, ttlMs: PORTAL_TTL_MS, now });
  const credsCache = new LruCache<RoleCredentials>({ max: 1000, ttlMs: 3_600_000, now });
  let rewritten: { from: Tool[]; tools: Tool[] } | undefined;

  async function authenticate(req: Req): Promise<Caller | null> {
    const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization ?? "");
    if (!m) return null;
    const aud = `${req.baseUrl}${req.path}`;
    const key = sha256(`${aud} ${m[1]!}`); // per resource URL: a cached token must not skip the audience check elsewhere
    let at = bearers.get(key) ?? null;
    if (!at) {
      at = await sealer.unseal<AtPayload>("at", aud, m[1]!);
      if (!at) return null;
      bearers.set(key, at, Math.max(0, at.exp * 1000 - now()));
    }
    const s = now() / 1000;
    if (at.exp <= s || at.ie < s + IDC_SKEW_S) return null;
    const tenant = at.t ?? single;
    if (!tenant) return null;
    return { ...at, aud, tenant };
  }

  async function toolList(): Promise<Tool[]> {
    const up = await upstream.getToolList();
    if (rewritten?.from !== up) rewritten = { from: up, tools: [LIST_ACCOUNTS_TOOL, ...up.map((t) => rewriteTool(t, cfg.docsTools))] };
    return rewritten.tools;
  }

  /** Portal call wrapper: expired IdC session → HTTP 401. */
  async function portal<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof IdcError && e.kind === "token_expired") throw new Reauth();
      throw e;
    }
  }

  async function listAccounts(at: Caller, args: Record<string, unknown>): Promise<ToolResult> {
    let accounts = accountsCache.get(at.sid);
    if (!accounts) {
      accounts = await portal(() => idc.listAccounts(at.tenant, at.at));
      accountsCache.set(at.sid, accounts);
    }
    const f = typeof args.name_filter === "string" ? args.name_filter.trim().toLowerCase() : "";
    const matching = f ? accounts.filter((a) => a.accountId === f || a.accountName.toLowerCase().includes(f)) : accounts;
    const withRoles = await mapLimit(matching, 8, async (a) => {
      const key = `${at.sid}#${a.accountId}`;
      let roles = rolesCache.get(key);
      if (!roles) {
        roles = await portal(() => idc.listAccountRoles(at.tenant, at.at, a.accountId));
        rolesCache.set(key, roles);
      }
      return { accountId: a.accountId, accountName: a.accountName, roles: roles.filter((r) => cfg.allowedRolePattern.test(r)) };
    });
    const out = { allowedRolePattern: cfg.allowedRolePattern.source, note: NOTE, accounts: withRoles };
    return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out };
  }

  async function roleCreds(at: Caller, account: string, role: string): Promise<RoleCredentials> {
    const key = `${at.sid}#${account}#${role}`;
    const hit = credsCache.get(key);
    if (hit) return hit;
    const c = await portal(() => idc.getRoleCredentials(at.tenant, at.at, account, role));
    credsCache.set(key, c, Math.max(0, c.expiration - CREDS_MARGIN_MS - now()));
    return c;
  }

  async function toolsCall(at: Caller, params: Record<string, unknown>): Promise<{ result?: ToolResult; error?: { code: number; message: string } }> {
    const name = typeof params.name === "string" ? params.name : "";
    const args = (params.arguments && typeof params.arguments === "object" ? params.arguments : {}) as Record<string, unknown>;
    const meta = params._meta as Record<string, unknown> | undefined;
    if (name === "list_accounts") return { result: await listAccounts(at, args) };

    const tools = await upstream.getToolList();
    if (!tools.some((t) => t.name === name)) return { error: { code: -32602, message: `Unknown tool: ${name}` } };

    const started = now();
    const log = (outcome: string, extra: Record<string, unknown> = {}) =>
      console.log(JSON.stringify({ msg: "tool_call", sid: at.sid, tool: name, ...extra, outcome, ms: now() - started }));

    if (cfg.docsTools.has(name)) {
      const r = await callUpstream(() => upstream.callTool(name, args, { meta }), "", "");
      log(r.error ? "rpc_error" : r.result?.isError ? "tool_error" : "ok");
      return r.error ? { error: r.error } : { result: r.result };
    }

    if (name === GET_TASKS) return getTasks(at, args, meta, log);

    const { account_id: account, role_name: role, ...rest } = args;
    if (typeof account !== "string" || !ACCOUNT_ID.test(account) || typeof role !== "string" || !role) {
      log("invalid_target");
      return { result: text("account_id (12 digits) and role_name are required. Call list_accounts to find them.", true) };
    }
    if (!cfg.allowedRolePattern.test(role)) {
      log("role_not_allowed", { account, role });
      return {
        result: text(
          `Role ${role} is not allowed by this Switchboard (allowedRolePattern: ${cfg.allowedRolePattern.source}). Call list_accounts to see usable roles.`,
          true,
        ),
      };
    }
    let creds: RoleCredentials;
    try {
      creds = await roleCreds(at, account, role);
    } catch (e) {
      if (e instanceof IdcError && e.kind === "no_access") {
        log("no_access", { account, role });
        return { result: text(`No access to role ${role} in ${account}`, true) };
      }
      throw e;
    }
    const up = await callUpstream(() => upstream.callTool(name, rest, { target: { creds }, meta }), account, role);
    const r = up.result ? { result: await wrapTasks(at, up.result, account, role, up.sessionId) } : up;
    log(r.error ? "rpc_error" : r.result?.isError ? "tool_error" : "ok", { account, role });
    return r;
  }

  async function wrapTasks(c: Caller, result: ToolResult, a: string, r: string, s: string | undefined): Promise<ToolResult> {
    const sid = c.sid;
    const exp = Math.floor(now() / 1000) + TASK_HANDLE_TTL_S;
    const { result: out, n } = await mapTaskIds(result, (t) => sealer.seal("tk", c.aud, { sid, a, r, t, s, exp } satisfies TkPayload));
    if (!n && JSON.stringify(result).includes("task_id")) console.warn(JSON.stringify({ msg: "task_id_shape_unknown", sid }));
    return out;
  }

  async function getTasks(
    at: Caller,
    args: Record<string, unknown>,
    meta: Record<string, unknown> | undefined,
    log: (outcome: string, extra?: Record<string, unknown>) => void,
  ): Promise<{ result?: ToolResult; error?: { code: number; message: string } }> {
    const { task_ids: ids, ...rest } = args;
    delete rest.account_id; // the handle decides the Target, never the model
    delete rest.role_name;
    if (!Array.isArray(ids) || ids.length === 0 || !ids.every((h) => typeof h === "string")) {
      log("bad_handle");
      return { result: text(BAD_HANDLE, true) };
    }
    const handles = ids as string[];
    const tks = await Promise.all(handles.map((h) => (h.startsWith("asb1.") ? sealer.unseal<TkPayload>("tk", at.aud, h) : null)));
    if (tks.some((t) => !t || t.sid !== at.sid)) {
      log("bad_handle");
      return { result: text(BAD_HANDLE, true) };
    }
    const first = tks[0]!;
    if (tks.some((t) => t!.a !== first.a || t!.r !== first.r || t!.s !== first.s)) {
      log("mixed_targets");
      return { result: text("Task Handles from different accounts must be polled separately", true) };
    }
    const byRaw = new Map(tks.map((t, i) => [t!.t, handles[i]!]));
    let creds: RoleCredentials;
    try {
      creds = await roleCreds(at, first.a, first.r);
    } catch (e) {
      if (e instanceof IdcError && e.kind === "no_access") return { result: text(`No access to role ${first.r} in ${first.a}`, true) };
      throw e;
    }
    const up = await callUpstream(
      () => upstream.callTool(GET_TASKS, { ...rest, task_ids: tks.map((t) => t!.t) }, { target: { creds }, sessionId: first.s, meta }),
      first.a,
      first.r,
    );
    if (!up.result) {
      log("rpc_error", { account: first.a, role: first.r });
      return up;
    }
    // Known ids map back to the caller's handles; unexpected ids get fresh handles for the same Target/session.
    const exp = Math.floor(now() / 1000) + TASK_HANDLE_TTL_S;
    const { result } = await mapTaskIds(up.result, async (t) =>
      byRaw.get(t) ?? sealer.seal("tk", at.aud, { sid: at.sid, a: first.a, r: first.r, t, s: first.s, exp } satisfies TkPayload),
    );
    log(result.isError ? "tool_error" : "ok", { account: first.a, role: first.r });
    return { result };
  }

  async function callUpstream(
    fn: () => ReturnType<Upstream["callTool"]>,
    account: string,
    role: string,
  ): Promise<{ result?: ToolResult; error?: { code: number; message: string }; sessionId?: string }> {
    try {
      const r = await fn();
      return r.error ? { error: r.error } : { result: r.result ?? {}, sessionId: r.sessionId };
    } catch (e) {
      if (e instanceof UpstreamForbiddenError) {
        return { result: text(`Role ${role} in ${account} lacks permissions for this call (or for AWS MCP Server).`, true) };
      }
      if (e instanceof UpstreamError) return { result: text(`AWS MCP Server error (HTTP ${e.status}). Try again later.`, true) };
      throw e;
    }
  }

  /** Only jsonrpc, id and result|error: MCP clients parse responses strictly and drop messages with extra keys. */
  const reply = (id: RpcMessage["id"], body: { result?: unknown; error?: unknown }, sid?: string): Res => ({
    ...jsonRes(200, { jsonrpc: "2.0", id: id ?? null, ...(body.error !== undefined ? { error: body.error } : { result: body.result }) }),
    sid,
  });

  return {
    async handle(req: Req): Promise<Res> {
      const at = await authenticate(req);
      if (!at) return unauthorized(req.baseUrl, req.path);

      let msg: RpcMessage;
      try {
        msg = JSON.parse(req.body) as RpcMessage;
      } catch {
        return reply(null, { error: { code: -32700, message: "Parse error" } }, at.sid);
      }
      if (!msg || typeof msg !== "object" || Array.isArray(msg) || typeof msg.method !== "string") {
        return reply(null, { error: { code: -32600, message: "Invalid Request (batches are not supported)" } }, at.sid);
      }
      if (msg.id === undefined) return { status: 202, sid: at.sid }; // notification

      const params = msg.params ?? {};
      try {
        switch (msg.method) {
          case "initialize": {
            const asked = params.protocolVersion as string;
            return reply(
              msg.id,
              {
                result: {
                  protocolVersion: SUPPORTED_VERSIONS.has(asked) ? asked : DEFAULT_VERSION,
                  capabilities: { tools: {} },
                  serverInfo: { name: "aws-mcp-switchboard", version: SERVER_VERSION },
                },
              },
              at.sid,
            );
          }
          case "ping":
            return reply(msg.id, { result: {} }, at.sid);
          case "tools/list":
            return reply(msg.id, { result: { tools: await toolList() } }, at.sid);
          case "tools/call":
            return reply(msg.id, await toolsCall(at, params), at.sid);
          default:
            return reply(msg.id, { error: { code: -32601, message: `Method not found: ${msg.method}` } }, at.sid);
        }
      } catch (e) {
        if (e instanceof Reauth) return { ...unauthorized(req.baseUrl, req.path), sid: at.sid };
        console.error(JSON.stringify({ msg: "mcp_error", sid: at.sid, method: msg.method, error: (e as Error).name }));
        return reply(msg.id, { error: { code: -32603, message: "Internal error" } }, at.sid);
      }
    },
  };
}

export type Mcp = ReturnType<typeof createMcp>;
