/**
 * IAM Identity Center: deployment-wide OIDC client bootstrap, device flow + refresh,
 * and the unsigned portal APIs (ListAccounts / ListAccountRoles / GetRoleCredentials).
 * Error mapping verified against IAM Identity Center.
 */
import {
  CreateTokenCommand,
  RegisterClientCommand,
  StartDeviceAuthorizationCommand,
  type SSOOIDCClient,
} from "@aws-sdk/client-sso-oidc";
import { GetRoleCredentialsCommand, ListAccountRolesCommand, ListAccountsCommand, type SSOClient } from "@aws-sdk/client-sso";
import { GetParameterCommand, PutParameterCommand, type SSMClient } from "@aws-sdk/client-ssm";
import type { Config } from "./config.js";
import { startUrlOf, type Idc as Tenant } from "./tenant.js";

export type IdcErrorKind = "pending" | "slow_down" | "expired" | "denied" | "invalid_grant" | "no_access" | "token_expired";

export class IdcError extends Error {
  constructor(readonly kind: IdcErrorKind) {
    super(kind);
    this.name = "IdcError";
  }
}

export interface OidcClient {
  clientId: string;
  clientSecret: string;
  /** Epoch seconds. */
  clientSecretExpiresAt: number;
}

export interface IdcTokens {
  accessToken: string;
  refreshToken?: string;
  /** Epoch seconds. */
  expiresAt: number;
  /** OIDC client the tokens were issued to (refresh tokens are bound to it). */
  clientId: string;
}

export interface DeviceAuthorization {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  interval: number;
  expiresIn: number;
  clientId: string;
}

export interface RoleCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  /** Epoch ms. */
  expiration: number;
}

export interface Account {
  accountId: string;
  accountName: string;
}

const ROTATE_BEFORE_S = 7 * 86_400;

/** Run `fn` over `items` with at most `limit` in flight; results keep input order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

const DEVICE_ERRORS: Record<string, IdcErrorKind> = {
  AuthorizationPendingException: "pending",
  SlowDownException: "slow_down",
  ExpiredTokenException: "expired",
  AccessDeniedException: "denied",
};

function portalError(e: unknown): unknown {
  const name = (e as Error).name;
  if (name === "ForbiddenException") return new IdcError("no_access");
  if (name === "UnauthorizedException") return new IdcError("token_expired");
  return e;
}

const isClient = (c: unknown): c is OidcClient => {
  const o = c as Partial<OidcClient> | null;
  return !!o && typeof o.clientId === "string" && typeof o.clientSecret === "string" && typeof o.clientSecretExpiresAt === "number";
};

export function createIdc(deps: {
  cfg: Config;
  /** SDK clients for one IdC region; called once per region per container. */
  clientsFor: (region: string) => { oidc: SSOOIDCClient; sso: SSOClient };
  ssm: SSMClient;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}) {
  const { cfg, ssm } = deps;
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const memo = new Map<string, Promise<OidcClient>>();
  const sdk = new Map<string, { oidc: SSOOIDCClient; sso: SSOClient }>();

  const clients = (region: string) => {
    let c = sdk.get(region);
    if (!c) sdk.set(region, (c = deps.clientsFor(region)));
    return c;
  };
  const startUrl = (t: Tenant) => (cfg.mode === "single" ? cfg.idcStartUrl : startUrlOf(t.d));
  const usable = (c: OidcClient | undefined): c is OidcClient => !!c && c.clientSecretExpiresAt > now() / 1000 + ROTATE_BEFORE_S;

  /** One SecureString parameter per IdC region: `<prefix>/<region>` = OidcClient JSON (standard tier, free). */
  const paramName = (region: string) => `${cfg.oidcParamPrefix}/${region}`;

  async function readStored(region: string): Promise<OidcClient | undefined> {
    try {
      const r = await ssm.send(new GetParameterCommand({ Name: paramName(region), WithDecryption: true }));
      const v: unknown = JSON.parse(r.Parameter?.Value ?? "");
      return isClient(v) ? v : undefined;
    } catch (e) {
      if ((e as Error).name === "ParameterNotFound" || e instanceof SyntaxError) return undefined;
      throw e;
    }
  }

  async function loadOrRegister(region: string): Promise<OidcClient> {
    const have = await readStored(region);
    if (usable(have)) return { clientId: have.clientId, clientSecret: have.clientSecret, clientSecretExpiresAt: have.clientSecretExpiresAt };
    const r = await clients(region).oidc.send(
      new RegisterClientCommand({ clientName: "aws-mcp-switchboard", clientType: "public", scopes: ["sso:account:access"] }),
    );
    const fresh: OidcClient = { clientId: r.clientId!, clientSecret: r.clientSecret!, clientSecretExpiresAt: r.clientSecretExpiresAt! };
    // Races between containers are harmless: last writer wins, a lost client stays valid until its own expiry.
    await ssm.send(new PutParameterCommand({ Name: paramName(region), Value: JSON.stringify(fresh), Type: "SecureString", Overwrite: true, Tier: "Standard" }));
    console.log(JSON.stringify({ msg: "oidc_client_registered", region, expiresAt: fresh.clientSecretExpiresAt }));
    return fresh;
  }

  function getOidcClient(region: string, opts: { refresh?: boolean } = {}): Promise<OidcClient> {
    let p = memo.get(region);
    if (opts.refresh || !p) {
      p = loadOrRegister(region);
      memo.set(region, p);
      p.catch(() => memo.delete(region));
    }
    return p;
  }

  async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await fn();
      } catch (e) {
        if ((e as Error).name === "TooManyRequestsException" && attempt < 5) {
          await sleep(100 * 2 ** attempt);
          continue;
        }
        throw portalError(e);
      }
    }
  }

  const tokens = (r: { accessToken?: string; refreshToken?: string; expiresIn?: number }, clientId: string, prevRt?: string): IdcTokens => ({
    accessToken: r.accessToken!,
    refreshToken: r.refreshToken ?? prevRt,
    expiresAt: Math.floor(now() / 1000) + (r.expiresIn ?? 3600),
    clientId,
  });

  return {
    getOidcClient,

    async startDeviceAuthorization(t: Tenant): Promise<DeviceAuthorization> {
      const c = await getOidcClient(t.r);
      const r = await clients(t.r).oidc.send(
        new StartDeviceAuthorizationCommand({ clientId: c.clientId, clientSecret: c.clientSecret, startUrl: startUrl(t) }),
      );
      return {
        deviceCode: r.deviceCode!,
        userCode: r.userCode!,
        verificationUri: r.verificationUri!,
        verificationUriComplete: r.verificationUriComplete!,
        interval: r.interval ?? 5,
        expiresIn: r.expiresIn ?? 600,
        clientId: c.clientId,
      };
    },

    /** Throws IdcError pending | slow_down | expired | denied | invalid_grant. */
    async pollDeviceToken(t: Tenant, deviceCode: string): Promise<IdcTokens> {
      const c = await getOidcClient(t.r);
      try {
        const r = await clients(t.r).oidc.send(
          new CreateTokenCommand({
            clientId: c.clientId,
            clientSecret: c.clientSecret,
            grantType: "urn:ietf:params:oauth:grant-type:device_code",
            deviceCode,
          }),
        );
        return tokens(r, c.clientId);
      } catch (e) {
        throw new IdcError(DEVICE_ERRORS[(e as Error).name] ?? "invalid_grant");
      }
    },

    /** Refresh with the client the refresh token was issued to; throws IdcError invalid_grant. */
    async refresh(t: Tenant, refreshToken: string, clientId: string): Promise<IdcTokens> {
      let c = await getOidcClient(t.r);
      if (c.clientId !== clientId) c = await getOidcClient(t.r, { refresh: true });
      if (c.clientId !== clientId) throw new IdcError("invalid_grant");
      try {
        const r = await clients(t.r).oidc.send(
          new CreateTokenCommand({ clientId: c.clientId, clientSecret: c.clientSecret, grantType: "refresh_token", refreshToken }),
        );
        return tokens(r, c.clientId, refreshToken);
      } catch {
        throw new IdcError("invalid_grant");
      }
    },

    async listAccounts(t: Tenant, accessToken: string): Promise<Account[]> {
      const { sso } = clients(t.r);
      const out: Account[] = [];
      let nextToken: string | undefined;
      do {
        const r = await withRetry(() => sso.send(new ListAccountsCommand({ accessToken, nextToken, maxResults: 100 })));
        for (const a of r.accountList ?? []) out.push({ accountId: a.accountId!, accountName: a.accountName ?? "" });
        nextToken = r.nextToken;
      } while (nextToken);
      return out;
    },

    async listAccountRoles(t: Tenant, accessToken: string, accountId: string): Promise<string[]> {
      const { sso } = clients(t.r);
      const out: string[] = [];
      let nextToken: string | undefined;
      do {
        const r = await withRetry(() => sso.send(new ListAccountRolesCommand({ accessToken, accountId, nextToken })));
        for (const x of r.roleList ?? []) if (x.roleName) out.push(x.roleName);
        nextToken = r.nextToken;
      } while (nextToken);
      return out;
    },

    async getRoleCredentials(t: Tenant, accessToken: string, accountId: string, roleName: string): Promise<RoleCredentials> {
      const r = await withRetry(() => clients(t.r).sso.send(new GetRoleCredentialsCommand({ accessToken, accountId, roleName })));
      const c = r.roleCredentials!;
      return { accessKeyId: c.accessKeyId!, secretAccessKey: c.secretAccessKey!, sessionToken: c.sessionToken!, expiration: Number(c.expiration) };
    },
  };
}

export type Idc = ReturnType<typeof createIdc>;
