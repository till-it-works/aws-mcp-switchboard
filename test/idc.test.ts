import { beforeEach, describe, expect, it } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  CreateTokenCommand,
  RegisterClientCommand,
  SSOOIDCClient,
  StartDeviceAuthorizationCommand,
} from "@aws-sdk/client-sso-oidc";
import { GetRoleCredentialsCommand, ListAccountRolesCommand, ListAccountsCommand, SSOClient } from "@aws-sdk/client-sso";
import { GetParameterCommand, PutParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { createIdc, IdcError, mapLimit } from "../lambda/idc.js";
import { loadConfig } from "../lambda/config.js";

const oidcMock = mockClient(SSOOIDCClient);
const ssoMock = mockClient(SSOClient);
const ssmMock = mockClient(SSMClient);

const NOW = Date.UTC(2026, 10, 20);
const DAY = 86_400;
const cfg = loadConfig({ IDC_START_URL: "https://d-1.awsapps.com/start", OIDC_PARAM_PREFIX: "/sb/oidc", KMS_KEY_ARN: "arn:key" });
const err = (name: string) => Object.assign(new Error(name), { name });
const param = (o: object) => ({ Parameter: { Value: JSON.stringify(o) } });
const VALID = { clientId: "cid-1", clientSecret: "cs-1", clientSecretExpiresAt: NOW / 1000 + 30 * DAY };
const stored = (byRegion: Record<string, object>) =>
  ssmMock.on(GetParameterCommand).callsFake((i: { Name: string }) => {
    const v = byRegion[i.Name.split("/").pop()!];
    if (!v) throw err("ParameterNotFound");
    return param(v);
  });

const T = { d: "d-1", r: "eu-central-1" };
let regions: string[] = [];

function mk(c = cfg) {
  return createIdc({
    cfg: c,
    clientsFor: (region) => {
      regions.push(region);
      return { oidc: new SSOOIDCClient({}), sso: new SSOClient({}) };
    },
    ssm: new SSMClient({}),
    now: () => NOW,
    sleep: async () => {},
  });
}

beforeEach(() => {
  oidcMock.reset();
  ssoMock.reset();
  ssmMock.reset();
  regions = [];
  oidcMock.on(RegisterClientCommand).resolves({ clientId: "cid-new", clientSecret: "cs-new", clientSecretExpiresAt: NOW / 1000 + 90 * DAY });
});

describe("OIDC client bootstrap (one SSM SecureString parameter per region)", () => {
  it("reuses a valid stored client without registering; reads <prefix>/<region> decrypted", async () => {
    stored({ "eu-central-1": VALID });
    const idc = mk();
    expect((await idc.getOidcClient(T.r)).clientId).toBe("cid-1");
    await idc.getOidcClient(T.r);
    expect(oidcMock.commandCalls(RegisterClientCommand)).toHaveLength(0);
    const gets = ssmMock.commandCalls(GetParameterCommand);
    expect(gets).toHaveLength(1); // memoized
    expect(gets[0]!.args[0].input).toEqual({ Name: "/sb/oidc/eu-central-1", WithDecryption: true });
  });

  it.each([
    ["expiring within 7 days", param({ ...VALID, clientSecretExpiresAt: NOW / 1000 + 6 * DAY })],
    ["empty JSON", param({})],
    ["non-JSON", { Parameter: { Value: "garbage" } }],
  ])("registers and stores a new client when the parameter is %s", async (_label, value) => {
    ssmMock.on(GetParameterCommand).resolves(value);
    const c = await mk().getOidcClient(T.r);
    expect(c.clientId).toBe("cid-new");
    const reg = oidcMock.commandCalls(RegisterClientCommand)[0]!.args[0].input;
    expect(reg).toEqual({ clientName: "aws-mcp-switchboard", clientType: "public", scopes: ["sso:account:access"] });
    const put = ssmMock.commandCalls(PutParameterCommand)[0]!.args[0].input;
    expect(put).toMatchObject({ Name: "/sb/oidc/eu-central-1", Type: "SecureString", Overwrite: true, Tier: "Standard" });
    expect(JSON.parse(put.Value!)).toEqual({ clientId: "cid-new", clientSecret: "cs-new", clientSecretExpiresAt: NOW / 1000 + 90 * DAY });
  });

  it("registers when the parameter does not exist yet", async () => {
    ssmMock.on(GetParameterCommand).rejects(err("ParameterNotFound"));
    expect((await mk().getOidcClient(T.r)).clientId).toBe("cid-new");
  });

  it("a new region gets its own parameter; other regions are untouched", async () => {
    stored({ "eu-central-1": VALID });
    const idc = mk();
    expect((await idc.getOidcClient("eu-central-1")).clientId).toBe("cid-1");
    expect((await idc.getOidcClient("us-east-1")).clientId).toBe("cid-new");
    const puts = ssmMock.commandCalls(PutParameterCommand);
    expect(puts.map((p) => p.args[0].input.Name)).toEqual(["/sb/oidc/us-east-1"]);
  });

  it("other SSM errors propagate", async () => {
    ssmMock.on(GetParameterCommand).rejects(err("AccessDeniedException"));
    await expect(mk().getOidcClient(T.r)).rejects.toMatchObject({ name: "AccessDeniedException" });
  });

  it("builds SDK clients once per region, in that region", async () => {
    stored({ "eu-central-1": VALID, "us-east-1": VALID });
    ssoMock.on(ListAccountsCommand).resolves({ accountList: [] });
    const idc = mk();
    await idc.listAccounts(T, "at");
    await idc.listAccounts(T, "at");
    await idc.listAccounts({ d: "x", r: "us-east-1" }, "at");
    expect(regions).toEqual(["eu-central-1", "us-east-1"]);
  });

  it("refresh:true re-reads the parameter and picks up a client rotated by another container", async () => {
    ssmMock.on(GetParameterCommand).resolvesOnce(param(VALID)).resolves(param({ ...VALID, clientId: "cid-2" }));
    const idc = mk();
    expect((await idc.getOidcClient(T.r)).clientId).toBe("cid-1");
    expect((await idc.getOidcClient(T.r, { refresh: true })).clientId).toBe("cid-2");
  });
});

describe("device flow + refresh", () => {
  beforeEach(() => void ssmMock.on(GetParameterCommand).resolves(param(VALID)));

  it("starts device authorization with the start URL", async () => {
    oidcMock.on(StartDeviceAuthorizationCommand).resolves({ deviceCode: "dc", userCode: "ABCD-EFGH", verificationUri: "v", verificationUriComplete: "vc", interval: 1, expiresIn: 600 });
    const d = await mk().startDeviceAuthorization(T);
    expect(d).toMatchObject({ deviceCode: "dc", userCode: "ABCD-EFGH", verificationUriComplete: "vc", interval: 1, expiresIn: 600, clientId: "cid-1" });
    expect(oidcMock.commandCalls(StartDeviceAuthorizationCommand)[0]!.args[0].input).toEqual({ clientId: "cid-1", clientSecret: "cs-1", startUrl: "https://d-1.awsapps.com/start" });
  });

  it("managed mode: start URL comes from the tenant's directory, not the config", async () => {
    stored({ "us-east-1": VALID });
    oidcMock.on(StartDeviceAuthorizationCommand).resolves({ deviceCode: "dc", userCode: "U", verificationUri: "v", verificationUriComplete: "vc" });
    const managed = loadConfig({ SWITCHBOARD_MODE: "managed", KMS_KEY_ARN: "arn:key" });
    await mk(managed).startDeviceAuthorization({ d: "my-corp", r: "us-east-1" });
    expect(oidcMock.commandCalls(StartDeviceAuthorizationCommand)[0]!.args[0].input.startUrl).toBe("https://my-corp.awsapps.com/start");
    expect(regions).toEqual(["us-east-1"]);
  });

  it("returns tokens with absolute expiry on device success", async () => {
    oidcMock.on(CreateTokenCommand).resolves({ accessToken: "at", refreshToken: "rt", expiresIn: 3600 });
    expect(await mk().pollDeviceToken(T, "dc")).toEqual({ accessToken: "at", refreshToken: "rt", expiresAt: NOW / 1000 + 3600, clientId: "cid-1" });
    expect(oidcMock.commandCalls(CreateTokenCommand)[0]!.args[0].input.grantType).toBe("urn:ietf:params:oauth:grant-type:device_code");
  });

  it.each([
    ["AuthorizationPendingException", "pending"],
    ["SlowDownException", "slow_down"],
    ["ExpiredTokenException", "expired"],
    ["AccessDeniedException", "denied"],
    ["InvalidGrantException", "invalid_grant"],
  ])("maps device CreateToken %s → %s", async (name, kind) => {
    oidcMock.on(CreateTokenCommand).rejects(err(name));
    await expect(mk().pollDeviceToken(T, "dc")).rejects.toMatchObject({ kind });
  });

  it("refreshes with the stored client, keeping the old refresh token when IdC does not rotate it", async () => {
    oidcMock.on(CreateTokenCommand).resolves({ accessToken: "at2", expiresIn: 3600 });
    expect(await mk().refresh(T, "rt", "cid-1")).toEqual({ accessToken: "at2", refreshToken: "rt", expiresAt: NOW / 1000 + 3600, clientId: "cid-1" });
  });

  it("returns a rotated refresh token", async () => {
    oidcMock.on(CreateTokenCommand).resolves({ accessToken: "at2", refreshToken: "rt2", expiresIn: 3600 });
    expect((await mk().refresh(T, "rt", "cid-1")).refreshToken).toBe("rt2");
  });

  it("refresh with a refresh token from another client re-reads the parameter, then fails with invalid_grant", async () => {
    const idc = mk();
    await expect(idc.refresh(T, "rt", "cid-old")).rejects.toMatchObject({ kind: "invalid_grant" });
    expect(ssmMock.commandCalls(GetParameterCommand)).toHaveLength(2);
    expect(oidcMock.commandCalls(CreateTokenCommand)).toHaveLength(0);
  });

  it("maps IdC refresh failure to invalid_grant", async () => {
    oidcMock.on(CreateTokenCommand).rejects(err("InvalidGrantException"));
    await expect(mk().refresh(T, "rt", "cid-1")).rejects.toBeInstanceOf(IdcError);
  });
});

describe("portal", () => {
  it("collects all ListAccounts pages", async () => {
    ssoMock
      .on(ListAccountsCommand, { accessToken: "at", nextToken: undefined, maxResults: 100 })
      .resolves({ accountList: [{ accountId: "1", accountName: "a", emailAddress: "x@y" }], nextToken: "n" })
      .on(ListAccountsCommand, { accessToken: "at", nextToken: "n", maxResults: 100 })
      .resolves({ accountList: [{ accountId: "2", accountName: "b" }] });
    expect(await mk().listAccounts(T, "at")).toEqual([
      { accountId: "1", accountName: "a" },
      { accountId: "2", accountName: "b" },
    ]);
  });

  it("retries ListAccountRoles on throttling", async () => {
    ssoMock
      .on(ListAccountRolesCommand)
      .rejectsOnce(err("TooManyRequestsException"))
      .rejectsOnce(err("TooManyRequestsException"))
      .resolves({ roleList: [{ roleName: "ReadOnlyAccess" }, { roleName: "AdministratorAccess" }] });
    expect(await mk().listAccountRoles(T, "at", "1")).toEqual(["ReadOnlyAccess", "AdministratorAccess"]);
  });

  it("returns role credentials with expiration in ms", async () => {
    ssoMock.on(GetRoleCredentialsCommand).resolves({ roleCredentials: { accessKeyId: "AK", secretAccessKey: "SK", sessionToken: "ST", expiration: NOW + 3_600_000 } });
    expect(await mk().getRoleCredentials(T, "at", "1", "ReadOnlyAccess")).toEqual({ accessKeyId: "AK", secretAccessKey: "SK", sessionToken: "ST", expiration: NOW + 3_600_000 });
  });

  it.each([
    ["ForbiddenException", "no_access"],
    ["UnauthorizedException", "token_expired"],
  ])("maps portal %s → %s", async (name, kind) => {
    ssoMock.on(GetRoleCredentialsCommand).rejects(err(name));
    ssoMock.on(ListAccountsCommand).rejects(err(name));
    await expect(mk().getRoleCredentials(T, "at", "1", "R")).rejects.toMatchObject({ kind });
    await expect(mk().listAccounts(T, "at")).rejects.toMatchObject({ kind });
  });
});

describe("mapLimit", () => {
  it("never runs more than the limit concurrently and keeps order", async () => {
    let running = 0;
    let peak = 0;
    const out = await mapLimit([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 3, async (n) => {
      running++;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, 5));
      running--;
      return n * 2;
    });
    expect(peak).toBeLessThanOrEqual(3);
    expect(out).toEqual([2, 4, 6, 8, 10, 12, 14, 16, 18, 20]);
  });
});
