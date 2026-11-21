import { describe, expect, it } from "vitest";
import { loadConfig } from "../lambda/config.js";
import { DEFAULT_REGION, isIdcRegion, mcpPath, parseDirectory, parseMcpPath, startUrlOf } from "../lambda/tenant.js";

describe("parseDirectory", () => {
  it.each([
    ["d-1234567890", "d-1234567890"],
    ["D-1234567890", "d-1234567890"],
    ["  my-corp ", "my-corp"],
    ["https://d-1234567890.awsapps.com/start", "d-1234567890"],
    ["https://my-corp.awsapps.com/start/#/", "my-corp"],
    ["d-1234567890.awsapps.com/start", "d-1234567890"],
  ])("%s → %s", (input, d) => expect(parseDirectory(input)).toBe(d));

  it.each([
    "",
    "-corp",
    "corp-",
    "a.b",
    "evil.com",
    "https://evil.com/start",
    "https://d-1.awsapps.com.evil.com/start",
    "x".repeat(64),
    "my_corp",
  ])("rejects %j", (input) => expect(parseDirectory(input)).toBeNull());
});

describe("regions", () => {
  it("default is eu-central-1", () => expect(DEFAULT_REGION).toBe("eu-central-1"));
  it.each(["eu-central-1", "us-east-1", "ap-southeast-2", "il-central-1", "mx-central-1"])("accepts %s", (r) => expect(isIdcRegion(r)).toBe(true));
  it.each(["", "eu-central", "EU-CENTRAL-1", "eu-central-1.evil.com", "us-gov-west-1", "cn-north-1", "eu-central-1/"])("rejects %j", (r) =>
    expect(isIdcRegion(r)).toBe(false),
  );
});

describe("startUrlOf", () => {
  it("builds the access portal URL", () => expect(startUrlOf("d-1234567890")).toBe("https://d-1234567890.awsapps.com/start"));
});

describe("parseMcpPath / mcpPath", () => {
  it("/mcp is the shared endpoint", () => expect(parseMcpPath("/mcp")).toEqual({ kind: "shared" }));
  it("/mcp/<d>/<r> names a tenant", () =>
    expect(parseMcpPath("/mcp/d-1234567890/us-east-1")).toEqual({ kind: "tenant", idc: { d: "d-1234567890", r: "us-east-1" } }));
  it("/mcp/<d> defaults the region", () => expect(parseMcpPath("/mcp/my-corp")).toEqual({ kind: "tenant", idc: { d: "my-corp", r: DEFAULT_REGION } }));
  it.each(["/", "/mcpx", "/mcp/", "/mcp/evil.com", "/mcp/d-1234567890/nowhere", "/mcp/a/eu-central-1/x", "/mcp/D-1234567890"])("rejects %j", (p) =>
    expect(parseMcpPath(p)).toBeNull(),
  );
  it("round-trips", () => {
    const idc = { d: "d-1234567890", r: "eu-west-1" };
    expect(parseMcpPath(mcpPath(idc))).toEqual({ kind: "tenant", idc });
    expect(mcpPath()).toBe("/mcp");
  });
});

describe("loadConfig mode", () => {
  it("defaults to single (one fixed Identity Center)", () => expect(loadConfig({ IDC_START_URL: "https://d-1234567890.awsapps.com/start" }).mode).toBe("single"));
  it("SWITCHBOARD_MODE=managed serves any Identity Center", () => expect(loadConfig({ SWITCHBOARD_MODE: "managed" }).mode).toBe("managed"));
  it("rejects unknown modes", () => expect(() => loadConfig({ SWITCHBOARD_MODE: "multi" })).toThrow(/SWITCHBOARD_MODE/));
  it("rejects SSM-reserved OIDC_PARAM_PREFIX (aws…/ssm…)", () => {
    for (const p of ["/aws-mcp-switchboard/oidc", "/AWS/x", "ssm/x"]) expect(() => loadConfig({ SWITCHBOARD_MODE: "managed", OIDC_PARAM_PREFIX: p })).toThrow(/reserved by SSM/);
    expect(loadConfig({ SWITCHBOARD_MODE: "managed" }).oidcParamPrefix).toBe("/mcp-switchboard/oidc");
  });
});
