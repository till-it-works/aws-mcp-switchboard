import { beforeAll, describe, expect, it } from "vitest";
import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { SwitchboardStack } from "../cdk/lib/stack.js";

const PROPS = { idcStartUrl: "https://d-1234567890.awsapps.com/start", idcRegion: "eu-central-1", env: { account: "111122223333", region: "eu-central-1" } };
const KEY_USE = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*", "kms:CreateGrant"];

let t: Template;
beforeAll(() => {
  t = Template.fromStack(new SwitchboardStack(new App(), "T", PROPS));
}, 120_000);

const resourceOf = (type: string) => Object.values(t.findResources(type))[0] as { Properties: Record<string, unknown> };

describe("SwitchboardStack", () => {
  it("creates a rotating symmetric KMS key", () => {
    t.hasResourceProperties("AWS::KMS::Key", { EnableKeyRotation: true });
    const p = resourceOf("AWS::KMS::Key").Properties;
    expect(p.KeySpec ?? "SYMMETRIC_DEFAULT").toBe("SYMMETRIC_DEFAULT"); // CFN default when omitted
    expect(p.KeyUsage ?? "ENCRYPT_DECRYPT").toBe("ENCRYPT_DECRYPT");
  });

  it("key policy: root admin without key use, Lambda role use with context, deny key use for everyone else", () => {
    const stmts = (resourceOf("AWS::KMS::Key").Properties.KeyPolicy as { Statement: Record<string, unknown>[] }).Statement;
    expect(stmts).toHaveLength(3);
    const [admin, use, deny] = stmts as [Record<string, unknown>, Record<string, unknown>, Record<string, unknown>];
    expect(admin).toMatchObject({ Effect: "Allow", Resource: "*" });
    expect(admin.Action).toBeUndefined();
    expect([...(admin.NotAction as string[])].sort()).toEqual([...KEY_USE].sort());
    expect(JSON.stringify(admin.Principal)).toContain(":root");

    expect(use).toMatchObject({
      Effect: "Allow",
      Action: ["kms:GenerateDataKey", "kms:Decrypt"],
      Condition: { StringEquals: { "kms:EncryptionContext:app": "aws-mcp-switchboard" } },
    });
    expect(JSON.stringify(use.Principal)).toContain("SwitchboardRole");

    expect(deny).toMatchObject({ Effect: "Deny", Principal: { AWS: "*" }, Resource: "*" });
    expect([...(deny.Action as string[])].sort()).toEqual([...KEY_USE].sort());
    expect(JSON.stringify(deny.Condition)).toContain("aws:PrincipalArn");
    expect(JSON.stringify(deny.Condition)).toContain("SwitchboardRole");
  });

  it("Lambda: arm64, nodejs24.x, 120 s, reserved concurrency 20, config env", () => {
    t.hasResourceProperties("AWS::Lambda::Function", {
      Architectures: ["arm64"],
      Runtime: "nodejs24.x",
      Timeout: 120,
      ReservedConcurrentExecutions: 20,
      Environment: {
        Variables: Match.objectLike({
          IDC_START_URL: PROPS.idcStartUrl,
          IDC_REGION: "eu-central-1",
          AWS_MCP_ENDPOINT: "https://aws-mcp.eu-central-1.api.aws/mcp",
          AWS_MCP_REGION: "eu-central-1",
          ALLOWED_ROLE_PATTERN: "^(ReadOnlyAccess|ViewOnlyAccess)$",
          KMS_KEY_ARN: Match.anyValue(),
          OIDC_PARAM_PREFIX: "/mcp-switchboard/T/oidc",
          SWITCHBOARD_MODE: "single",
        }),
      },
    });
  });

  it("reserved concurrency can be disabled", () => {
    const t2 = Template.fromStack(new SwitchboardStack(new App(), "T2", { ...PROPS, reservedConcurrency: null }));
    const fn = Object.values(t2.findResources("AWS::Lambda::Function"))[0] as { Properties: Record<string, unknown> };
    expect(fn.Properties.ReservedConcurrentExecutions).toBeUndefined();
  }, 120_000);

  it("no public Function URL by default (opt-in via publicUrl)", () => {
    t.resourceCountIs("AWS::Lambda::Url", 0);
    expect(Object.keys(t.findOutputs("BaseUrl"))).toHaveLength(0);
  });

  it("publicUrl: Function URL with AuthType NONE, no CORS config, BaseUrl output", () => {
    const t2 = Template.fromStack(new SwitchboardStack(new App(), "T3", { ...PROPS, publicUrl: true }));
    t2.hasResourceProperties("AWS::Lambda::Url", { AuthType: "NONE" });
    expect((Object.values(t2.findResources("AWS::Lambda::Url"))[0] as { Properties: Record<string, unknown> }).Properties.Cors).toBeUndefined();
    t2.hasOutput("BaseUrl", {});
  }, 120_000);

  it("no Secrets Manager; logs kept 14 days; everything tagged app=aws-mcp-switchboard", () => {
    t.resourceCountIs("AWS::SecretsManager::Secret", 0);
    t.hasResourceProperties("AWS::Logs::LogGroup", { RetentionInDays: 14 });
    t.hasResourceProperties("AWS::KMS::Key", { Tags: Match.arrayWith([{ Key: "app", Value: "aws-mcp-switchboard" }]) });
  });

  it("role denies every action via AWS MCP Server and grants only the needed actions", () => {
    const docs = Object.values(t.findResources("AWS::IAM::Policy")).map((p) => JSON.stringify((p as { Properties: unknown }).Properties));
    const all = docs.join("\n");
    expect(all).toMatch(/"Effect":"Deny".*"Action":"\*".*"aws:ViaAWSMCPService":"true"|"Action":"\*".*"Condition":\{"Bool":\{"aws:ViaAWSMCPService":"true"\}\}.*"Effect":"Deny"/);
    expect(all).toContain('"Action":["ssm:GetParameter","ssm:PutParameter"]');
    expect(all).toContain(":parameter/mcp-switchboard/T/oidc/*");
    expect(all).not.toContain("secretsmanager:");
    expect(all).toContain("sts:GetCallerIdentity");
    expect(all).toContain("kms:GenerateDataKey");
    expect(all).not.toMatch(/"sso:|"sso-oidc:/);
  });
});
