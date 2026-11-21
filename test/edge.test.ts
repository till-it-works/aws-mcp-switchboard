import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { SwitchboardStack } from "../cdk/lib/stack.js";
import { SwitchboardEdgeStack } from "../cdk/lib/edge.js";

const ACCOUNT = "111122223333";
const DOMAIN = { name: "switchboard.example.com", zoneName: "example.com", hostedZoneId: "Z123" };

let edge: Template;
let main: Template;
let single: Template;
beforeAll(() => {
  const app = new App();
  const e = new SwitchboardEdgeStack(app, "Edge", { env: { account: ACCOUNT, region: "us-east-1" }, domain: DOMAIN });
  const m = new SwitchboardStack(app, "Main", {
    env: { account: ACCOUNT, region: "eu-central-1" },
    mode: "managed",
    domain: { ...DOMAIN, certificate: e.certificate, webAclArn: e.webAclArn },
    costGuard: { email: "ops@example.com" },
  });
  edge = Template.fromStack(e);
  main = Template.fromStack(m);
  single = Template.fromStack(new SwitchboardStack(new App(), "S", { env: { account: ACCOUNT, region: "eu-central-1" }, idcStartUrl: "https://d-1234567890.awsapps.com/start" }));
}, 180_000);

const props = (t: Template, type: string) => Object.values(t.findResources(type)).map((r) => (r as { Properties: Record<string, unknown> }).Properties);

describe("edge stack (us-east-1)", () => {
  it("must live in us-east-1", () => {
    expect(() => new SwitchboardEdgeStack(new App(), "X", { env: { account: ACCOUNT, region: "eu-central-1" }, domain: DOMAIN })).toThrow(/us-east-1/);
  });

  it("DNS-validated certificate for the domain", () => {
    edge.hasResourceProperties("AWS::CertificateManager::Certificate", {
      DomainName: DOMAIN.name,
      ValidationMethod: "DNS",
      DomainValidationOptions: [{ DomainName: DOMAIN.name, HostedZoneId: "Z123" }],
    });
  });

  it("certificate logical id follows the domain, so a domain change creates a new cross-region export", () => {
    const ids = Object.keys(edge.findResources("AWS::CertificateManager::Certificate"));
    expect(ids).toHaveLength(1);
    expect(ids[0]).toMatch(/^Certificateswitchboardexamplecom/);
  });

  it("WAF web ACL (CLOUDFRONT scope): blocks an IP above 300 requests / 5 min", () => {
    edge.hasResourceProperties("AWS::WAFv2::WebACL", {
      Scope: "CLOUDFRONT",
      DefaultAction: { Allow: {} },
      Rules: [Match.objectLike({ Action: { Block: {} }, Statement: { RateBasedStatement: { Limit: 300, AggregateKeyType: "IP", EvaluationWindowSec: 300 } } })],
    });
  });
});

describe("main stack behind CloudFront (managed)", () => {
  it("Lambda env: managed, BASE_URL = custom domain, origin secret, no IdC start URL", () => {
    const env = (props(main, "AWS::Lambda::Function").find((p) => JSON.stringify(p).includes("SWITCHBOARD_MODE"))!.Environment as { Variables: Record<string, unknown> }).Variables;
    expect(env.SWITCHBOARD_MODE).toBe("managed");
    expect(env.BASE_URL).toBe(`https://${DOMAIN.name}`);
    expect(env.ORIGIN_SECRET).toBeDefined();
    expect(env.IDC_START_URL).toBeUndefined();
    expect(env.BRANDING).toBeUndefined();
  });

  it("CloudFront: alias + cert, WAF attached, all edge locations (flat-rate plans), no caching, all viewer headers except Host, HTTPS only", () => {
    main.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        Aliases: [DOMAIN.name],
        WebACLId: Match.anyValue(),
        ViewerCertificate: Match.objectLike({ SslSupportMethod: "sni-only" }),
        PriceClass: "PriceClass_All",
        DefaultCacheBehavior: Match.objectLike({
          CachePolicyId: "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
          OriginRequestPolicyId: "b689b0a8-53d0-40ab-baf2-68738e2966ac",
          ViewerProtocolPolicy: "https-only",
          AllowedMethods: Match.arrayWith(["OPTIONS", "POST", "DELETE"]),
          FunctionAssociations: [Match.objectLike({ EventType: "viewer-request" })],
        }),
      }),
    });
  });

  it("origin: Function URL with the origin secret header (same value as the Lambda env) and 60 s read timeout", () => {
    const dist = props(main, "AWS::CloudFront::Distribution")[0]!.DistributionConfig as { Origins: Record<string, unknown>[] };
    const o = dist.Origins[0]!;
    expect(o.OriginCustomHeaders).toEqual([{ HeaderName: "x-origin-verify", HeaderValue: expect.anything() }]);
    expect((o.CustomOriginConfig as Record<string, unknown>).OriginReadTimeout).toBe(60);
    const env = (props(main, "AWS::Lambda::Function").find((p) => JSON.stringify(p).includes("SWITCHBOARD_MODE"))!.Environment as { Variables: Record<string, unknown> }).Variables;
    expect(JSON.stringify((o.OriginCustomHeaders as { HeaderValue: unknown }[])[0]!.HeaderValue)).toBe(JSON.stringify(env.ORIGIN_SECRET));
    expect(JSON.stringify(env.ORIGIN_SECRET)).toContain("AWS::StackId");
    main.hasResourceProperties("AWS::Lambda::Url", { AuthType: "NONE" });
  });

  it("CloudFront Function answers the discovery 401 at the edge for the domain, with tenant paths in managed mode", () => {
    const code = props(main, "AWS::CloudFront::Function")[0]!.FunctionCode as string;
    expect(code).toContain(`"https://${DOMAIN.name}/.well-known/oauth-protected-resource"`);
    expect(code).toContain("www-authenticate");
    expect(code).toContain("eu\\-central\\-1");
  });

  it("Route 53 A + AAAA alias to the distribution", () => {
    for (const Type of ["A", "AAAA"]) main.hasResourceProperties("AWS::Route53::RecordSet", { Name: `${DOMAIN.name}.`, Type, HostedZoneId: "Z123" });
  });

  it("outputs the URL and the breaker reset inputs", () => {
    main.hasOutput("Url", { Value: `https://${DOMAIN.name}` });
    main.hasOutput("FunctionName", {});
    main.hasOutput("ReservedConcurrency", { Value: "20" });
  });
});

describe("cost guard", () => {
  it("alarm: > 1000 invocations in 5 min → SNS topic with email", () => {
    main.hasResourceProperties("AWS::CloudWatch::Alarm", {
      MetricName: "Invocations",
      Namespace: "AWS/Lambda",
      Statistic: "Sum",
      Period: 300,
      Threshold: 1000,
      ComparisonOperator: "GreaterThanThreshold",
      TreatMissingData: "notBreaching",
      AlarmActions: [Match.anyValue()],
    });
    main.hasResourceProperties("AWS::SNS::Subscription", { Protocol: "email", Endpoint: "ops@example.com" });
    main.hasResourceProperties("AWS::SNS::Subscription", { Protocol: "lambda" });
  });

  it("breaker Lambda may only throttle the switchboard function", () => {
    const pols = props(main, "AWS::IAM::Policy").map((p) => JSON.stringify(p));
    const b = pols.find((p) => p.includes("lambda:PutFunctionConcurrency"))!;
    expect(b).toBeDefined();
    expect(b).not.toContain('"Resource":"*"');
    const fn = props(main, "AWS::Lambda::Function").find((p) => JSON.stringify(p).includes("TARGET_FUNCTION_NAME"));
    expect(fn).toBeDefined();
  });

  it("budget: 5 USD/month on tag app=aws-mcp-switchboard, email at 80 % actual and 100 % forecast", () => {
    main.hasResourceProperties("AWS::Budgets::Budget", {
      Budget: Match.objectLike({
        BudgetType: "COST",
        TimeUnit: "MONTHLY",
        BudgetLimit: { Amount: 5, Unit: "USD" },
        CostFilters: { TagKeyValue: ["user:app$aws-mcp-switchboard"] },
      }),
      NotificationsWithSubscribers: [
        Match.objectLike({ Notification: Match.objectLike({ NotificationType: "ACTUAL", Threshold: 80 }) }),
        Match.objectLike({ Notification: Match.objectLike({ NotificationType: "FORECASTED", Threshold: 100 }) }),
      ],
    });
  });

  it("off unless configured", () => {
    single.resourceCountIs("AWS::CloudWatch::Alarm", 0);
    single.resourceCountIs("AWS::Budgets::Budget", 0);
    single.resourceCountIs("AWS::CloudFront::Distribution", 0);
  });
});

describe("modes", () => {
  it("single mode requires idcStartUrl", () => {
    expect(() => new SwitchboardStack(new App(), "X", { env: { account: ACCOUNT, region: "eu-central-1" } })).toThrow(/idcStartUrl/);
  });

  it("hostedNotice: true → HOSTED_NOTICE=on (absent by default)", () => {
    const t = Template.fromStack(new SwitchboardStack(new App(), "H", { env: { account: ACCOUNT, region: "eu-central-1" }, mode: "managed", hostedNotice: true }));
    t.hasResourceProperties("AWS::Lambda::Function", { Environment: { Variables: Match.objectLike({ HOSTED_NOTICE: "on" }) } });
    const env = (props(main, "AWS::Lambda::Function").find((p) => JSON.stringify(p).includes("SWITCHBOARD_MODE"))!.Environment as { Variables: Record<string, unknown> }).Variables;
    expect(env.HOSTED_NOTICE).toBeUndefined();
  });

  it("legal: content inlined into the bundle (not the environment); invalid config fails synth", () => {
    const app = new App();
    const legal = { pages: [{ slug: "terms", title: "Terms", html: "<p>operator-terms-marker</p>" }], links: [{ label: "Terms", href: "/terms" }] };
    const s = new SwitchboardStack(app, "L", { env: { account: ACCOUNT, region: "eu-central-1" }, mode: "managed", legal });
    const fn = s.node.findChild("Handler");
    const code = fn.node.findChild("Code") as unknown as { assetPath: string };
    app.synth();
    const out = readdirSync(join(app.outdir, code.assetPath)).find((f) => f.endsWith(".mjs"))!;
    expect(readFileSync(join(app.outdir, code.assetPath, out), "utf8")).toContain("operator-terms-marker");
    expect(JSON.stringify(Template.fromStack(s).toJSON())).not.toContain("operator-terms-marker");
    expect(() => new SwitchboardStack(new App(), "LX", { env: { account: ACCOUNT, region: "eu-central-1" }, mode: "managed", legal: { pages: [{ slug: "mcp", title: "x", html: "" }] } })).toThrow(/reserved/);
  }, 120_000);

  it("branding: false → BRANDING=off", () => {
    const t = Template.fromStack(new SwitchboardStack(new App(), "B", { env: { account: ACCOUNT, region: "eu-central-1" }, mode: "managed", branding: false }));
    t.hasResourceProperties("AWS::Lambda::Function", { Environment: { Variables: Match.objectLike({ BRANDING: "off" }) } });
  }, 120_000);
});
