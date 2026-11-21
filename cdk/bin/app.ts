/**
 * Self-host app. Values come from cdk.context.json or -c flags (see README):
 *   mode=single|managed, idcStartUrl, idcRegion, allowedRolePattern, reservedConcurrency=<n>|none, publicUrl=true,
 *   domainName + zoneName + hostedZoneId (CloudFront + custom domain; adds the us-east-1 edge stack),
 *   alertEmail [+ budgetUsd, invocationsPer5Min] (cost guard), branding=false, hostedNotice=true.
 */
import { App } from "aws-cdk-lib";
import { SwitchboardEdgeStack } from "../lib/edge.js";
import { SwitchboardStack } from "../lib/stack.js";

const app = new App();
const ctx = (k: string) => app.node.tryGetContext(k) as string | undefined;
const num = (k: string) => (ctx(k) === undefined ? undefined : Number(ctx(k)));
const rc = ctx("reservedConcurrency");
const mode = ctx("mode") === "managed" ? "managed" : "single";
const idcStartUrl = ctx("idcStartUrl");
if (mode === "single" && !idcStartUrl) throw new Error("Missing context idcStartUrl: pass -c idcStartUrl=https://d-xxxxxxxxxx.awsapps.com/start (or -c mode=managed)");

const stackName = ctx("stackName") ?? "AwsMcpSwitchboard";
const account = process.env.CDK_DEFAULT_ACCOUNT;
const domainName = ctx("domainName");
const domain = domainName ? { name: domainName, zoneName: ctx("zoneName") ?? "", hostedZoneId: ctx("hostedZoneId") ?? "" } : undefined;
if (domain && (!domain.zoneName || !domain.hostedZoneId)) throw new Error("domainName needs zoneName and hostedZoneId");
const edge = domain ? new SwitchboardEdgeStack(app, `${stackName}Edge`, { env: { account, region: "us-east-1" }, domain, rateLimitPer5Min: num("rateLimitPer5Min") }) : undefined;
const email = ctx("alertEmail");

new SwitchboardStack(app, stackName, {
  env: { account, region: process.env.CDK_DEFAULT_REGION ?? "eu-central-1" },
  mode,
  idcStartUrl,
  idcRegion: ctx("idcRegion") ?? "eu-central-1",
  allowedRolePattern: ctx("allowedRolePattern"),
  reservedConcurrency: rc === undefined ? undefined : rc === "none" ? null : Number(rc),
  publicUrl: ctx("publicUrl") === "true",
  branding: ctx("branding") !== "false",
  hostedNotice: ctx("hostedNotice") === "true",
  domain: domain && edge ? { ...domain, certificate: edge.certificate, webAclArn: edge.webAclArn, originReadTimeoutSeconds: num("originReadTimeoutSeconds") } : undefined,
  costGuard: email ? { email, budgetUsd: num("budgetUsd"), invocationsPer5Min: num("invocationsPer5Min") } : undefined,
});
