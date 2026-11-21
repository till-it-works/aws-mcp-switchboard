/**
 * Switchboard stack: KMS key + policy, Lambda; optionally CloudFront + custom domain (with SwitchboardEdgeStack)
 * and the cost guard. OIDC client registrations live in SSM parameters the Lambda writes itself.
 */
import { fileURLToPath } from "node:url";
import { Aws, CfnOutput, Duration, Fn, RemovalPolicy, Stack, Tags, type StackProps } from "aws-cdk-lib";
import type * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as targets from "aws-cdk-lib/aws-route53-targets";
import { NodejsFunction, OutputFormat } from "aws-cdk-lib/aws-lambda-nodejs";
import type { Construct } from "constructs";
import { CostGuard, type CostGuardProps } from "./cost-guard.js";
import type { DomainProps } from "./edge.js";
import { edgeAuthCode } from "./edge-auth.js";
import { validateLegal, type Legal } from "../../lambda/legal.js";

export interface SwitchboardStackProps extends StackProps {
  /** single (default): one Identity Center, `idcStartUrl` required. managed: any Identity Center, chosen per connector URL or at sign-in. */
  mode?: "single" | "managed";
  idcStartUrl?: string;
  /** Home region of the single-mode Identity Center. Default eu-central-1. */
  idcRegion?: string;
  /** Regex on permission set name. Default: AWS predefined read-only permission sets. */
  allowedRolePattern?: string;
  awsMcpEndpoint?: string;
  awsMcpRegion?: string;
  /** Lambda reserved concurrency; `null` = unreserved (accounts with a concurrency limit of 10). Default 20. */
  reservedConcurrency?: number | null;
  /** Expose the Lambda via a public Function URL (AuthType NONE). Default false: no public endpoint. */
  publicUrl?: boolean;
  /** Serve via CloudFront at a custom domain. Certificate + web ACL come from SwitchboardEdgeStack (us-east-1). */
  domain?: DomainProps & {
    certificate: acm.ICertificate;
    webAclArn?: string;
    /** CloudFront origin response timeout; > 60 needs a Service Quotas increase. Default 60. */
    originReadTimeoutSeconds?: number;
  };
  /** Invocation breaker + budget. Off when omitted. */
  costGuard?: CostGuardProps;
  /** till-it-works branding on the pages. Default true. */
  branding?: boolean;
  /** Operator-hosted demo: pages say "exploration only, rate-limited" and point to the repo for self-hosting. Default false. */
  hostedNotice?: boolean;
  /** Repo linked from the landing page. */
  repoUrl?: string;
  /**
   * Operator legal pages served at `/<slug>` and footer links on every page (e.g. imprint, terms, privacy).
   * Inlined into the Lambda bundle at synth time; keep the content in your deployment repo.
   */
  legal?: Partial<Legal>;
}

const ENCRYPTION_CONTEXT_APP = "aws-mcp-switchboard";
/** Every KMS action that uses key material; only the Lambda role may perform them (and only two of them). */
const KEY_USE_ACTIONS = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*", "kms:CreateGrant"];

export class SwitchboardStack extends Stack {
  constructor(scope: Construct, id: string, props: SwitchboardStackProps) {
    const mode = props.mode ?? "single";
    if (mode === "single" && !props.idcStartUrl) throw new Error("single mode needs idcStartUrl (or use mode: \"managed\")");
    const legal = validateLegal(props.legal);
    super(scope, id, { ...props, crossRegionReferences: props.crossRegionReferences ?? !!props.domain });
    Tags.of(this).add("app", "aws-mcp-switchboard");
    const oidcParamPrefix = `/mcp-switchboard/${this.stackName}/oidc`;

    const role = new iam.Role(this, "SwitchboardRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole")],
    });

    const key = new kms.Key(this, "SealKey", {
      description: "aws-mcp-switchboard: envelope key for client-held sealed blobs",
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
      policy: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            sid: "RootAdminWithoutKeyUse",
            effect: iam.Effect.ALLOW,
            principals: [new iam.AccountRootPrincipal()],
            notActions: KEY_USE_ACTIONS,
            resources: ["*"],
          }),
          new iam.PolicyStatement({
            sid: "LambdaRoleUse",
            effect: iam.Effect.ALLOW,
            principals: [new iam.ArnPrincipal(role.roleArn)],
            actions: ["kms:GenerateDataKey", "kms:Decrypt"],
            resources: ["*"],
            conditions: { StringEquals: { "kms:EncryptionContext:app": ENCRYPTION_CONTEXT_APP } },
          }),
          new iam.PolicyStatement({
            sid: "DenyKeyUseForOthers",
            effect: iam.Effect.DENY,
            principals: [new iam.AnyPrincipal()],
            actions: KEY_USE_ACTIONS,
            resources: ["*"],
            conditions: { StringNotEquals: { "aws:PrincipalArn": role.roleArn } },
          }),
        ],
      }),
    });

    const policy = new iam.Policy(this, "SwitchboardPolicy", {
      roles: [role],
      statements: [
        // One SecureString per IdC region, created by the Lambda (CloudFormation cannot create SecureStrings); default aws/ssm key.
        new iam.PolicyStatement({
          actions: ["ssm:GetParameter", "ssm:PutParameter"],
          resources: [`arn:${Aws.PARTITION}:ssm:${Aws.REGION}:${Aws.ACCOUNT_ID}:parameter${oidcParamPrefix}/*`],
        }),
        new iam.PolicyStatement({
          actions: ["kms:GenerateDataKey", "kms:Decrypt"],
          resources: [key.keyArn],
          conditions: { StringEquals: { "kms:EncryptionContext:app": ENCRYPTION_CONTEXT_APP } },
        }),
        new iam.PolicyStatement({ actions: ["sts:GetCallerIdentity"], resources: ["*"] }),
        // Lambda creds sign only tools/list + docs tools; they must never run an AWS call through AWS MCP Server.
        new iam.PolicyStatement({
          sid: "DenyEverythingViaAwsMcp",
          effect: iam.Effect.DENY,
          actions: ["*"],
          resources: ["*"],
          conditions: { Bool: { "aws:ViaAWSMCPService": "true" } },
        }),
      ],
    });

    const reserved = props.reservedConcurrency === null ? null : (props.reservedConcurrency ?? 20);
    // Shared by CloudFront (origin header) and the Lambda (check): the stack's UUID, known only inside the account.
    const originSecret = Fn.select(2, Fn.split("/", Aws.STACK_ID));

    const fn = new NodejsFunction(this, "Handler", {
      entry: fileURLToPath(new URL("../../lambda/handler.ts", import.meta.url)),
      handler: "handler",
      runtime: lambda.Runtime.NODEJS_24_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 512,
      timeout: Duration.seconds(120),
      role,
      reservedConcurrentExecutions: reserved ?? undefined,
      logGroup: new logs.LogGroup(this, "HandlerLogs", { retention: logs.RetentionDays.TWO_WEEKS, removalPolicy: RemovalPolicy.DESTROY }),
      environment: {
        SWITCHBOARD_MODE: mode,
        ...(props.idcStartUrl ? { IDC_START_URL: props.idcStartUrl } : {}),
        IDC_REGION: props.idcRegion ?? "eu-central-1",
        AWS_MCP_ENDPOINT: props.awsMcpEndpoint ?? "https://aws-mcp.eu-central-1.api.aws/mcp",
        AWS_MCP_REGION: props.awsMcpRegion ?? "eu-central-1",
        ALLOWED_ROLE_PATTERN: props.allowedRolePattern ?? "^(ReadOnlyAccess|ViewOnlyAccess)$",
        KMS_KEY_ARN: key.keyArn,
        OIDC_PARAM_PREFIX: oidcParamPrefix,
        ...(props.branding === false ? { BRANDING: "off" } : {}),
        ...(props.hostedNotice ? { HOSTED_NOTICE: "on" } : {}),
        ...(props.repoUrl ? { REPO_URL: props.repoUrl } : {}),
        ...(props.domain ? { BASE_URL: `https://${props.domain.name}`, ORIGIN_SECRET: originSecret } : {}),
        NODE_OPTIONS: "--enable-source-maps",
      },
      bundling: {
        format: OutputFormat.ESM,
        mainFields: ["module", "main"],
        target: "node22",
        minify: true,
        sourceMap: true,
        bundleAwsSDK: true,
        banner: "import { createRequire } from 'module';const require = createRequire(import.meta.url);",
        ...(legal.pages.length || legal.links.length ? { define: { "process.env.SWITCHBOARD_LEGAL": JSON.stringify(JSON.stringify(legal)) } } : {}),
      },
    });
    fn.node.addDependency(policy);

    if (props.publicUrl || props.domain) {
      // AuthType NONE: OAC would require clients to sign POST bodies. Behind CloudFront the Lambda rejects
      // requests without the origin secret header before doing any work.
      const url = fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });
      if (props.publicUrl) new CfnOutput(this, "BaseUrl", { value: url.url, description: "Function URL; MCP endpoint = <BaseUrl>mcp" });
      if (props.domain) this.cloudFront(props.domain, url, originSecret, mode === "managed");
    }

    if (props.costGuard) new CostGuard(this, "CostGuard", { ...props.costGuard, target: fn });

    new CfnOutput(this, "FunctionName", { value: fn.functionName, description: "for npm run breaker:reset" });
    new CfnOutput(this, "ReservedConcurrency", { value: reserved === null ? "none" : String(reserved), description: "restored by npm run breaker:reset" });
  }

  private cloudFront(domain: NonNullable<SwitchboardStackProps["domain"]>, url: lambda.IFunctionUrl, originSecret: string, managed: boolean) {
    // Discovery 401 with WWW-Authenticate is answered at the edge (see edge-auth.ts).
    const edgeAuth = new cloudfront.Function(this, "EdgeAuth", {
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      code: cloudfront.FunctionCode.fromInline(edgeAuthCode({ baseUrl: `https://${domain.name}`, managed })),
    });
    const dist = new cloudfront.Distribution(this, "Cdn", {
      comment: "aws-mcp-switchboard",
      domainNames: [domain.name],
      certificate: domain.certificate,
      webAclId: domain.webAclArn,
      // CloudFront flat-rate plans (Free/Pro) only accept distributions on all edge locations.
      priceClass: cloudfront.PriceClass.PRICE_CLASS_ALL,
      defaultBehavior: {
        origin: new origins.FunctionUrlOrigin(url, {
          customHeaders: { "x-origin-verify": originSecret },
          readTimeout: Duration.seconds(domain.originReadTimeoutSeconds ?? 60),
        }),
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        functionAssociations: [{ function: edgeAuth, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST }],
      },
    });
    const zone = route53.HostedZone.fromHostedZoneAttributes(this, "Zone", { zoneName: domain.zoneName, hostedZoneId: domain.hostedZoneId });
    const target = route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(dist));
    new route53.ARecord(this, "AliasA", { zone, recordName: domain.name, target });
    new route53.AaaaRecord(this, "AliasAAAA", { zone, recordName: domain.name, target });
    new CfnOutput(this, "Url", { value: `https://${domain.name}`, description: "MCP endpoint = <Url>/mcp" });
  }
}
