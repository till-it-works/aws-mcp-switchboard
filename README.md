# AWS MCP Switchboard

**One MCP login for all AWS accounts your IAM Identity Center lets you access** — basically `aws sso login` for MCP. Sign in once; each tool call names the Target (`account_id` + `role_name`) and runs through the official [AWS MCP Server](https://docs.aws.amazon.com/aws-mcp/) with that role's short-lived credentials.

**Try it:** <https://aws-mcp-switchboard.inc.till-it-works.de> — hosted instance for exploration only (rate-limited, no SLA, read-only roles). For real use, [deploy it in your own AWS account](#deploy-in-your-own-aws-account).

- **Stateless:** no database. Client registrations, pending logins, auth codes, tokens and Task Handles are KMS-sealed blobs held by the client.
- **Small:** one Lambda, one KMS key (~$1/month). Optional CloudFront + custom domain, WAF rate limit and a cost breaker.
- **No new power:** a user reaches exactly the Targets they could reach with `aws sso login`, narrowed by `ALLOWED_ROLE_PATTERN` (default: read-only).
- **Any Identity Center (managed mode):** one deployment serves every IdC instance; directory and region travel in the connector URL and inside the sealed tokens, never stored server-side.

```
MCP client ──OAuth 2.1 (DCR, PKCE)──▶ Switchboard (Lambda) ──device flow──▶ IAM Identity Center
     │                                       │  GetRoleCredentials(account, role)
     └──── tools/call {account_id, role_name}┴──SigV4 (role creds)──▶ AWS MCP Server ──▶ AWS APIs
```

## Tools

| Tool | What it does |
|---|---|
| `list_accounts(name_filter?)` | Accounts and allowed roles of the signed-in user. Also returns `allowedRolePattern` and a note, so a user or agent that misses a role knows it is hidden by configuration. |
| `aws___run_script`, `aws___get_presigned_url` | Upstream tools with two extra required arguments: `account_id`, `role_name`. Upstream annotations (`destructiveHint`, …) are kept. |
| `aws___get_tasks` | Takes **Task Handles** instead of raw task ids. Long-running calls (> ~96 s) return a handle bound to the caller, Target and upstream session, so a model can never poll the wrong account. |
| `aws___search_documentation`, `aws___read_documentation`, `aws___retrieve_skill`, `aws___list_regions`, `aws___get_regional_availability` | Docs tools, unchanged; signed with the Lambda role. |

## Modes and connector URLs

| Mode | Connector URL | Identity Center |
|---|---|---|
| `single` (default) | `<base>/mcp` | fixed at deploy time (`idcStartUrl`, `idcRegion`) |
| `managed` | `<base>/mcp/<directory>/<region>` | from the URL, e.g. `/mcp/d-1234567890/eu-central-1` (region optional, default `eu-central-1`) |
| `managed` | `<base>/mcp` | asked at sign-in ("which Identity Center?"), remembered in a cookie |

`<directory>` is the part before `.awsapps.com` of the access portal URL (`d-xxxxxxxxxx` or an alias). The landing page at `<base>/` builds the URL. A token is only valid at the URL it was issued for.

## Deploy in your own AWS account

Prerequisites:

- Node.js ≥ 22, AWS CDK bootstrapped in the deploy account/region (and in `us-east-1` when using a custom domain).
- For `single` mode: your Identity Center **start URL** and **home region**.
- Nothing to register in Identity Center: the Lambda registers its own public OIDC client per IdC region on first use, like the AWS CLI. It is stored as an SSM SecureString parameter (`/mcp-switchboard/<stack>/oidc/<region>`, free tier) and renewed 7 days before expiry.
- Nothing to install in the target accounts. AWS MCP Server needs no MCP-specific IAM actions; each AWS call is authorized by the permission set's own policies.

```bash
git clone https://github.com/till-it-works/aws-mcp-switchboard && cd aws-mcp-switchboard
npm ci && npm test
AWS_PROFILE=<admin-profile> npx cdk deploy --all \
  -c idcStartUrl=https://d-xxxxxxxxxx.awsapps.com/start \
  -c idcRegion=eu-central-1 \
  -c publicUrl=true
```

Keep your values out of git in `cdk.context.json` (gitignored); `-c` flags override it. `npm run deploy` wraps `cdk deploy` (profile from `AWS_PROFILE`).

| Context key | Meaning |
|---|---|
| `mode` | `single` (default) or `managed` |
| `idcStartUrl`, `idcRegion` | single mode: your Identity Center (`idcRegion` default `eu-central-1`) |
| `allowedRolePattern` | regex on permission set names, default `^(ReadOnlyAccess\|ViewOnlyAccess)$` |
| `publicUrl` | `true` exposes the Lambda Function URL directly. Default: no public endpoint |
| `domainName`, `zoneName`, `hostedZoneId` | serve via CloudFront at your domain (Route 53 zone). Adds a `us-east-1` stack with the ACM certificate and a WAF rate limit |
| `rateLimitPer5Min` | WAF: requests per IP per 5 min before blocking, default 300 |
| `originReadTimeoutSeconds` | CloudFront origin timeout, default 60; up to the account's Service Quotas value "Response timeout per origin" (`L-AECE9FA7`) |
| `alertEmail` | enables the cost guard (below) |
| `budgetUsd`, `invocationsPer5Min` | cost guard limits, defaults 5 and 1000 |
| `reservedConcurrency` | default 20; `none` for accounts with the 10-execution default quota |
| `branding` | `false` removes the till-it-works "also by" line |
| `legal` | Your legal pages and footer links: `{ pages: [{ slug, title, html }], links: [{ label, href }] }`. Pages are served at `/<slug>`, links (`https://`, `mailto:` or `/<slug>`) appear on every page. The content is inlined into the Lambda bundle at synth time, so keep it in your deployment repo |
| `hostedNotice` | `true` for a shared demo instance: pages say "exploration only, rate-limited" and point to the repo / TypeScript dependency for self-hosting |
| `stackName` | default `AwsMcpSwitchboard` |

**No public endpoint by default.** Without `publicUrl` or `domainName` the stack creates the Lambda and KMS key but nothing reachable from the internet.

### As a library (operator repo)

```ts
import { App } from "aws-cdk-lib";
import { SwitchboardEdgeStack, SwitchboardStack } from "aws-mcp-switchboard";

const app = new App();
const domain = { name: "switchboard.example.com", zoneName: "example.com", hostedZoneId: "Z0123456789" };
const edge = new SwitchboardEdgeStack(app, "SwitchboardEdge", { env: { account: "123456789012", region: "us-east-1" }, domain });
new SwitchboardStack(app, "Switchboard", {
  env: { account: "123456789012", region: "eu-central-1" },
  mode: "managed",
  domain: { ...domain, certificate: edge.certificate, webAclArn: edge.webAclArn },
  costGuard: { email: "ops@example.com", budgetUsd: 5 },
  reservedConcurrency: null,
});
```

`package.json`: `"aws-mcp-switchboard": "github:till-it-works/aws-mcp-switchboard#v0.3.1"` plus `aws-cdk-lib`, `constructs`, `esbuild`, `tsx` (the package ships TypeScript sources).

### Cost guard

With `alertEmail` (or `costGuard`):

1. **Invocation breaker:** CloudWatch alarm on Lambda `Invocations` > 1000 per 5 min → SNS → email + breaker Lambda sets the switchboard's reserved concurrency to **0**. The service stays off until you reset it:
   ```bash
   AWS_PROFILE=<admin-profile> AWS_REGION=eu-central-1 npm run breaker:reset -- <StackName>
   ```
2. **Budget:** $5/month on tag `app=aws-mcp-switchboard`, email at 80 % actual and 100 % forecast. Activate the `app` cost allocation tag in Billing once.
3. **Edge (with a domain):** WAF IP rate limit; requests that bypass CloudFront are rejected by the Lambda before any KMS or IdC call (origin header).

Subscribing the distribution to the CloudFront flat-rate **Free** plan (1M requests + 100 GB/month, no overage charges, WAF included) is a one-time step after deploy (the distribution uses all edge locations, which the plans require):

```bash
aws pricing-plan-manager create-subscription --region us-east-1 --plan-family CloudFront --plan-tier FREE \
  --resource-arns <distribution ARN> <web ACL ARN from the Edge stack>
```

### Configuration (Lambda environment)

| Variable | Default |
|---|---|
| `SWITCHBOARD_MODE` | `single` |
| `IDC_START_URL`, `IDC_REGION` | from context (single mode) |
| `ALLOWED_ROLE_PATTERN` | `^(ReadOnlyAccess\|ViewOnlyAccess)$` |
| `AWS_MCP_ENDPOINT`, `AWS_MCP_REGION` | `https://aws-mcp.eu-central-1.api.aws/mcp`, `eu-central-1` |
| `ALLOWED_REDIRECT_URIS` | claude.ai, claude.com, ChatGPT, vscode.dev, `http://localhost:*`, `http://127.0.0.1:*` |
| `DOCS_TOOLS` | the five docs tools above |
| `ACCESS_TTL_SECONDS` | `3600` (capped by the Identity Center token expiry) |
| `OIDC_PARAM_PREFIX` | SSM path for the OIDC client registrations |
| `BASE_URL` | derived from the request host; set by the stack for a custom domain |
| `ORIGIN_SECRET` | set by the stack behind CloudFront; requests without the matching `x-origin-verify` header get 403 |
| `BRANDING`, `REPO_URL` | `off` removes the branding; repo linked from the landing page |
| `HOSTED_NOTICE` | `on` shows the exploration-only notice (set by `hostedNotice`) |

## Connect a client

- **claude.ai / Claude Desktop:** Settings → Connectors → Add custom connector → connector URL → Connect.
- **Claude Code:** `claude mcp add --transport http aws <connector URL>`, then `/mcp` → authenticate.
- Any client with MCP authorization (protocol 2025-03-26, 2025-06-18 or 2025-11-25; DCR + PKCE S256 + refresh tokens).

**Login:** the client opens the Switchboard page, which shows a code and a button to IAM Identity Center. Approve there (check the code matches), then come back to the Switchboard page: it shows how long the session lasts and a **Finish** button that returns to the client. On phones, go back to the page instead of closing the Identity Center window. Users must approve only codes from a page they opened themselves.

**How often users reconnect:** access blobs live ≤ 1 h and refresh silently; a full re-login is needed when the Identity Center session ends (the IdC "session duration" setting, 1 h – 90 d).

## Security notes

- **Token broker.** The Switchboard can act as the user in all their assigned accounts until the IdC session expires — the same power as an `aws sso login` cache on a laptop. Nothing is stored server-side: each client holds its own sealed blobs. Only the Lambda role may use the KMS key (key policy denies `Decrypt`/`GenerateDataKey` to every other principal, account admins included), so blobs can't be decrypted or forged outside the Lambda.
- **Hosted (managed) deployments:** users trust the operator — the operator's Lambda handles their IdC tokens. Self-host if that is not acceptable.
- **Blobs are bearer tokens.** HTTPS only; the Lambda never logs `Authorization` headers, `/token` or `/poll` bodies, codes, blobs or credentials (access log: method, path, status, duration, session id).
- **Device-code phishing.** The login is structurally a device-code flow. A nonce cookie binds polling to the browser that opened the page; users should approve only codes they started.
- **Auth codes** live 10 min (time to read the approved page before tapping Finish) and are bound to PKCE; single use is best-effort per container (stateless).
- **`ALLOWED_ROLE_PATTERN` matches by name only.** An admin can create a permission set named `ReadOnlyAccess` with any policy; the real bound is what IdC admins attach. `ReadOnlyAccess` includes data reads (`s3:GetObject`, DynamoDB items, logs); `ViewOnlyAccess` is metadata-only. Orgs with custom names set their own pattern.
- **Who can use it:** anyone who can sign in to the IdC instance, limited to their own assignments. Restrict further with IdC assignments or SCPs.
- **Org-wide guardrail (recommended):** SCPs or permission-set policies can deny on `aws:ViaAWSMCPService = true` (or `aws:CalledViaAWSMCP`). Every Switchboard call is an AWS MCP Server call, so such denies apply — the cleanest way to forbid AI-driven writes regardless of client.
- **Origin lock (custom domain):** CloudFront sends an origin header whose value is the stack's UUID (only visible to principals who can read the stack); the Lambda rejects requests without it before any KMS or IdC call. It keeps scanners off the Function URL so the WAF rate limit can't be bypassed; it is not an authentication boundary (every MCP call still needs a sealed token). The cost breaker caps a bypass either way.
- **Lambda role:** no AWS access beyond its SSM parameters, KMS key and `sts:GetCallerIdentity`, plus an explicit `Deny *` when `aws:ViaAWSMCPService = true`, so docs tools signed with it can't touch AWS resources.
- **Revocation:** revoke the user's IdC sessions (or the user signs out of the access portal) → the next refresh fails → access ends within ≤ 1 h. Kill switch for everyone: disable the KMS key (all blobs invalid).

## Known limitations

- **Function URLs remap `WWW-Authenticate`** to `x-amzn-Remapped-www-authenticate`, and CloudFront never runs viewer-response functions on 4xx. Behind CloudFront (custom domain) a viewer-request CloudFront Function therefore answers token-less `POST /mcp…` itself with a proper `WWW-Authenticate` 401. On a plain Function URL, or when an expired/invalid token is rejected by the Lambda, clients fall back to `/.well-known/oauth-protected-resource[/<path>]` discovery.
- Upstream long-running calls hold the request ~96 s before returning a Task Handle; behind CloudFront the default origin timeout is 60 s (raise via Service Quotas + `originReadTimeoutSeconds`).
- The AWS MCP Server endpoint region is configurable; one per deployment.

## Development

```bash
npm test         # vitest (AWS SDK and fetch mocked)
npm run build    # tsc --noEmit
npm run lint
npx tsx scripts/preview-pages.ts                                     # login/landing pages on http://127.0.0.1:8766
npx tsx scripts/e2e-login.ts <BaseUrl> login|refresh|rpc '<json>'   # scripted OAuth client for E2E
```

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Bundled fonts: SIL OFL 1.1 ([licenses/OFL-1.1-fonts.txt](licenses/OFL-1.1-fonts.txt)). Security reports: [SECURITY.md](SECURITY.md). The till-it-works branding is on by default and can be switched off (`branding: false`) or removed.
