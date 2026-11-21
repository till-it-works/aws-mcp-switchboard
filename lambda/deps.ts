/** Lazily-built per-container dependencies (SDK clients, sealer, OAuth facade, upstream, MCP endpoint). Tests inject fakes via setDeps. */
import { KMSClient } from "@aws-sdk/client-kms";
import { SSOOIDCClient } from "@aws-sdk/client-sso-oidc";
import { SSOClient } from "@aws-sdk/client-sso";
import { SSMClient } from "@aws-sdk/client-ssm";
import { loadConfig, type Config } from "./config.js";
import { createSealer, type Sealer } from "./seal.js";
import { createIdc, type Idc } from "./idc.js";
import { createOAuth, type OAuth } from "./oauth.js";
import { createUpstream, type Upstream } from "./upstream.js";
import { createMcp, type Mcp } from "./mcp.js";

export interface Deps {
  cfg: Config;
  sealer: Sealer;
  idc: Idc;
  oauth: OAuth;
  upstream: Upstream;
  mcp: Mcp;
}

let cached: Deps | undefined;

export function getDeps(): Deps {
  if (cached) return cached;
  const cfg = loadConfig();
  const sealer = createSealer({ kms: new KMSClient({}), keyArn: cfg.kmsKeyArn });
  const idc = createIdc({
    cfg,
    clientsFor: (region) => ({ oidc: new SSOOIDCClient({ region }), sso: new SSOClient({ region }) }),
    ssm: new SSMClient({}),
  });
  const upstream = createUpstream({ cfg });
  cached = { cfg, sealer, idc, upstream, oauth: createOAuth({ cfg, sealer, idc }), mcp: createMcp({ cfg, sealer, idc, upstream }) };
  return cached;
}

export function setDeps(d: Deps | undefined): void {
  cached = d;
}
