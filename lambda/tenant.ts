/**
 * Tenant = one IAM Identity Center instance, addressed by its access-portal directory label
 * (`d-xxxxxxxxxx` or an alias) and home region. Never stored server-side: it travels in the
 * connector URL (`/mcp/<d>/<r>`) and inside the sealed blobs.
 */

export interface Idc {
  /** Directory label: `d-xxxxxxxxxx` or alias, lowercase. */
  d: string;
  /** IdC home region. */
  r: string;
}

export const DEFAULT_REGION = "eu-central-1";

/** Commercial-partition regions (aws). Explicit list: region strings end up in SDK endpoint hostnames. */
export const IDC_REGIONS = [
  "af-south-1",
  "ap-east-1",
  "ap-east-2",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-south-1",
  "ap-south-2",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-southeast-3",
  "ap-southeast-4",
  "ap-southeast-5",
  "ap-southeast-6",
  "ap-southeast-7",
  "ca-central-1",
  "ca-west-1",
  "eu-central-1",
  "eu-central-2",
  "eu-north-1",
  "eu-south-1",
  "eu-south-2",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "il-central-1",
  "me-central-1",
  "me-south-1",
  "mx-central-1",
  "sa-east-1",
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
] as const;

const REGIONS = new Set<string>(IDC_REGIONS);
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PORTAL = ".awsapps.com";

export const isIdcRegion = (r: string): boolean => REGIONS.has(r);

/** Directory label from `d-…`, an alias, or a pasted access-portal URL; null if not recognisable. */
export function parseDirectory(input: string): string | null {
  const s = input.trim().toLowerCase();
  if (s.includes("/") || s.includes(".")) {
    let host: string;
    try {
      host = new URL(/^[a-z]+:\/\//.test(s) ? s : `https://${s}`).hostname;
    } catch {
      return null;
    }
    if (!host.endsWith(PORTAL)) return null;
    const label = host.slice(0, -PORTAL.length);
    return LABEL.test(label) ? label : null;
  }
  return LABEL.test(s) ? s : null;
}

export const startUrlOf = (d: string): string => `https://${d}${PORTAL}/start`;

export type McpTarget = { kind: "shared" } | { kind: "tenant"; idc: Idc };

/** `/mcp` → shared; `/mcp/<d>[/<r>]` → tenant (canonical lowercase only); anything else → null. */
export function parseMcpPath(path: string): McpTarget | null {
  if (path === "/mcp") return { kind: "shared" };
  const m = /^\/mcp\/([^/]+)(?:\/([^/]+))?$/.exec(path);
  if (!m) return null;
  const d = m[1]!;
  const r = m[2] ?? DEFAULT_REGION;
  if (parseDirectory(d) !== d || d.includes(".") || !isIdcRegion(r)) return null;
  return { kind: "tenant", idc: { d, r } };
}

/** Single mode: the deployment's one Identity Center as a tenant. */
export const configuredIdc = (startUrl: string, region: string): Idc => ({ d: parseDirectory(startUrl) ?? "default", r: region });

export const mcpPath = (idc?: Idc): string => (idc ? `/mcp/${idc.d}/${idc.r}` : "/mcp");
