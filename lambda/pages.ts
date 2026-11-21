/** HTML for the browser-facing login pages (device pairing, errors) and their self-hosted fonts. Styled after till-it-works.de. */
import type { Res } from "./http.js";
import type { Config } from "./config.js";
import { ALSO_BY } from "./branding.js";
import type { LegalLink, LegalPage } from "./legal.js";
import { FONTS } from "./fonts.js";
import { DEFAULT_REGION, IDC_REGIONS, startUrlOf, type Idc } from "./tenant.js";

export const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export const FONT_PATHS = Object.keys(FONTS).map((k) => `/assets/${k}`);
const fontPath = (prefix: string) => FONT_PATHS.find((p) => p.startsWith(`/assets/${prefix}-`))!;

const NOSNIFF = { "x-content-type-options": "nosniff" };

/** Login pages: own-origin fonts and images as data: URIs; script only with the per-response nonce; forms only where a page has one. */
export const PAGE_CSP = (scriptNonce?: string, form = false) =>
  `default-src 'none'; script-src ${scriptNonce ? `'nonce-${scriptNonce}'` : "'none'"}; style-src 'unsafe-inline'; font-src 'self'; img-src data:; connect-src 'self'; base-uri 'none'; form-action ${form ? "'self'" : "'none'"}; frame-ancestors 'none'`;

/** Every HTML page goes out with the same security headers; only the script nonce and form permission vary. */
export const htmlRes = (status: number, body: string, opts: { scriptNonce?: string; cookies?: string[]; form?: boolean } = {}): Res => ({
  status,
  headers: {
    "content-type": "text/html; charset=utf-8",
    "content-security-policy": PAGE_CSP(opts.scriptNonce, opts.form),
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
    pragma: "no-cache",
    ...NOSNIFF,
  },
  body,
  ...(opts.cookies ? { cookies: opts.cookies } : {}),
});

/** GET /assets/<font>.woff2 — file names carry a content hash, so they are cached immutably. */
export function fontAsset(path: string): Res | undefined {
  const name = path.startsWith("/assets/") ? path.slice("/assets/".length) : "";
  if (!Object.hasOwn(FONTS, name)) return undefined;
  return {
    status: 200,
    headers: { "content-type": "font/woff2", "cache-control": "public, max-age=31536000, immutable", ...NOSNIFF },
    body: FONTS[name],
    isBase64Encoded: true,
  };
}

/** Identity Center directory id (or alias) from the access portal URL. */
export function directoryOf(startUrl: string): string {
  try {
    const host = new URL(startUrl).hostname;
    return host.endsWith(".awsapps.com") ? host.split(".")[0]! : host;
  } catch {
    return "—";
  }
}

const REGION_NAMES: Record<string, string> = {
  "us-east-1": "N. Virginia", "us-east-2": "Ohio", "us-west-1": "N. California", "us-west-2": "Oregon",
  "ca-central-1": "Canada", "sa-east-1": "São Paulo",
  "eu-central-1": "Frankfurt", "eu-central-2": "Zurich", "eu-west-1": "Ireland", "eu-west-2": "London", "eu-west-3": "Paris",
  "eu-north-1": "Stockholm", "eu-south-1": "Milan", "eu-south-2": "Spain",
  "ap-northeast-1": "Tokyo", "ap-northeast-2": "Seoul", "ap-northeast-3": "Osaka", "ap-southeast-1": "Singapore",
  "ap-southeast-2": "Sydney", "ap-south-1": "Mumbai", "ap-east-1": "Hong Kong", "me-central-1": "UAE", "af-south-1": "Cape Town",
};
export const regionName = (r: string) => REGION_NAMES[r] ?? "";

const FONT_FACES = `
@font-face{font-family:"Space Grotesk";src:url(${fontPath("space-grotesk")}) format("woff2");font-weight:300 700;font-display:swap}
@font-face{font-family:"Plus Jakarta Sans";src:url(${fontPath("plus-jakarta-sans")}) format("woff2");font-weight:200 800;font-display:swap}
@font-face{font-family:"JetBrains Mono";src:url(${fontPath("jetbrains-mono")}) format("woff2");font-weight:100 800;font-display:swap}`;

const PRELOADS = FONT_PATHS.map((p) => `<link rel="preload" href="${p}" as="font" type="font/woff2" crossorigin>`).join("");

const BASE_CSS = `${FONT_FACES}
html{overflow-x:clip;-webkit-text-size-adjust:100%}
:root{
  --primary:#0ea5a0;--primary-dark:#0d9488;--teal-50:#f0fdfa;--teal-100:#ccfbf1;--teal-200:#99f6e4;--teal-300:#5eead4;--teal-700:#0f766e;
  --ink:#0f2027;--ink-2:#374151;--ink-3:#6b7280;--ink-4:#9ca3af;--rule:#e5e7eb;--surface:#fafffe;
  --hl-teal:#5eead473;--hl-yellow:#fde04780;
  --display:"Space Grotesk","Helvetica Neue",sans-serif;--body:"Plus Jakarta Sans","Helvetica Neue",sans-serif;--mono:"JetBrains Mono",Menlo,monospace;
  --ease:cubic-bezier(.16,1,.3,1);--shadow-teal:0 4px 20px #0ea5a04d;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--surface);color:var(--ink);font:400 15px/1.55 var(--body);min-height:100vh;display:flex;flex-direction:column}
a{color:inherit}
.wrap{width:100%;max-width:960px;margin:0 auto;padding:0 40px}
@media (max-width:640px){.wrap{padding:0 16px}}
main{flex:1;display:flex;flex-direction:column;justify-content:center;padding-bottom:16px}
.eyebrow{font:500 11px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--primary)}
h1{font:700 clamp(32px,5vw,44px)/1.05 var(--display);letter-spacing:-.035em;margin:0}
.col{width:100%;max-width:600px;margin:0 auto;padding:clamp(32px,8vh,80px) 0 0}
.head{text-align:center;margin:0 0 26px}
.head .eyebrow{margin:0 0 14px}
.head h1{font-size:clamp(34px,9vw,54px);line-height:1.02;letter-spacing:-.04em}
.hl{position:relative;white-space:nowrap;padding:0 .1em;z-index:0}
.hl::before{content:"";position:absolute;inset:.1em -.02em 0;background:var(--hl-teal);border-radius:3px;z-index:-1;transform-origin:left;transform:scaleX(0) rotate(-1deg);animation:swipe .9s .3s var(--ease) forwards}
@keyframes swipe{to{transform:scaleX(1) rotate(-1deg)}}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.fade{opacity:0;transform:translateY(8px);animation:rise .7s var(--ease) forwards}
.err{color:#e11d48}
.lede{color:var(--ink-2);max-width:560px}
.made+.legal{margin-top:-18px}
.made{margin:24px 0 32px;padding-top:16px;border-top:1px solid var(--rule);display:flex;flex-wrap:wrap;align-items:center;gap:8px 22px;font:500 11px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--ink-4)}
.made a{display:inline-flex;align-items:center;gap:8px;text-decoration:none;font:400 13px var(--body);letter-spacing:0;text-transform:none;color:var(--ink-3);transition:color .2s}
.made a:hover{color:var(--ink)}
.made b{font:600 13px var(--display);color:var(--ink)}
.made img{width:22px;height:22px;border-radius:5px}
.legal{display:flex;flex-wrap:wrap;gap:6px 18px;margin:24px 0 32px;font:400 12px var(--body)}
.legal a{color:var(--ink-4)}
.d1{animation-delay:.05s}.d2{animation-delay:.15s}.d3{animation-delay:.25s}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-delay:0s!important;transition-duration:.01ms!important}}`;

const DEVICE_CSS = `
.card{background:#fff;border:1px solid var(--rule);border-radius:14px;padding:20px;position:relative;overflow:hidden;box-shadow:0 10px 32px -18px #0f202733}
.card::after{content:"";position:absolute;inset:0 0 auto;height:3px;background:linear-gradient(90deg,var(--teal-300),var(--primary),var(--teal-700),var(--teal-300));background-size:200% 100%;animation:sheen 3s linear infinite}
@keyframes sheen{to{background-position:-200% 0}}
.code{display:flex;justify-content:center;gap:4px;margin:12px 0 14px}
.code span{display:grid;place-items:center;flex:1 1 0;min-width:0;max-width:34px;height:42px;border-radius:8px;background:var(--teal-50);border:1px solid var(--teal-100);font:600 20px var(--mono);opacity:0;transform:translateY(8px);animation:rise .5s var(--ease) forwards}
.code span.dash{flex:0 0 10px;background:none;border:0;color:var(--ink-4)}
.btn{display:flex;justify-content:center;align-items:center;gap:8px;background:var(--primary);color:#fff;text-decoration:none;font:500 14px var(--display);padding:11px 16px;border-radius:8px;transition:transform .15s var(--ease),box-shadow .2s var(--ease),background .2s}
.btn:hover{background:var(--primary-dark);box-shadow:var(--shadow-teal);transform:translateY(-1px)}
.btn .arr{transition:transform .2s var(--ease)}
.btn:hover .arr{transform:translateX(3px)}
.status{display:flex;align-items:center;gap:10px;margin-top:14px;font-size:13px;color:var(--ink-2)}
.dot{position:relative;width:8px;height:8px;border-radius:50%;background:var(--primary);flex:none}
.dot::before,.dot::after{content:"";position:absolute;inset:0;border-radius:50%;background:var(--primary);animation:ping 1.8s var(--ease) infinite}
.dot::after{animation-delay:.9s}
@keyframes ping{from{transform:scale(1);opacity:.5}to{transform:scale(3.2);opacity:0}}
.timer{margin-left:auto;font:500 11px var(--mono);color:var(--ink-4)}
.done,.failed{display:none}
.card[data-state=approved] .waiting,.card[data-state=failed] .waiting{display:none}
.card[data-state=approved] .done,.card[data-state=failed] .failed{display:block;animation:rise .5s var(--ease)}
.check{width:44px;height:44px;margin:4px 0 10px}
.check circle{stroke:var(--primary);stroke-width:3;fill:var(--teal-50);stroke-dasharray:190;stroke-dashoffset:190;animation:draw .7s var(--ease) forwards}
.check polyline{stroke:var(--primary);stroke-width:4;fill:none;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:40;stroke-dashoffset:40;animation:draw .45s .45s var(--ease) forwards}
@keyframes draw{to{stroke-dashoffset:0}}
.state-title{font:700 20px/1.2 var(--display);letter-spacing:-.02em;margin:0 0 4px}
.state-text{color:var(--ink-3);margin:0;font-size:13px}
.back-hint{display:none;margin:12px 0 0;font-size:13px;line-height:1.5;color:var(--ink-2);background:var(--teal-50);border-left:3px solid var(--teal-300);border-radius:8px;padding:8px 10px}
@media (pointer:coarse){.back-hint{display:block}}
.card[data-opened] .back-hint{display:block;animation:rise .4s var(--ease)}
.facts{list-style:none;margin:14px 0 16px;padding:0;display:grid;gap:8px;text-align:left}
.facts li{font-size:13.5px;line-height:1.5;color:var(--ink-2);background:var(--teal-50);border-left:3px solid var(--teal-300);border-radius:8px;padding:8px 10px}
.facts b{color:var(--ink);font-weight:600;margin-right:4px}
.facts .pattern{font-size:12px;white-space:normal;overflow-wrap:anywhere}
.done .fine{margin-top:8px;font-size:12px}
.failed .state-title{margin-top:10px}
dl{margin:22px 0 0}
.row:first-child{border-top:1px solid var(--rule)}
.row{display:grid;grid-template-columns:72px minmax(0,1fr);gap:14px;align-items:baseline;padding:11px 0;border-bottom:1px solid var(--rule);opacity:0;transform:translateY(6px);animation:rise .6s var(--ease) forwards}
.row:nth-child(2){animation-delay:.1s}.row:nth-child(3){animation-delay:.2s}.row:nth-child(4){animation-delay:.3s}
.row dt{font:500 11px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--primary)}
.row dd{margin:0;font:400 14px var(--mono);overflow-wrap:anywhere}
@media (max-width:560px){.row{grid-template-columns:1fr;gap:3px}}
.hlv b{font-weight:500;background:var(--hl-yellow);padding:0 4px;border-radius:2px}
.pattern{background:var(--ink);color:var(--teal-200);padding:2px 8px;border-radius:5px;font-size:13px;white-space:nowrap}
.row dd.scroll{overflow-x:auto;overflow-wrap:normal;scrollbar-width:thin}
.row dd.note{font:400 13.5px/1.5 var(--body);color:var(--ink-2)}
.row dd.note b{font-weight:600;color:var(--ink)}
.row dd.note a{color:inherit}`;

const head = (title: string, css: string) =>
  `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>${PRELOADS}
<style>${BASE_CSS}${css}</style></head>`;



export interface SiteInfo {
  startUrl: string;
  region: string;
  rolePattern: string;
}

/** What the sign-in page shows: the configured Identity Center (single mode) or the tenant's (managed). */
export const siteInfo = (cfg: Config, t?: Idc): SiteInfo =>
  cfg.mode === "managed" && t
    ? { startUrl: startUrlOf(t.d), region: t.r, rolePattern: cfg.allowedRolePattern.source }
    : { startUrl: cfg.idcStartUrl, region: cfg.idcRegion, rolePattern: cfg.allowedRolePattern.source };

/** Sign-in + Region rows: portal link with the directory highlighted, region with its city. */
function idcRows(site: SiteInfo): string {
  const portal = site.startUrl.replace(/^https?:\/\//, "");
  const dir = directoryOf(site.startUrl);
  const at = portal.indexOf(dir);
  const portalHtml = at < 0 ? escapeHtml(portal) : `${escapeHtml(portal.slice(0, at))}<b>${escapeHtml(dir)}</b>${escapeHtml(portal.slice(at + dir.length))}`;
  const city = regionName(site.region);
  return `<div class="row"><dt>Sign-in</dt><dd class="hlv"><a href="${escapeHtml(site.startUrl)}" target="_blank" rel="noopener noreferrer">${portalHtml}</a></dd></div>
      <div class="row"><dt>Region</dt><dd class="hlv"><b>${escapeHtml(site.region)}</b>${city ? ` ${escapeHtml(city)}` : ""}</dd></div>`;
}

const FORM_CSS = `
label{display:block;font:500 11px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--primary);margin:0 0 6px}
input,select{width:100%;font:400 16px var(--mono);color:var(--ink);background:var(--surface);border:1px solid var(--rule);border-radius:8px;padding:10px 12px;margin:0 0 16px}
input:focus,select:focus{outline:2px solid var(--teal-300);border-color:var(--primary)}
.hint{font-size:13px;color:var(--ink-3);margin:-10px 0 16px}
p.err{margin:0 0 14px;font-size:13px}`;

const CHOOSE_CSS = `${FORM_CSS}
.card{background:#fff;border:1px solid var(--rule);border-radius:14px;padding:22px;box-shadow:0 10px 32px -18px #0f202733}
button{width:100%;font:500 14px var(--display);color:#fff;background:var(--primary);border:0;border-radius:8px;padding:11px 16px;cursor:pointer}
button:hover{background:var(--primary-dark);box-shadow:var(--shadow-teal)}`;

/** Managed `/mcp` login: pick the Identity Center, then GET /authorize again with idc_d / idc_r added. */
const NOTICE_CSS = `
.notice{margin:24px 0 0;text-align:center;font-size:13px;color:var(--ink-3)}
.notice b{color:var(--ink);font-family:var(--display)}
.notice a{color:var(--primary)}
.notice code{font:400 12px var(--mono);overflow-wrap:anywhere}`;

/**
 * One-line notice for an operator-hosted instance (HOSTED_NOTICE=on): exploration only, self-host instead.
 * `repoUrl` is linked; a github.com repo also gets its `npm i github:owner/repo` line.
 */
function hostedNotice(repoUrl: string | undefined): string {
  if (!repoUrl) return "";
  const gh = /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+?)(?:\.git)?\/?$/.exec(repoUrl)?.[1];
  const dep = gh ? ` or <code>npm i github:${escapeHtml(gh)}</code>` : "";
  return `<p class="notice fade d3"><b>Exploration only</b>: rate-limited, no SLA. For real use, host it yourself: <a href="${escapeHtml(repoUrl)}" target="_blank" rel="noopener noreferrer">GitHub repo</a>${dep}.</p>`;
}

/** Operator footer links (imprint, terms, privacy …). */
function legalLinks(links: LegalLink[] | undefined): string {
  if (!links?.length) return "";
  return `<p class="legal">${links.map((a) => `<a href="${escapeHtml(a.href)}">${escapeHtml(a.label)}</a>`).join("")}</p>`;
}

const DOC_CSS = `
.doc{font-size:15px;color:var(--ink-2)}
.doc h2{font:600 18px/1.3 var(--display);letter-spacing:-.01em;color:var(--ink);margin:28px 0 8px}
.doc h3{font:600 15px var(--display);color:var(--ink);margin:18px 0 6px}
.doc p,.doc ul{margin:0 0 12px}.doc ul{padding-left:20px}.doc li{margin:0 0 4px}
.doc a{color:var(--primary)}
.doc code{font:400 13px var(--mono);background:var(--teal-50);padding:1px 5px;border-radius:4px}
.back{display:inline-block;margin:0 0 6px;font:500 11px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--primary);text-decoration:none}`;

/** `/<slug>`: an operator legal page (trusted operator HTML). */
export function legalPage(opts: { page: LegalPage; links?: LegalLink[]; branding: boolean }): string {
  const { page, links, branding } = opts;
  return `${head(`${escapeHtml(page.title)} · AWS MCP Switchboard`, DOC_CSS + "h1{font-size:clamp(30px,7vw,40px)}")}<body>
<main class="wrap"><div class="col">
  <a class="back" href="/">← AWS MCP Switchboard</a>
  <h1>${escapeHtml(page.title)}</h1>
  <article class="doc">${page.html}</article>
${branding ? ALSO_BY.replace(" fade d3", "") : ""}
${legalLinks(links)}
</div></main></body></html>`;
}

export function choosePage(opts: { params: [string, string][]; directory: string; region: string; error?: string; hosted?: string; links?: LegalLink[] }): string {
  const hidden = opts.params.map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join("");
  const options = IDC_REGIONS.map((r) => `<option value="${r}"${r === opts.region ? " selected" : ""}>${r}${regionName(r) ? ` · ${regionName(r)}` : ""}</option>`).join("");
  return `${head("AWS MCP Switchboard · sign in", CHOOSE_CSS + NOTICE_CSS)}<body>
<main class="wrap"><div class="col">
  <header class="head"><p class="eyebrow fade d1">AWS MCP Switchboard</p><h1 class="fade d1">Which <span class="hl">Identity Center?</span></h1></header>
  <form class="card fade d2" method="get" action="/authorize">${hidden}
    ${opts.error ? `<p class="err">${escapeHtml(opts.error)}</p>` : ""}
    <label for="idc_d">Directory ID or sign-in link</label>
    <input id="idc_d" name="idc_d" value="${escapeHtml(opts.directory)}" placeholder="d-xxxxxxxxxx or sign-in link" autocomplete="off" spellcheck="false" required>
    <p class="hint">Your AWS access portal URL, or just the part before .awsapps.com.</p>
    <label for="idc_r">Identity Center region</label>
    <select id="idc_r" name="idc_r">${options}</select>
    <button type="submit">continue →</button>
  </form>
  ${hostedNotice(opts.hosted)}
  ${legalLinks(opts.links)}
</div></main></body></html>`;
}

const LANDING_CSS = `${DEVICE_CSS}${FORM_CSS}
.lede{margin:14px auto 0;max-width:470px;font-size:16px}
.lede code{font:400 14px var(--mono);background:var(--teal-50);padding:1px 6px;border-radius:4px;white-space:nowrap}
.copybar{display:flex;align-items:center;gap:6px;background:var(--ink);border-radius:12px;padding:6px;text-align:left}
.url{flex:1;min-width:0;color:var(--teal-200);padding:8px 10px;font:400 13px/1.45 var(--mono);overflow-wrap:anywhere}
.url.bad{color:#fda4af}
.url.empty{color:#94a3b8}
.copybar .btn{border:0;cursor:pointer;flex:none;padding:10px 18px}
.btn[disabled]{opacity:.45;cursor:default;box-shadow:none;transform:none}
.fold{margin:14px 0 0;text-align:left;background:#fff;border:1px solid var(--rule);border-radius:12px}
.fold summary{cursor:pointer;list-style:none;padding:13px 16px;font:600 14px var(--display);display:flex;justify-content:space-between;gap:12px}
.fold summary::-webkit-details-marker{display:none}
.fold summary::after{content:"+";color:var(--primary);font-family:var(--mono);transition:transform .3s var(--ease)}
.fold[open] summary::after{transform:rotate(45deg)}
.fold .inner{padding:0 16px 16px;font-size:14px;color:var(--ink-2)}
/* Smooth open/close where ::details-content and interpolate-size exist; elsewhere the content just fades in. */
.fold{interpolate-size:allow-keywords}
.fold::details-content{block-size:0;overflow:clip;transition:block-size .35s var(--ease),content-visibility .35s allow-discrete}
.fold[open]::details-content{block-size:auto}
.fold[open] .inner{animation:unfold .35s var(--ease)}
@keyframes unfold{from{opacity:0;transform:translateY(-6px)}}
@media (prefers-reduced-motion:reduce){.fold::details-content{transition:none}}
.fold .inner input,.fold .inner select{background:#fff}
.fold .inner select{margin:0}
.fold .inner p{margin:0 0 10px}.fold .inner p:last-child{margin:0}
.fold .inner b{font-family:var(--display);color:var(--ink)}
.fold .inner code{font:400 12px var(--mono);background:var(--teal-50);padding:2px 6px;border-radius:4px;overflow-wrap:anywhere}
.fold .inner a{color:var(--primary)}
.fold dl{margin:0}
.chain{list-style:none;margin:4px 0 0;padding:0}
.chain>li{position:relative;display:grid;grid-template-columns:40px minmax(0,1fr);gap:14px;padding:0 0 18px}
.chain>li:last-child{padding:0}
.chain>li:not(:last-child)::after{content:"";position:absolute;left:19px;top:44px;bottom:4px;width:2px;background:repeating-linear-gradient(var(--teal-200) 0 6px,transparent 6px 11px)}
.chain .ic{width:40px;height:40px;border-radius:10px;display:grid;place-items:center;background:#fff;border:1px solid var(--rule)}
.chain .ic svg{width:20px;height:20px;stroke:var(--ink-2);fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.chain .key .ic{background:var(--ink);border-color:var(--ink)}.chain .key .ic svg{stroke:var(--teal-200)}
.chain .dest .ic{background:var(--teal-50);border-color:var(--teal-200)}.chain .dest .ic svg{stroke:var(--teal-700)}
.chain b{font:600 15px var(--display);color:var(--ink)}
.chain small{font:500 10.5px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--ink-4);margin-left:6px}
.fold .chain p{margin:3px 0 0;font-size:14px;color:var(--ink-2)}
.chain p b{font-size:14px}
.chain code{font:400 12px var(--mono);background:var(--teal-50);padding:1px 5px;border-radius:4px}
.side{display:grid;gap:6px;margin:10px 0 0}
.side span{display:block;font-size:13px;color:var(--ink-3);background:#fff;border:1px solid var(--rule);border-left:3px solid var(--teal-300);border-radius:8px;padding:7px 10px}
.side span b{font-size:13px;margin-right:4px}
.accts{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 0}
.accts span{font:500 11.5px var(--mono);color:var(--teal-700);background:var(--teal-50);border:1px solid var(--teal-200);border-radius:999px;padding:4px 10px}
`;

/** First role name in the allowed-role pattern, for the example chips; "your role" when the pattern names none. */
const exampleRole = (pattern: string) => /[A-Za-z][\w+=,.@-]*/.exec(pattern)?.[0] ?? "your role";

const icon = (d: string) => `<span class="ic"><svg viewBox="0 0 24 24" aria-hidden="true">${d}</svg></span>`;

/** "How it works": client → switchboard (KMS, Identity Center) → official AWS MCP Server as the user. */
function howItWorks(rolePattern: string): string {
  const role = escapeHtml(exampleRole(rolePattern));
  return `<details class="fold how fade d3"><summary>How it works</summary><div class="inner">
    <ol class="chain">
      <li>${icon('<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>')}<div>
        <b>Your AI client</b><small>Claude</small>
        <p>Keeps your sign-in as a sealed token and sends it with every call.</p></div></li>
      <li class="key">${icon('<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>')}<div>
        <b>Switchboard</b><small>AWS Lambda</small>
        <p>Unseals the token per call, picks the account and role you asked for, forwards the call. Stores nothing.</p>
        <div class="side">
          <span><b>KMS</b>holds the key that seals and unseals your token. Without it the token is useless.</span>
          <span><b>IAM Identity Center</b>turns your sign-in into short-lived credentials for one of your roles.</span>
        </div></div></li>
      <li class="dest">${icon('<path d="M4 7l8-4 8 4v10l-8 4-8-4z"/><path d="M4 7l8 4 8-4M12 11v10"/>')}<div>
        <b>AWS MCP Server</b><small>official, by AWS</small>
        <p>Runs <b>as you</b> in the target account, with your role credentials. Same rights as <code>aws sso login</code>, nothing more.</p>
        <div class="accts"><span>prod · ${role}</span><span>staging · ${role}</span><span>…</span></div></div></li>
    </ol>
  </div></details>`;
}

/**
 * `/`. Managed: build the connector URL for one Identity Center (stays in the browser, nothing is sent).
 * Single (`single` set): the one connector URL and the configured Identity Center.
 */
export function landingPage(opts: { baseUrl: string; rolePattern: string; scriptNonce: string; repoUrl: string; branding: boolean; single?: SiteInfo; hosted?: string; links?: LegalLink[] }): string {
  const { baseUrl, rolePattern, scriptNonce, repoUrl, branding, single, hosted, links } = opts;
  const options = IDC_REGIONS.map((r) => `<option value="${r}"${r === DEFAULT_REGION ? " selected" : ""}>${r}${regionName(r) ? ` · ${regionName(r)}` : ""}</option>`).join("");
  // Managed: no URL until a directory is entered (Copy stays disabled).
  const connector = single ? `${baseUrl}/mcp` : `${baseUrl}/mcp/<directory>/${DEFAULT_REGION}`;
  const idc = single
    ? `<details class="fold fade d3" open><summary>Identity Center</summary><div class="inner"><dl>${idcRows(single)}</dl></div></details>`
    : `<details class="fold fade d3" open><summary>Your Identity Center</summary><div class="inner">
      <label for="d">Directory or sign-in link</label>
      <input id="d" placeholder="d-xxxxxxxxxx or https://…" autocomplete="off" spellcheck="false">
      <p class="hint">Your directory name (d-xxxxxxxxxx or its alias) or your https:// sign-in link.</p>
      <label for="r">Region</label>
      <select id="r">${options}</select>
    </div></details>`;
  return `${head("AWS MCP Switchboard", LANDING_CSS + NOTICE_CSS)}<body>
<main class="wrap"><div class="col">
  <header class="head"><p class="eyebrow fade d1">AWS MCP Switchboard</p>
  <h1 class="fade d1">One login.<br><span class="hl">Every account.</span></h1>
  <p class="lede fade d2">One MCP login for all AWS accounts your IAM Identity Center lets you access. Basically <code>aws sso login</code> for MCP.</p></header>
  <div class="copybar fade d2"><div class="url${single ? "" : " empty"}" id="url">${escapeHtml(connector)}</div><button class="btn" id="copy" type="button"${single ? "" : " disabled"}>Copy</button></div>
  ${idc}
  <details class="fold fade d3"><summary>How to connect</summary><div class="inner">
    <p><b>claude.ai</b> · Settings → Connectors → Add custom connector → paste the URL.</p>
    <p><b>Claude Code</b> · <code id="cc">claude mcp add --transport http aws ${escapeHtml(connector)}</code></p>
    <p><b>Sign in</b> · your client opens the login page; approve the code in IAM Identity Center.</p>
  </div></details>
  ${howItWorks(rolePattern)}
  <details class="fold fade d3"><summary>Roles &amp; self-hosting</summary><div class="inner">
    <p><b>Read-only roles.</b> Only roles matching <span class="pattern">${escapeHtml(rolePattern)}</span> can be used.</p>
    <p><b>Run your own.</b> Open source, Apache-2.0. <a href="${escapeHtml(repoUrl)}" target="_blank" rel="noopener noreferrer">Deploy in your own AWS account →</a></p>
  </div></details>
  ${hostedNotice(hosted)}
${branding ? ALSO_BY : ""}
${legalLinks(links)}
</div></main>
<script nonce="${scriptNonce}">
const BASE = ${JSON.stringify(baseUrl)};
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const $ = (id) => document.getElementById(id);
/** Directory name (d-… or alias) or an https:// access portal link → directory; "" when empty; null when invalid. */
function directory(s) {
  s = s.trim();
  if (!s) return "";
  if (/^https:\\/\\//i.test(s)) {
    let h;
    try { h = new URL(s).hostname; } catch { return null; }
    if (!h.endsWith(".awsapps.com")) return null;
    s = h.slice(0, -".awsapps.com".length);
  }
  s = s.toLowerCase();
  return LABEL.test(s) ? s : null;
}
function update() {
  const d = directory($("d").value), r = $("r").value;
  const url = d ? BASE + "/mcp/" + d + "/" + r : null;
  const shown = url ?? (d === null ? "not a directory name or https:// sign-in link" : BASE + "/mcp/<directory>/" + r);
  $("url").textContent = shown;
  $("url").classList.toggle("bad", d === null);
  $("url").classList.toggle("empty", d === "");
  $("copy").disabled = !url;
  $("cc").textContent = "claude mcp add --transport http aws " + (url ?? BASE + "/mcp/<directory>/" + r);
}
if ($("d")) {
  $("d").addEventListener("input", update);
  $("r").addEventListener("change", update);
  update();
}
$("copy").addEventListener("click", async () => {
  if ($("copy").disabled) return;
  await navigator.clipboard.writeText($("url").textContent);
  $("copy").textContent = "Copied";
  setTimeout(() => { $("copy").textContent = "Copy"; }, 1500);
});
</script></body></html>`;
}

const SESSION_DOCS = "https://docs.aws.amazon.com/singlesignon/latest/userguide/user-interactive-sessions.html";

/**
 * How long a connection lasts: as long as the user's Identity Center session. Its duration is an IdC setting
 * (console only: no sso-admin API sets it) and is not returned with the tokens, so the page states the default
 * and where in the console to change it.
 */
function sessionHelp(site: SiteInfo): string {
  const r = escapeHtml(site.region);
  return `<b>Longer:</b> an Identity Center admin changes it in the <a href="https://${r}.console.aws.amazon.com/singlesignon/home?region=${r}" target="_blank" rel="noopener noreferrer">Identity Center console (${r})</a> → Settings → Authentication → Session duration → Configure → User interactive sessions, up to 90 days (console only, <a href="${SESSION_DOCS}" target="_blank" rel="noopener noreferrer">AWS docs</a>). Applies to new sessions, so connect again afterwards.`;
}

const sessionRow = (site: SiteInfo) =>
  `<div class="row"><dt>Session</dt><dd class="note">Stays signed in as long as your Identity Center session: <b>8&nbsp;h</b> by default (until <span data-until>8&nbsp;h from now</span>), up to 90 days if your admin set more. ${sessionHelp(site)}</dd></div>`;

export function devicePage(opts: {
  userCode: string;
  verifyUrl: string;
  pending: string;
  interval: number;
  expiresIn: number;
  scriptNonce: string;
  site: SiteInfo;
  branding?: boolean;
  hosted?: string;
  links?: LegalLink[];
}): string {
  const { userCode, verifyUrl, pending, interval, expiresIn, scriptNonce, site, branding = true, hosted, links } = opts;
  const tiles = [...userCode]
    .map((c, i) => `<span${c === "-" ? ' class="dash"' : ""} style="animation-delay:${(0.35 + i * 0.05).toFixed(2)}s">${escapeHtml(c)}</span>`)
    .join("");
  return `${head("AWS MCP Switchboard · sign in", DEVICE_CSS + NOTICE_CSS)}<body>
<main class="wrap"><div class="col">
  <header class="head"><p class="eyebrow fade d1">AWS MCP Switchboard</p><h1 class="fade d1">Approve <span class="hl">sign-in.</span></h1></header>
    <div class="card fade d2" id="card" data-state="waiting">
      <div class="waiting">
        <div class="eyebrow">your code</div>
        <div class="code" aria-label="${escapeHtml(userCode)}">${tiles}</div>
        <a class="btn" href="${escapeHtml(verifyUrl)}" target="_blank" rel="noopener noreferrer">open IAM Identity Center <span class="arr">→</span></a>
        <div class="status" role="status"><span class="dot" aria-hidden="true"></span><span>waiting for approval…</span><span class="timer" id="timer"></span></div>
        <p class="back-hint"><b>On a phone:</b> after you approve in Identity Center, don't close the window. Go back to this page (‹ or swipe back): it finishes the sign-in by itself.</p>
      </div>
      <div class="done" role="status">
        <svg class="check" viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="29"/><polyline points="20,33 29,42 45,23"/></svg>
        <p class="state-title">approved.</p>
        <p class="state-text">One step left: finish in your client.</p>
        <ul class="facts">
          <li><b>Signed in</b> until <span data-until>8&nbsp;h from now</span> with the default Identity Center session of 8&nbsp;h (up to 90 days if your admin set more).</li>
          <li><b>Roles</b> <span class="pattern">${escapeHtml(site.rolePattern)}</span> in every account Identity Center gives you.</li>
          <li><b>Ends early</b> when you sign out of the access portal or an admin ends your session. Then connect again.</li>
          <li>${sessionHelp(site)}</li>
        </ul>
        <a class="btn" id="finish" href="#"><span>Finish in <span id="client">your client</span></span><span class="arr">→</span></a>
        <p class="state-text fine">The finish link is valid for 10 minutes.</p>
      </div>
      <div class="failed" role="status">
        <div class="eyebrow err">sign-in stopped</div>
        <p class="state-title">code expired or denied.</p>
        <p class="state-text">Connect again from your AI client.</p>
      </div>
    </div>
    <dl class="fade d3">
      ${idcRows(site)}
      <div class="row"><dt>Roles</dt><dd class="scroll"><span class="pattern">${escapeHtml(site.rolePattern)}</span></dd></div>
      ${sessionRow(site)}
    </dl>
  ${hostedNotice(hosted)}
${branding ? ALSO_BY : ""}
${legalLinks(links)}
</div></main>
<script nonce="${scriptNonce}">
const PENDING = ${JSON.stringify(pending)};
const TTL = ${Math.max(1, Math.floor(expiresIn))};
let interval = ${Math.max(1, Math.floor(interval))};
const card = document.getElementById("card"), timer = document.getElementById("timer");
const started = Date.now();
function showUntil() {
  const t = new Date(Date.now() + 8 * 3600 * 1000).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" });
  for (const el of document.querySelectorAll("[data-until]")) el.textContent = t;
}
showUntil();
const finish = document.getElementById("finish");
function clientName(u) {
  const h = new URL(u).hostname;
  const is = (d) => h === d || h.endsWith("." + d);
  if (is("claude.ai") || is("claude.com")) return "Claude";
  if (is("chatgpt.com") || is("openai.com")) return "ChatGPT";
  if (is("vscode.dev")) return "VS Code";
  return "your client";
}
function clock() {
  if (card.dataset.state !== "waiting") return;
  const left = Math.max(0, TTL - Math.floor((Date.now() - started) / 1000));
  timer.textContent = Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0");
  setTimeout(clock, 1000);
}
clock();
let pollTimer, inflight = false, lastPoll = 0;
function schedule(ms) { clearTimeout(pollTimer); pollTimer = setTimeout(tick, ms); }
async function tick() {
  if (card.dataset.state !== "waiting" || inflight) return;
  inflight = true;
  lastPoll = Date.now();
  try {
    const r = await fetch("/poll", { method: "POST", headers: { "content-type": "application/json" }, credentials: "same-origin", body: JSON.stringify({ pending: PENDING }) });
    const b = await r.json().catch(() => ({}));
    if (r.ok && b.status === "ok") {
      // No auto-redirect: the user reads the facts and leaves explicitly (on phones the redirect closes the sheet).
      finish.href = b.redirect;
      document.getElementById("client").textContent = clientName(b.redirect);
      showUntil();
      card.dataset.state = "approved";
      return;
    }
    if (r.ok && b.status === "pending") { if (b.interval) interval = b.interval; return schedule(interval * 1000); }
    card.dataset.state = "failed";
  } catch { schedule(interval * 1000); } finally { inflight = false; }
}
// Back from Identity Center (tab switch, or back navigation restoring this page from bfcache): check as soon as
// the poll interval allows (polling earlier makes Identity Center answer slow_down, which only adds delay).
function pollNow() { if (!document.hidden && !inflight) schedule(Math.max(0, lastPoll + interval * 1000 - Date.now())); }
document.addEventListener("visibilitychange", pollNow);
window.addEventListener("pageshow", pollNow);
document.querySelector(".btn").addEventListener("click", () => { card.dataset.opened = "1"; });
schedule(interval * 1000);
</script></body></html>`;
}

export function errorPage(message: string): string {
  return `${head("AWS MCP Switchboard", "h1{margin:12px 0 8px}")}<body>
<main class="wrap">
  <div>
    <div class="eyebrow err fade d1">AWS MCP Switchboard · sign-in problem</div>
    <h1 class="fade d2">that didn't work.</h1>
    <p class="lede fade d3">${escapeHtml(message)}</p>
  </div>
</main></body></html>`;
}
