import { describe, expect, it } from "vitest";
import { choosePage, devicePage, directoryOf, errorPage, fontAsset, FONT_PATHS, htmlRes, landingPage, legalPage, regionName } from "../lambda/pages.js";

const site = { startUrl: "https://d-1234567890.awsapps.com/start", region: "eu-central-1", rolePattern: "^(ReadOnlyAccess|ViewOnlyAccess)$" };
const page = (over: Partial<Parameters<typeof devicePage>[0]> = {}) =>
  devicePage({ userCode: "ABCD-EFGH", verifyUrl: "https://idc/verify?code=ABCD-EFGH", pending: "asb1.x", interval: 5, expiresIn: 600, scriptNonce: "N1", site, ...over });

describe("devicePage", () => {
  it("shows the user code as tiles and links to the verification URL", () => {
    const h = page();
    for (const c of "ABCDEFGH") expect(h).toContain(`>${c}</span>`);
    expect(h).toContain('class="dash"');
    expect(h).toContain('href="https://idc/verify?code=ABCD-EFGH"');
  });

  it("is titled AWS MCP Switchboard (tab and headline)", () => {
    const h = page();
    expect(h).toContain("<title>AWS MCP Switchboard · sign in</title>");
    expect(h).toMatch(/class="eyebrow[^"]*">AWS MCP Switchboard</);
    expect(h).toMatch(/<h1[^>]*>Approve <span class="hl">sign-in\.<\/span><\/h1>/);
    expect(errorPage("x")).toContain("<title>AWS MCP Switchboard</title>");
  });

  it("keeps the polling contract: nonce'd script, PENDING literal, /poll", () => {
    const h = page();
    expect(h).toContain('<script nonce="N1">');
    expect(h).toMatch(/const PENDING = "asb1\.x";/);
    expect(h).toContain('fetch("/poll"');
    expect(h).toContain("const TTL = 600;");
  });

  it("shows sign-in URL (directory highlighted), region and role pattern — values only", () => {
    const h = page();
    expect(h).toContain("<b>d-1234567890</b>.awsapps.com/start");
    expect(h).toContain("<b>eu-central-1</b> Frankfurt");
    expect(h).toContain("^(ReadOnlyAccess|ViewOnlyAccess)$");
    for (const k of ["idcStartUrl", "idcRegion", "allowedRolePattern", "your permissions"]) expect(h).not.toContain(k);
  });

  it("says how long the connection stays signed in and where to change it", () => {
    const h = page();
    expect(h).toMatch(/<dt>Session<\/dt>/);
    expect(h).toContain("Identity Center session");
    expect(h).toContain("<b>8&nbsp;h</b> by default");
    expect(h).toContain("up to 90 days");
    expect(h).toContain("data-until");
    expect(h).toContain("Settings → Authentication → Session duration → Configure");
    expect(h).toContain('href="https://docs.aws.amazon.com/singlesignon/latest/userguide/user-interactive-sessions.html"');
    // local end time for the default, filled in by the page script
    expect(h).toMatch(/Date\.now\(\) \+ 8 \* 3600 \* 1000/);
  });

  it("shows how to make the session longer: Identity Center console in the directory's region (console only, no CLI)", () => {
    const h = page({ site: { ...site, region: "eu-west-1" } });
    const done = /<div class="done"[^]*?<\/div>\s*<div class="failed"/.exec(h)![0];
    for (const part of [done, /<dt>Session<\/dt>[^]*?<\/div>/.exec(h)![0]]) {
      expect(part).toContain('href="https://eu-west-1.console.aws.amazon.com/singlesignon/home?region=eu-west-1"');
      expect(part).toContain("Settings → Authentication → Session duration → Configure");
      expect(part).toMatch(/console only/);
      expect(part).not.toContain("aws sso-admin");
    }
  });

  it("tells phone users to come back instead of closing, and finishes as soon as the page is visible again", () => {
    const h = page();
    expect(h).toContain('class="back-hint"');
    expect(h).toMatch(/don.t close the window/i);
    expect(h).toMatch(/back to this page/i);
    expect(h).toMatch(/@media \(pointer:coarse\)/);
    // tapping the button marks the card, so the hint is shown on every device from then on
    expect(h).toMatch(/\.btn[^]*addEventListener\("click"[^]*dataset\.opened/);
    // returning (tab switch or back navigation from bfcache) polls right away
    expect(h).toContain('addEventListener("visibilitychange"');
    expect(h).toContain('addEventListener("pageshow"');
  });

  it("approved state stays open with the key facts and an explicit finish button (no auto-redirect)", () => {
    const h = page();
    const done = /<div class="done"[^]*?<\/div>\s*<div class="failed"/.exec(h)![0];
    expect(done).toContain('id="finish"');
    expect(done).toMatch(/Finish in <span id="client">/);
    expect(done).toContain("data-until");
    expect(done).toContain("^(ReadOnlyAccess|ViewOnlyAccess)$");
    expect(done).toMatch(/sign out of the access portal/);
    expect(done).toMatch(/10 minutes/);
    expect(h).not.toMatch(/location\.href = b\.redirect/);
    expect(h).toMatch(/finish\.href = b\.redirect/);
  });

  it("page script parses (a SyntaxError would stop polling silently)", () => {
    const js = /<script nonce="N1">([^]*?)<\/script>/.exec(page())![1]!;
    expect(() => new Function(js)).not.toThrow();
  });

  it("is a single column without the flow diagram", () => {
    const h = page();
    expect(h).toContain('class="col"');
    expect(h).not.toContain("<svg class=\"flow\"");
  });

  it("links costpulse and korpus", () => {
    const h = page();
    expect(h).toContain('href="https://costpulse.cloud"');
    expect(h).toContain('href="https://korpus.cloud"');
  });

  it("escapes all dynamic values", () => {
    const h = page({ userCode: "<A>", verifyUrl: 'https://x/"><script>', site: { ...site, rolePattern: "^<x>$", startUrl: "https://a.example/<s>" } });
    expect(h).not.toContain("<A>");
    expect(h).not.toContain('"><script>');
    expect(h).toContain("^&lt;x&gt;$");
    expect(h).not.toContain("<s>");
  });

  it("loads fonts from this origin only — no third-party requests", () => {
    const h = page();
    for (const p of FONT_PATHS) expect(h).toContain(`url(${p})`);
    expect(h).not.toMatch(/googleapis|gstatic/);
  });
});

describe("errorPage", () => {
  it("escapes the message and uses the same styling", () => {
    const h = errorPage("bad <b>thing</b>");
    expect(h).toContain("bad &lt;b&gt;thing&lt;/b&gt;");
    expect(h).toContain("@font-face");
  });
});

describe("htmlRes", () => {
  it("sends the same security headers for every page; script only with a nonce", () => {
    const plain = htmlRes(400, "x").headers!;
    expect(plain).toMatchObject({ "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "cache-control": "no-store" });
    expect(plain["content-security-policy"]).toContain("script-src 'none'");
    const r = htmlRes(200, "y", { scriptNonce: "N", cookies: ["c=1"] });
    expect(r.headers!["content-security-policy"]).toContain("script-src 'nonce-N'");
    expect(r.cookies).toEqual(["c=1"]);
  });
});

describe("helpers", () => {
  it.each([
    ["https://d-1234567890.awsapps.com/start", "d-1234567890"],
    ["https://my-corp.awsapps.com/start/", "my-corp"],
    ["https://sso.example.com/start", "sso.example.com"],
    ["not a url", "—"],
  ])("directoryOf(%s) = %s", (u, d) => expect(directoryOf(u)).toBe(d));

  it("regionName knows common regions and falls back to empty", () => {
    expect(regionName("eu-central-1")).toBe("Frankfurt");
    expect(regionName("us-east-1")).toBe("N. Virginia");
    expect(regionName("xx-nowhere-9")).toBe("");
  });

  it("fontAsset serves known fonts as immutable base64 woff2, unknown → undefined", () => {
    const r = fontAsset(FONT_PATHS[0]!)!;
    expect(r.status).toBe(200);
    expect(r.isBase64Encoded).toBe(true);
    expect(r.headers?.["content-type"]).toBe("font/woff2");
    expect(r.headers?.["cache-control"]).toContain("immutable");
    expect(Buffer.from(r.body!, "base64").subarray(0, 4).toString()).toBe("wOF2");
    expect(fontAsset("/assets/nope.woff2")).toBeUndefined();
    expect(fontAsset("/assets/constructor")).toBeUndefined();
  });
});

describe("landingPage", () => {
  const REPO = "https://github.com/till-it-works/aws-mcp-switchboard";
  const land = (over: Partial<Parameters<typeof landingPage>[0]> = {}) =>
    landingPage({ baseUrl: "https://sb.example", rolePattern: "^(ReadOnlyAccess)$", scriptNonce: "N2", repoUrl: REPO, branding: true, ...over });

  it("managed: builder with directory field and region select (eu-central-1 default); no URL and Copy disabled until a directory is given", () => {
    const h = land();
    expect(h).toContain('id="d"');
    expect(h).toContain('<option value="eu-central-1" selected>');
    expect(h).toContain('<div class="url empty" id="url">https://sb.example/mcp/&lt;directory&gt;/eu-central-1</div>');
    expect(h).toContain('id="copy" type="button" disabled>Copy');
    expect(h).toContain("input,select{width:100%;font:400 16px"); // < 16px makes iOS zoom on focus
    expect(h).toContain(".fold::details-content{block-size:0"); // fold-outs open and close smoothly
    expect(h).toContain('<script nonce="N2">');
    expect(h).toContain('const BASE = "https://sb.example";');
  });

  it("builder script: directory name or alias, or an https:// sign-in link; Copy only with a valid directory", () => {
    const h = land();
    const js = h.slice(h.indexOf('<script nonce="N2">') + '<script nonce="N2">'.length, h.lastIndexOf("</script>"));
    type El = { value: string; textContent: string; disabled: boolean; cls: Set<string>; classList: { toggle(c: string, on: boolean): void }; addEventListener(): void };
    const el = (value = ""): El => {
      const cls = new Set<string>();
      return { value, textContent: "", disabled: false, cls, classList: { toggle: (c, on) => void (on ? cls.add(c) : cls.delete(c)) }, addEventListener: () => {} };
    };
    const dom: Record<string, El> = { d: el(), r: el("eu-central-1"), url: el(), copy: el(), cc: el() };
    const update = new Function("document", "navigator", `${js}; return update;`)({ getElementById: (id: string) => dom[id] }, {}) as () => void;
    const check = (input: string, url: string | null, cls?: string) => {
      dom.d!.value = input;
      update();
      expect(dom.copy!.disabled, input).toBe(url === null);
      if (url) expect(dom.url!.textContent).toBe(url);
      if (cls) expect(dom.url!.cls.has(cls), input).toBe(true);
    };
    check("", null, "empty");
    check("d-1234567890", "https://sb.example/mcp/d-1234567890/eu-central-1");
    check("My-Org", "https://sb.example/mcp/my-org/eu-central-1");
    check("https://my-org.awsapps.com/start#/", "https://sb.example/mcp/my-org/eu-central-1");
    check("my-org.awsapps.com/start", null, "bad");
    check("http://my-org.awsapps.com/start", null, "bad");
    check("https://evil.example/start", null, "bad");
    expect(dom.cc!.textContent).toBe("claude mcp add --transport http aws https://sb.example/mcp/<directory>/eu-central-1");
  });

  it("pitch: one MCP login for all Identity Center accounts, aws sso login for MCP", () => {
    expect(land()).toContain("One MCP login for all AWS accounts your IAM Identity Center lets you access. Basically <code>aws sso login</code> for MCP.");
  });

  it("how it works: client → Lambda (KMS, Identity Center) → official AWS MCP Server as the user", () => {
    const h = land();
    const at = h.indexOf('<details class="fold how');
    expect(at).toBeGreaterThan(-1);
    const how = h.slice(at, h.indexOf("</details>", at));
    expect(how).toContain("<summary>How it works</summary>");
    expect(how).not.toMatch(/<details[^>]*\bopen\b/);
    for (const s of ["Your AI client", "AWS Lambda", "<b>KMS</b>", "<b>IAM Identity Center</b>", "<b>AWS MCP Server</b><small>official, by AWS</small>", "<b>as you</b> in the target account"]) {
      expect(how).toContain(s);
    }
    expect(how).toContain("prod · ReadOnlyAccess");
    expect(land({ rolePattern: ".*" })).toContain("prod · your role");
    expect(land({ single: { startUrl: "https://d-1234567890.awsapps.com/start", region: "eu-central-1", rolePattern: ".*" } })).toContain('<details class="fold how');
  });

  it("links the repo for self-hosting and shows the role pattern", () => {
    const h = land();
    expect(h).toContain(`href="${REPO}"`);
    expect(h).toContain("^(ReadOnlyAccess)$");
  });

  it("single: fixed connector URL and the configured Identity Center, no builder", () => {
    const h = land({ single: { startUrl: "https://my-corp.awsapps.com/start", region: "us-east-1", rolePattern: "^(ReadOnlyAccess)$" } });
    expect(h).not.toContain('id="d"');
    expect(h).toMatch(/id="url">https:\/\/sb\.example\/mcp</);
    expect(h).toContain("<b>my-corp</b>.awsapps.com/start");
    expect(h).toContain("<b>us-east-1</b>");
  });

  it("branding: till-it-works also-by line, no legal links of its own; off removes it", () => {
    const on = land();
    expect(on).toContain("https://costpulse.cloud");
    expect(on).not.toContain('class="legal"');
    const off = land({ branding: false });
    for (const k of ["costpulse", "korpus", "till-it-works.de", "till-it-works"]) expect(off.replace(REPO, "")).not.toContain(k);
  });
});

describe("operator legal links and pages", () => {
  const links = [{ label: "Imprint", href: "https://op.example/imprint" }, { label: "Terms", href: "/terms" }];
  it("footer links on landing, chooser and sign-in page, independent of branding", () => {
    const land = landingPage({ baseUrl: "https://sb.example", rolePattern: ".*", scriptNonce: "n", repoUrl: "https://r.example", branding: false, links });
    for (const h of [land, choosePage({ params: [], directory: "", region: "eu-central-1", links }), page({ links })]) {
      expect(h).toContain('<p class="legal"><a href="https://op.example/imprint">Imprint</a><a href="/terms">Terms</a></p>');
    }
  });
  it("legal page: title, operator HTML, back link, footer", () => {
    const h = legalPage({ page: { slug: "terms", title: "Terms <of> use", html: "<h2>1. Scope</h2><p>x</p>" }, links, branding: true });
    expect(h).toContain("<title>Terms &lt;of&gt; use · AWS MCP Switchboard</title>");
    expect(h).toContain("<h1>Terms &lt;of&gt; use</h1>");
    expect(h).toContain('<article class="doc"><h2>1. Scope</h2><p>x</p></article>');
    expect(h).toContain('href="/">← AWS MCP Switchboard');
    expect(h).toContain('href="/terms">Terms<');
    expect(h).toContain("costpulse.cloud");
    expect(h).toContain(".made img{"); // also-by styles ship with every page
    expect(h).toContain("html{overflow-x:clip"); // no sideways panning on phones
  });
});

describe("branding off on the sign-in page", () => {
  it("drops the also-by line", () => {
    expect(page({ branding: false })).not.toContain("costpulse");
    expect(page()).toContain("costpulse");
  });
});

describe("hosted notice (operator demo instance)", () => {
  const REPO = "https://github.com/till-it-works/aws-mcp-switchboard";
  const land = (hosted?: string) =>
    landingPage({ baseUrl: "https://sb.example", rolePattern: "^(ReadOnlyAccess)$", scriptNonce: "N2", repoUrl: REPO, branding: true, hosted });

  it("landing: exploration-only, rate-limited, self-host via the repo or the TypeScript dependency", () => {
    const h = land(REPO);
    expect(h).toContain('class="notice');
    expect(h).toMatch(/exploration only/i);
    expect(h).toMatch(/rate-limited/i);
    expect(h).toContain(`href="${REPO}"`);
    expect(h).toContain("npm i github:till-it-works/aws-mcp-switchboard");
  });

  it("off by default (self-hosted deployments)", () => {
    expect(land()).not.toContain('class="notice');
    expect(page()).not.toContain('class="notice');
    expect(choosePage({ params: [], directory: "", region: "eu-central-1" })).not.toContain('class="notice');
  });

  it("also on the Identity Center chooser and the sign-in page", () => {
    expect(choosePage({ params: [], directory: "", region: "eu-central-1", hosted: REPO })).toMatch(/class="notice[^"]*"[\s\S]*exploration only/i);
    expect(page({ hosted: REPO })).toMatch(/class="notice[^"]*"[\s\S]*exploration only/i);
  });

  it("non-GitHub repo URL: link only, no npm dependency line", () => {
    const h = land("https://git.example.com/sb");
    expect(h).toContain('href="https://git.example.com/sb"');
    expect(h).not.toContain("npm i ");
  });
});
