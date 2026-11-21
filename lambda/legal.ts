/**
 * Operator legal pages (terms, privacy, …) served by the switchboard at `/<slug>`, plus the footer links.
 * Content is the operator's: the CDK stack inlines it into the bundle (`legal` prop), so it is never
 * part of this repo and not limited by the Lambda environment size.
 */

export interface LegalPage {
  /** Served at `/<slug>`. Lowercase letters, digits and dashes. */
  slug: string;
  title: string;
  /** Trusted operator HTML (the page body). Scripts are blocked by the page CSP. */
  html: string;
}

export interface LegalLink {
  label: string;
  /** `https://…`, `mailto:…`, or `/<slug>` of a page. */
  href: string;
}

export interface Legal {
  pages: LegalPage[];
  links: LegalLink[];
}

/** Top-level paths the switchboard already routes. */
const RESERVED = new Set(["mcp", "authorize", "token", "register", "poll", "assets"]);
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,40}[a-z0-9])?$/;

/** Throws on anything the handler couldn't serve unambiguously. Used at synth time and at cold start. */
export function validateLegal(l: Partial<Legal> | undefined): Legal {
  const pages = l?.pages ?? [];
  const links = l?.links ?? [];
  const slugs = new Set<string>();
  for (const p of pages) {
    if (!SLUG.test(p.slug) || RESERVED.has(p.slug)) throw new Error(`legal page slug ${JSON.stringify(p.slug)} is invalid or reserved`);
    if (slugs.has(p.slug)) throw new Error(`legal page slug ${JSON.stringify(p.slug)} is used twice`);
    if (!p.title?.trim() || typeof p.html !== "string") throw new Error(`legal page ${p.slug} needs a title and html`);
    slugs.add(p.slug);
  }
  for (const a of links) {
    if (!a.label?.trim()) throw new Error("legal link needs a label");
    const local = a.href.startsWith("/") && slugs.has(a.href.slice(1));
    if (!local && !/^(https:\/\/|mailto:)\S+$/.test(a.href)) throw new Error(`legal link ${JSON.stringify(a.href)} must be https://, mailto: or /<page slug>`);
  }
  return { pages, links };
}

export function parseLegal(json: string | undefined): Legal {
  return json ? validateLegal(JSON.parse(json) as Partial<Legal>) : { pages: [], links: [] };
}
