import { describe, expect, it } from "vitest";
import { parseLegal, validateLegal } from "../lambda/legal.js";

describe("legal config", () => {
  const terms = { slug: "terms", title: "Terms", html: "<p>t</p>" };

  it("empty when not configured", () => {
    expect(parseLegal(undefined)).toEqual({ pages: [], links: [] });
    expect(validateLegal(undefined)).toEqual({ pages: [], links: [] });
  });

  it("accepts pages and https / mailto / page-slug links", () => {
    const l = { pages: [terms], links: [{ label: "Terms", href: "/terms" }, { label: "Imprint", href: "https://op.example/i" }, { label: "Mail", href: "mailto:a@b.c" }] };
    expect(parseLegal(JSON.stringify(l))).toEqual(l);
  });

  it.each([
    ["reserved slug", { pages: [{ ...terms, slug: "authorize" }] }],
    ["bad slug", { pages: [{ ...terms, slug: "Terms/x" }] }],
    ["duplicate slug", { pages: [terms, terms] }],
    ["missing title", { pages: [{ ...terms, title: " " }] }],
    ["link to unknown page", { pages: [terms], links: [{ label: "P", href: "/privacy" }] }],
    ["http link", { links: [{ label: "I", href: "http://op.example" }] }],
    ["javascript link", { links: [{ label: "I", href: "javascript:alert(1)" }] }],
    ["empty label", { links: [{ label: "", href: "https://op.example" }] }],
  ])("rejects %s", (_n, l) => {
    expect(() => validateLegal(l)).toThrow();
  });
});
