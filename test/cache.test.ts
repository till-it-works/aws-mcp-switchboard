import { describe, expect, it } from "vitest";
import { LruCache } from "../lambda/cache.js";

describe("LruCache", () => {
  it("returns stored values until their TTL passes", () => {
    let now = 1_000;
    const c = new LruCache<string>({ max: 10, ttlMs: 100, now: () => now });
    c.set("a", "A");
    c.set("b", "B", 500);
    expect(c.get("a")).toBe("A");
    now += 101;
    expect(c.get("a")).toBeUndefined();
    expect(c.get("b")).toBe("B");
    now += 400;
    expect(c.get("b")).toBeUndefined();
  });

  it("evicts the least recently used entry beyond max", () => {
    const c = new LruCache<number>({ max: 2, ttlMs: 10_000 });
    c.set("a", 1);
    c.set("b", 2);
    expect(c.get("a")).toBe(1); // a is now most recent
    c.set("c", 3);
    expect(c.get("b")).toBeUndefined();
    expect(c.get("a")).toBe(1);
    expect(c.get("c")).toBe(3);
  });

  it("deletes entries", () => {
    const c = new LruCache<number>({ max: 2, ttlMs: 10_000 });
    c.set("a", 1);
    c.delete("a");
    expect(c.get("a")).toBeUndefined();
  });
});
