/** Tiny in-memory LRU with per-entry TTL. Per Lambda container; lost on cold start by design. */
export class LruCache<V> {
  private readonly map = new Map<string, { v: V; exp: number }>();
  private readonly max: number;
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(opts: { max: number; ttlMs: number; now?: () => number }) {
    this.max = opts.max;
    this.ttlMs = opts.ttlMs;
    this.now = opts.now ?? Date.now;
  }

  get(key: string): V | undefined {
    const e = this.map.get(key);
    if (!e) return undefined;
    this.map.delete(key);
    if (e.exp <= this.now()) return undefined;
    this.map.set(key, e); // re-insert = most recently used
    return e.v;
  }

  set(key: string, value: V, ttlMs = this.ttlMs): void {
    this.map.delete(key);
    this.map.set(key, { v: value, exp: this.now() + ttlMs });
    while (this.map.size > this.max) {
      const oldest = this.map.keys().next().value as string;
      this.map.delete(oldest);
    }
  }

  delete(key: string): void {
    this.map.delete(key);
  }
}
