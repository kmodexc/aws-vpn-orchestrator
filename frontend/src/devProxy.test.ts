import { describe, expect, it } from "vitest";
import { DEV_PROXY_PATTERNS } from "../vite.config";

// Mirrors Vite's matcher: keys starting with "^" are regexes, others are plain prefixes.
function proxied(url: string): boolean {
  return DEV_PROXY_PATTERNS.some((key) =>
    key.startsWith("^") ? new RegExp(key).test(url) : url.startsWith(key),
  );
}

describe("dev server proxy patterns", () => {
  it("are all anchored regexes (no plain prefixes)", () => {
    for (const key of DEV_PROXY_PATTERNS) expect(key.startsWith("^")).toBe(true);
  });

  it.each([
    "/api/me",
    "/api/events?limit=50",
    "/auth/login?return_to=%2F",
    "/auth/callback?code=x&state=y",
    "/auth/logout",
    "/s/sometoken",
    "/i/sometoken/config.json",
    "/healthz",
    "/healthz?x=1",
  ])("proxies backend path %s", (url) => {
    expect(proxied(url)).toBe(true);
  });

  it.each([
    "/",
    "/index.html",
    "/src/main.tsx",
    "/src/styles.css",
    "/src/components/Dashboard.tsx?t=123",
    "/@vite/client",
    "/@react-refresh",
    "/node_modules/.vite/deps/react.js",
    "/icon.svg",
    "/apix",
    "/authors",
    "/s",
    "/settings",
    "/i",
    "/images/a.png",
    "/healthzz",
  ])("serves %s from Vite", (url) => {
    expect(proxied(url)).toBe(false);
  });
});
