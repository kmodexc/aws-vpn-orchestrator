import { describe, expect, it, vi } from "vitest";
import {
  ApiClient,
  ApiError,
  describeError,
  loginUrl,
  parseRetryAfter,
  safeNavigationUrl,
  type FetchLike,
} from "./api";

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function mockFetch(res: Response | (() => Promise<Response>)) {
  return vi.fn<FetchLike>(() => (typeof res === "function" ? res() : Promise.resolve(res)));
}

const ME = {
  sub: "abc",
  username: "alice",
  email: null,
  roles: ["vpn-admin"],
  csrf_token: "csrf-123",
  is_admin: true,
};

const STATUS = {
  provider: "lightsail",
  region: "ap-southeast-1",
  instance: "ingress-1",
  state: "running",
  public_ip: "203.0.113.7",
  cooldown_remaining_s: 0,
  last_rotation_at: null,
};

describe("ApiClient", () => {
  it("sends same-origin GETs and parses /api/me", async () => {
    const f = mockFetch(jsonResponse(200, ME));
    const api = new ApiClient({ fetch: f });
    const me = await api.me();
    expect(me.username).toBe("alice");
    const [path, init] = f.mock.calls[0] ?? [];
    expect(path).toBe("/api/me");
    expect(init?.credentials).toBe("same-origin");
    expect(init?.method).toBe("GET");
  });

  it("sends CSRF token and JSON content type on mutating requests", async () => {
    const f = vi.fn<FetchLike>();
    f.mockResolvedValueOnce(jsonResponse(200, ME));
    f.mockResolvedValueOnce(jsonResponse(200, { public_ip: "203.0.113.9" }));
    const api = new ApiClient({ fetch: f });
    await api.me();
    const r = await api.rotate("  blocked  ");
    expect(r.public_ip).toBe("203.0.113.9");
    const [path, init] = f.mock.calls[1] ?? [];
    expect(path).toBe("/api/ingress/rotate");
    expect(init?.method).toBe("POST");
    const headers = init?.headers as Record<string, string>;
    expect(headers["X-CSRF-Token"]).toBe("csrf-123");
    expect(headers["Content-Type"]).toBe("application/json");
    expect(init?.credentials).toBe("same-origin");
    expect(init?.body).toBe(JSON.stringify({ reason: "blocked" }));
  });

  it("overrides the page's no-referrer policy so POSTs carry the real Origin (CSRF check)", async () => {
    // With the document's `Referrer-Policy: no-referrer` and a non-"cors" mode, browsers send
    // `Origin: null` on POST, which the backend rejects as `csrf`. Every request must therefore
    // either use mode "cors" or set referrerPolicy "same-origin".
    const f = mockFetch(() => Promise.resolve(jsonResponse(200, { ok: true })));
    const api = new ApiClient({ fetch: f });
    api.setCsrfToken("csrf-123");
    await api.start();
    await api.stop();
    f.mockImplementationOnce(() => Promise.resolve(jsonResponse(200, { public_ip: "203.0.113.9" })));
    await api.rotate();
    f.mockImplementationOnce(() =>
      Promise.resolve(jsonResponse(200, { logout_url: "https://auth.kmode.dev/logout" })),
    );
    await api.logout();
    expect(f.mock.calls.map(([p]) => p)).toEqual([
      "/api/ingress/start",
      "/api/ingress/stop",
      "/api/ingress/rotate",
      "/auth/logout",
    ]);
    for (const [, init] of f.mock.calls) {
      expect(init.method).toBe("POST");
      expect(init.mode).toBe("same-origin");
      expect(init.referrerPolicy).toBe("same-origin");
      expect(init.credentials).toBe("same-origin");
    }
  });

  it("omits an empty rotate reason and rejects an overlong one", async () => {
    const f = mockFetch(() => Promise.resolve(jsonResponse(200, { public_ip: "203.0.113.9" })));
    const api = new ApiClient({ fetch: f });
    await api.rotate("   ");
    expect(f.mock.calls[0]?.[1].body).toBe("{}");
    await expect(api.rotate("x".repeat(201))).rejects.toMatchObject({ code: "bad_request" });
  });

  it("calls onUnauthorized on 401", async () => {
    const onUnauthorized = vi.fn();
    const f = mockFetch(jsonResponse(401, { error: "unauthorized", message: "no" }));
    const api = new ApiClient({ fetch: f, onUnauthorized });
    await expect(api.status()).rejects.toMatchObject({ status: 401, code: "unauthorized" });
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("calls onForbidden on 403 forbidden but not on 403 csrf", async () => {
    const onForbidden = vi.fn();
    const api1 = new ApiClient({
      fetch: mockFetch(jsonResponse(403, { error: "forbidden", message: "x" })),
      onForbidden,
    });
    await expect(api1.status()).rejects.toMatchObject({ code: "forbidden" });
    expect(onForbidden).toHaveBeenCalledOnce();

    const api2 = new ApiClient({
      fetch: mockFetch(jsonResponse(403, { error: "csrf", message: "x" })),
      onForbidden,
    });
    await expect(api2.start()).rejects.toMatchObject({ code: "csrf" });
    expect(onForbidden).toHaveBeenCalledOnce();
  });

  it("maps 409 to conflict", async () => {
    const api = new ApiClient({
      fetch: mockFetch(jsonResponse(409, { error: "conflict", message: "busy" })),
    });
    const err = await api.stop().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("conflict");
    expect(describeError(err)).toMatch(/already running/);
  });

  it("reads retry_after_s from a 429 cooldown body", async () => {
    const api = new ApiClient({
      fetch: mockFetch(
        jsonResponse(429, { error: "cooldown", message: "wait", retry_after_s: 75 }, { "Retry-After": "80" }),
      ),
    });
    const err = (await api.rotate().catch((e: unknown) => e)) as ApiError;
    expect(err.code).toBe("cooldown");
    expect(err.retryAfterS).toBe(75);
    expect(describeError(err)).toContain("1 min 15 s");
  });

  it("falls back to the Retry-After header for rate limiting", async () => {
    const api = new ApiClient({
      fetch: mockFetch(
        new Response("Too Many Requests", { status: 429, headers: { "Retry-After": "12" } }),
      ),
    });
    const err = (await api.status().catch((e: unknown) => e)) as ApiError;
    expect(err.code).toBe("rate_limited");
    expect(err.retryAfterS).toBe(12);
  });

  it("maps 503 to unavailable", async () => {
    const api = new ApiClient({
      fetch: mockFetch(jsonResponse(503, { error: "unavailable", message: "aws down" })),
    });
    const err = (await api.status().catch((e: unknown) => e)) as ApiError;
    expect(err.code).toBe("unavailable");
    expect(describeError(err)).not.toContain("aws down");
  });

  it("maps a plain-text 500 to internal and keeps a sane request id", async () => {
    const api = new ApiClient({
      fetch: mockFetch(new Response("oops", { status: 500, headers: { "X-Request-Id": "req-42" } })),
    });
    const err = (await api.status().catch((e: unknown) => e)) as ApiError;
    expect(err.code).toBe("internal");
    expect(err.requestId).toBe("req-42");
  });

  it("drops a malformed request id", async () => {
    const api = new ApiClient({
      fetch: mockFetch(
        new Response("oops", { status: 500, headers: { "X-Request-Id": "<script>alert(1)</script>" } }),
      ),
    });
    const err = (await api.status().catch((e: unknown) => e)) as ApiError;
    expect(err.requestId).toBeNull();
  });

  it("ignores unknown error codes and uses the HTTP status", async () => {
    const api = new ApiClient({
      fetch: mockFetch(jsonResponse(404, { error: "weird", message: "x" })),
    });
    await expect(api.status()).rejects.toMatchObject({ code: "not_found" });
  });

  it("reports network failures", async () => {
    const api = new ApiClient({ fetch: mockFetch(() => Promise.reject(new TypeError("fail"))) });
    await expect(api.status()).rejects.toMatchObject({ code: "network", status: 0 });
  });

  it("rejects malformed success bodies", async () => {
    const api = new ApiClient({
      fetch: mockFetch(jsonResponse(200, { ...STATUS, cooldown_remaining_s: "5" })),
    });
    await expect(api.status()).rejects.toMatchObject({ code: "bad_response" });
  });

  it("rejects unknown event actions", async () => {
    const api = new ApiClient({
      fetch: mockFetch(
        jsonResponse(200, [{ at: 1, action: "explode", ip: null, detail: "", actor: "a" }]),
      ),
    });
    await expect(api.events()).rejects.toMatchObject({ code: "bad_response" });
  });

  it("clamps the events limit", async () => {
    const f = mockFetch(() => Promise.resolve(jsonResponse(200, [])));
    const api = new ApiClient({ fetch: f });
    await api.events(5000);
    expect(f.mock.calls[0]?.[0]).toBe("/api/events?limit=200");
  });

  it("loads, saves and resets protocol settings with CSRF", async () => {
    const settings = {
      reality_sni: "www.example.com",
      hy2_sni: "www.bing.com",
      hysteria2: true,
      hy2_obfs: true,
      shadowsocks: false,
    };
    const response = {
      settings,
      defaults: { ...settings, reality_sni: "www.microsoft.com", hy2_obfs: false, shadowsocks: true },
      overridden: true,
      ports: { vless_tcp: 443, hy2_udp: 443, ss: 8443 },
    };
    const f = vi.fn<FetchLike>();
    f.mockResolvedValueOnce(jsonResponse(200, ME));
    f.mockResolvedValueOnce(jsonResponse(200, response));
    f.mockResolvedValueOnce(jsonResponse(200, response));
    f.mockResolvedValueOnce(jsonResponse(200, { ...response, overridden: false }));
    const api = new ApiClient({ fetch: f });
    await api.me();

    const got = await api.settings();
    expect(got.settings.reality_sni).toBe("www.example.com");
    expect(got.ports.ss).toBe(8443);

    await api.saveSettings(settings);
    const [path, init] = f.mock.calls[2] ?? [];
    expect(path).toBe("/api/settings");
    expect(init?.method).toBe("PUT");
    const headers = init?.headers as Record<string, string>;
    expect(headers["X-CSRF-Token"]).toBe("csrf-123");
    expect(headers["Content-Type"]).toBe("application/json");
    expect(init?.body).toBe(JSON.stringify(settings));

    const reset = await api.resetSettings();
    expect(reset.overridden).toBe(false);
    const [, del] = f.mock.calls[3] ?? [];
    expect(del?.method).toBe("DELETE");
    expect(del?.body).toBeUndefined();
    expect((del?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-123");
  });

  it("rejects malformed settings", async () => {
    const api = new ApiClient({
      fetch: mockFetch(
        jsonResponse(200, {
          settings: { reality_sni: "a.example.com" },
          defaults: {},
          overridden: false,
          ports: { vless_tcp: 443, hy2_udp: 443, ss: 8443 },
        }),
      ),
    });
    await expect(api.settings()).rejects.toMatchObject({ code: "bad_response" });
  });

  it("accepts settings events", async () => {
    const api = new ApiClient({
      fetch: mockFetch(
        jsonResponse(200, [{ at: 1, action: "settings", ip: null, detail: "x", actor: "a" }]),
      ),
    });
    expect((await api.events())[0]?.action).toBe("settings");
  });

  it("parses telemetry and log chunks, validates the debug-log request", async () => {
    const telemetry = {
      report: {
        last_report_at: 1_700_000_000,
        version: "1.14.4",
        uptime_s: 120,
        connections: 3,
        upload_total: 1000,
        download_total: 5000,
        upload_24h: 1000,
        download_24h: 5000,
        config_sha256: "ab".repeat(32),
        log_lines: 2,
        log_dropped: 0,
      },
      debug_log: { level: "info", until: 1_700_001_800 },
      log_level: "info",
      now: 1_700_000_060,
    };
    const f = vi.fn<FetchLike>();
    f.mockResolvedValueOnce(jsonResponse(200, ME));
    f.mockResolvedValueOnce(jsonResponse(200, telemetry));
    f.mockResolvedValueOnce(
      jsonResponse(200, { lines: [{ seq: 7, text: "x" }], next: 8, dropped: 1 }),
    );
    f.mockResolvedValueOnce(jsonResponse(200, { ...telemetry, debug_log: null, log_level: "warn" }));
    const api = new ApiClient({ fetch: f });
    await api.me();
    const t = await api.telemetry();
    expect(t.report.connections).toBe(3);
    expect(t.debug_log?.level).toBe("info");
    const l = await api.logs(7);
    expect(f.mock.calls[2]?.[0]).toBe("/api/ingress/logs?after=7");
    expect(l.lines[0]?.text).toBe("x");
    expect(l.next).toBe(8);
    const cleared = await api.clearDebugLog();
    expect(cleared.debug_log).toBeNull();
    expect(f.mock.calls[3]?.[1]?.method).toBe("DELETE");
    await expect(api.setDebugLog("info", 0)).rejects.toMatchObject({ code: "bad_request" });
    await expect(api.setDebugLog("info", 5000)).rejects.toMatchObject({ code: "bad_request" });
  });

  it("rejects malformed telemetry", async () => {
    const api = new ApiClient({
      fetch: mockFetch(jsonResponse(200, { report: { connections: "3" }, debug_log: null, log_level: "warn", now: 1 })),
    });
    await expect(api.telemetry()).rejects.toMatchObject({ code: "bad_response" });
  });

  it("does not trigger onUnauthorized on logout", async () => {
    const onUnauthorized = vi.fn();
    const api = new ApiClient({
      fetch: mockFetch(jsonResponse(401, { error: "unauthorized", message: "x" })),
      onUnauthorized,
    });
    await expect(api.logout()).rejects.toMatchObject({ code: "unauthorized" });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});

describe("helpers", () => {
  it("parseRetryAfter prefers the body value", () => {
    expect(parseRetryAfter(10, "99")).toBe(10);
    expect(parseRetryAfter(undefined, "99")).toBe(99);
    expect(parseRetryAfter(undefined, "Wed, 21 Oct 2015 07:28:00 GMT")).toBeNull();
    expect(parseRetryAfter(-1, null)).toBeNull();
  });

  it("safeNavigationUrl only allows https (or http on localhost)", () => {
    const origin = "https://vpn.example.com";
    expect(safeNavigationUrl("https://auth.kmode.dev/logout?x=1", origin)).toBe(
      "https://auth.kmode.dev/logout?x=1",
    );
    expect(safeNavigationUrl("javascript:alert(1)", origin)).toBeNull();
    expect(safeNavigationUrl("data:text/html,hi", origin)).toBeNull();
    expect(safeNavigationUrl("http://evil.example/", origin)).toBeNull();
    expect(safeNavigationUrl("/", origin)).toBe("https://vpn.example.com/");
  });

  it("loginUrl builds a sanitized return_to", () => {
    expect(loginUrl("/", "")).toBe("/auth/login?return_to=%2F");
    expect(loginUrl("/x", "?login_error=denied&a=1")).toBe("/auth/login?return_to=%2Fx%3Fa%3D1");
    expect(loginUrl("//evil.example", "")).toBe("/auth/login?return_to=%2F");
  });

});
