import { describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError, type FetchLike, type Me } from "./api";
import { performLogout, type LogoutClient } from "./logout";

const ORIGIN = "https://vpn.example.com";

const ME = {
  sub: "abc",
  username: "alice",
  email: null,
  roles: ["vpn-admin"],
  is_admin: true,
  csrf_token: "fresh-token",
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function err(status: number, code: ApiError["code"]): ApiError {
  return new ApiError(status, code, code);
}

function fakeClient(
  logoutResults: (ApiError | string)[],
  meResult: ApiError | null = null,
) {
  const queue = [...logoutResults];
  const logout = vi.fn(() => {
    const next = queue.shift();
    if (next === undefined) return Promise.reject(new Error("unexpected logout call"));
    return next instanceof ApiError ? Promise.reject(next) : Promise.resolve({ logout_url: next });
  });
  const me = vi.fn<(notify?: boolean) => Promise<Me>>(() =>
    meResult !== null ? Promise.reject(meResult) : Promise.resolve(ME),
  );
  const client: LogoutClient = { logout, me };
  return { client, logout, me };
}

describe("performLogout", () => {
  it("redirects to the logout URL on success", async () => {
    const c = fakeClient(["https://auth.kmode.dev/logout?x=1"]);
    await expect(performLogout(c.client, ORIGIN)).resolves.toEqual({
      kind: "redirect",
      target: "https://auth.kmode.dev/logout?x=1",
    });
    expect(c.me).not.toHaveBeenCalled();
  });

  it("falls back to / for an unsafe logout URL", async () => {
    const c = fakeClient(["javascript:alert(1)"]);
    await expect(performLogout(c.client, ORIGIN)).resolves.toEqual({ kind: "redirect", target: "/" });
  });

  it("treats 401 as already signed out", async () => {
    const c = fakeClient([err(401, "unauthorized")]);
    await expect(performLogout(c.client, ORIGIN)).resolves.toEqual({ kind: "no_session" });
    expect(c.me).not.toHaveBeenCalled();
  });

  it("refreshes the CSRF token once and retries after a csrf failure", async () => {
    const c = fakeClient([err(403, "csrf"), `${ORIGIN}/`]);
    await expect(performLogout(c.client, ORIGIN)).resolves.toEqual({
      kind: "redirect",
      target: `${ORIGIN}/`,
    });
    expect(c.me).toHaveBeenCalledTimes(1);
    expect(c.me).toHaveBeenCalledWith(false);
    expect(c.logout).toHaveBeenCalledTimes(2);
  });

  it("reports failure (session still active) when the retry fails with csrf again", async () => {
    const c = fakeClient([err(403, "csrf"), err(403, "csrf")]);
    const out = await performLogout(c.client, ORIGIN);
    expect(out.kind).toBe("failed");
    expect(c.logout).toHaveBeenCalledTimes(2);
    expect(c.me).toHaveBeenCalledTimes(1);
  });

  it("reports failure when the CSRF refresh is forbidden (no csrf token available)", async () => {
    const c = fakeClient([err(403, "csrf")], err(403, "forbidden"));
    const out = await performLogout(c.client, ORIGIN);
    expect(out.kind).toBe("failed");
    expect(c.logout).toHaveBeenCalledTimes(1);
  });

  it("treats 401 during the CSRF refresh as already signed out", async () => {
    const c = fakeClient([err(403, "csrf")], err(401, "unauthorized"));
    await expect(performLogout(c.client, ORIGIN)).resolves.toEqual({ kind: "no_session" });
  });

  it("does not claim sign-out on 403 forbidden, 5xx or network errors", async () => {
    for (const e of [err(403, "forbidden"), err(503, "unavailable"), err(0, "network")]) {
      const c = fakeClient([e]);
      const out = await performLogout(c.client, ORIGIN);
      expect(out.kind).toBe("failed");
      expect(c.me).not.toHaveBeenCalled();
      expect(c.logout).toHaveBeenCalledTimes(1);
    }
  });

  it("works end-to-end with ApiClient: retry sends the refreshed token, no global handlers fire", async () => {
    const onUnauthorized = vi.fn();
    const onForbidden = vi.fn();
    const responses = [
      jsonResponse(403, { error: "csrf", message: "x" }),
      jsonResponse(200, ME),
      jsonResponse(200, { logout_url: `${ORIGIN}/` }),
    ];
    const f = vi.fn<FetchLike>(() => {
      const r = responses.shift();
      return r ? Promise.resolve(r) : Promise.reject(new Error("unexpected fetch"));
    });
    const api = new ApiClient({ fetch: f, onUnauthorized, onForbidden });
    api.setCsrfToken("stale-token");

    await expect(performLogout(api, ORIGIN)).resolves.toEqual({
      kind: "redirect",
      target: `${ORIGIN}/`,
    });

    const headersOf = (i: number) => f.mock.calls[i]?.[1].headers as Record<string, string>;
    expect(f.mock.calls.map((c) => c[0])).toEqual(["/auth/logout", "/api/me", "/auth/logout"]);
    expect(headersOf(0)["X-CSRF-Token"]).toBe("stale-token");
    expect(headersOf(2)["X-CSRF-Token"]).toBe("fresh-token");
    expect(onUnauthorized).not.toHaveBeenCalled();
    expect(onForbidden).not.toHaveBeenCalled();
  });

  it("ApiClient.me(false) does not trigger the global 403 handler", async () => {
    const onForbidden = vi.fn();
    const api = new ApiClient({
      fetch: () => Promise.resolve(jsonResponse(403, { error: "forbidden", message: "x" })),
      onForbidden,
    });
    await expect(api.me(false)).rejects.toMatchObject({ code: "forbidden" });
    expect(onForbidden).not.toHaveBeenCalled();
  });
});
