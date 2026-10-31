// Sign-out flow (docs/SPEC.md §11).
//
// Security rule: the UI may only claim "signed out" when the server confirmed it, i.e. the logout
// request succeeded, or the server answered 401 (there is no session left to destroy). Any other
// failure (CSRF rejection, 403, 5xx, network) leaves the HttpOnly session cookie valid, so the
// caller must NOT pretend the user is signed out.

import { ApiError, safeNavigationUrl, type LogoutResponse, type Me } from "./api";

/** The part of ApiClient the logout flow needs (kept small so it can be tested with fakes). */
export interface LogoutClient {
  logout(): Promise<LogoutResponse>;
  me(notify?: boolean): Promise<Me>;
}

export type LogoutOutcome =
  /** The server destroyed the session; navigate to `target` (IdP end-session or "/"). */
  | { kind: "redirect"; target: string }
  /** The server says there is no session (401): nothing left to destroy. */
  | { kind: "no_session" }
  /** The server session could not be ended and may still be active. */
  | { kind: "failed"; error: unknown };

export const LOGOUT_FAILED_MESSAGE =
  "Sign-out failed: your session is still active. Reload the page and try again.";

export const LOGOUT_FAILED_FORBIDDEN_MESSAGE =
  "The server session could not be ended. It grants no access to this app, but close the " +
  "browser to make sure it is gone.";

function isCode(e: unknown, code: string): boolean {
  return e instanceof ApiError && e.code === code;
}

function redirect(res: LogoutResponse, origin: string): LogoutOutcome {
  return { kind: "redirect", target: safeNavigationUrl(res.logout_url, origin) ?? "/" };
}

/**
 * POST /auth/logout. On a CSRF rejection (e.g. stale token after a backend restart) the CSRF
 * token is refreshed once via GET /api/me and the logout is retried exactly once.
 */
export async function performLogout(client: LogoutClient, origin: string): Promise<LogoutOutcome> {
  try {
    return redirect(await client.logout(), origin);
  } catch (e) {
    if (isCode(e, "unauthorized")) return { kind: "no_session" };
    if (!isCode(e, "csrf")) return { kind: "failed", error: e };
  }

  // CSRF check failed: refresh the token without triggering the global 401/403 handlers.
  try {
    await client.me(false);
  } catch (e) {
    if (isCode(e, "unauthorized")) return { kind: "no_session" };
    return { kind: "failed", error: e };
  }

  try {
    return redirect(await client.logout(), origin);
  } catch (e) {
    if (isCode(e, "unauthorized")) return { kind: "no_session" };
    return { kind: "failed", error: e };
  }
}
