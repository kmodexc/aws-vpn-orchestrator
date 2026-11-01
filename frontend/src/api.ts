// Typed client for the vpn-control REST API (docs/SPEC.md §5).
//
// - All requests are same-origin with credentials: "same-origin".
// - Mutating requests send X-CSRF-Token and Content-Type: application/json.
// - Every response body is validated at runtime before it is handed to the UI.

// ---------- Types (mirror SPEC.md §5 exactly) ----------

export type ErrorCode =
  | "unauthorized"
  | "forbidden"
  | "csrf"
  | "not_found"
  | "bad_request"
  | "cooldown"
  | "rate_limited"
  | "conflict"
  | "unavailable"
  | "internal";

/** Error codes the server can send plus client-side ones. */
export type ClientErrorCode = ErrorCode | "network" | "bad_response";

export interface Me {
  sub: string;
  username: string;
  email: string | null;
  roles: string[];
  csrf_token: string | null;
}

export interface Status {
  provider: string;
  region: string;
  instance: string;
  state: string;
  public_ip: string | null;
  cooldown_remaining_s: number;
  last_rotation_at: number | null;
}

export interface OkResponse {
  ok: true;
}

export interface RotateResponse {
  public_ip: string;
}

export type EventAction = "start" | "stop" | "rotate" | "settings" | "error";

export interface EventEntry {
  at: number;
  action: EventAction;
  ip: string | null;
  detail: string;
  actor: string;
}

export interface Subscription {
  url: string;
  links: string[] | null;
}

export interface WireGuard {
  enabled: boolean;
  ingress_public_key: string | null;
  ingress_address: string;
  vps_peer_snippet: string | null;
}

/** Protocol options changeable at runtime (`/api/settings`). */
export interface ProtocolSettings {
  reality_sni: string;
  hy2_sni: string;
  hysteria2: boolean;
  hy2_obfs: boolean;
  shadowsocks: boolean;
}

export interface SettingsResponse {
  settings: ProtocolSettings;
  defaults: ProtocolSettings;
  overridden: boolean;
  ports: { vless_tcp: number; hy2_udp: number; ss: number };
}

export interface LogoutResponse {
  logout_url: string;
}

export interface RotateRequest {
  reason?: string;
}

export const MAX_REASON_LENGTH = 200;
export const MAX_EVENTS = 200;

// ---------- Errors ----------

const ERROR_CODES: readonly ErrorCode[] = [
  "unauthorized",
  "forbidden",
  "csrf",
  "not_found",
  "bad_request",
  "cooldown",
  "rate_limited",
  "conflict",
  "unavailable",
  "internal",
];

export class ApiError extends Error {
  readonly status: number;
  readonly code: ClientErrorCode;
  /** Seconds to wait before retrying (429 cooldown / rate_limited), if known. */
  readonly retryAfterS: number | null;
  /** Server request id (X-Request-Id), useful when reporting internal errors. */
  readonly requestId: string | null;

  constructor(
    status: number,
    code: ClientErrorCode,
    message: string,
    retryAfterS: number | null = null,
    requestId: string | null = null,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryAfterS = retryAfterS;
    this.requestId = requestId;
  }
}

/** Friendly, fixed text for an error. Server-provided messages are not shown verbatim. */
export function describeError(err: unknown): string {
  if (!(err instanceof ApiError)) {
    return "Something went wrong. Please try again.";
  }
  switch (err.code) {
    case "unauthorized":
      return "Your session has expired. Please sign in again.";
    case "forbidden":
      return "Your account lacks the required role.";
    case "csrf":
      return "Security check failed. Reload the page and try again.";
    case "not_found":
      return "Not found.";
    case "bad_request":
      return "The request was rejected as invalid.";
    case "cooldown":
      return err.retryAfterS !== null
        ? `IP rotation is cooling down. Try again in ${formatSeconds(err.retryAfterS)}.`
        : "IP rotation is cooling down. Try again later.";
    case "rate_limited":
      return err.retryAfterS !== null
        ? `Too many requests. Try again in ${formatSeconds(err.retryAfterS)}.`
        : "Too many requests. Please wait a moment.";
    case "conflict":
      return "Another operation is already running. Wait for it to finish.";
    case "unavailable":
      return "The cloud provider or login service is unavailable right now. Try again shortly.";
    case "internal":
      return err.requestId !== null
        ? `Internal server error (request id ${err.requestId}).`
        : "Internal server error.";
    case "network":
      return "Network error. Check your connection and try again.";
    case "bad_response":
      return "Unexpected response from the server.";
  }
}

function formatSeconds(s: number): string {
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r === 0 ? `${m} min` : `${m} min ${r} s`;
}

function codeForStatus(status: number): ErrorCode {
  switch (status) {
    case 400:
    case 413:
    case 415:
    case 422:
      return "bad_request";
    case 401:
      return "unauthorized";
    case 403:
      return "forbidden";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    case 429:
      return "rate_limited";
    case 502:
    case 503:
    case 504:
      return "unavailable";
    default:
      return "internal";
  }
}

function isErrorCode(v: unknown): v is ErrorCode {
  return typeof v === "string" && (ERROR_CODES as readonly string[]).includes(v);
}

/** Parse a non-negative integer number of seconds (body value or Retry-After header). */
export function parseRetryAfter(bodyValue: unknown, header: string | null): number | null {
  if (typeof bodyValue === "number" && Number.isFinite(bodyValue) && bodyValue >= 0) {
    return Math.ceil(bodyValue);
  }
  if (header !== null && /^\d{1,9}$/.test(header.trim())) {
    return Number.parseInt(header.trim(), 10);
  }
  return null;
}

// ---------- Runtime validation helpers ----------

type Json = Record<string, unknown>;

function isObject(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function isString(v: unknown): v is string {
  return typeof v === "string";
}
function isStringOrNull(v: unknown): v is string | null {
  return v === null || typeof v === "string";
}
function isInt(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v);
}
function isIntOrNull(v: unknown): v is number | null {
  return v === null || isInt(v);
}
function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(isString);
}

function bad(): never {
  throw new ApiError(0, "bad_response", "Unexpected response from the server.");
}

export function parseMe(v: unknown): Me {
  if (
    isObject(v) &&
    isString(v.sub) &&
    isString(v.username) &&
    isStringOrNull(v.email) &&
    isStringArray(v.roles) &&
    isStringOrNull(v.csrf_token)
  ) {
    return {
      sub: v.sub,
      username: v.username,
      email: v.email,
      roles: v.roles,
      csrf_token: v.csrf_token,
    };
  }
  return bad();
}

export function parseStatus(v: unknown): Status {
  if (
    isObject(v) &&
    isString(v.provider) &&
    isString(v.region) &&
    isString(v.instance) &&
    isString(v.state) &&
    isStringOrNull(v.public_ip) &&
    isInt(v.cooldown_remaining_s) &&
    v.cooldown_remaining_s >= 0 &&
    isIntOrNull(v.last_rotation_at)
  ) {
    return {
      provider: v.provider,
      region: v.region,
      instance: v.instance,
      state: v.state,
      public_ip: v.public_ip,
      cooldown_remaining_s: v.cooldown_remaining_s,
      last_rotation_at: v.last_rotation_at,
    };
  }
  return bad();
}

export function parseOk(v: unknown): OkResponse {
  if (isObject(v) && v.ok === true) return { ok: true };
  return bad();
}

export function parseRotate(v: unknown): RotateResponse {
  if (isObject(v) && isString(v.public_ip)) return { public_ip: v.public_ip };
  return bad();
}

const EVENT_ACTIONS: readonly EventAction[] = ["start", "stop", "rotate", "settings", "error"];

function parseEvent(v: unknown): EventEntry {
  if (
    isObject(v) &&
    isInt(v.at) &&
    isString(v.action) &&
    (EVENT_ACTIONS as readonly string[]).includes(v.action) &&
    isStringOrNull(v.ip) &&
    isString(v.detail) &&
    isString(v.actor)
  ) {
    return {
      at: v.at,
      action: v.action as EventAction,
      ip: v.ip,
      detail: v.detail,
      actor: v.actor,
    };
  }
  return bad();
}

export function parseEvents(v: unknown): EventEntry[] {
  if (!Array.isArray(v)) return bad();
  return v.map(parseEvent);
}

export function parseSubscription(v: unknown): Subscription {
  if (isObject(v) && isString(v.url) && (v.links === null || isStringArray(v.links))) {
    return { url: v.url, links: v.links };
  }
  return bad();
}

export function parseWireGuard(v: unknown): WireGuard {
  if (
    isObject(v) &&
    typeof v.enabled === "boolean" &&
    isStringOrNull(v.ingress_public_key) &&
    isString(v.ingress_address) &&
    isStringOrNull(v.vps_peer_snippet)
  ) {
    return {
      enabled: v.enabled,
      ingress_public_key: v.ingress_public_key,
      ingress_address: v.ingress_address,
      vps_peer_snippet: v.vps_peer_snippet,
    };
  }
  return bad();
}

function parseProtocolSettings(v: unknown): ProtocolSettings {
  if (
    isObject(v) &&
    isString(v.reality_sni) &&
    isString(v.hy2_sni) &&
    typeof v.hysteria2 === "boolean" &&
    typeof v.hy2_obfs === "boolean" &&
    typeof v.shadowsocks === "boolean"
  ) {
    return {
      reality_sni: v.reality_sni,
      hy2_sni: v.hy2_sni,
      hysteria2: v.hysteria2,
      hy2_obfs: v.hy2_obfs,
      shadowsocks: v.shadowsocks,
    };
  }
  return bad();
}

export function parseSettings(v: unknown): SettingsResponse {
  if (
    isObject(v) &&
    typeof v.overridden === "boolean" &&
    isObject(v.ports) &&
    isInt(v.ports.vless_tcp) &&
    isInt(v.ports.hy2_udp) &&
    isInt(v.ports.ss)
  ) {
    return {
      settings: parseProtocolSettings(v.settings),
      defaults: parseProtocolSettings(v.defaults),
      overridden: v.overridden,
      ports: { vless_tcp: v.ports.vless_tcp, hy2_udp: v.ports.hy2_udp, ss: v.ports.ss },
    };
  }
  return bad();
}

export function parseLogout(v: unknown): LogoutResponse {
  if (isObject(v) && isString(v.logout_url)) return { logout_url: v.logout_url };
  return bad();
}

// ---------- Client ----------

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface ApiClientOptions {
  fetch?: FetchLike;
  /** Called on any 401 (session missing/expired). */
  onUnauthorized?: () => void;
  /** Called on a 403 with code "forbidden" (role missing). */
  onForbidden?: () => void;
}

export class ApiClient {
  private readonly fetchImpl: FetchLike;
  private csrfToken: string | null = null;
  onUnauthorized: (() => void) | undefined;
  onForbidden: (() => void) | undefined;

  constructor(opts: ApiClientOptions = {}) {
    this.fetchImpl = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.onUnauthorized = opts.onUnauthorized;
    this.onForbidden = opts.onForbidden;
  }

  setCsrfToken(token: string | null): void {
    this.csrfToken = token;
  }

  // ----- endpoints -----

  /**
   * Loads the current user and stores its CSRF token.
   * With `notify = false`, a 401/403 does not trigger onUnauthorized/onForbidden.
   */
  async me(notify = true): Promise<Me> {
    const me = parseMe(await this.get("/api/me", notify));
    this.csrfToken = me.csrf_token;
    return me;
  }

  async status(): Promise<Status> {
    return parseStatus(await this.get("/api/status"));
  }

  async start(): Promise<OkResponse> {
    return parseOk(await this.post("/api/ingress/start", {}));
  }

  async stop(): Promise<OkResponse> {
    return parseOk(await this.post("/api/ingress/stop", {}));
  }

  async rotate(reason?: string): Promise<RotateResponse> {
    const body: RotateRequest = {};
    const trimmed = reason?.trim() ?? "";
    if (trimmed.length > MAX_REASON_LENGTH) {
      throw new ApiError(0, "bad_request", "Reason is too long.");
    }
    if (trimmed !== "") body.reason = trimmed;
    return parseRotate(await this.post("/api/ingress/rotate", body));
  }

  async events(limit = 50): Promise<EventEntry[]> {
    const n = Math.min(Math.max(1, Math.floor(limit)), MAX_EVENTS);
    return parseEvents(await this.get(`/api/events?limit=${n}`));
  }

  async subscription(): Promise<Subscription> {
    return parseSubscription(await this.get("/api/subscription"));
  }

  async wireguard(): Promise<WireGuard> {
    return parseWireGuard(await this.get("/api/wireguard"));
  }

  async settings(): Promise<SettingsResponse> {
    return parseSettings(await this.get("/api/settings"));
  }

  async saveSettings(settings: ProtocolSettings): Promise<SettingsResponse> {
    return parseSettings(await this.send("PUT", "/api/settings", settings));
  }

  /** Drops the override; the `.env` defaults apply again. */
  async resetSettings(): Promise<SettingsResponse> {
    return parseSettings(await this.send("DELETE", "/api/settings"));
  }

  /** Destroys the session. Does not trigger onUnauthorized. */
  async logout(): Promise<LogoutResponse> {
    const res = parseLogout(await this.post("/auth/logout", {}, false));
    this.csrfToken = null;
    return res;
  }

  // ----- transport -----

  private get(path: string, notify = true): Promise<unknown> {
    return this.request(path, { method: "GET", headers: { Accept: "application/json" } }, notify);
  }

  private post(path: string, body: object, notify = true): Promise<unknown> {
    return this.send("POST", path, body, notify);
  }

  /** A state-changing request: carries the CSRF token; `body` is sent as JSON if given. */
  private send(
    method: "POST" | "PUT" | "DELETE",
    path: string,
    body?: object,
    notify = true,
  ): Promise<unknown> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.csrfToken !== null) headers["X-CSRF-Token"] = this.csrfToken;
    const init: RequestInit = { method, headers };
    if (body !== undefined) init.body = JSON.stringify(body);
    return this.request(path, init, notify);
  }

  private async request(path: string, init: RequestInit, notify: boolean): Promise<unknown> {
    // Only ever talk to our own origin.
    if (!path.startsWith("/") || path.startsWith("//")) {
      throw new ApiError(0, "bad_request", "Invalid request path.");
    }
    let res: Response;
    try {
      res = await this.fetchImpl(path, {
        ...init,
        credentials: "same-origin",
        mode: "same-origin",
        // The document runs under `Referrer-Policy: no-referrer` (SPEC §10, header and <meta>).
        // Inherited by fetch, that policy makes the browser send `Origin: null` on every
        // non-GET/HEAD request whose mode is not "cors" (Fetch spec, "append a request
        // `Origin` header"), and the backend's CSRF check (SPEC §4.4) rejects that with 403.
        // "same-origin" sends the real Origin (and Referer) only to our own origin, which is
        // the only origin `mode: "same-origin"` allows anyway. Navigations keep no-referrer.
        referrerPolicy: "same-origin",
        cache: "no-store",
        redirect: "error",
      });
    } catch {
      throw new ApiError(0, "network", "Network error.");
    }

    let body: unknown = null;
    const ct = res.headers.get("Content-Type") ?? "";
    if (ct.toLowerCase().includes("application/json")) {
      try {
        body = await res.json();
      } catch {
        body = null;
      }
    }

    if (res.ok) {
      if (body === null) bad();
      return body;
    }

    const err = toApiError(res, body);
    if (notify) {
      if (err.code === "unauthorized") this.onUnauthorized?.();
      else if (err.code === "forbidden") this.onForbidden?.();
    }
    throw err;
  }
}

function toApiError(res: Response, body: unknown): ApiError {
  const status = res.status;
  let code: ErrorCode = codeForStatus(status);
  let retryRaw: unknown = undefined;
  if (isObject(body)) {
    if (isErrorCode(body.error)) code = body.error;
    retryRaw = body.retry_after_s;
  }
  // A 401 is always "unauthorized" regardless of the body.
  if (status === 401) code = "unauthorized";
  const retryAfterS =
    status === 429 || status === 503 ? parseRetryAfter(retryRaw, res.headers.get("Retry-After")) : null;
  const requestId = res.headers.get("X-Request-Id");
  const safeRequestId = requestId !== null && /^[A-Za-z0-9._-]{1,64}$/.test(requestId) ? requestId : null;
  return new ApiError(status, code, `HTTP ${status} ${code}`, retryAfterS, safeRequestId);
}

/**
 * Accept a logout URL only if it is absolute http(s) (https unless localhost).
 * Prevents navigating to javascript: or other dangerous schemes.
 */
export function safeNavigationUrl(raw: string, currentOrigin: string): string | null {
  let u: URL;
  try {
    u = new URL(raw, currentOrigin);
  } catch {
    return null;
  }
  if (u.protocol === "https:") return u.toString();
  if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) {
    return u.toString();
  }
  return null;
}

/** Build the login URL with a sanitized same-origin return path. */
export function loginUrl(pathname: string, search: string): string {
  const params = new URLSearchParams(search);
  params.delete("login_error");
  const qs = params.toString();
  let returnTo = pathname + (qs === "" ? "" : `?${qs}`);
  if (!returnTo.startsWith("/") || returnTo.startsWith("//") || returnTo.includes("\\")) {
    returnTo = "/";
  }
  return `/auth/login?return_to=${encodeURIComponent(returnTo)}`;
}

/** Friendly text for the `login_error` query parameter set by /auth/callback (SPEC §4.1). */
export function loginErrorMessage(code: string | null): string | null {
  switch (code) {
    case null:
      return null;
    case "denied":
      return "Sign-in was cancelled or denied.";
    case "invalid":
      return "Sign-in failed or expired. Please try again.";
    case "forbidden":
      return "Your account lacks the required role for this app.";
    case "unavailable":
      return "The login service is unavailable right now. Try again shortly.";
    default:
      return "Sign-in failed. Please try again.";
  }
}
