// Small, pure time helpers (unit-tested).

/** "just now", "42 s ago", "5 min ago", "3 h ago", "2 d ago", or a date for older entries. */
export function relativeTime(atUnixS: number, nowMs: number): string {
  const diffS = Math.round(nowMs / 1000 - atUnixS);
  if (diffS < 0) {
    // Small clock skew between server and phone: treat as now.
    return diffS > -60 ? "just now" : absoluteDate(atUnixS);
  }
  if (diffS < 10) return "just now";
  if (diffS < 60) return `${diffS} s ago`;
  const m = Math.floor(diffS / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d} d ago`;
  return absoluteDate(atUnixS);
}

/** ISO-like UTC timestamp "2026-10-31 12:34 UTC" (stable, locale-free). */
export function absoluteDate(atUnixS: number): string {
  const iso = new Date(atUnixS * 1000).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

/** Deadline (ms since epoch) for a countdown of `remainingS` seconds measured at `fetchedAtMs`. */
export function cooldownDeadline(remainingS: number, fetchedAtMs: number): number {
  const s = Number.isFinite(remainingS) && remainingS > 0 ? remainingS : 0;
  return fetchedAtMs + s * 1000;
}

/** Whole seconds left until `deadlineMs` (rounded up, never negative). */
export function secondsUntil(deadlineMs: number, nowMs: number): number {
  const left = Math.ceil((deadlineMs - nowMs) / 1000);
  return left > 0 ? left : 0;
}

/** "0:00" style countdown, "1:05:09" above one hour. */
export function formatCountdown(totalS: number): string {
  const s = Math.max(0, Math.floor(totalS));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const ss = String(sec).padStart(2, "0");
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${ss}`;
  return `${m}:${ss}`;
}

const TRANSITIONAL = new Set([
  "pending",
  "starting",
  "stopping",
  "rebooting",
  "shutting-down",
]);

export function isTransitional(state: string): boolean {
  return TRANSITIONAL.has(state.toLowerCase());
}

export const FAST_POLL_MS = 5_000;
export const SLOW_POLL_MS = 30_000;

/** Poll interval per SPEC §11: 5 s while transitional, else 30 s. */
export function pollInterval(state: string | null): number {
  return state !== null && isTransitional(state) ? FAST_POLL_MS : SLOW_POLL_MS;
}
