import { describe, expect, it } from "vitest";
import {
  absoluteDate,
  cooldownDeadline,
  FAST_POLL_MS,
  formatCountdown,
  pollInterval,
  relativeTime,
  secondsUntil,
  SLOW_POLL_MS,
} from "./time";

const NOW_S = 1_800_000_000;
const NOW_MS = NOW_S * 1000;

describe("relativeTime", () => {
  it("formats recent times", () => {
    expect(relativeTime(NOW_S, NOW_MS)).toBe("just now");
    expect(relativeTime(NOW_S - 5, NOW_MS)).toBe("just now");
    expect(relativeTime(NOW_S - 42, NOW_MS)).toBe("42 s ago");
    expect(relativeTime(NOW_S - 5 * 60, NOW_MS)).toBe("5 min ago");
    expect(relativeTime(NOW_S - 3 * 3600, NOW_MS)).toBe("3 h ago");
    expect(relativeTime(NOW_S - 2 * 86400, NOW_MS)).toBe("2 d ago");
  });

  it("falls back to an absolute date for old entries", () => {
    expect(relativeTime(NOW_S - 90 * 86400, NOW_MS)).toBe(absoluteDate(NOW_S - 90 * 86400));
  });

  it("tolerates small clock skew", () => {
    expect(relativeTime(NOW_S + 20, NOW_MS)).toBe("just now");
    expect(relativeTime(NOW_S + 3600, NOW_MS)).toBe(absoluteDate(NOW_S + 3600));
  });

  it("absoluteDate is UTC and locale-free", () => {
    expect(absoluteDate(0)).toBe("1970-01-01 00:00 UTC");
  });
});

describe("cooldown", () => {
  it("counts down whole seconds, rounding up and never negative", () => {
    const d = cooldownDeadline(120, NOW_MS);
    expect(secondsUntil(d, NOW_MS)).toBe(120);
    expect(secondsUntil(d, NOW_MS + 500)).toBe(120);
    expect(secondsUntil(d, NOW_MS + 1000)).toBe(119);
    expect(secondsUntil(d, NOW_MS + 119_001)).toBe(1);
    expect(secondsUntil(d, NOW_MS + 120_000)).toBe(0);
    expect(secondsUntil(d, NOW_MS + 999_999)).toBe(0);
  });

  it("treats invalid remaining values as no cooldown", () => {
    expect(cooldownDeadline(-5, NOW_MS)).toBe(NOW_MS);
    expect(cooldownDeadline(Number.NaN, NOW_MS)).toBe(NOW_MS);
  });

  it("formats countdowns", () => {
    expect(formatCountdown(0)).toBe("0:00");
    expect(formatCountdown(5)).toBe("0:05");
    expect(formatCountdown(65)).toBe("1:05");
    expect(formatCountdown(3725)).toBe("1:02:05");
    expect(formatCountdown(-3)).toBe("0:00");
  });
});

describe("pollInterval", () => {
  it("polls fast while transitional", () => {
    expect(pollInterval("pending")).toBe(FAST_POLL_MS);
    expect(pollInterval("stopping")).toBe(FAST_POLL_MS);
    expect(pollInterval("starting")).toBe(FAST_POLL_MS);
    expect(pollInterval("running")).toBe(SLOW_POLL_MS);
    expect(pollInterval("stopped")).toBe(SLOW_POLL_MS);
    expect(pollInterval(null)).toBe(SLOW_POLL_MS);
  });
});
