import { describe, expect, it } from "vitest";
import { formatBytes, formatDuration } from "./format";

describe("formatBytes", () => {
  it("picks a unit and sensible precision", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(999)).toBe("999 B");
    expect(formatBytes(1500)).toBe("1.50 KB");
    expect(formatBytes(12_345_678)).toBe("12.3 MB");
    expect(formatBytes(1_070_000_000)).toBe("1.07 GB");
    expect(formatBytes(250_000_000_000)).toBe("250 GB");
    expect(formatBytes(-1)).toBe("–");
    expect(formatBytes(Number.NaN)).toBe("–");
  });
});

describe("formatDuration", () => {
  it("scales from seconds to days", () => {
    expect(formatDuration(45)).toBe("45 s");
    expect(formatDuration(12 * 60 + 5)).toBe("12 min");
    expect(formatDuration(3 * 3600 + 5 * 60)).toBe("3 h 05 min");
    expect(formatDuration(2 * 86400 + 4 * 3600)).toBe("2 d 4 h");
    expect(formatDuration(-3)).toBe("–");
  });
});
