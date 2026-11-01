// Small, pure formatting helpers (unit-tested).

/** "0 B", "512 B", "1.5 KB", "12.3 MB", "1.07 GB" (decimal units, like network vendors). */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "–";
  if (n < 1000) return `${Math.round(n)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n;
  let i = -1;
  do {
    v /= 1000;
    i += 1;
  } while (v >= 1000 && i < units.length - 1);
  const digits = v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return `${v.toFixed(digits)} ${units[i]}`;
}

/** "45 s", "12 min", "3 h 05 min", "2 d 4 h". */
export function formatDuration(totalS: number): string {
  if (!Number.isFinite(totalS) || totalS < 0) return "–";
  const s = Math.floor(totalS);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ${String(m % 60).padStart(2, "0")} min`;
  const d = Math.floor(h / 24);
  return `${d} d ${h % 24} h`;
}
