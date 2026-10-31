import { useEffect, useState } from "react";

/** Current time in ms, re-rendering every `intervalMs` while `active`. */
export function useNow(intervalMs: number, active = true): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return undefined;
    const id = window.setInterval(() => {
      setNow(Date.now());
    }, intervalMs);
    return () => {
      window.clearInterval(id);
    };
  }, [intervalMs, active]);
  return now;
}

/** True while the document is visible (Page Visibility API). */
export function usePageVisible(): boolean {
  const [visible, setVisible] = useState(() => document.visibilityState !== "hidden");
  useEffect(() => {
    const onChange = () => {
      setVisible(document.visibilityState !== "hidden");
    };
    document.addEventListener("visibilitychange", onChange);
    return () => {
      document.removeEventListener("visibilitychange", onChange);
    };
  }, []);
  return visible;
}

/**
 * Seconds remaining until `deadline` (ms), ticking once per second and stopping at zero.
 * `setAt` is when the deadline was computed (so a stale clock never shows a larger value).
 */
export function useCountdown(deadline: number, setAt: number): number {
  const [now, setNow] = useState(setAt);
  useEffect(() => {
    if (deadline <= setAt) return undefined;
    const id = window.setInterval(() => {
      const t = Date.now();
      setNow(t);
      if (t >= deadline) window.clearInterval(id);
    }, 1000);
    return () => {
      window.clearInterval(id);
    };
  }, [deadline, setAt]);
  const left = Math.ceil((deadline - Math.max(now, setAt)) / 1000);
  return left > 0 ? left : 0;
}
