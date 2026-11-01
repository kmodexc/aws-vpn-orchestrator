import { useCallback, useEffect, useId, useRef, useState } from "react";
import { describeError, type ApiClient, type LogLine } from "../api";
import { usePageVisible } from "../hooks";

interface Props {
  api: ApiClient;
}

const POLL_MS = 5_000;
const MAX_SHOWN = 2000;

/** Live tail of the ingress' sing-box journal, as reported once a minute. Memory-only. */
export function LogsCard({ api }: Props) {
  const visible = usePageVisible();
  const [open, setOpen] = useState(false);
  const [lines, setLines] = useState<LogLine[]>([]);
  const [dropped, setDropped] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [follow, setFollow] = useState(true);
  const next = useRef(0);
  const epoch = useRef<number | null>(null);
  const pre = useRef<HTMLPreElement>(null);
  const bodyId = useId();
  const filterId = useId();

  const fetchMore = useCallback(async () => {
    try {
      let chunk = await api.logs(epoch.current === null ? 0 : next.current);
      const restarted = epoch.current !== null && chunk.epoch !== epoch.current;
      if (restarted) {
        // The server restarted or the buffer was cleared: its numbering starts over.
        chunk = await api.logs(0);
        setLines([]);
      }
      epoch.current = chunk.epoch;
      next.current = chunk.next;
      setDropped(chunk.dropped);
      setError(null);
      if (chunk.lines.length > 0) {
        setLines((old) => {
          const all = (restarted ? [] : old).concat(chunk.lines);
          return all.length > MAX_SHOWN ? all.slice(all.length - MAX_SHOWN) : all;
        });
      }
    } catch (e) {
      setError(describeError(e));
    }
  }, [api]);

  // Poll while open and visible.
  useEffect(() => {
    if (!open || !visible) return undefined;
    let cancelled = false;
    let timer: number | undefined;
    const tick = async () => {
      await fetchMore();
      if (!cancelled) timer = window.setTimeout(() => void tick(), POLL_MS);
    };
    void tick();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [open, visible, fetchMore]);

  // Keep the newest line in view unless the reader scrolled up.
  useEffect(() => {
    const el = pre.current;
    if (el !== null && follow) el.scrollTop = el.scrollHeight;
  }, [lines, follow]);

  const onScroll = () => {
    const el = pre.current;
    if (el === null) return;
    setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
  };

  const clear = async () => {
    try {
      const chunk = await api.clearLogs();
      epoch.current = chunk.epoch;
      next.current = chunk.next;
      setLines([]);
      setDropped(0);
      setError(null);
    } catch (e) {
      setError(describeError(e));
    }
  };

  const needle = filter.trim().toLowerCase();
  const shown = needle === "" ? lines : lines.filter((l) => l.text.toLowerCase().includes(needle));

  return (
    <section className="card" aria-labelledby="logs-title">
      <div className="card__head">
        <h2 id="logs-title" className="card__title">
          Ingress log
        </h2>
        <button
          type="button"
          className="btn btn--small"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => {
            setOpen((v) => !v);
          }}
        >
          {open ? "Hide" : "Show"}
        </button>
      </div>
      <div id={bodyId} hidden={!open}>
        {open && (
          <>
            <p className="muted small">
              sing-box journal lines as reported by the ingress (about once a minute). Held in
              memory only; gone when the control plane restarts, and discarded one hour after
              debug logging ends. At level <code>warn</code> only problems appear.
            </p>
            <div className="inline-fields">
              <div className="field">
                <label htmlFor={filterId}>Filter</label>
                <input
                  id={filterId}
                  type="search"
                  value={filter}
                  placeholder="e.g. error, reality, 203.0.113"
                  onChange={(e) => {
                    setFilter(e.target.value);
                  }}
                />
              </div>
              <div className="settings__actions settings__actions--end">
                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    setFollow(true);
                    const el = pre.current;
                    if (el !== null) el.scrollTop = el.scrollHeight;
                  }}
                  disabled={follow}
                >
                  Jump to end
                </button>
                <button type="button" className="btn" onClick={() => void clear()}>
                  Clear
                </button>
              </div>
            </div>
            {error !== null && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            <pre ref={pre} className="log" onScroll={onScroll} aria-live="off">
              {shown.length === 0
                ? "(no lines)"
                : shown.map((l) => l.text).join("\n")}
            </pre>
            <p className="muted small">
              {shown.length} of {lines.length} lines
              {dropped > 0 && ` · ${dropped} dropped (buffer or report cap)`}
            </p>
          </>
        )}
      </div>
    </section>
  );
}
