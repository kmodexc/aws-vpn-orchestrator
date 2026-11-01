import { useId, useState } from "react";
import { describeError, type ApiClient, type DebugLogLevel, type Telemetry } from "../api";
import { formatBytes, formatDuration } from "../format";
import { absoluteDate, relativeTime } from "../time";

interface Props {
  api: ApiClient;
  telemetry: Telemetry | null;
  error: string | null;
  now: number;
  /** Called after the log level was changed (so the dashboard refreshes at once). */
  onChanged: (t: Telemetry) => void;
}

/** The ingress reports once a minute; after this long without one, something is wrong. */
const STALE_AFTER_S = 25 * 60;

const LEVELS: { value: DebugLogLevel; label: string }[] = [
  { value: "info", label: "info — connections, reloads, errors" },
  { value: "debug", label: "debug — plus handshake details (noisy)" },
  { value: "trace", label: "trace — everything (very noisy)" },
];

export function IngressCard({ api, telemetry, error, now, onChanged }: Props) {
  const [level, setLevel] = useState<DebugLogLevel>("info");
  const [minutes, setMinutes] = useState(60);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const levelId = useId();
  const minutesId = useId();

  const apply = async (action: () => Promise<Telemetry>) => {
    setBusy(true);
    setActionError(null);
    try {
      onChanged(await action());
    } catch (e) {
      setActionError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  const r = telemetry?.report ?? null;
  const nowS = now / 1000;
  let checkin: React.ReactNode;
  if (r === null) {
    checkin = <span className="muted">Loading…</span>;
  } else if (r.last_report_at === null) {
    checkin = <span className="warn">No report yet — is the ingress running the current bootstrap?</span>;
  } else {
    const age = nowS - r.last_report_at;
    const text = relativeTime(r.last_report_at, now);
    checkin =
      age > STALE_AFTER_S ? (
        <span className="warn" title={absoluteDate(r.last_report_at)}>
          {text} — no report for {formatDuration(age)}
        </span>
      ) : (
        <span title={absoluteDate(r.last_report_at)}>{text}</span>
      );
  }

  const debug = telemetry?.debug_log ?? null;
  const debugActive = telemetry !== null && debug !== null && debug.until > telemetry.now;
  const debugLeftS = debug !== null ? debug.until - nowS : 0;

  return (
    <section className="card" aria-labelledby="ingress-title">
      <div className="card__head">
        <h2 id="ingress-title" className="card__title">
          Ingress health
        </h2>
      </div>
      {error !== null && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <dl className="kv">
        <dt>Last report</dt>
        <dd>{checkin}</dd>
        <dt>Connections</dt>
        <dd>{r?.connections ?? <span className="muted">–</span>}</dd>
        <dt>Traffic (24 h)</dt>
        <dd>
          {r === null ? "–" : `↑ ${formatBytes(r.upload_24h)} · ↓ ${formatBytes(r.download_24h)}`}
        </dd>
        <dt>sing-box</dt>
        <dd>
          {r?.version ?? "–"}
          {r?.uptime_s != null && <span className="muted"> · up {formatDuration(r.uptime_s)}</span>}
        </dd>
        <dt>Log level</dt>
        <dd>
          <span className="mono">{telemetry?.log_level ?? "–"}</span>
          {debugActive && (
            <span className="muted"> · back to warn in {formatDuration(Math.max(0, debugLeftS))}</span>
          )}
        </dd>
      </dl>

      <form
        className="settings"
        onSubmit={(e) => {
          e.preventDefault();
          void apply(() => api.setDebugLog(level, minutes));
        }}
      >
        <p className="muted small">
          Debug logging records every connection with client address and destination on the
          ingress and shows it below. It switches itself off; keep it short.
        </p>
        <div className="inline-fields">
          <div className="field">
            <label htmlFor={levelId}>Level</label>
            <select
              id={levelId}
              value={level}
              onChange={(e) => {
                setLevel(e.target.value as DebugLogLevel);
              }}
            >
              {LEVELS.map((l) => (
                <option key={l.value} value={l.value}>
                  {l.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field field--narrow">
            <label htmlFor={minutesId}>Minutes</label>
            <input
              id={minutesId}
              type="number"
              min={1}
              max={1440}
              required
              value={minutes}
              onChange={(e) => {
                setMinutes(Number(e.target.value));
              }}
            />
          </div>
        </div>
        {actionError !== null && <p className="error">{actionError}</p>}
        <div className="settings__actions">
          <button type="submit" className="btn btn--primary" disabled={busy}>
            {busy ? "Applying…" : debugActive ? "Change" : "Enable debug logging"}
          </button>
          <button
            type="button"
            className="btn"
            disabled={busy || !debugActive}
            onClick={() => {
              void apply(() => api.clearDebugLog());
            }}
          >
            Back to warn now
          </button>
        </div>
      </form>
    </section>
  );
}
