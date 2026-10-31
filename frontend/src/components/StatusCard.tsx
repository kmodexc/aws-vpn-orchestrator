import { useState } from "react";
import type { Status } from "../api";
import { absoluteDate, formatCountdown, isTransitional, relativeTime } from "../time";
import { ConfirmDialog } from "./ConfirmDialog";

export type Action = "start" | "stop" | "rotate";

interface Props {
  status: Status | null;
  loading: boolean;
  statusError: string | null;
  cooldownS: number;
  now: number;
  busy: Action | null;
  actionError: string | null;
  actionNotice: string | null;
  onAction: (action: Action, reason: string) => void;
  onRefresh: () => void;
}

const KNOWN_STATES = new Set(["running", "stopped", "pending", "starting", "stopping"]);

function badgeClass(state: string): string {
  const s = state.toLowerCase();
  if (KNOWN_STATES.has(s)) return `badge badge--${s}`;
  if (isTransitional(s)) return "badge badge--pending";
  return "badge badge--unknown";
}

interface ConfirmCfg {
  title: string;
  message: string;
  label: string;
  danger: boolean;
}

const CONFIRM: Record<Action, ConfirmCfg> = {
  start: {
    title: "Start the ingress server?",
    message: "The server boots and the VPN becomes available in a minute or two.",
    label: "Start",
    danger: false,
  },
  stop: {
    title: "Stop the ingress server?",
    message: "All VPN connections drop until the server is started again.",
    label: "Stop",
    danger: true,
  },
  rotate: {
    title: "Rotate the public IP?",
    message:
      "The server gets a new public IP address. Active connections drop; clients must refresh their subscription.",
    label: "Rotate IP",
    danger: true,
  },
};

const BUSY_LABEL: Record<Action, string> = {
  start: "Starting…",
  stop: "Stopping…",
  rotate: "Rotating…",
};

export function StatusCard({
  status,
  loading,
  statusError,
  cooldownS,
  now,
  busy,
  actionError,
  actionNotice,
  onAction,
  onRefresh,
}: Props) {
  const [confirming, setConfirming] = useState<Action | null>(null);

  const state = status === null ? "" : status.state.toLowerCase();
  const transitional = isTransitional(state);
  const idle = status !== null && busy === null;
  const canStart = idle && state !== "running" && !transitional;
  const canStop = idle && state !== "stopped" && !transitional;
  const canRotate = idle && cooldownS === 0;

  const confirmCfg = confirming !== null ? CONFIRM[confirming] : null;

  let rotateLabel = "Rotate IP";
  if (busy === "rotate") rotateLabel = BUSY_LABEL.rotate;
  else if (cooldownS > 0) rotateLabel = `Rotate IP (${formatCountdown(cooldownS)})`;

  return (
    <section className="card" aria-labelledby="status-title">
      <div className="card__head">
        <h2 id="status-title" className="card__title">
          Ingress server
        </h2>
        <button
          type="button"
          className="btn btn--small btn--ghost"
          onClick={onRefresh}
          disabled={loading}
        >
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      {status === null ? (
        <p className={statusError === null ? "muted" : "error"} role="status">
          {statusError ?? "Loading status…"}
        </p>
      ) : (
        <>
          <div className="status-main">
            <span className={badgeClass(status.state)}>{status.state}</span>
            <span className="status-ip mono">{status.public_ip ?? "no public IP"}</span>
          </div>
          <dl className="kv">
            <dt>Provider</dt>
            <dd>{status.provider}</dd>
            <dt>Region</dt>
            <dd>{status.region}</dd>
            <dt>Instance</dt>
            <dd className="break">{status.instance}</dd>
            <dt>Last rotation</dt>
            <dd>
              {status.last_rotation_at === null ? (
                "never"
              ) : (
                <time
                  dateTime={new Date(status.last_rotation_at * 1000).toISOString()}
                  title={absoluteDate(status.last_rotation_at)}
                >
                  {relativeTime(status.last_rotation_at, now)}
                </time>
              )}
            </dd>
            <dt>Rotate cooldown</dt>
            <dd>
              {cooldownS > 0 ? (
                <span className="cooldown" role="timer">
                  {formatCountdown(cooldownS)}
                </span>
              ) : (
                "ready"
              )}
            </dd>
          </dl>
          {statusError !== null && (
            <p className="error" role="alert">
              {statusError}
            </p>
          )}
        </>
      )}

      <div className="actions">
        <button
          type="button"
          className="btn btn--primary"
          disabled={!canStart}
          onClick={() => {
            setConfirming("start");
          }}
        >
          {busy === "start" ? BUSY_LABEL.start : "Start"}
        </button>
        <button
          type="button"
          className="btn"
          disabled={!canStop}
          onClick={() => {
            setConfirming("stop");
          }}
        >
          {busy === "stop" ? BUSY_LABEL.stop : "Stop"}
        </button>
        <button
          type="button"
          className="btn btn--accent"
          disabled={!canRotate}
          onClick={() => {
            setConfirming("rotate");
          }}
        >
          {rotateLabel}
        </button>
      </div>

      <div className="action-status" role="status" aria-live="polite">
        {actionError !== null && <p className="error">{actionError}</p>}
        {actionError === null && actionNotice !== null && <p className="notice">{actionNotice}</p>}
      </div>

      <ConfirmDialog
        open={confirmCfg !== null}
        title={confirmCfg?.title ?? ""}
        message={confirmCfg?.message ?? ""}
        confirmLabel={confirmCfg?.label ?? "OK"}
        danger={confirmCfg?.danger ?? false}
        withReason={confirming === "rotate"}
        onCancel={() => {
          setConfirming(null);
        }}
        onConfirm={(reason) => {
          const a = confirming;
          setConfirming(null);
          if (a !== null) onAction(a, reason);
        }}
      />
    </section>
  );
}
