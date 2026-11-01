import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError,
  describeError,
  type ApiClient,
  type EventEntry,
  type Me,
  type Status,
  type Telemetry,
  type WireGuard,
} from "../api";
import { useCountdown, useNow, usePageVisible } from "../hooks";
import { cooldownDeadline, FAST_POLL_MS, pollInterval, SLOW_POLL_MS } from "../time";
import { EventLog } from "./EventLog";
import { IngressCard } from "./IngressCard";
import { LogsCard } from "./LogsCard";
import { SettingsCard } from "./SettingsCard";
import { StatusCard, type Action } from "./StatusCard";
import { SubscriptionCard } from "./SubscriptionCard";
import { WireGuardCard } from "./WireGuardCard";

interface Props {
  api: ApiClient;
  me: Me;
  onLogout: () => void;
  loggingOut: boolean;
  logoutError: string | null;
}

/** After an action, poll fast for this long even if the state is not yet transitional. */
const FAST_AFTER_ACTION_MS = 60_000;

interface Cooldown {
  deadline: number;
  setAt: number;
}

export function Dashboard({ api, me, onLogout, loggingOut, logoutError }: Props) {
  const visible = usePageVisible();

  const [status, setStatus] = useState<Status | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [cooldown, setCooldown] = useState<Cooldown>({ deadline: 0, setAt: 0 });

  const [events, setEvents] = useState<EventEntry[] | null>(null);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [wg, setWg] = useState<WireGuard | null>(null);
  const [settingsVersion, setSettingsVersion] = useState(0);
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null);
  const [telemetryAt, setTelemetryAt] = useState(0);
  const [telemetryError, setTelemetryError] = useState<string | null>(null);

  const [busy, setBusy] = useState<Action | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Restarting the poll loop (e.g. after an action) is done by bumping this nonce.
  const [pollNonce, setPollNonce] = useState(0);
  const fastUntil = useRef(0);
  const lastStatusKey = useRef<string | null>(null);
  const lastEventsAt = useRef(0);

  const loadEvents = useCallback(async () => {
    try {
      const ev = await api.events(50);
      setEvents(ev);
      setEventsError(null);
      lastEventsAt.current = Date.now();
    } catch (e) {
      setEventsError(describeError(e));
    }
  }, [api]);

  const loadTelemetry = useCallback(async () => {
    try {
      const t = await api.telemetry();
      setTelemetry(t);
      setTelemetryAt(Date.now());
      setTelemetryError(null);
    } catch (e) {
      setTelemetryError(describeError(e));
    }
  }, [api]);

  /** Fetch status; refresh events when something changed. Returns the state (or null). */
  const loadStatus = useCallback(async (): Promise<string | null> => {
    setLoading(true);
    void loadTelemetry();
    try {
      const s = await api.status();
      const fetchedAt = Date.now();
      setStatus(s);
      setStatusError(null);
      setCooldown({ deadline: cooldownDeadline(s.cooldown_remaining_s, fetchedAt), setAt: fetchedAt });
      const key = `${s.state}|${s.public_ip ?? ""}|${s.last_rotation_at ?? ""}`;
      if (key !== lastStatusKey.current || fetchedAt - lastEventsAt.current >= SLOW_POLL_MS) {
        lastStatusKey.current = key;
        void loadEvents();
      }
      return s.state;
    } catch (e) {
      setStatusError(describeError(e));
      return null;
    } finally {
      setLoading(false);
    }
  }, [api, loadEvents, loadTelemetry]);

  // Poll loop: 5 s while transitional (or just after an action), else 30 s. Paused when hidden.
  useEffect(() => {
    if (!visible) return undefined;
    let cancelled = false;
    let timer: number | undefined;
    const tick = async () => {
      const state = await loadStatus();
      if (cancelled) return;
      const fast = Date.now() < fastUntil.current;
      const delay = fast ? FAST_POLL_MS : pollInterval(state);
      timer = window.setTimeout(() => void tick(), delay);
    };
    void tick();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [visible, loadStatus, pollNonce]);

  // WireGuard info rarely changes: fetch once.
  useEffect(() => {
    let cancelled = false;
    api.wireguard().then(
      (w) => {
        if (!cancelled) setWg(w);
      },
      () => {
        // Non-essential card; 401/403 are handled globally by the client.
      },
    );
    return () => {
      cancelled = true;
    };
  }, [api]);

  const cooldownS = useCountdown(cooldown.deadline, cooldown.setAt);
  const slowNow = useNow(15_000, visible);

  const runAction = useCallback(
    async (action: Action, reason: string) => {
      setBusy(action);
      setActionError(null);
      setActionNotice(null);
      try {
        if (action === "start") {
          await api.start();
          setActionNotice("Start requested. The server is booting…");
        } else if (action === "stop") {
          await api.stop();
          setActionNotice("Stop requested.");
        } else {
          const r = await api.rotate(reason);
          setActionNotice(`New public IP: ${r.public_ip}. Clients must refresh their subscription.`);
        }
      } catch (e) {
        if (e instanceof ApiError && e.code === "cooldown" && e.retryAfterS !== null) {
          const t = Date.now();
          setCooldown({ deadline: cooldownDeadline(e.retryAfterS, t), setAt: t });
        }
        setActionError(describeError(e));
      } finally {
        setBusy(null);
        fastUntil.current = Date.now() + FAST_AFTER_ACTION_MS;
        lastStatusKey.current = null; // force an events refresh
        setPollNonce((n) => n + 1);
      }
    },
    [api],
  );

  const manualRefresh = useCallback(() => {
    lastStatusKey.current = null;
    setPollNonce((n) => n + 1);
  }, []);

  return (
    <div className="page">
      <header className="topbar">
        <div className="topbar__brand">
          <span className="logo" aria-hidden="true" />
          <span>Console</span>
        </div>
        <div className="topbar__user">
          <span className="topbar__name" title={me.email ?? undefined}>
            {me.username}
          </span>
          <button
            type="button"
            className="btn btn--small"
            onClick={onLogout}
            disabled={loggingOut}
          >
            {loggingOut ? "Signing out…" : "Sign out"}
          </button>
        </div>
      </header>
      {logoutError !== null && (
        <p className="error banner" role="alert">
          {logoutError}
        </p>
      )}
      <main className="main">
        <StatusCard
          status={status}
          loading={loading}
          statusError={statusError}
          cooldownS={cooldownS}
          now={slowNow}
          busy={busy}
          actionError={actionError}
          actionNotice={actionNotice}
          onAction={(a, r) => void runAction(a, r)}
          onRefresh={manualRefresh}
        />
        <SubscriptionCard
          api={api}
          ipKey={status?.public_ip ?? null}
          refreshKey={settingsVersion}
        />
        <SettingsCard
          api={api}
          onSaved={() => {
            setSettingsVersion((n) => n + 1);
            manualRefresh();
          }}
        />
        <IngressCard
          api={api}
          telemetry={telemetry}
          error={telemetryError}
          now={slowNow}
          fetchedAt={telemetryAt}
          onChanged={(t) => {
            setTelemetry(t);
            setTelemetryAt(Date.now());
            manualRefresh();
          }}
        />
        <LogsCard api={api} />
        {wg?.enabled === true && <WireGuardCard wg={wg} />}
        <EventLog events={events} error={eventsError} now={slowNow} />
      </main>
    </div>
  );
}
