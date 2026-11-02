import { useEffect, useState } from "react";
import { describeError, type ApiClient, type LifecycleView, type Status } from "../api";
import { ConfirmDialog } from "./ConfirmDialog";
const names: Record<string, string> = { "ap-northeast-1": "Tokyo, Japan", "ap-southeast-1": "Singapore", "ap-east-1": "Hong Kong" };
const stages: Record<string, string> = {
  creating: "Creating and configuring the replacement server…",
  waiting_ready: "Waiting for the VPN to report ready…",
  reconnect: "New server active. Refresh your VPN subscription and reconnect now.",
  cleaning: "Deleting previous resources and releasing their IPs…",
  complete: "Finished. Previous resources have been removed.", failed: "Operation needs attention.",
};
interface Props { api: ApiClient; status: Status | null; statusError: string | null; onMode: (enabled: boolean) => void; onChanged: () => void; }
export function LifecycleCard({ api, status, statusError, onMode, onChanged }: Props) {
  const [view, setView] = useState<LifecycleView | null>(null);
  const [selected, setSelected] = useState("ap-east-1");
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [confirmation, setConfirmation] = useState<"switch" | "delete" | null>(null);
  useEffect(() => {
    let disposed = false;
    let timer: number | undefined;
    async function poll() {
      try {
        const result = await api.lifecycle();
        if (!disposed) { setView(result); onMode(result.enabled); setError(null); }
      } catch (e) { if (!disposed) setError(describeError(e)); }
      if (!disposed) timer = window.setTimeout(() => void poll(), 5000);
    }
    void poll();
    return () => { disposed = true; window.clearTimeout(timer); };
  }, [api, onMode]);
  async function act(action: "switch" | "delete" | "retry_cleanup") {
    setSending(true); setError(null); setConfirmation(null);
    try {
      await api.lifecycleAction(action, action === "switch" ? selected : undefined);
      setView(await api.lifecycle()); onChanged();
    } catch (e) { setError(describeError(e)); }
    finally { setSending(false); }
  }
  if (view === null) return error ? <p className="error" role="alert">Region controls: {error}</p> : null;
  if (!view.enabled) return null;
  const job = view.job;
  const busy = sending || (job !== null && !["complete", "failed"].includes(job.stage));
  const pending = view.cleanup_pending.length > 0;
  return <section className="card" aria-labelledby="lifecycle-title">
    <h2 id="lifecycle-title" className="card__title">On-demand VPN server</h2>
    <p>Active: {view.active ? names[view.active.region] ?? view.active.region : "No server"}</p>
    {view.active && <p className="muted small">{status?.state ?? "Checking state…"} · {status?.public_ip ?? "No public IP"}</p>}
    {statusError && <p className="error" role="alert">{statusError}</p>}
    <p className="muted small">One server is normally billed. Switching takes several minutes and briefly bills both servers. Stopped Lightsail servers still cost money.</p>
    <div className="field"><label htmlFor="lifecycle-region">Region</label>
      <select id="lifecycle-region" value={selected} onChange={e => { setSelected(e.target.value); }} disabled={busy || pending}>
        {view.regions.map(region => <option key={region} value={region}>{names[region] ?? region}</option>)}
      </select>
    </div>
    <button className="btn btn--primary btn--block" disabled={busy || pending} onClick={() => { setConfirmation("switch"); }}>{view.active?.region === selected ? "Recreate server" : view.active ? "Switch region" : "Create server"}</button>
    <button className="btn btn--block" disabled={busy || pending || !view.active} onClick={() => { setConfirmation("delete"); }}>Delete server and release IP</button>
    {job && <div role="status" aria-live="polite"><p>{stages[job.stage]}</p>
      {job.stage === "reconnect" && job.cleanup_after !== null && <p>Old server scheduled for deletion at {new Date(job.cleanup_after * 1000).toLocaleTimeString()}.</p>}
      {job.error && <p className="error">{job.error}</p>}
    </div>}
    {pending && <p className="error">{view.cleanup_pending.length} deployment(s) awaiting cleanup; charges may continue.</p>}
    {pending && job?.stage === "failed" && <button className="btn" disabled={sending} onClick={() => void act("retry_cleanup")}>Retry cleanup</button>}
    {error && <p className="error" role="alert">{error}</p>}
    <ConfirmDialog open={confirmation !== null} title={confirmation === "delete" ? "Delete VPN server?" : "Create server in selected region?"}
      message={confirmation === "delete" ? "Permanently delete the active ingress disk and release its IP. VPN access ends; instance charges stop after deletion. You can create a new server later."
        : `Create a billable server in ${names[selected] ?? selected}. After readiness checks, it becomes active and the old server is deleted after the reconnect window. Refresh your VPN subscription when prompted. Existing servers outside on-demand management are not removed.`}
      confirmLabel={confirmation === "delete" ? "Delete server" : "Create and switch"} danger={confirmation === "delete"}
      onCancel={() => { setConfirmation(null); }} onConfirm={() => { if (confirmation) void act(confirmation); }} />
  </section>;
}
