import { useEffect, useState } from "react";
import { describeError, type ApiClient, type IngressTarget } from "../api";
import { ConfirmDialog } from "./ConfirmDialog";

interface Props {
  api: ApiClient;
  onChanged: () => void;
}

/** Phone-friendly promotion of one of the pre-provisioned ingress targets. */
export function TargetCard({ api, onChanged }: Props) {
  const [targets, setTargets] = useState<IngressTarget[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState("");
  const [confirming, setConfirming] = useState<IngressTarget | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = () => {
    void api.targets().then(
      (items) => {
        setTargets(items);
        setError(null);
        setSelected(items.find((item) => item.active)?.id || items[0]?.id || "");
      },
      (e: unknown) => {
        setError(describeError(e));
      },
    );
  };

  useEffect(() => {
    load();
    // The list is configuration-backed; refresh after a promotion, not on every status poll.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api]);

  const selectedTarget = targets?.find((target) => target.id === selected) ?? null;
  const active = targets?.find((target) => target.active) ?? null;

  async function promote(reason: string) {
    if (selectedTarget === null || selectedTarget.active) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api.switchTarget(selectedTarget.id, reason);
      setNotice(`Switched to ${selectedTarget.region}. Clients may need to refresh their subscription.`);
      load();
      onChanged();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
      setConfirming(null);
    }
  }

  return (
    <section className="card" aria-labelledby="targets-title">
      <div className="card__head">
        <h2 id="targets-title" className="card__title">
          Ingress region
        </h2>
        <button type="button" className="btn btn--small btn--ghost" onClick={load} disabled={busy}>
          Refresh
        </button>
      </div>
      <p className="muted small">
        Switches between configured, already-provisioned servers. This does not create AWS instances.
      </p>
      {targets === null ? (
        <p className={error === null ? "muted" : "error"}>{error ?? "Loading targets…"}</p>
      ) : targets.length < 2 ? (
        <p className="muted">Only one target is configured.</p>
      ) : (
        <>
          <div className="field">
            <label htmlFor="target-select">Target</label>
            <select
              id="target-select"
              value={selected}
              onChange={(event) => {
                setSelected(event.target.value);
              }}
              disabled={busy}
            >
              {targets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.id} — {target.region}{target.active ? " (active)" : ""}
                </option>
              ))}
            </select>
          </div>
          {selectedTarget !== null && (
            <dl className="kv">
              <dt>Provider</dt>
              <dd>{selectedTarget.provider}</dd>
              <dt>Region</dt>
              <dd>{selectedTarget.region}</dd>
              <dt>Instance</dt>
              <dd className="break">{selectedTarget.instance}</dd>
            </dl>
          )}
          <button
            type="button"
            className="btn btn--primary btn--block"
            disabled={busy || selectedTarget === null || selectedTarget.active}
            onClick={() => {
              setConfirming(selectedTarget);
            }}
          >
            {busy ? "Switching…" : selectedTarget?.active ? "Already active" : "Switch region"}
          </button>
          {active !== null && <p className="muted small">Active now: {active.id} ({active.region})</p>}
        </>
      )}
      {error !== null && <p className="error" role="alert">{error}</p>}
      {notice !== null && <p className="notice" role="status">{notice}</p>}
      <ConfirmDialog
        open={confirming !== null}
        title="Switch ingress region?"
        message={
          confirming === null
            ? ""
            : `Promote ${confirming.id} in ${confirming.region}. Existing connections may drop.`
        }
        confirmLabel="Switch"
        withReason
        onCancel={() => {
          setConfirming(null);
        }}
        onConfirm={(reason) => void promote(reason)}
      />
    </section>
  );
}
