import { useEffect, useId, useState } from "react";
import { describeError, type ApiClient, type ProtocolSettings, type SettingsResponse } from "../api";

interface Props {
  api: ApiClient;
  /** Called after a successful save or reset (e.g. to refresh the event log). */
  onSaved: () => void;
}

const APPLY_NOTE =
  "The server applies it within 10 minutes; clients must refresh their subscription.";

function sameSettings(a: ProtocolSettings, b: ProtocolSettings): boolean {
  return (
    a.reality_sni === b.reality_sni &&
    a.hy2_sni === b.hy2_sni &&
    a.hysteria2 === b.hysteria2 &&
    a.hy2_obfs === b.hy2_obfs &&
    a.shadowsocks === b.shadowsocks
  );
}

export function SettingsCard({ api, onSaved }: Props) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<SettingsResponse | null>(null);
  const [draft, setDraft] = useState<ProtocolSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const bodyId = useId();
  const realityId = useId();
  const hy2SniId = useId();
  const hy2Id = useId();
  const obfsId = useId();
  const ssId = useId();

  // Fetch lazily, when the card is opened.
  useEffect(() => {
    if (!open) return undefined;
    let cancelled = false;
    api.settings().then(
      (s) => {
        if (cancelled) return;
        setData(s);
        setDraft(s.settings);
        setError(null);
      },
      (e: unknown) => {
        if (!cancelled) setError(describeError(e));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [api, open]);

  const apply = async (action: () => Promise<SettingsResponse>, done: string) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const s = await action();
      setData(s);
      setDraft(s.settings);
      setNotice(done);
      onSaved();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  };

  const update = (patch: Partial<ProtocolSettings>) => {
    setDraft((d) => (d === null ? d : { ...d, ...patch }));
    setNotice(null);
  };

  const dirty = data !== null && draft !== null && !sameSettings(data.settings, draft);

  return (
    <section className="card" aria-labelledby="settings-title">
      <div className="card__head">
        <h2 id="settings-title" className="card__title">
          Protocol settings
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
        {open && error !== null && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {open && draft === null && error === null && <p className="muted">Loading…</p>}
        {open && data !== null && draft !== null && (
          <form
            className="settings"
            onSubmit={(e) => {
              e.preventDefault();
              void apply(() => api.saveSettings(draft), `Saved. ${APPLY_NOTE}`);
            }}
          >
            <p className="muted">
              {data.overridden
                ? "Changed here; overrides the values from .env."
                : "Values from .env (not changed here)."}
            </p>

            <div className="field">
              <label htmlFor={realityId}>REALITY camouflage target</label>
              <input
                id={realityId}
                type="text"
                inputMode="url"
                autoComplete="off"
                spellCheck={false}
                required
                maxLength={253}
                value={draft.reality_sni}
                onChange={(e) => {
                  update({ reality_sni: e.target.value });
                }}
              />
              <span className="field__hint">
                A real TLS 1.3 site, reachable from where you are and not blocked there. Default:{" "}
                {data.defaults.reality_sni}
              </span>
            </div>

            <div className="check">
              <input
                id={hy2Id}
                type="checkbox"
                checked={draft.hysteria2}
                onChange={(e) => {
                  update({ hysteria2: e.target.checked });
                }}
              />
              <label htmlFor={hy2Id}>Hysteria2 (UDP {data.ports.hy2_udp})</label>
              <span className="field__hint">Fast on lossy networks; UDP is often throttled.</span>
            </div>

            <div className="check">
              <input
                id={obfsId}
                type="checkbox"
                checked={draft.hy2_obfs}
                disabled={!draft.hysteria2}
                onChange={(e) => {
                  update({ hy2_obfs: e.target.checked });
                }}
              />
              <label htmlFor={obfsId}>Hysteria2 Salamander obfuscation</label>
              <span className="field__hint">
                Hides that the UDP traffic is QUIC. Needs a client that supports it (e.g. Hiddify).
              </span>
            </div>

            <div className="field">
              <label htmlFor={hy2SniId}>Hysteria2 server name</label>
              <input
                id={hy2SniId}
                type="text"
                inputMode="url"
                autoComplete="off"
                spellCheck={false}
                required
                maxLength={253}
                disabled={!draft.hysteria2}
                value={draft.hy2_sni}
                onChange={(e) => {
                  update({ hy2_sni: e.target.value });
                }}
              />
              <span className="field__hint">Default: {data.defaults.hy2_sni}</span>
            </div>

            <div className="check">
              <input
                id={ssId}
                type="checkbox"
                checked={draft.shadowsocks}
                onChange={(e) => {
                  update({ shadowsocks: e.target.checked });
                }}
              />
              <label htmlFor={ssId}>Shadowsocks-2022 (TCP+UDP {data.ports.ss})</label>
              <span className="field__hint">
                Easy to detect as fully encrypted traffic; using it can get the IP blocked for all
                protocols. Keep off where censorship is strong.
              </span>
            </div>

            <p className="muted small">
              VLESS-REALITY (TCP {data.ports.vless_tcp}) is always on. Ports are set in .env.
            </p>

            {notice !== null && <p className="notice">{notice}</p>}

            <div className="settings__actions">
              <button type="submit" className="btn btn--primary" disabled={busy || !dirty}>
                {busy ? "Saving…" : "Save"}
              </button>
              <button
                type="button"
                className="btn"
                disabled={busy || !dirty}
                onClick={() => {
                  setDraft(data.settings);
                  setNotice(null);
                }}
              >
                Discard changes
              </button>
              <button
                type="button"
                className="btn"
                disabled={busy || !data.overridden}
                onClick={() => {
                  void apply(() => api.resetSettings(), `Reset to .env. ${APPLY_NOTE}`);
                }}
              >
                Reset to .env
              </button>
            </div>
          </form>
        )}
      </div>
    </section>
  );
}
