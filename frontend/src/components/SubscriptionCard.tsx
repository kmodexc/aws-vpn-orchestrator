import { useEffect, useId, useRef, useState } from "react";
import { describeError, type ApiClient, type Subscription } from "../api";
import { CopyButton } from "./CopyButton";
import { QrCanvas } from "./QrCanvas";

interface Props {
  api: ApiClient;
  /** Changes whenever the public IP changes, so the links are re-fetched. */
  ipKey: string | null;
  /** Any change re-fetches: bumped after a settings change, or on a timer (user view). */
  refreshKey: number;
}

export function linkLabel(link: string, index: number): string {
  const scheme = /^([a-z0-9+.-]+):\/\//i.exec(link)?.[1]?.toLowerCase() ?? "link";
  const hash = link.lastIndexOf("#");
  let name = "";
  if (hash >= 0) {
    const raw = link.slice(hash + 1);
    try {
      name = decodeURIComponent(raw);
    } catch {
      name = raw;
    }
  }
  return name !== "" ? `${name} (${scheme})` : `${scheme} #${index + 1}`;
}

function LinkItem({ link, index }: { link: string; index: number }) {
  const ref = useRef<HTMLElement>(null);
  const label = linkLabel(link, index);
  return (
    <li className="link">
      <div className="link__head">
        <span className="link__label">{label}</span>
        <CopyButton text={link} fallbackRef={ref} ariaLabel={`Copy link ${label}`} />
      </div>
      <code ref={ref} className="mono break small">
        {link}
      </code>
    </li>
  );
}

export function SubscriptionCard({ api, ipKey, refreshKey }: Props) {
  const [show, setShow] = useState(false);
  const [showLinks, setShowLinks] = useState(false);
  const [sub, setSub] = useState<Subscription | null>(null);
  const [error, setError] = useState<string | null>(null);
  const urlRef = useRef<HTMLElement>(null);
  const bodyId = useId();
  const linksId = useId();

  const visible = show || showLinks;

  // Fetch lazily (only when something is shown) and again when the IP changes.
  useEffect(() => {
    if (!visible) return undefined;
    let cancelled = false;
    api.subscription().then(
      (s) => {
        if (cancelled) return;
        setSub(s);
        setError(null);
      },
      (e: unknown) => {
        if (!cancelled) setError(describeError(e));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [api, visible, ipKey, refreshKey]);

  const loading = sub === null && error === null;

  let linksBody: React.ReactNode = null;
  if (showLinks && sub !== null) {
    if (sub.links === null) {
      linksBody = <p className="muted">No links: the ingress has no public IP right now.</p>;
    } else if (sub.links.length === 0) {
      linksBody = <p className="muted">No links.</p>;
    } else {
      linksBody = (
        <ul className="links">
          {sub.links.map((l, i) => (
            <LinkItem key={`${i}-${l}`} link={l} index={i} />
          ))}
        </ul>
      );
    }
  }

  return (
    <section className="card" aria-labelledby="sub-title">
      <div className="card__head">
        <h2 id="sub-title" className="card__title">
          Subscription
        </h2>
      </div>
      <p className="muted">
        Import the URL in Hiddify, v2rayNG or another client. It always contains the current IP.
        Keep it secret.
      </p>
      <div className="toggles">
        <button
          type="button"
          className="btn"
          aria-expanded={show}
          aria-controls={bodyId}
          onClick={() => {
            setShow((v) => !v);
          }}
        >
          {show ? "Hide URL & QR" : "Show URL & QR"}
        </button>
        <button
          type="button"
          className="btn"
          aria-expanded={showLinks}
          aria-controls={linksId}
          onClick={() => {
            setShowLinks((v) => !v);
          }}
        >
          {showLinks ? "Hide links" : "Show links"}
        </button>
      </div>

      {visible && error !== null && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      <div id={bodyId} hidden={!show}>
        {show && sub !== null && (
          <>
            <div className="copy-row">
              <code ref={urlRef} className="mono break">
                {sub.url}
              </code>
              <CopyButton text={sub.url} fallbackRef={urlRef} ariaLabel="Copy subscription URL" />
            </div>
            <QrCanvas value={sub.url} label="QR code of the subscription URL" />
          </>
        )}
        {show && loading && <p className="muted">Loading…</p>}
      </div>

      <div id={linksId} hidden={!showLinks}>
        {linksBody}
        {showLinks && loading && <p className="muted">Loading…</p>}
      </div>
    </section>
  );
}
