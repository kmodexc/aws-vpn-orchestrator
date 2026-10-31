import { useRef } from "react";
import type { WireGuard } from "../api";
import { CopyButton } from "./CopyButton";

export function WireGuardCard({ wg }: { wg: WireGuard }) {
  const keyRef = useRef<HTMLPreElement>(null);
  const snippetRef = useRef<HTMLPreElement>(null);
  return (
    <section className="card" aria-labelledby="wg-title">
      <div className="card__head">
        <h2 id="wg-title" className="card__title">
          WireGuard exit
        </h2>
      </div>
      <dl className="kv">
        <dt>Ingress address</dt>
        <dd className="mono">{wg.ingress_address}</dd>
      </dl>
      {wg.ingress_public_key !== null && (
        <div className="block">
          <div className="block__head">
            <h3 className="block__title">Ingress public key</h3>
            <CopyButton
              text={wg.ingress_public_key}
              fallbackRef={keyRef}
              ariaLabel="Copy ingress public key"
            />
          </div>
          <pre ref={keyRef} className="pre">
            {wg.ingress_public_key}
          </pre>
        </div>
      )}
      {wg.vps_peer_snippet !== null && (
        <div className="block">
          <div className="block__head">
            <h3 className="block__title">VPS peer snippet</h3>
            <CopyButton
              text={wg.vps_peer_snippet}
              fallbackRef={snippetRef}
              ariaLabel="Copy VPS peer snippet"
            />
          </div>
          <pre ref={snippetRef} className="pre">
            {wg.vps_peer_snippet}
          </pre>
        </div>
      )}
    </section>
  );
}
