import type { EventEntry } from "../api";
import { absoluteDate, relativeTime } from "../time";

interface Props {
  events: EventEntry[] | null;
  error: string | null;
  now: number;
}

export function EventLog({ events, error, now }: Props) {
  let body: React.ReactNode;
  if (events === null) {
    body = error === null ? <p className="muted">Loading…</p> : null;
  } else if (events.length === 0) {
    body = <p className="muted">No events yet.</p>;
  } else {
    body = (
      <table className="events">
        <thead>
          <tr>
            <th scope="col">When</th>
            <th scope="col">Action</th>
            <th scope="col">Details</th>
          </tr>
        </thead>
        <tbody>
          {events.map((ev, i) => (
            <tr key={`${ev.at}-${i}`}>
              <td className="nowrap">
                <time dateTime={new Date(ev.at * 1000).toISOString()} title={absoluteDate(ev.at)}>
                  {relativeTime(ev.at, now)}
                </time>
              </td>
              <td>
                <span className={`tag tag--${ev.action}`}>{ev.action}</span>
              </td>
              <td className="events__details">
                {ev.ip !== null && <span className="mono">{ev.ip}</span>}
                {ev.detail !== "" && <span className="events__detail">{ev.detail}</span>}
                <span className="events__actor">by {ev.actor}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }

  return (
    <section className="card" aria-labelledby="events-title">
      <div className="card__head">
        <h2 id="events-title" className="card__title">
          Event log
        </h2>
      </div>
      {error !== null && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {body}
    </section>
  );
}
