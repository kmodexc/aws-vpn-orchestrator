import type { ApiClient, Me } from "../api";
import { SubscriptionCard } from "./SubscriptionCard";

interface Props {
  api: ApiClient;
  me: Me;
  onLogout: () => void;
  loggingOut: boolean;
  logoutError: string | null;
}

/** What a user-role account sees: the subscription to join, and nothing else. */
export function UserHome({ api, me, onLogout, loggingOut, logoutError }: Props) {
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
        <SubscriptionCard api={api} ipKey={null} settingsVersion={0} />
      </main>
    </div>
  );
}
