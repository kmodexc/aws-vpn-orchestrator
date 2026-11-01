import { useCallback, useEffect, useState } from "react";
import { ApiClient, ApiError, describeError, loginUrl, type Me } from "./api";
import { LOGOUT_FAILED_FORBIDDEN_MESSAGE, LOGOUT_FAILED_MESSAGE, performLogout } from "./logout";
import { Dashboard } from "./components/Dashboard";
import { UserHome } from "./components/UserHome";
import { ErrorScreen, ForbiddenScreen, LoadingScreen, LoginScreen } from "./components/Screens";

type View =
  | { kind: "loading" }
  | { kind: "login"; message: string | null }
  | { kind: "forbidden" }
  | { kind: "error"; message: string }
  | { kind: "dashboard"; me: Me };

const api = new ApiClient();

export function App() {
  const [view, setView] = useState<View>({ kind: "loading" });
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const [loadNonce, setLoadNonce] = useState(0);

  // Global 401/403 handling from any API call made after the first load.
  useEffect(() => {
    api.onUnauthorized = () => {
      api.setCsrfToken(null);
      setView({ kind: "login", message: "Your session has expired. Please sign in again." });
    };
    api.onForbidden = () => {
      setView({ kind: "forbidden" });
    };
    return () => {
      api.onUnauthorized = undefined;
      api.onForbidden = undefined;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    api.me().then(
      (me) => {
        if (!cancelled) setView({ kind: "dashboard", me });
      },
      (e: unknown) => {
        if (cancelled) return;
        if (e instanceof ApiError && e.code === "unauthorized") {
          // A failed sign-in never reaches the SPA: the backend answers `/?login_error=…`
          // for anonymous visitors with its own page.
          setView({ kind: "login", message: null });
        } else if (e instanceof ApiError && e.code === "forbidden") {
          setView({ kind: "forbidden" });
        } else {
          setView({ kind: "error", message: describeError(e) });
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [loadNonce]);

  const signIn = useCallback(() => {
    window.location.assign(loginUrl(window.location.pathname, window.location.search));
  }, []);

  /**
   * `fromForbidden`: the user is on the "Access denied" screen (the session has no admin role and
   * therefore grants no access). Only there may a failed logout fall back to the login screen.
   */
  const logout = useCallback(async (fromForbidden: boolean) => {
    setLoggingOut(true);
    setLogoutError(null);
    const outcome = await performLogout(api, window.location.origin);
    switch (outcome.kind) {
      case "redirect":
        window.location.assign(outcome.target);
        return;
      case "no_session":
        // The server confirmed there is no session left to destroy.
        setLoggingOut(false);
        api.setCsrfToken(null);
        setView({ kind: "login", message: null });
        return;
      case "failed":
        setLoggingOut(false);
        if (fromForbidden) {
          api.setCsrfToken(null);
          setView({ kind: "login", message: LOGOUT_FAILED_FORBIDDEN_MESSAGE });
        } else {
          // Never pretend to be signed out: the session cookie is still valid.
          setLogoutError(LOGOUT_FAILED_MESSAGE);
        }
        return;
    }
  }, []);

  switch (view.kind) {
    case "loading":
      return <LoadingScreen />;
    case "login":
      return <LoginScreen message={view.message} onSignIn={signIn} />;
    case "forbidden":
      return (
        <ForbiddenScreen
          onLogout={() => void logout(true)}
          loggingOut={loggingOut}
          error={logoutError}
        />
      );
    case "error":
      return (
        <ErrorScreen
          message={view.message}
          onRetry={() => {
            setView({ kind: "loading" });
            setLoadNonce((n) => n + 1);
          }}
        />
      );
    case "dashboard":
      if (!view.me.is_admin) {
        return (
          <UserHome
            api={api}
            me={view.me}
            onLogout={() => void logout(false)}
            loggingOut={loggingOut}
            logoutError={logoutError}
          />
        );
      }
      return (
        <Dashboard
          api={api}
          me={view.me}
          onLogout={() => void logout(false)}
          loggingOut={loggingOut}
          logoutError={logoutError}
        />
      );
  }
}
