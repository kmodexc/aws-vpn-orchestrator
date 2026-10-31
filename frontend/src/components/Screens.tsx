interface CenterProps {
  children: React.ReactNode;
  labelledBy: string;
}

function Center({ children, labelledBy }: CenterProps) {
  return (
    <main className="center">
      <section className="card card--narrow" aria-labelledby={labelledBy}>
        <div className="brand">
          <span className="logo" aria-hidden="true" />
          <span>VPN Control</span>
        </div>
        {children}
      </section>
    </main>
  );
}

export function LoadingScreen() {
  return (
    <Center labelledBy="loading-title">
      <h1 id="loading-title" className="screen-title">
        Loading…
      </h1>
      <p className="muted" role="status">
        Checking your session.
      </p>
    </Center>
  );
}

interface LoginProps {
  message: string | null;
  onSignIn: () => void;
}

export function LoginScreen({ message, onSignIn }: LoginProps) {
  return (
    <Center labelledBy="login-title">
      <h1 id="login-title" className="screen-title">
        Sign in
      </h1>
      <p className="muted">Sign in with your kmode.dev account to manage the VPN.</p>
      <div role="alert" aria-live="assertive">
        {message !== null && <p className="error">{message}</p>}
      </div>
      <button type="button" className="btn btn--primary btn--block" onClick={onSignIn}>
        Sign in
      </button>
    </Center>
  );
}

interface ForbiddenProps {
  onLogout: () => void;
  loggingOut: boolean;
  error: string | null;
}

export function ForbiddenScreen({ onLogout, loggingOut, error }: ForbiddenProps) {
  return (
    <Center labelledBy="forbidden-title">
      <h1 id="forbidden-title" className="screen-title">
        Access denied
      </h1>
      <p>Your account lacks the required role. Ask an administrator to grant it, then sign in again.</p>
      <div role="alert">{error !== null && <p className="error">{error}</p>}</div>
      <button
        type="button"
        className="btn btn--block"
        onClick={onLogout}
        disabled={loggingOut}
      >
        {loggingOut ? "Signing out…" : "Sign out"}
      </button>
    </Center>
  );
}

interface ErrorProps {
  message: string;
  onRetry: () => void;
}

export function ErrorScreen({ message, onRetry }: ErrorProps) {
  return (
    <Center labelledBy="error-title">
      <h1 id="error-title" className="screen-title">
        Cannot reach the server
      </h1>
      <p className="error" role="alert">
        {message}
      </p>
      <button type="button" className="btn btn--primary btn--block" onClick={onRetry}>
        Try again
      </button>
    </Center>
  );
}
