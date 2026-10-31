//! Server-side, in-memory sessions and pending logins (SPEC §4.1).
//!
//! Maps are keyed by the SHA-256 of the cookie value, so the raw cookie value is never stored.
//! Both maps are capped; when full, the oldest entry is evicted.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::secret::Secret;
use crate::util::{RandomError, ct_eq_str, lock, random_token, sha256};

pub const MAX_SESSIONS: usize = 10_000;
pub const MAX_PENDING_LOGINS: usize = 1_000;
pub const PENDING_LOGIN_TTL: Duration = Duration::from_secs(600);

/// Identity data stored in a session.
#[derive(Debug, Clone)]
pub struct SessionData {
    pub sub: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    /// Kept for `id_token_hint` on logout.
    pub id_token: Option<Secret<String>>,
}

/// A copy of a live session handed to request handlers.
#[derive(Debug, Clone)]
pub struct SessionView {
    pub data: SessionData,
    pub csrf_token: Secret<String>,
}

#[derive(Debug)]
struct Session {
    data: SessionData,
    csrf_token: Secret<String>,
    created_at: Instant,
    last_seen: Instant,
}

/// State kept between `/auth/login` and `/auth/callback`.
#[derive(Debug)]
pub struct PendingLogin {
    pub state: Secret<String>,
    pub nonce: Secret<String>,
    pub pkce_verifier: Secret<String>,
    pub return_to: String,
    pub created_at: Instant,
}

impl PendingLogin {
    /// Constant-time comparison of the `state` parameter.
    pub fn state_matches(&self, state: &str) -> bool {
        ct_eq_str(self.state.expose(), state)
    }
}

#[derive(Debug, Default)]
struct Maps {
    sessions: HashMap<[u8; 32], Session>,
    pending: HashMap<[u8; 32], PendingLogin>,
}

#[derive(Debug)]
pub struct SessionStore {
    idle_timeout: Duration,
    absolute_timeout: Duration,
    max_sessions: usize,
    max_pending: usize,
    maps: Mutex<Maps>,
}

impl SessionStore {
    pub fn new(idle_timeout: Duration, absolute_timeout: Duration) -> Self {
        Self::with_limits(
            idle_timeout,
            absolute_timeout,
            MAX_SESSIONS,
            MAX_PENDING_LOGINS,
        )
    }

    pub fn with_limits(
        idle_timeout: Duration,
        absolute_timeout: Duration,
        max_sessions: usize,
        max_pending: usize,
    ) -> Self {
        Self {
            idle_timeout,
            absolute_timeout,
            max_sessions: max_sessions.max(1),
            max_pending: max_pending.max(1),
            maps: Mutex::new(Maps::default()),
        }
    }

    pub fn absolute_timeout(&self) -> Duration {
        self.absolute_timeout
    }

    /// Create a session. Returns the cookie value (256 random bits, base64url).
    ///
    /// This is the only way to create a session; the HTTP layer calls it after a successful
    /// OIDC callback. Tests call it directly to obtain a session cookie.
    pub fn create(&self, data: SessionData) -> Result<String, RandomError> {
        self.create_at(data, Instant::now())
    }

    pub fn create_at(&self, data: SessionData, now: Instant) -> Result<String, RandomError> {
        let cookie = random_token()?;
        let csrf_token = Secret::new(random_token()?);
        let mut maps = lock(&self.maps);
        if maps.sessions.len() >= self.max_sessions {
            Self::purge_sessions(&mut maps, now, self.idle_timeout, self.absolute_timeout);
        }
        while maps.sessions.len() >= self.max_sessions {
            let oldest = maps
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.created_at)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    maps.sessions.remove(&k);
                }
                None => break,
            }
        }
        maps.sessions.insert(
            sha256(cookie.as_bytes()),
            Session {
                data,
                csrf_token,
                created_at: now,
                last_seen: now,
            },
        );
        Ok(cookie)
    }

    /// Look up a session and refresh its idle timer. Expired sessions are removed.
    pub fn get(&self, cookie: &str) -> Option<SessionView> {
        self.get_at(cookie, Instant::now())
    }

    pub fn get_at(&self, cookie: &str, now: Instant) -> Option<SessionView> {
        let key = sha256(cookie.as_bytes());
        let mut maps = lock(&self.maps);
        let expired = {
            let s = maps.sessions.get(&key)?;
            is_expired(s, now, self.idle_timeout, self.absolute_timeout)
        };
        if expired {
            maps.sessions.remove(&key);
            return None;
        }
        let s = maps.sessions.get_mut(&key)?;
        s.last_seen = now;
        Some(SessionView {
            data: s.data.clone(),
            csrf_token: s.csrf_token.clone(),
        })
    }

    /// Destroy a session. Returns it if it existed and was still valid.
    pub fn remove(&self, cookie: &str) -> Option<SessionView> {
        let now = Instant::now();
        let mut maps = lock(&self.maps);
        let s = maps.sessions.remove(&sha256(cookie.as_bytes()))?;
        if is_expired(&s, now, self.idle_timeout, self.absolute_timeout) {
            return None;
        }
        Some(SessionView {
            data: s.data,
            csrf_token: s.csrf_token,
        })
    }

    /// Store a pending login. Returns the login cookie value.
    pub fn create_pending(&self, pending: PendingLogin) -> Result<String, RandomError> {
        let cookie = random_token()?;
        let now = pending.created_at;
        let mut maps = lock(&self.maps);
        if maps.pending.len() >= self.max_pending {
            maps.pending
                .retain(|_, p| now.saturating_duration_since(p.created_at) <= PENDING_LOGIN_TTL);
        }
        while maps.pending.len() >= self.max_pending {
            let oldest = maps
                .pending
                .iter()
                .min_by_key(|(_, p)| p.created_at)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    maps.pending.remove(&k);
                }
                None => break,
            }
        }
        maps.pending.insert(sha256(cookie.as_bytes()), pending);
        Ok(cookie)
    }

    /// Remove and return a pending login (single use). `None` if unknown or expired.
    pub fn take_pending(&self, cookie: &str) -> Option<PendingLogin> {
        self.take_pending_at(cookie, Instant::now())
    }

    pub fn take_pending_at(&self, cookie: &str, now: Instant) -> Option<PendingLogin> {
        let p = lock(&self.maps)
            .pending
            .remove(&sha256(cookie.as_bytes()))?;
        (now.saturating_duration_since(p.created_at) <= PENDING_LOGIN_TTL).then_some(p)
    }

    /// Drop expired sessions and pending logins (run periodically).
    pub fn purge_expired(&self) {
        self.purge_expired_at(Instant::now());
    }

    pub fn purge_expired_at(&self, now: Instant) {
        let mut maps = lock(&self.maps);
        Self::purge_sessions(&mut maps, now, self.idle_timeout, self.absolute_timeout);
        maps.pending
            .retain(|_, p| now.saturating_duration_since(p.created_at) <= PENDING_LOGIN_TTL);
    }

    fn purge_sessions(maps: &mut Maps, now: Instant, idle: Duration, absolute: Duration) {
        maps.sessions
            .retain(|_, s| !is_expired(s, now, idle, absolute));
    }

    /// (sessions, pending logins)
    pub fn len(&self) -> (usize, usize) {
        let maps = lock(&self.maps);
        (maps.sessions.len(), maps.pending.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == (0, 0)
    }
}

fn is_expired(s: &Session, now: Instant, idle: Duration, absolute: Duration) -> bool {
    now.saturating_duration_since(s.last_seen) > idle
        || now.saturating_duration_since(s.created_at) > absolute
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(sub: &str) -> SessionData {
        SessionData {
            sub: sub.into(),
            username: sub.into(),
            email: None,
            roles: vec!["vpn-admin".into()],
            id_token: None,
        }
    }

    fn store() -> SessionStore {
        SessionStore::new(Duration::from_secs(1800), Duration::from_secs(43_200))
    }

    #[test]
    fn create_and_get() {
        let s = store();
        let cookie = s.create(data("alice")).unwrap();
        assert_eq!(cookie.len(), 43);
        let v = s.get(&cookie).unwrap();
        assert_eq!(v.data.sub, "alice");
        assert_eq!(v.csrf_token.expose().len(), 43);
        assert!(s.get("unknown").is_none());
    }

    #[test]
    fn idle_timeout_expires_and_activity_extends() {
        let s = store();
        let t0 = Instant::now();
        let cookie = s.create_at(data("a"), t0).unwrap();
        // activity at 20 min keeps it alive at 40 min
        assert!(s.get_at(&cookie, t0 + Duration::from_secs(1200)).is_some());
        assert!(s.get_at(&cookie, t0 + Duration::from_secs(2400)).is_some());
        // 30 min + 1 s of inactivity → gone, and stays gone
        assert!(
            s.get_at(&cookie, t0 + Duration::from_secs(2400 + 1801))
                .is_none()
        );
        assert!(
            s.get_at(&cookie, t0 + Duration::from_secs(2400 + 1802))
                .is_none()
        );
    }

    #[test]
    fn absolute_timeout_expires_despite_activity() {
        let s = SessionStore::new(Duration::from_secs(1800), Duration::from_secs(3600));
        let t0 = Instant::now();
        let cookie = s.create_at(data("a"), t0).unwrap();
        for m in [20u64, 40, 59] {
            assert!(
                s.get_at(&cookie, t0 + Duration::from_secs(m * 60))
                    .is_some()
            );
        }
        assert!(s.get_at(&cookie, t0 + Duration::from_secs(3601)).is_none());
    }

    #[test]
    fn remove_destroys_session() {
        let s = store();
        let cookie = s.create(data("a")).unwrap();
        assert!(s.remove(&cookie).is_some());
        assert!(s.get(&cookie).is_none());
        assert!(s.remove(&cookie).is_none());
    }

    #[test]
    fn capacity_evicts_oldest() {
        let s =
            SessionStore::with_limits(Duration::from_secs(1800), Duration::from_secs(3600), 2, 2);
        let t0 = Instant::now();
        let c1 = s.create_at(data("1"), t0).unwrap();
        let c2 = s.create_at(data("2"), t0 + Duration::from_secs(1)).unwrap();
        let c3 = s.create_at(data("3"), t0 + Duration::from_secs(2)).unwrap();
        let now = t0 + Duration::from_secs(3);
        assert!(s.get_at(&c1, now).is_none());
        assert!(s.get_at(&c2, now).is_some());
        assert!(s.get_at(&c3, now).is_some());
        assert_eq!(s.len().0, 2);
    }

    fn pending(now: Instant) -> PendingLogin {
        PendingLogin {
            state: Secret::new("state-value".into()),
            nonce: Secret::new("nonce".into()),
            pkce_verifier: Secret::new("verifier".into()),
            return_to: "/".into(),
            created_at: now,
        }
    }

    #[test]
    fn pending_login_is_single_use_and_expires() {
        let s = store();
        let t0 = Instant::now();
        let c = s.create_pending(pending(t0)).unwrap();
        let p = s.take_pending_at(&c, t0 + Duration::from_secs(5)).unwrap();
        assert!(p.state_matches("state-value"));
        assert!(!p.state_matches("state-valuf"));
        assert!(s.take_pending_at(&c, t0 + Duration::from_secs(6)).is_none());

        let c = s.create_pending(pending(t0)).unwrap();
        assert!(
            s.take_pending_at(&c, t0 + Duration::from_secs(601))
                .is_none()
        );
    }

    #[test]
    fn pending_capacity_and_purge() {
        let s = SessionStore::with_limits(Duration::from_secs(60), Duration::from_secs(60), 10, 3);
        let t0 = Instant::now();
        for _ in 0..5 {
            s.create_pending(pending(t0)).unwrap();
        }
        assert_eq!(s.len().1, 3);
        s.create_at(data("x"), t0).unwrap();
        s.purge_expired_at(t0 + Duration::from_secs(700));
        assert!(s.is_empty());
    }
}
