//! Per-IP token-bucket rate limiting and a failure limiter (SPEC §10), with bounded memory.
//!
//! IPv6 clients are keyed by their /64 prefix, because a single host usually controls a whole
//! /64. Because one customer allocation (typically a /48 or /56) contains many /64s, IPv6
//! failures are additionally counted per /48 with a higher threshold, so a single allocation can
//! neither multiply its guesses nor fill the failure table.
//!
//! The failure table never drops a failure: when it is full, the entry with the least remaining
//! effect is evicted (first an unblocked one, else the block that expires soonest).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::app::AppState;
use crate::error::{ApiError, plain_status};
use crate::http::request_context::client_ip_of;
use crate::util::lock;

pub const MAX_TRACKED_KEYS: usize = 20_000;
pub const FAILURE_WINDOW: Duration = Duration::from_secs(600);
pub const FAILURE_THRESHOLD: usize = 10;
/// Failures from one IPv6 /48 (summed over all its /64s) within [`FAILURE_WINDOW`] that block
/// the whole /48.
pub const V6_NET_FAILURE_THRESHOLD: usize = 100;
pub const BLOCK_DURATION: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteClass {
    Auth,
    Token,
    Api,
    Unlimited,
}

impl RouteClass {
    pub fn classify(path: &str) -> Self {
        let under = |p: &str| path == p || path.starts_with(&format!("{p}/"));
        if under("/auth") {
            Self::Auth
        } else if under("/s") || under("/i") {
            Self::Token
        } else if under("/api") {
            Self::Api
        } else {
            Self::Unlimited
        }
    }

    /// Requests per minute (also the burst size).
    fn per_minute(self) -> Option<f64> {
        match self {
            Self::Auth => Some(20.0),
            Self::Token => Some(30.0),
            Self::Api => Some(120.0),
            Self::Unlimited => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// Key of the failure table. The variants keep a /64 key and a /48 key with the same address
/// bits (e.g. `2001:db8:1::`) apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FailureKey {
    /// IPv4 address or IPv6 /64 prefix (see [`ip_key`]).
    Client(IpAddr),
    /// IPv6 /48 prefix.
    V6Net48(Ipv6Addr),
}

impl FailureKey {
    fn threshold(self) -> usize {
        match self {
            Self::Client(_) => FAILURE_THRESHOLD,
            Self::V6Net48(_) => V6_NET_FAILURE_THRESHOLD,
        }
    }
}

/// All failure-table keys an address counts against.
fn failure_keys(ip: IpAddr) -> impl Iterator<Item = FailureKey> {
    let net = match ip {
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(FailureKey::V6Net48(Ipv6Addr::new(
                s[0], s[1], s[2], 0, 0, 0, 0, 0,
            )))
        }
    };
    std::iter::once(FailureKey::Client(ip_key(ip))).chain(net)
}

#[derive(Debug, Default)]
struct FailureState {
    /// Failure times inside the window, oldest first. Bounded by the key's threshold.
    recent: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

impl FailureState {
    fn is_blocked(&self, now: Instant) -> bool {
        self.blocked_until.is_some_and(|u| u > now)
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<(RouteClass, IpAddr), Bucket>>,
    failures: Mutex<HashMap<FailureKey, FailureState>>,
    max_keys: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(MAX_TRACKED_KEYS)
    }
}

/// IPv4 as is; IPv6 truncated to its /64 prefix.
pub fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

fn ceil_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

impl RateLimiter {
    pub fn new(max_keys: usize) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            max_keys: max_keys.max(1),
        }
    }

    /// Take one token. `Err(retry_after_s)` when the bucket is empty.
    pub fn check(&self, class: RouteClass, ip: IpAddr, now: Instant) -> Result<(), u64> {
        let Some(per_minute) = class.per_minute() else {
            return Ok(());
        };
        let rate = per_minute / 60.0;
        let key = (class, ip_key(ip));
        let mut buckets = lock(&self.buckets);
        if !buckets.contains_key(&key) && buckets.len() >= self.max_keys {
            // Drop buckets that have refilled completely (equivalent to absent), then, if still
            // full, the least recently used one.
            buckets.retain(|(c, _), b| {
                let cap = c.per_minute().unwrap_or(0.0);
                b.tokens + now.saturating_duration_since(b.updated).as_secs_f64() * cap / 60.0 < cap
            });
            if buckets.len() >= self.max_keys {
                if let Some(oldest) = buckets
                    .iter()
                    .min_by_key(|(_, b)| b.updated)
                    .map(|(k, _)| *k)
                {
                    buckets.remove(&oldest);
                }
            }
        }
        let bucket = buckets.entry(key).or_insert(Bucket {
            tokens: per_minute,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(per_minute);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - bucket.tokens) / rate;
            Err(ceil_secs(Duration::from_secs_f64(wait)).max(1))
        }
    }

    /// `Some(retry_after_s)` while the IP (or, for IPv6, its /48) is blocked by the failure
    /// limiter.
    pub fn blocked(&self, ip: IpAddr, now: Instant) -> Option<u64> {
        let failures = lock(&self.failures);
        failure_keys(ip)
            .filter_map(|k| failures.get(&k)?.blocked_until)
            .filter(|until| *until > now)
            .max()
            .map(|until| ceil_secs(until - now).max(1))
    }

    /// Count a failed token/auth attempt. The 10th failure within 10 minutes blocks the client
    /// (IPv4 address or IPv6 /64) for 10 minutes; for IPv6, the 100th failure within 10 minutes
    /// from one /48 blocks the whole /48 for 10 minutes. A failure is always recorded, even when
    /// the table is full.
    pub fn record_failure_at(&self, ip: IpAddr, now: Instant) {
        let mut failures = lock(&self.failures);
        for key in failure_keys(ip) {
            self.make_room(&mut failures, key, now);
            let state = failures.entry(key).or_default();
            if state.is_blocked(now) {
                // Already blocked (e.g. a request that was in flight when the block started):
                // the block is not extended, so it ends on schedule.
                continue;
            }
            while state
                .recent
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) > FAILURE_WINDOW)
            {
                state.recent.pop_front();
            }
            state.recent.push_back(now);
            if state.recent.len() >= key.threshold() {
                state.blocked_until = Some(now + BLOCK_DURATION);
                state.recent.clear();
                match key {
                    FailureKey::Client(client) => {
                        tracing::warn!(%client, "too many failed attempts; blocking for 10 minutes");
                    }
                    FailureKey::V6Net48(net) => {
                        tracing::warn!(client = %format_args!("{net}/48"), "too many failed attempts from one IPv6 /48; blocking it for 10 minutes");
                    }
                }
            }
        }
    }

    /// Ensure `key` can be inserted without exceeding `max_keys`. Never refuses: when the table
    /// is full of active entries, evict the one with the least remaining effect: the unblocked
    /// entry whose last failure is oldest, otherwise the block that expires soonest.
    fn make_room(
        &self,
        failures: &mut HashMap<FailureKey, FailureState>,
        key: FailureKey,
        now: Instant,
    ) {
        if failures.contains_key(&key) || failures.len() < self.max_keys {
            return;
        }
        Self::purge_failures(failures, now);
        while failures.len() >= self.max_keys {
            let victim = failures
                .iter()
                .min_by_key(|(_, f)| match f.blocked_until.filter(|u| *u > now) {
                    // Unblocked entries sort before blocked ones.
                    None => (false, f.recent.back().copied()),
                    Some(until) => (true, Some(until)),
                })
                .map(|(k, _)| *k);
            match victim {
                Some(k) => {
                    if failures.get(&k).is_some_and(|f| f.is_blocked(now)) {
                        tracing::warn!(
                            "failure table full of blocked clients; evicting the block that expires soonest"
                        );
                    }
                    failures.remove(&k);
                }
                None => break,
            }
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        self.record_failure_at(ip, Instant::now());
    }

    fn purge_failures(failures: &mut HashMap<FailureKey, FailureState>, now: Instant) {
        failures.retain(|_, f| {
            let recent = f
                .recent
                .back()
                .is_some_and(|t| now.saturating_duration_since(*t) <= FAILURE_WINDOW);
            f.is_blocked(now) || recent
        });
    }

    /// Drop state that no longer has any effect (run periodically).
    pub fn purge(&self, now: Instant) {
        lock(&self.buckets).retain(|(c, _), b| {
            let cap = c.per_minute().unwrap_or(0.0);
            b.tokens + now.saturating_duration_since(b.updated).as_secs_f64() * cap / 60.0 < cap
        });
        Self::purge_failures(&mut lock(&self.failures), now);
    }

    /// (buckets, failure entries)
    pub fn tracked(&self) -> (usize, usize) {
        (lock(&self.buckets).len(), lock(&self.failures).len())
    }
}

fn too_many(class: RouteClass, retry_after_s: u64) -> Response {
    if class == RouteClass::Api {
        return ApiError::RateLimited { retry_after_s }.into_response();
    }
    let mut resp = plain_status(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests");
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_s.max(1)));
    resp
}

pub async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let class = RouteClass::classify(req.uri().path());
    if class == RouteClass::Unlimited {
        return next.run(req).await;
    }
    let ip = client_ip_of(req.extensions());
    let now = Instant::now();
    if let Some(retry) = state.limiter.blocked(ip, now) {
        return too_many(class, retry);
    }
    if let Err(retry) = state.limiter.check(class, ip, now) {
        tracing::info!(?class, "rate limited");
        return too_many(class, retry);
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classification() {
        assert_eq!(RouteClass::classify("/auth/login"), RouteClass::Auth);
        assert_eq!(RouteClass::classify("/s/x"), RouteClass::Token);
        assert_eq!(RouteClass::classify("/i/x/config.json"), RouteClass::Token);
        assert_eq!(RouteClass::classify("/api/status"), RouteClass::Api);
        assert_eq!(RouteClass::classify("/healthz"), RouteClass::Unlimited);
        assert_eq!(RouteClass::classify("/index.html"), RouteClass::Unlimited);
        assert_eq!(RouteClass::classify("/settings"), RouteClass::Unlimited);
    }

    #[test]
    fn token_bucket_limits_and_refills() {
        let l = RateLimiter::default();
        let t0 = Instant::now();
        let a = ip("192.0.2.1");
        for _ in 0..20 {
            assert!(l.check(RouteClass::Auth, a, t0).is_ok());
        }
        let retry = l.check(RouteClass::Auth, a, t0).unwrap_err();
        assert!((1..=3).contains(&retry), "{retry}");
        // another IP and another class are independent
        assert!(l.check(RouteClass::Auth, ip("192.0.2.2"), t0).is_ok());
        assert!(l.check(RouteClass::Api, a, t0).is_ok());
        // 3 s later one token (20/min) has been refilled
        assert!(
            l.check(RouteClass::Auth, a, t0 + Duration::from_secs(3))
                .is_ok()
        );
        assert!(l.check(RouteClass::Unlimited, a, t0).is_ok());
    }

    #[test]
    fn ipv6_is_grouped_by_64() {
        assert_eq!(ip_key(ip("2001:db8:1:2:3:4:5:6")), ip("2001:db8:1:2::"));
        let l = RateLimiter::default();
        let t0 = Instant::now();
        for i in 0..30 {
            let addr = ip(&format!("2001:db8:1:2::{i:x}"));
            assert!(l.check(RouteClass::Token, addr, t0).is_ok());
        }
        assert!(
            l.check(RouteClass::Token, ip("2001:db8:1:2::ffff"), t0)
                .is_err()
        );
    }

    #[test]
    fn failure_limiter_blocks_after_ten_failures() {
        let l = RateLimiter::default();
        let t0 = Instant::now();
        let a = ip("198.51.100.7");
        for i in 0..9 {
            l.record_failure_at(a, t0 + Duration::from_secs(i));
        }
        assert!(l.blocked(a, t0 + Duration::from_secs(9)).is_none());
        l.record_failure_at(a, t0 + Duration::from_secs(10));
        let retry = l.blocked(a, t0 + Duration::from_secs(10)).unwrap();
        assert_eq!(retry, 600);
        assert!(l.blocked(a, t0 + Duration::from_secs(10 + 601)).is_none());
        assert!(l.blocked(ip("198.51.100.8"), t0).is_none());
    }

    #[test]
    fn failures_outside_window_do_not_count() {
        let l = RateLimiter::default();
        let t0 = Instant::now();
        let a = ip("198.51.100.9");
        for i in 0..9 {
            l.record_failure_at(a, t0 + Duration::from_secs(i));
        }
        let later = t0 + Duration::from_secs(700);
        l.record_failure_at(a, later);
        assert!(l.blocked(a, later).is_none());
    }

    #[test]
    fn memory_is_bounded() {
        let l = RateLimiter::new(100);
        let t0 = Instant::now();
        for i in 0..1000u32 {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            let _ = l.check(RouteClass::Api, addr, t0);
            l.record_failure_at(addr, t0);
        }
        let (b, f) = l.tracked();
        assert!(b <= 100, "{b}");
        assert!(f <= 100, "{f}");
        l.purge(t0 + Duration::from_secs(3600));
        assert_eq!(l.tracked(), (0, 0));
    }

    fn block(l: &RateLimiter, addr: IpAddr, at: Instant) {
        for _ in 0..FAILURE_THRESHOLD {
            l.record_failure_at(addr, at);
        }
        assert!(l.blocked(addr, at).is_some(), "{addr} should be blocked");
    }

    #[test]
    fn saturated_failure_table_still_records_failures() {
        let l = RateLimiter::new(10);
        let t0 = Instant::now();
        for i in 0..10u32 {
            let addr = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            block(&l, addr, t0 + Duration::from_secs(u64::from(i)));
        }
        assert_eq!(l.tracked().1, 10);

        // A new client is still counted and blocked after 10 failures.
        let t1 = t0 + Duration::from_secs(60);
        let newcomer = ip("198.51.100.77");
        for i in 0..9 {
            l.record_failure_at(newcomer, t1 + Duration::from_secs(i));
        }
        assert!(l.blocked(newcomer, t1 + Duration::from_secs(9)).is_none());
        l.record_failure_at(newcomer, t1 + Duration::from_secs(10));
        assert!(l.blocked(newcomer, t1 + Duration::from_secs(10)).is_some());
        assert!(l.tracked().1 <= 10);

        // The block that expires soonest was evicted; the others are intact.
        let first = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000));
        assert!(l.blocked(first, t1 + Duration::from_secs(10)).is_none());
        let last = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0009));
        assert!(l.blocked(last, t1 + Duration::from_secs(10)).is_some());
    }

    #[test]
    fn unblocked_entries_are_evicted_before_blocked_ones() {
        let l = RateLimiter::new(3);
        let t0 = Instant::now();
        let blocked_a = ip("192.0.2.1");
        block(&l, blocked_a, t0);
        let pending = ip("192.0.2.2");
        l.record_failure_at(pending, t0);
        let blocked_b = ip("192.0.2.3");
        block(&l, blocked_b, t0);
        l.record_failure_at(ip("192.0.2.4"), t0 + Duration::from_secs(1));
        assert_eq!(l.tracked().1, 3);
        assert!(l.blocked(blocked_a, t0).is_some());
        assert!(l.blocked(blocked_b, t0).is_some());
    }

    #[test]
    fn ipv6_failures_are_aggregated_per_48() {
        let l = RateLimiter::default();
        let t0 = Instant::now();
        // 100 failures spread over 25 different /64s of one /48, 4 each: no /64 reaches its own
        // threshold, but the /48 does.
        for i in 0..(V6_NET_FAILURE_THRESHOLD as u32) {
            let addr = ip(&format!("2001:db8:7:{:x}::1", i / 4));
            assert!(l.blocked(addr, t0).is_none(), "blocked too early at {i}");
            l.record_failure_at(addr, t0);
        }
        // Every /64 in the /48 is now blocked, including ones that never failed.
        assert_eq!(l.blocked(ip("2001:db8:7:ffff::9"), t0), Some(600));
        // A neighbouring /48 is unaffected.
        assert!(l.blocked(ip("2001:db8:8::1"), t0).is_none());
        // /64 and /48 keys with identical address bits (2001:db8:a::) do not collide: blocking
        // the /64 2001:db8:a:0::/64 must not block the rest of 2001:db8:a::/48.
        block(&l, ip("2001:db8:a::1"), t0);
        assert!(l.blocked(ip("2001:db8:a:1::1"), t0).is_none());
    }

    #[test]
    fn one_ipv6_48_cannot_fill_the_failure_table() {
        let l = RateLimiter::new(1000);
        let t0 = Instant::now();
        // An attacker with a /48 tries to block 1000 /64s (10 failures each). Once the /48 is
        // blocked, the middleware rejects every further request, so at most
        // V6_NET_FAILURE_THRESHOLD failures are ever recorded from it.
        let mut recorded = 0;
        'outer: for net in 0..1000u32 {
            for _ in 0..FAILURE_THRESHOLD {
                let addr = ip(&format!("2001:db8:9:{net:x}::1"));
                if l.blocked(addr, t0).is_some() {
                    break 'outer;
                }
                l.record_failure_at(addr, t0);
                recorded += 1;
            }
        }
        assert_eq!(recorded, V6_NET_FAILURE_THRESHOLD);
        // 10 blocked /64s + the /48.
        assert_eq!(
            l.tracked().1,
            V6_NET_FAILURE_THRESHOLD / FAILURE_THRESHOLD + 1
        );
    }
}
