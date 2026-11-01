//! What the ingress reports about itself (`POST /i/{token}/report`, once a minute): a few
//! counters and its recent sing-box log lines. Kept **in memory only** — the log lines can
//! contain client addresses and destinations while debug logging is on, and that must not end up
//! on disk. Everything here is gone after a restart; the next report refills it.

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::util::{lock, unix_now};

/// Lines kept for the log card.
pub const MAX_LOG_LINES: usize = 2000;
/// Per report: more lines than this are dropped (the ingress caps itself lower).
pub const MAX_LINES_PER_REPORT: usize = 400;
pub const MAX_LINE_CHARS: usize = 1000;
/// Hourly traffic buckets kept (48 h).
const MAX_HOURS: usize = 48;

/// The report body sent by the ingress. Unknown fields are rejected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressReport {
    /// sing-box version string, e.g. "1.14.4".
    pub version: String,
    /// Seconds since sing-box started; `None` when it is not running.
    pub uptime_s: Option<u64>,
    /// Active proxied connections; `None` when sing-box or its API is unreachable.
    pub connections: Option<u32>,
    /// Cumulative bytes since sing-box started (reset on restart).
    pub upload_total: Option<u64>,
    pub download_total: Option<u64>,
    /// Lowercase hex SHA-256 of the config file the ingress currently runs.
    pub config_sha256: String,
    /// New journal lines since the previous report, oldest first.
    #[serde(default)]
    pub log: Vec<String>,
    /// Lines the ingress had to drop before sending (backlog larger than its cap).
    #[serde(default)]
    pub log_dropped: u64,
}

/// What the control plane answers: enough for the ingress to know whether to re-pull its config.
#[derive(Debug, Serialize)]
pub struct ReportReply {
    pub config_sha256: String,
    pub config_stale: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub seq: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HourBucket {
    /// Start of the hour, unix seconds.
    pub hour: i64,
    pub upload: u64,
    pub download: u64,
}

/// Latest counters as shown on the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub last_report_at: Option<i64>,
    pub version: Option<String>,
    pub uptime_s: Option<u64>,
    pub connections: Option<u32>,
    pub upload_total: Option<u64>,
    pub download_total: Option<u64>,
    /// Bytes in the last 24 h (sum of the hourly buckets).
    pub upload_24h: u64,
    pub download_24h: u64,
    pub config_sha256: Option<String>,
    pub log_lines: usize,
    pub log_dropped: u64,
}

#[derive(Debug, Default)]
struct Inner {
    last_report_at: Option<i64>,
    version: Option<String>,
    uptime_s: Option<u64>,
    connections: Option<u32>,
    upload_total: Option<u64>,
    download_total: Option<u64>,
    config_sha256: Option<String>,
    hours: VecDeque<HourBucket>,
    logs: VecDeque<LogLine>,
    next_seq: u64,
    /// Lines dropped anywhere (by the ingress, or here when the buffer was full).
    log_dropped: u64,
}

#[derive(Debug, Default)]
pub struct Telemetry {
    inner: Mutex<Inner>,
}

/// Keep a journal line printable and bounded. Control characters (incl. ANSI escapes) are
/// removed, not escaped, so nothing can mess with the log view or a terminal.
pub fn sanitize_line(line: &str) -> String {
    let mut out: String = line
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .map(|c| if c == '\t' { ' ' } else { c })
        .collect();
    if out.chars().count() > MAX_LINE_CHARS {
        out = out.chars().take(MAX_LINE_CHARS).collect();
        out.push('…');
    }
    out
}

fn delta(prev: Option<u64>, now: Option<u64>) -> u64 {
    match (prev, now) {
        // Counter went backwards: sing-box restarted, the new total is the delta.
        (Some(p), Some(n)) => n.checked_sub(p).unwrap_or(n),
        (None, Some(n)) => n,
        _ => 0,
    }
}

impl Telemetry {
    pub fn record(&self, report: IngressReport) {
        self.record_at(report, unix_now());
    }

    pub fn record_at(&self, report: IngressReport, now: i64) {
        let mut t = lock(&self.inner);

        // Traffic: attribute the growth since the previous report to the current hour.
        let up = delta(t.upload_total, report.upload_total);
        let down = delta(t.download_total, report.download_total);
        let hour = now - now.rem_euclid(3600);
        match t.hours.back_mut() {
            Some(b) if b.hour == hour => {
                b.upload = b.upload.saturating_add(up);
                b.download = b.download.saturating_add(down);
            }
            _ => {
                t.hours.push_back(HourBucket {
                    hour,
                    upload: up,
                    download: down,
                });
                while t.hours.len() > MAX_HOURS {
                    t.hours.pop_front();
                }
            }
        }

        t.last_report_at = Some(now);
        t.version = Some(crate::util::sanitize_text(&report.version, 32));
        t.uptime_s = report.uptime_s;
        t.connections = report.connections;
        t.upload_total = report.upload_total;
        t.download_total = report.download_total;
        t.config_sha256 = Some(report.config_sha256);

        // Logs: newest MAX_LINES_PER_REPORT of this report, then the buffer cap.
        let lines = report.log;
        let skip = lines.len().saturating_sub(MAX_LINES_PER_REPORT);
        t.log_dropped = t
            .log_dropped
            .saturating_add(report.log_dropped)
            .saturating_add(skip as u64);
        for line in lines.into_iter().skip(skip) {
            let seq = t.next_seq;
            t.next_seq += 1;
            t.logs.push_back(LogLine {
                seq,
                text: sanitize_line(&line),
            });
            if t.logs.len() > MAX_LOG_LINES {
                t.logs.pop_front();
                t.log_dropped = t.log_dropped.saturating_add(1);
            }
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snapshot_at(unix_now())
    }

    pub fn snapshot_at(&self, now: i64) -> Snapshot {
        let t = lock(&self.inner);
        let since = now - 24 * 3600;
        let (upload_24h, download_24h) = t
            .hours
            .iter()
            .filter(|b| b.hour + 3600 > since)
            .fold((0u64, 0u64), |(u, d), b| {
                (u.saturating_add(b.upload), d.saturating_add(b.download))
            });
        Snapshot {
            last_report_at: t.last_report_at,
            version: t.version.clone(),
            uptime_s: t.uptime_s,
            connections: t.connections,
            upload_total: t.upload_total,
            download_total: t.download_total,
            upload_24h,
            download_24h,
            config_sha256: t.config_sha256.clone(),
            log_lines: t.logs.len(),
            log_dropped: t.log_dropped,
        }
    }

    /// Lines with `seq >= after`, oldest first, at most `limit`.
    pub fn logs_after(&self, after: u64, limit: usize) -> Vec<LogLine> {
        let t = lock(&self.inner);
        // seq is monotonic and contiguous within the buffer: binary-search the start.
        let start = t.logs.partition_point(|l| l.seq < after);
        t.logs.iter().skip(start).take(limit).cloned().collect()
    }

    /// The next sequence number a new line will get (so a client can start "from now").
    pub fn next_seq(&self) -> u64 {
        lock(&self.inner).next_seq
    }

    /// Forget all log lines (the counters stay). Used when debug logging is switched off.
    pub fn clear_logs(&self) {
        let mut t = lock(&self.inner);
        t.logs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(up: Option<u64>, down: Option<u64>, log: Vec<String>) -> IngressReport {
        IngressReport {
            version: "1.14.4".into(),
            uptime_s: Some(10),
            connections: Some(2),
            upload_total: up,
            download_total: down,
            config_sha256: "ab".repeat(32),
            log,
            log_dropped: 0,
        }
    }

    #[test]
    fn traffic_is_attributed_per_hour_and_survives_counter_resets() {
        let t = Telemetry::default();
        let h0 = 1_700_000_000 - (1_700_000_000 % 3600);
        t.record_at(report(Some(100), Some(1000), vec![]), h0 + 10);
        t.record_at(report(Some(150), Some(1500), vec![]), h0 + 70);
        // restart: totals start over
        t.record_at(report(Some(20), Some(30), vec![]), h0 + 3700);
        let s = t.snapshot_at(h0 + 3800);
        assert_eq!(s.upload_24h, 100 + 50 + 20);
        assert_eq!(s.download_24h, 1000 + 500 + 30);
        assert_eq!(s.connections, Some(2));
        assert_eq!(s.last_report_at, Some(h0 + 3700));
        // buckets older than 24 h fall out of the sum
        let s = t.snapshot_at(h0 + 3700 + 25 * 3600);
        assert_eq!(s.upload_24h, 0);
    }

    #[test]
    fn logs_are_bounded_sequenced_and_sanitized() {
        let t = Telemetry::default();
        t.record_at(
            report(
                None,
                None,
                vec!["a\x1b[31mred\x1b[0m".into(), "b\tc".into()],
            ),
            1,
        );
        let lines = t.logs_after(0, 10);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].text, "a[31mred[0m");
        assert_eq!(lines[1].text, "b c");
        assert_eq!(lines[1].seq, 1);
        assert_eq!(t.logs_after(1, 10).len(), 1);
        assert_eq!(t.logs_after(5, 10).len(), 0);
        assert_eq!(t.next_seq(), 2);

        // Per report only the newest MAX_LINES_PER_REPORT lines are kept.
        let many: Vec<String> = (0..(MAX_LINES_PER_REPORT + 50))
            .map(|i| i.to_string())
            .collect();
        t.record_at(report(None, None, many), 2);
        let s = t.snapshot_at(3);
        assert_eq!(s.log_lines, 2 + MAX_LINES_PER_REPORT);
        assert_eq!(s.log_dropped, 50);
        assert_eq!(t.logs_after(2, 1)[0].text, "50");

        // The buffer itself is capped; the oldest lines go.
        let reports = MAX_LOG_LINES / MAX_LINES_PER_REPORT + 1;
        for r in 0..reports {
            let lines = (0..MAX_LINES_PER_REPORT)
                .map(|i| format!("r{r}-{i}"))
                .collect();
            t.record_at(report(None, None, lines), 4);
        }
        let s = t.snapshot_at(5);
        assert_eq!(s.log_lines, MAX_LOG_LINES);
        let pushed_out = 2 + MAX_LINES_PER_REPORT + reports * MAX_LINES_PER_REPORT - MAX_LOG_LINES;
        assert_eq!(s.log_dropped, 50 + pushed_out as u64);
        let last = t.logs_after(0, usize::MAX);
        assert_eq!(last.len(), MAX_LOG_LINES);
        assert_eq!(
            last.last().unwrap().text,
            format!("r{}-{}", reports - 1, MAX_LINES_PER_REPORT - 1)
        );
        // sequence numbers stay contiguous across the pops
        assert_eq!(last[1].seq, last[0].seq + 1);

        t.clear_logs();
        assert_eq!(t.snapshot_at(4).log_lines, 0);
    }

    #[test]
    fn long_lines_are_truncated() {
        let line = "x".repeat(MAX_LINE_CHARS + 10);
        let out = sanitize_line(&line);
        assert_eq!(out.chars().count(), MAX_LINE_CHARS + 1);
        assert!(out.ends_with('…'));
    }
}
