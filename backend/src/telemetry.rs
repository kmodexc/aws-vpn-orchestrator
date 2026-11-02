//! What the ingress reports about itself (`POST /i/{token}/report`, once a minute): a few
//! counters and its recent sing-box log lines. Kept **in memory only** — the log lines can
//! contain client addresses and destinations while debug logging is on, and that must not end up
//! on disk. Everything here is gone after a restart; the next report refills it. Lines collected
//! during debug logging are purged [`LOG_RETENTION_AFTER_DEBUG_S`] after it ends.

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
/// How long the buffered lines survive after debug logging ended (time to read them).
pub const LOG_RETENTION_AFTER_DEBUG_S: i64 = 3600;

/// The report body sent by the ingress. Unknown fields are rejected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressReport {
    #[serde(default)]
    pub deployment_id: Option<String>,
    /// sing-box version string, e.g. "1.14.4".
    pub version: String,
    /// Seconds since sing-box started; `None` when it is not running.
    pub uptime_s: Option<u64>,
    /// Active proxied connections; `None` when sing-box or its API is unreachable.
    pub connections: Option<u32>,
    /// Cumulative bytes since sing-box started (reset on restart). `None` = not read this time.
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

/// A page of log lines for the dashboard.
#[derive(Debug, Serialize)]
pub struct LogChunk {
    pub lines: Vec<LogLine>,
    /// Pass as `after` next time to get only newer lines.
    pub next: u64,
    pub dropped: u64,
    /// Identifies this buffer's lifetime; it changes when the control plane restarts (sequence
    /// numbers start over) or the buffer is cleared, so a client knows to start from 0.
    pub epoch: u64,
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
    /// When the buffered lines will be discarded, if a purge is scheduled.
    pub log_purge_at: Option<i64>,
}

#[derive(Debug, Default)]
struct Inner {
    last_report_at: Option<i64>,
    version: Option<String>,
    uptime_s: Option<u64>,
    connections: Option<u32>,
    /// Last *known* totals; a report without them leaves these untouched, so the next delta is
    /// still computed against the previous reading and not against zero.
    upload_total: Option<u64>,
    download_total: Option<u64>,
    config_sha256: Option<String>,
    hours: VecDeque<HourBucket>,
    logs: VecDeque<LogLine>,
    next_seq: u64,
    /// Lines dropped anywhere (by the ingress, or here when the buffer was full).
    log_dropped: u64,
    epoch: u64,
    purge_at: Option<i64>,
}

#[derive(Debug)]
pub struct Telemetry {
    inner: Mutex<Inner>,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::with_epoch(unix_now().unsigned_abs())
    }
}

/// Keep a journal line printable and bounded. ANSI escape sequences (colours `ESC [ … m`, OSC
/// strings) are removed whole and other control characters dropped, so nothing can mess with the
/// log view or a terminal. sing-box is also asked not to colour its output (`disable_color`), but
/// journal lines from other units may still carry escapes.
pub fn sanitize_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => match chars.peek() {
                // CSI: ESC [ <params 0x30-0x3F> <intermediates 0x20-0x2F> <final 0x40-0x7E>
                Some('[') => {
                    chars.next();
                    for d in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&d) {
                            break;
                        }
                    }
                }
                // OSC: ESC ] … terminated by BEL or ESC \
                Some(']') => {
                    chars.next();
                    let mut prev = '\0';
                    for d in chars.by_ref() {
                        if d == '\x07' || (prev == '\x1b' && d == '\\') {
                            break;
                        }
                        prev = d;
                    }
                }
                // Two-character escapes (ESC c, ESC =, …): drop the pair.
                Some(_) => {
                    chars.next();
                }
                None => {}
            },
            '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
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
        // Not read this time: attribute nothing; the next reading carries the growth.
        (_, None) => 0,
    }
}

impl Inner {
    fn clear_logs(&mut self) {
        self.logs.clear();
        self.epoch = self.epoch.wrapping_add(1);
        self.purge_at = None;
    }

    fn purge_if_due(&mut self, now: i64) {
        if self.purge_at.is_some_and(|at| at <= now) && !self.logs.is_empty() {
            self.clear_logs();
        } else if self.purge_at.is_some_and(|at| at <= now) {
            self.purge_at = None;
        }
    }
}

impl Telemetry {
    pub fn with_epoch(epoch: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                epoch,
                ..Inner::default()
            }),
        }
    }

    pub fn record(&self, report: IngressReport) {
        self.record_at(report, unix_now());
    }

    pub fn record_at(&self, report: IngressReport, now: i64) {
        let mut t = lock(&self.inner);
        t.purge_if_due(now);

        // Traffic: attribute the growth since the previous reading to the current hour.
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
        if report.upload_total.is_some() {
            t.upload_total = report.upload_total;
        }
        if report.download_total.is_some() {
            t.download_total = report.download_total;
        }
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
        let mut t = lock(&self.inner);
        t.purge_if_due(now);
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
            log_purge_at: t.purge_at,
        }
    }

    /// Lines with `seq >= after`, oldest first, at most `limit` — plus the cursor for the next
    /// call, all read under one lock so a report landing in between cannot be skipped.
    pub fn chunk(&self, after: u64, limit: usize) -> LogChunk {
        self.chunk_at(after, limit, unix_now())
    }

    pub fn chunk_at(&self, after: u64, limit: usize, now: i64) -> LogChunk {
        let mut t = lock(&self.inner);
        t.purge_if_due(now);
        // seq is monotonic and contiguous within the buffer: binary-search the start.
        let start = t.logs.partition_point(|l| l.seq < after);
        let lines: Vec<LogLine> = t.logs.iter().skip(start).take(limit).cloned().collect();
        // Everything before `next` has been handed out; a client that asked beyond the end
        // gets the real end, so it never waits for sequence numbers that will not come.
        let next = lines.last().map_or(t.next_seq, |l| l.seq + 1);
        LogChunk {
            lines,
            next,
            dropped: t.log_dropped,
            epoch: t.epoch,
        }
    }

    /// Forget all log lines now (the counters stay). Starts a new epoch.
    pub fn clear_logs(&self) -> LogChunk {
        let mut t = lock(&self.inner);
        t.clear_logs();
        LogChunk {
            lines: Vec::new(),
            next: t.next_seq,
            dropped: t.log_dropped,
            epoch: t.epoch,
        }
    }

    /// Discard the buffered lines at `at` (unix s). Called whenever debug logging is set or
    /// ended, so connection records never linger beyond the retention period.
    pub fn schedule_purge(&self, at: i64) {
        lock(&self.inner).purge_at = Some(at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(up: Option<u64>, down: Option<u64>, log: Vec<String>) -> IngressReport {
        IngressReport {
            deployment_id: None,
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
        let t = Telemetry::with_epoch(1);
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
    fn a_report_without_totals_does_not_inflate_traffic() {
        let t = Telemetry::with_epoch(1);
        let h0 = 1_700_000_000 - (1_700_000_000 % 3600);
        t.record_at(report(Some(500), Some(500), vec![]), h0 + 10);
        // stats API unreachable this minute
        t.record_at(report(None, None, vec![]), h0 + 70);
        let s = t.snapshot_at(h0 + 80);
        assert_eq!(s.upload_total, Some(500), "last known total is kept");
        assert_eq!(s.connections, Some(2));
        // next reading: only the growth counts, not the whole counter
        t.record_at(report(Some(510), Some(520), vec![]), h0 + 130);
        let s = t.snapshot_at(h0 + 140);
        assert_eq!(s.upload_24h, 510);
        assert_eq!(s.download_24h, 520);
    }

    #[test]
    fn logs_are_bounded_sequenced_and_sanitized() {
        let t = Telemetry::with_epoch(7);
        t.record_at(
            report(
                None,
                None,
                vec!["a\x1b[31mred\x1b[0m".into(), "b\tc".into()],
            ),
            1,
        );
        let c = t.chunk_at(0, 10, 1);
        assert_eq!(c.lines.len(), 2);
        assert_eq!(c.lines[0].text, "ared");
        assert_eq!(c.lines[1].text, "b c");
        assert_eq!(c.lines[1].seq, 1);
        assert_eq!(c.next, 2);
        assert_eq!(c.epoch, 7);
        assert_eq!(t.chunk_at(1, 10, 1).lines.len(), 1);
        // asking beyond the end returns the real end, not the caller's cursor
        let c = t.chunk_at(5, 10, 1);
        assert_eq!(c.lines.len(), 0);
        assert_eq!(c.next, 2);

        // Per report only the newest MAX_LINES_PER_REPORT lines are kept.
        let many: Vec<String> = (0..(MAX_LINES_PER_REPORT + 50))
            .map(|i| i.to_string())
            .collect();
        t.record_at(report(None, None, many), 2);
        let s = t.snapshot_at(3);
        assert_eq!(s.log_lines, 2 + MAX_LINES_PER_REPORT);
        assert_eq!(s.log_dropped, 50);
        assert_eq!(t.chunk_at(2, 1, 3).lines[0].text, "50");

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
        let last = t.chunk_at(0, usize::MAX, 5);
        assert_eq!(last.lines.len(), MAX_LOG_LINES);
        assert_eq!(
            last.lines.last().unwrap().text,
            format!("r{}-{}", reports - 1, MAX_LINES_PER_REPORT - 1)
        );
        // sequence numbers stay contiguous across the pops
        assert_eq!(last.lines[1].seq, last.lines[0].seq + 1);

        // clearing starts a new epoch
        let c = t.clear_logs();
        assert_eq!(c.epoch, 8);
        assert_eq!(t.snapshot_at(6).log_lines, 0);
    }

    #[test]
    fn scheduled_purge_discards_lines_after_the_retention() {
        let t = Telemetry::with_epoch(1);
        t.record_at(report(None, None, vec!["x".into()]), 100);
        t.schedule_purge(200);
        assert_eq!(t.snapshot_at(199).log_lines, 1);
        assert_eq!(t.snapshot_at(199).log_purge_at, Some(200));
        let c = t.chunk_at(0, 10, 200);
        assert!(c.lines.is_empty());
        assert_eq!(c.epoch, 2, "a purge is a new epoch");
        assert_eq!(t.snapshot_at(201).log_purge_at, None);
        // lines arriving after the purge are kept again
        t.record_at(report(None, None, vec!["y".into()]), 300);
        assert_eq!(t.chunk_at(0, 10, 300).lines[0].text, "y");
    }

    #[test]
    fn ansi_sequences_are_removed_whole() {
        // sing-box's own colouring: 16-colour, 256-colour, reset, around a bracketed id
        assert_eq!(
            sanitize_line("+0000 \x1b[36mINFO\x1b[0m [\x1b[38;5;105m1928943449\x1b[0m 19ms] ok"),
            "+0000 INFO [1928943449 19ms] ok"
        );
        assert_eq!(sanitize_line("\x1b[1;31mE\x1b[0m"), "E");
        // OSC hyperlink with BEL and with ST terminators
        assert_eq!(
            sanitize_line("a\x1b]8;;http://x\x07b\x1b]8;;\x1b\\c"),
            "abc"
        );
        // two-character escape and a bare trailing ESC
        assert_eq!(sanitize_line("x\x1bcy\x1b"), "xy");
        // an unterminated CSI eats the rest instead of leaking half a sequence
        assert_eq!(sanitize_line("ok\x1b[38;5"), "ok");
        // other control characters vanish, tabs become spaces
        assert_eq!(sanitize_line("a\x00b\rc\td"), "abc d");
    }

    #[test]
    fn long_lines_are_truncated() {
        let line = "x".repeat(MAX_LINE_CHARS + 10);
        let out = sanitize_line(&line);
        assert_eq!(out.chars().count(), MAX_LINE_CHARS + 1);
        assert!(out.ends_with('…'));
    }
}
