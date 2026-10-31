//! Persistent state in `STATE_DIR/state.json`: event log, burned IPs, last rotation time.
//! Holds no secrets. Writes are atomic (temp file + rename) with mode 0600 on unix.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::util::{random_bytes, unix_now};

pub const MAX_EVENTS: usize = 500;
pub const MAX_BURNED_IPS: usize = 500;
const STATE_FILE: &str = "state.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventAction {
    Start,
    Stop,
    Rotate,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub at: i64,
    pub action: EventAction,
    pub ip: Option<String>,
    pub detail: String,
    pub actor: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default)]
    pub burned_ips: Vec<String>,
    #[serde(default)]
    pub last_rotation_at: Option<i64>,
}

impl PersistedState {
    fn enforce_caps(&mut self) {
        if self.events.len() > MAX_EVENTS {
            let excess = self.events.len() - MAX_EVENTS;
            self.events.drain(..excess);
        }
        if self.burned_ips.len() > MAX_BURNED_IPS {
            let excess = self.burned_ips.len() - MAX_BURNED_IPS;
            self.burned_ips.drain(..excess);
        }
    }

    pub fn push_event(&mut self, event: Event) {
        self.events.push(event);
        self.enforce_caps();
    }

    pub fn burn_ip(&mut self, ip: &str) {
        if !self.burned_ips.iter().any(|b| b == ip) {
            self.burned_ips.push(ip.to_string());
        }
        self.enforce_caps();
    }

    pub fn is_burned(&self, ip: &str) -> bool {
        self.burned_ips.iter().any(|b| b == ip)
    }
}

#[derive(Debug)]
pub struct StateStore {
    dir: PathBuf,
    data: Mutex<PersistedState>,
}

impl StateStore {
    /// Open (or create) the state store. A corrupt state file is moved aside and a fresh state
    /// is started; an unwritable directory is a fatal error.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        create_private_dir(dir)?;
        let path = dir.join(STATE_FILE);
        let data = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<PersistedState>(&bytes) {
                Ok(mut s) => {
                    s.enforce_caps();
                    s
                }
                Err(e) => {
                    let aside = dir.join(format!("{STATE_FILE}.corrupt-{}", unix_now()));
                    tracing::error!(error = %e, moved_to = %aside.display(), "state file is corrupt; starting with empty state");
                    std::fs::rename(&path, &aside)?;
                    PersistedState::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PersistedState::default(),
            Err(e) => return Err(anyhow::anyhow!("cannot read {}: {e}", path.display())),
        };
        // Prove at startup that the directory is writable.
        write_atomic(dir, &data)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            data: Mutex::new(data),
        })
    }

    /// A copy of the current state.
    pub async fn snapshot(&self) -> PersistedState {
        self.data.lock().await.clone()
    }

    /// Apply a mutation and persist it. The lock is held across the write so that writes are
    /// never reordered. The in-memory state is updated even if persisting fails (so that e.g.
    /// the rotation cooldown is still enforced); the write error is returned to the caller.
    pub async fn update<R>(&self, f: impl FnOnce(&mut PersistedState) -> R) -> anyhow::Result<R> {
        let mut guard = self.data.lock().await;
        let result = f(&mut guard);
        guard.enforce_caps();
        let dir = self.dir.clone();
        let to_write = guard.clone();
        tokio::task::spawn_blocking(move || write_atomic(&dir, &to_write)).await??;
        Ok(result)
    }

    /// Append an event (convenience wrapper around [`update`](Self::update)).
    pub async fn record(
        &self,
        action: EventAction,
        ip: Option<String>,
        detail: String,
        actor: String,
    ) -> anyhow::Result<()> {
        self.update(|s| {
            s.push_event(Event {
                at: unix_now(),
                action,
                ip,
                detail,
                actor,
            });
        })
        .await
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

fn write_atomic(dir: &Path, state: &PersistedState) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(state)?;
    let tmp = dir.join(format!(
        ".{STATE_FILE}.tmp-{}",
        hex::encode(random_bytes::<8>()?)
    ));
    let result = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(&json)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, dir.join(STATE_FILE))?;
        #[cfg(unix)]
        {
            // Persist the rename itself.
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(result?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path()).unwrap();
        store
            .record(
                EventAction::Rotate,
                Some("203.0.113.5".into()),
                "test".into(),
                "alice".into(),
            )
            .await
            .unwrap();
        store
            .update(|s| {
                s.burn_ip("203.0.113.4");
                s.last_rotation_at = Some(42);
            })
            .await
            .unwrap();
        drop(store);
        let store = StateStore::open(dir.path()).unwrap();
        let snap = store.snapshot().await;
        assert_eq!(snap.events.len(), 1);
        assert_eq!(snap.events[0].actor, "alice");
        assert!(snap.is_burned("203.0.113.4"));
        assert_eq!(snap.last_rotation_at, Some(42));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(STATE_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn caps_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path()).unwrap();
        store
            .update(|s| {
                for i in 0..(MAX_EVENTS + 10) {
                    s.push_event(Event {
                        at: i64::try_from(i).unwrap(),
                        action: EventAction::Start,
                        ip: None,
                        detail: String::new(),
                        actor: "x".into(),
                    });
                }
                for i in 0..(MAX_BURNED_IPS + 3) {
                    s.burn_ip(&format!("10.0.{}.{}", i / 256, i % 256));
                }
            })
            .await
            .unwrap();
        let snap = store.snapshot().await;
        assert_eq!(snap.events.len(), MAX_EVENTS);
        assert_eq!(snap.events[0].at, 10);
        assert_eq!(snap.burned_ips.len(), MAX_BURNED_IPS);
    }

    #[test]
    fn corrupt_file_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(STATE_FILE), b"{not json").unwrap();
        let store = StateStore::open(dir.path()).unwrap();
        drop(store);
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n.starts_with("state.json.corrupt-")));
    }
}
