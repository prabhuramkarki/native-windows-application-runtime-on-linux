//! [`Cached`]: a host probe's result, reused for a bounded time. A command that runs for a moment probes once; a
//! long-lived process (the daemon) sees a changed host again once the result is older than the bound.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A probe result reused for at most `ttl`, then probed again. The lock is held while probing, so concurrent callers
/// share one probe instead of starting one each.
pub struct Cached<T> {
    ttl: Duration,
    slot: Mutex<Option<(Instant, Arc<T>)>>,
}

impl<T> Cached<T> {
    pub const fn new(ttl: Duration) -> Cached<T> {
        Cached {
            ttl,
            slot: Mutex::new(None),
        }
    }

    /// The value probed at most `ttl` before `now`, or a fresh `probe()`.
    pub fn get_at(&self, now: Instant, probe: impl FnOnce() -> T) -> Arc<T> {
        let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, v)) = &*slot
            && now.saturating_duration_since(*at) < self.ttl
        {
            return v.clone();
        }
        let v = Arc::new(probe());
        *slot = Some((now, v.clone()));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cached_probe_is_reused_within_its_ttl_and_redone_after() {
        let c = Cached::new(Duration::from_secs(30));
        let t0 = Instant::now();
        let runs = std::cell::Cell::new(0);
        let probe = || {
            runs.set(runs.get() + 1);
            runs.get()
        };
        assert_eq!(*c.get_at(t0, probe), 1);
        assert_eq!(*c.get_at(t0 + Duration::from_secs(29), probe), 1, "within the ttl");
        assert_eq!(
            *c.get_at(t0 + Duration::from_secs(30), probe),
            2,
            "expired: probed again"
        );
        assert_eq!(*c.get_at(t0 + Duration::from_secs(31), probe), 2);
        // a caller whose `now` predates the stored probe (it waited on the lock) gets that probe
        assert_eq!(*c.get_at(t0, probe), 2);
        assert_eq!(runs.get(), 2);
    }
}
