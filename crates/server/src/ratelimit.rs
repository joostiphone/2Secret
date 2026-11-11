//! A tiny in-memory limiter for failed authentication attempts.

use std::collections::HashMap;
use std::sync::Mutex;

pub struct RateLimiter {
    entries: Mutex<HashMap<String, Entry>>,
    max_failures: u32,
    window_secs: i64,
}

#[derive(Clone, Copy)]
struct Entry {
    failures: u32,
    window_start: i64,
}

impl RateLimiter {
    pub fn new(max_failures: u32, window_secs: i64) -> Self {
        Self { entries: Mutex::new(HashMap::new()), max_failures, window_secs }
    }

    /// May another attempt be made for this key?
    pub fn allowed(&self, key: &str, now: i64) -> bool {
        let mut map = self.entries.lock().expect("rate limiter lock");
        if map.len() > 100_000 {
            let window = self.window_secs;
            map.retain(|_, e| now - e.window_start < window);
        }
        match map.get(key) {
            Some(e) if now - e.window_start < self.window_secs => e.failures < self.max_failures,
            _ => true,
        }
    }

    pub fn record_failure(&self, key: &str, now: i64) {
        let mut map = self.entries.lock().expect("rate limiter lock");
        let e = map.entry(key.to_string()).or_insert(Entry { failures: 0, window_start: now });
        if now - e.window_start >= self.window_secs {
            *e = Entry { failures: 0, window_start: now };
        }
        e.failures += 1;
    }

    pub fn reset(&self, key: &str) {
        self.entries.lock().expect("rate limiter lock").remove(key);
    }

    /// Forgets keys whose window has passed, so addresses and e-mail
    /// addresses are not kept in memory longer than the window.
    pub fn prune(&self, now: i64) {
        let window = self.window_secs;
        self.entries.lock().expect("rate limiter lock").retain(|_, e| now - e.window_start < window);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().expect("rate limiter lock").len()
    }
}

/// Work running at the same time per key (client address): one address
/// cannot take every password-hash slot of the server.
pub struct Inflight {
    running: Mutex<HashMap<String, u32>>,
    max: u32,
}

/// One unit of work in [`Inflight`]; done when dropped.
pub struct InflightGuard<'a> {
    inflight: &'a Inflight,
    key: String,
}

impl Inflight {
    pub fn new(max: u32) -> Self {
        Self { running: Mutex::new(HashMap::new()), max }
    }

    /// Start one more for `key`, unless `max` are running already.
    pub fn enter(&self, key: &str) -> Option<InflightGuard<'_>> {
        let mut map = self.running.lock().unwrap_or_else(|p| p.into_inner());
        let n = map.entry(key.to_string()).or_insert(0);
        if *n >= self.max {
            return None;
        }
        *n += 1;
        Some(InflightGuard { inflight: self, key: key.to_string() })
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        let mut map = self.inflight.running.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflight_limits_per_key() {
        let inflight = Inflight::new(2);
        let a = inflight.enter("a").unwrap();
        let _b = inflight.enter("a").unwrap();
        assert!(inflight.enter("a").is_none());
        assert!(inflight.enter("b").is_some());
        drop(a);
        assert!(inflight.enter("a").is_some());
    }

    #[test]
    fn prune_forgets_expired_keys() {
        let rl = RateLimiter::new(3, 60);
        rl.record_failure("old", 0);
        rl.record_failure("new", 30);
        rl.prune(59);
        assert_eq!(rl.len(), 2);
        rl.prune(60);
        assert_eq!(rl.len(), 1);
        assert!(rl.allowed("old", 60));
        rl.prune(90);
        assert_eq!(rl.len(), 0);
    }

    #[test]
    fn limits_and_resets() {
        let rl = RateLimiter::new(3, 60);
        for _ in 0..3 {
            assert!(rl.allowed("a", 0));
            rl.record_failure("a", 0);
        }
        assert!(!rl.allowed("a", 10));
        assert!(rl.allowed("b", 10));
        assert!(rl.allowed("a", 61));
        rl.record_failure("a", 61);
        assert!(rl.allowed("a", 62));
        rl.reset("a");
        assert!(rl.allowed("a", 62));
    }
}
