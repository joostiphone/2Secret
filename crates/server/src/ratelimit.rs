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
}

#[cfg(test)]
mod tests {
    use super::*;

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
