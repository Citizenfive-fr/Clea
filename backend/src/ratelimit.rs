//! In-memory failure counter with temporary bans of increasing length.
//!
//! After `max_failures` failures inside `window`, the key is banned. Each new ban
//! doubles the duration (base, 2x, 4x...) up to `max_ban`. Strikes are forgotten
//! after `STRIKE_MEMORY` without activity. Nothing is persisted: keys (IP, email)
//! only live in memory and are lost on restart.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

use crate::error::AppError;

const STRIKE_MEMORY: Duration = Duration::from_secs(24 * 3600);
/// Hard cap on tracked keys, so random emails or spoofed IPs cannot exhaust memory
const MAX_ENTRIES: usize = 100_000;

struct Entry {
    failures: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
    strikes: u32,
    last_seen: Instant,
}

pub struct RateLimiter {
    entries: Mutex<HashMap<String, Entry>>,
    max_failures: u32,
    window: Duration,
    base_ban: Duration,
    max_ban: Duration,
}

impl RateLimiter {
    pub fn new(max_failures: u32, window: Duration, base_ban: Duration, max_ban: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_failures,
            window,
            base_ban,
            max_ban,
        }
    }

    /// Err(remaining ban time) if the key is currently banned.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        self.check_at(key, Instant::now())
    }

    pub fn record_failure(&self, key: &str) {
        self.record_failure_at(key, Instant::now());
    }

    /// Forgets the failures of a key (strikes are kept).
    pub fn clear_failures(&self, key: &str) {
        if let Some(e) = self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(key)
        {
            e.failures = 0;
        }
    }

    /// Drops entries with no active ban and no recent activity.
    pub fn purge(&self) {
        self.purge_at(Instant::now());
    }

    fn check_at(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        match entries.get(key).and_then(|e| e.banned_until) {
            Some(until) if until > now => Err(until - now),
            _ => Ok(()),
        }
    }

    fn record_failure_at(&self, key: &str, now: Instant) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());

        if !entries.contains_key(key) && entries.len() >= MAX_ENTRIES {
            purge_entries(&mut entries, now, self.window);
            if entries.len() >= MAX_ENTRIES {
                tracing::warn!("Limiteur de débit plein : nouvelle clé non suivie");
                return;
            }
        }

        let entry = entries.entry(key.to_string()).or_insert(Entry {
            failures: 0,
            window_start: now,
            banned_until: None,
            strikes: 0,
            last_seen: now,
        });

        // Old strikes are forgotten after a long quiet period
        if now.duration_since(entry.last_seen) >= STRIKE_MEMORY {
            entry.strikes = 0;
        }
        entry.last_seen = now;

        if now.duration_since(entry.window_start) >= self.window {
            entry.failures = 0;
            entry.window_start = now;
        }
        entry.failures += 1;

        if entry.failures >= self.max_failures {
            let factor = 1u32 << entry.strikes.min(16);
            let ban = self.base_ban.saturating_mul(factor).min(self.max_ban);
            entry.banned_until = Some(now + ban);
            entry.strikes += 1;
            entry.failures = 0;
            entry.window_start = now;
        }
    }

    fn purge_at(&self, now: Instant) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        purge_entries(&mut entries, now, self.window);
    }
}

fn purge_entries(entries: &mut HashMap<String, Entry>, now: Instant, window: Duration) {
    entries.retain(|_, e| {
        let banned = e.banned_until.is_some_and(|u| u > now);
        let remembered = now.duration_since(e.last_seen) < STRIKE_MEMORY.max(window);
        banned || remembered
    });
}

/// 429 error telling the user how long the ban lasts.
pub fn ban_error(remaining: Duration) -> AppError {
    let minutes = remaining.as_secs().div_ceil(60).max(1);
    AppError::TooManyRequests(format!(
        "Trop de tentatives. Réessaie dans {minutes} minute(s)."
    ))
}

/// Client IP used as rate-limit key.
/// With `trust_proxy`, the rightmost X-Forwarded-For entry is used: it is the one added
/// by our own reverse proxy, unlike the left ones which the client can forge.
/// IPv6 addresses are reduced to their /64 prefix (one subscriber = one /64).
pub fn client_key(headers: &HeaderMap, peer: SocketAddr, trust_proxy: bool) -> String {
    let forwarded = trust_proxy
        .then(|| {
            headers
                .get_all("x-forwarded-for")
                .iter()
                .next_back()
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
        })
        .flatten();

    match forwarded.unwrap_or_else(|| peer.ip()) {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => {
            let o = ip.octets();
            format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                u16::from_be_bytes([o[0], o[1]]),
                u16::from_be_bytes([o[2], o[3]]),
                u16::from_be_bytes([o[4], o[5]]),
                u16::from_be_bytes([o[6], o[7]]),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> RateLimiter {
        RateLimiter::new(
            3,
            Duration::from_secs(900),
            Duration::from_secs(10),
            Duration::from_secs(40),
        )
    }

    #[test]
    fn bans_then_doubles_on_repeat_up_to_max() {
        let rl = limiter();
        let t0 = Instant::now();

        for _ in 0..3 {
            rl.record_failure_at("ip", t0);
        }
        assert!(rl.check_at("ip", t0 + Duration::from_secs(5)).is_err());
        assert!(rl.check_at("ip", t0 + Duration::from_secs(11)).is_ok());

        // Second offense: 20 s
        let t1 = t0 + Duration::from_secs(11);
        for _ in 0..3 {
            rl.record_failure_at("ip", t1);
        }
        assert!(rl.check_at("ip", t1 + Duration::from_secs(15)).is_err());
        assert!(rl.check_at("ip", t1 + Duration::from_secs(21)).is_ok());

        // Third offense: 40 s, then capped at 40 s
        let t2 = t1 + Duration::from_secs(21);
        for _ in 0..3 {
            rl.record_failure_at("ip", t2);
        }
        assert!(rl.check_at("ip", t2 + Duration::from_secs(39)).is_err());
        let t3 = t2 + Duration::from_secs(41);
        for _ in 0..3 {
            rl.record_failure_at("ip", t3);
        }
        assert!(rl.check_at("ip", t3 + Duration::from_secs(39)).is_err());
        assert!(rl.check_at("ip", t3 + Duration::from_secs(41)).is_ok());
    }

    #[test]
    fn keys_are_independent_and_purge_keeps_recent() {
        let rl = limiter();
        let t0 = Instant::now();
        for _ in 0..3 {
            rl.record_failure_at("a", t0);
        }
        assert!(rl.check_at("b", t0).is_ok());
        rl.purge_at(t0 + Duration::from_secs(100));
        assert!(rl.check_at("a", t0 + Duration::from_secs(1)).is_err());
        rl.purge_at(t0 + STRIKE_MEMORY + Duration::from_secs(1));
        assert!(rl.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn forwarded_header_only_trusted_when_enabled() {
        let peer: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 203.0.113.7".parse().unwrap());
        assert_eq!(client_key(&h, peer, false), "10.0.0.1");
        assert_eq!(client_key(&h, peer, true), "203.0.113.7");

        // IPv6: all addresses of one /64 share the same key
        let mut h6 = HeaderMap::new();
        h6.insert(
            "x-forwarded-for",
            "2001:db8:1:2:aaaa::1, 2001:db8:1:2:bbbb::9"
                .parse()
                .unwrap(),
        );
        assert_eq!(client_key(&h6, peer, true), "2001:db8:1:2::/64");
        h6.insert(
            "x-forwarded-for",
            "2001:db8:1:2:1111:2222:3333:4444".parse().unwrap(),
        );
        assert_eq!(client_key(&h6, peer, true), "2001:db8:1:2::/64");

        h.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(client_key(&h, peer, true), "10.0.0.1");
    }
}
