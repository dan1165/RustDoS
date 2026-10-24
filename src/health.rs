//! Target health monitoring.
//!
//! A background prober connects to the target port on a fixed interval and
//! records latency and failures, so the UI can show whether the attack is
//! actually hurting the target rather than just counting our own packets.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

pub const UNKNOWN: u8 = 0;
pub const UP: u8 = 1;
pub const DEGRADED: u8 = 2;
pub const DOWN: u8 = 3;

pub struct Health {
    avg_ms: AtomicU64,
    ok: AtomicU64,
    fail: AtomicU64,
    consec_fail: AtomicU64,
    state: AtomicU8,
}

impl Health {
    pub fn new() -> Self {
        Self {
            avg_ms: AtomicU64::new(0),
            ok: AtomicU64::new(0),
            fail: AtomicU64::new(0),
            consec_fail: AtomicU64::new(0),
            state: AtomicU8::new(UNKNOWN),
        }
    }

    pub fn state(&self) -> u8 {
        self.state.load(Ordering::Relaxed)
    }

    pub fn avg_ms(&self) -> u64 {
        self.avg_ms.load(Ordering::Relaxed)
    }

    /// Success ratio in 0..=1, or None before any sample.
    pub fn success_pct(&self) -> Option<f64> {
        let ok = self.ok.load(Ordering::Relaxed);
        let fail = self.fail.load(Ordering::Relaxed);
        let total = ok + fail;
        if total == 0 {
            None
        } else {
            Some(ok as f64 / total as f64)
        }
    }

    fn record(&self, ms: Option<u64>) {
        match ms {
            Some(ms) => {
                self.ok.fetch_add(1, Ordering::Relaxed);
                self.consec_fail.store(0, Ordering::Relaxed);
                let prev = self.avg_ms.load(Ordering::Relaxed);
                let next = if prev == 0 {
                    ms
                } else {
                    // Exponential moving average, 7/8 weight on history.
                    (prev * 7 + ms) / 8
                };
                self.avg_ms.store(next, Ordering::Relaxed);
                let s = if next > 800 { DEGRADED } else { UP };
                self.state.store(s, Ordering::Relaxed);
            }
            None => {
                self.fail.fetch_add(1, Ordering::Relaxed);
                let cf = self.consec_fail.fetch_add(1, Ordering::Relaxed) + 1;
                if cf >= 3 {
                    self.state.store(DOWN, Ordering::Relaxed);
                } else if self.state.load(Ordering::Relaxed) == UP {
                    self.state.store(DEGRADED, Ordering::Relaxed);
                }
            }
        }
    }
}

impl Default for Health {
    fn default() -> Self {
        Self::new()
    }
}

pub fn spawn(health: Arc<Health>, ip: Ipv4Addr, port: u16, stop: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        while !stop.load(Ordering::Relaxed) {
            tick.tick().await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let t0 = Instant::now();
            let r = tokio::time::timeout(
                Duration::from_millis(1200),
                TcpStream::connect((ip, port)),
            )
            .await;
            match r {
                Ok(Ok(_)) => health.record(Some(t0.elapsed().as_millis() as u64)),
                _ => health.record(None),
            }
        }
    });
}
