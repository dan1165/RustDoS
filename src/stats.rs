//! Lock-free counters for live statistics.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};


use crate::vectors::ALL;

pub struct Stats {
    packets: [AtomicU64; 15],
    bytes: [AtomicU64; 15],
    errors: AtomicU64,
    pub stop: AtomicBool,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            packets: std::array::from_fn(|_| AtomicU64::new(0)),
            bytes: std::array::from_fn(|_| AtomicU64::new(0)),
            errors: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        }
    }

    #[inline]
    pub fn hit(&self, idx: usize, nbytes: usize) {
        self.packets[idx].fetch_add(1, Ordering::Relaxed);
        self.bytes[idx].fetch_add(nbytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn running(&self) -> bool {
        !self.stop.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn total_packets(&self) -> u64 {
        self.packets.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    pub fn per_vector(&self) -> Vec<(usize, u64, u64)> {
        (0..ALL.len())
            .map(|i| {
                (
                    i,
                    self.packets[i].load(Ordering::Relaxed),
                    self.bytes[i].load(Ordering::Relaxed),
                )
            })
            .collect()
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub fn human_rate(n: f64) -> String {
    if n >= 1_000_000.0 {
        format!("{:.2}M", n / 1_000_000.0)
    } else if n >= 1_000.0 {
        format!("{:.1}k", n / 1_000.0)
    } else {
        format!("{n:.0}")
    }
}
