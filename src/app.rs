//! Application state and input handling.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

use crate::attack::{self, Ctx};
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
    pub focus: usize,
    pub phase: Phase,
    pub target: Option<Target>,
    pub selected: [bool; ALL.len()],
    pub cursor: usize,
    pub stats: Option<Arc<Stats>>,
    pub log: Vec<String>,
    pub message: String,
    pub iface: Option<Iface>,
    pub raw_ok: bool,
    pub quit: bool,
    pub pps: f64,
    pub bps: f64,
    samples: VecDeque<(Instant, u64, u64)>,
    scan_rx: Option<mpsc::Receiver<ScanOutcome>>,
    pub started_at: Option<Instant>,
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
            focus: 0,
            phase: Phase::Input,
            target: None,
            selected: [false; ALL.len()],
            cursor: 0,
            stats: None,
            log,
            message: "enter a target, then press Enter to scan".into(),
            iface,
            raw_ok,
            quit: false,
            pps: 0.0,
            bps: 0.0,
            samples: VecDeque::new(),
            scan_rx: None,
            started_at: None,
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
        self.phase = Phase::Scanning;
        self.message = "resolving and fingerprinting target...".into();
        let (tx, rx) = mpsc::channel(1);
        self.scan_rx = Some(rx);
        tokio::spawn(async move {
            let res = async {
                t.resolve()?;
                target::fingerprint(&mut t)?;
                Ok::<Target, String>(t)
            }
            .await;
            let _ = tx.send(ScanOutcome { target: res }).await;
        });
    }

    pub fn poll_scan(&mut self) {
        let Some(rx) = self.scan_rx.as_mut() else {
            return;
        };
        let Some(out) = rx.try_recv().ok() else {
            return;
        };
        self.scan_rx = None;
        match out.target {
            Ok(t) => {
                let ips = t
                    .ips
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                self.note(format!(
                    "target {} -> {} | service: {} | port {}",
                    t.input,
                    ips,
                    t.service.label(),
                    t.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
                ));
                let plan = vectors::plan_for(t.service, t.port, self.raw_ok);
                self.selected = [false; ALL.len()];
                for v in &plan {
                    self.selected[v.index()] = true;
                }
                self.message = format!(
                    "{} vectors auto-selected - Enter to start, Space to toggle",
                    plan.len()
                );
                self.target = Some(t);
                self.phase = Phase::Ready;
            }
            Err(e) => {
                self.note(format!("scan failed: {e}"));
                self.message = e;
                self.phase = Phase::Input;
            }
        }
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
            self.iface.as_ref().and_then(|i| RawSock::open(i).ok()).map(Arc::new)
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
            budgets: ALL
                .iter()
                .map(|s| Arc::new(attack::Budget::new(attack::raw_rate(s.vector))))
                .collect(),
        });

        self.note(format!(
            "attacking {ip}:{port} with {} vectors",
            vectors.len()
        ));
        attack::launch(ctx, vectors);
        self.stats = Some(stats);
        self.started_at = Some(Instant::now());
        self.samples.clear();
        self.phase = Phase::Running;
        self.message = "running - Enter/x to stop".into();
    }

    pub fn stop_attack(&mut self) {
        if let Some(s) = &self.stats {
            s.stop();
        }
        self.phase = Phase::Stopped;
        self.message = "stopped - Enter to restart, Esc to edit target".into();
        self.note("attack stopped".to_string());
    }

    pub fn tick(&mut self) {
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
                } else if c.is_ascii_digit() && self.port_input.len() < 5 {
                    self.port_input.push(c);
                }
            }
            KeyCode::Backspace => {
                if self.focus == 0 {
                    self.target_input.pop();
                } else {
                    self.port_input.pop();
                }
            }
            KeyCode::Tab => self.focus = 1 - self.focus,
            KeyCode::Enter => self.start_scan(),
            KeyCode::Esc => {
                if self.target_input.is_empty() && self.port_input.is_empty() {
                    self.quit = true;
                } else {
                    self.target_input.clear();
                    self.port_input.clear();
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
            }
            KeyCode::Char('n') => self.selected = [false; ALL.len()],
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
