//! Terminal rendering, with layouts for large, medium and tiny terminals.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Phase};
use crate::bypass;
use crate::health;
use crate::stats::human_rate;
use crate::vectors::ALL;

const ACCENT: Color = Color::Rgb(0, 220, 200);
const DIM: Color = Color::Rgb(110, 120, 130);
const OK: Color = Color::Rgb(120, 230, 120);
const WARN: Color = Color::Rgb(240, 200, 90);
const BAD: Color = Color::Rgb(240, 110, 110);

fn layer_color(layer: &str) -> Color {
    match layer {
        "L1" => Color::Rgb(255, 140, 200),
        "L2" => Color::Rgb(200, 140, 255),
        "L3" => Color::Rgb(140, 180, 255),
        "L4" => Color::Rgb(120, 220, 220),
        _ => Color::Rgb(150, 240, 160),
    }
}

struct Plan {
    header: Rect,
    target: Option<Rect>,
    vectors: Rect,
    stats: Rect,
    log: Option<Rect>,
    footer: Rect,
    compact: bool,
}

fn plan(area: Rect) -> Plan {
    let (w, h) = (area.width, area.height);
    // The target fields are the most important thing on screen, so they stay
    // visible at every size; only the log, gauge and descriptions drop away.
    if h < 10 || w < 34 {
        let r = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);
        Plan {
            header: r[0],
            target: Some(r[1]),
            vectors: r[2],
            stats: r[3],
            log: None,
            footer: r[4],
            compact: true,
        }
    } else if h < 14 || w < 46 {
        let r = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(2),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .split(area);
        Plan {
            header: r[0],
            target: Some(r[1]),
            vectors: r[2],
            stats: r[3],
            log: None,
            footer: r[4],
            compact: true,
        }
    } else if h < 26 || w < 90 {
        let r = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(6),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);
        Plan {
            header: r[0],
            target: Some(r[1]),
            vectors: r[2],
            stats: r[3],
            log: None,
            footer: r[4],
            compact: true,
        }
    } else {
        let r = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(4),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .split(area);
        let c = Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)])
            .split(r[1]);
        Plan {
            header: r[0],
            target: Some(c[0]),
            vectors: c[1],
            stats: r[2],
            log: Some(r[3]),
            footer: r[4],
            compact: false,
        }
    }
}

pub fn draw(f: &mut Frame, app: &App) {
    let p = plan(f.area());
    draw_header(f, p.header, app, p.compact);
    if let Some(t) = p.target {
        draw_target(f, t, app, p.compact);
    }
    draw_vectors(f, p.vectors, app);
    draw_stats(f, p.stats, app);
    if let Some(l) = p.log {
        draw_log(f, l, app);
    }
    draw_footer(f, p.footer, app);
}

fn state_of(app: &App) -> (&'static str, Color) {
    match app.phase {
        Phase::Input => ("IDLE", DIM),
        Phase::Scanning => ("SCANNING", WARN),
        Phase::Ready => ("ARMED", ACCENT),
        Phase::Running => ("ATTACKING", BAD),
        Phase::Stopped => ("STOPPED", WARN),
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App, compact: bool) {
    let (state, color) = state_of(app);
    let mut spans = vec![
        Span::styled("Rust", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(
            "DoS",
            Style::default()
                .fg(Color::Rgb(255, 90, 160))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(format!("[{state}]"), Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ];
    if compact {
        if let Some(t) = &app.target {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                format!("{}:{}", t.host, t.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())),
                Style::default().fg(Color::White),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }
    spans.push(Span::styled("  L1-L7 stress tester", Style::default().fg(DIM)));
    if app.auto_mode {
        spans.push(Span::raw("  "));
        spans.push(Span::styled("AUTO", Style::default().fg(OK).add_modifier(Modifier::BOLD)));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color));
    f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn field(f: &mut Frame, area: Rect, label: &str, value: &str, focused: bool, hint: &str) {
    let style = if focused {
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(DIM)
    };
    let text = if value.is_empty() {
        Line::from(Span::styled(hint, Style::default().fg(Color::Rgb(80, 88, 96))))
    } else {
        Line::from(Span::styled(value, Style::default().fg(Color::White)))
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(style)
        .title(Span::styled(format!(" {label} "), style));
    f.render_widget(Paragraph::new(text).block(block), area);
}

fn draw_target(f: &mut Frame, area: Rect, app: &App, compact: bool) {
    let editing = matches!(app.phase, Phase::Input | Phase::Scanning);

    if compact {
        let show_info = area.height >= 4;
        let mut cons = vec![
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ];
        if show_info {
            cons.push(Constraint::Min(1));
        }
        let rows = Layout::vertical(cons).split(area);
        let line = |label: &str, val: &str, focus: bool, hint: &str| {
            let s = if focus {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(DIM)
            };
            let v = if val.is_empty() {
                Span::styled(hint.to_string(), Style::default().fg(Color::Rgb(80, 88, 96)))
            } else {
                Span::styled(val.to_string(), Style::default().fg(Color::White))
            };
            Line::from(vec![Span::styled(format!("{label:<7}"), s), v])
        };
        f.render_widget(
            Paragraph::new(line(
                "target",
                &app.target_input,
                editing && app.focus == 0,
                "ip / domain / url",
            )),
            rows[0],
        );
        f.render_widget(
            Paragraph::new(line(
                "port",
                &app.port_input,
                editing && app.focus == 1,
                "auto (scan all)",
            )),
            rows[1],
        );
        f.render_widget(
            Paragraph::new(line(
                "min",
                &app.minutes_input,
                editing && app.focus == 2,
                "0 = unlimited",
            )),
            rows[2],
        );
        if show_info {
            let info = if app.phase == Phase::Scanning {
                format!(
                    "scanning {}/65535, {} open",
                    app.scan_seen,
                    app.open_ports.len()
                )
            } else {
                format!("{} | {} ports", app.service_label(), app.open_ports.len())
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(info, Style::default().fg(DIM)))),
                rows[3],
            );
        }
        return;
    }

    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(6),
    ])
    .split(area);
    field(
        f,
        rows[0],
        "target (ip / domain / url)",
        &app.target_input,
        editing && app.focus == 0,
        "example.com",
    );
    let pair = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    field(
        f,
        pair[0],
        "port (optional)",
        &app.port_input,
        editing && app.focus == 1,
        "auto",
    );
    field(
        f,
        pair[1],
        "minutes (0=inf)",
        &app.minutes_input,
        editing && app.focus == 2,
        "0",
    );

    let mut lines: Vec<Line> = Vec::new();
    if let Some(t) = &app.target {
        lines.push(Line::from(vec![
            Span::styled("host    ", Style::default().fg(DIM)),
            Span::styled(t.host.clone(), Style::default().fg(Color::White)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("address ", Style::default().fg(DIM)),
            Span::styled(
                t.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
                Style::default().fg(Color::White),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("service ", Style::default().fg(DIM)),
            Span::styled(app.service_label(), Style::default().fg(WARN)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("tls     ", Style::default().fg(DIM)),
            Span::styled(
                if app.is_tls() { "yes" } else { "no" },
                Style::default().fg(if app.is_tls() { OK } else { DIM }),
            ),
        ]));
    } else if app.phase == Phase::Scanning {
        lines.push(Line::from(Span::styled(
            format!("scanning {}/65535", app.scan_seen),
            Style::default().fg(WARN),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "no target scanned yet",
            Style::default().fg(DIM),
        )));
    }
    if !app.open_ports.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("open    ", Style::default().fg(DIM)),
            Span::styled(
                app.open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                Style::default().fg(OK),
            ),
        ]));
    }
    if let Some(r) = &app.recon {
        let color = if r.cdn.is_some() { WARN } else { OK };
        lines.push(Line::from(vec![
            Span::styled("bypass  ", Style::default().fg(DIM)),
            Span::styled(bypass::summary(r), Style::default().fg(color)),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("iface   ", Style::default().fg(DIM)),
        Span::styled(
            app.iface
                .as_ref()
                .map(|i| format!("{} ({})", i.name, i.ip))
                .unwrap_or_else(|| "none".into()),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("raw     ", Style::default().fg(DIM)),
        Span::styled(
            if app.raw_ok { "available" } else { "unavailable" },
            Style::default().fg(if app.raw_ok { OK } else { BAD }),
        ),
    ]));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .title(Span::styled(" target ", Style::default().fg(DIM)));
    f.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        rows[2],
    );
}

fn draw_vectors(f: &mut Frame, area: Rect, app: &App) {
    let counts = app.stats.as_ref().map(|s| s.per_vector());
    let visible = area.height.saturating_sub(2) as usize;
    let offset = if visible > 0 && app.cursor >= visible {
        app.cursor + 1 - visible
    } else {
        0
    };

    let items: Vec<ListItem> = ALL
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible.max(1))
        .map(|(i, spec)| {
            let on = app.selected[i];
            let usable = !spec.raw || app.raw_ok;
            let mark = if on { "[x]" } else { "[ ]" };
            let mark_style = if on {
                Style::default().fg(OK).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(DIM)
            };
            let name_style = if !usable {
                Style::default().fg(Color::Rgb(90, 90, 90))
            } else if on {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(DIM)
            };
            let mut spans = vec![
                Span::styled(mark, mark_style),
                Span::raw(" "),
                Span::styled(
                    format!("{:<3}", spec.layer),
                    Style::default().fg(layer_color(spec.layer)),
                ),
                Span::styled(format!("{:<13}", spec.name), name_style),
            ];
            if spec.needs_port && area.width > 50 {
                spans.push(Span::styled(" :p ", Style::default().fg(Color::Rgb(80, 88, 96))));
            }
            if area.width > 62 {
                spans.push(Span::styled(
                    spec.desc,
                    Style::default().fg(Color::Rgb(100, 108, 116)),
                ));
            }
            if let Some(c) = &counts {
                let (_, pkts, _) = c[i];
                if pkts > 0 {
                    spans.push(Span::raw(" "));
                    spans.push(Span::styled(
                        format!("{}p", human_rate(pkts as f64)),
                        Style::default().fg(ACCENT),
                    ));
                }
            }
            let mut item = ListItem::new(Line::from(spans));
            if app.phase == Phase::Ready && i == app.cursor {
                item = item.style(Style::default().bg(Color::Rgb(30, 40, 48)));
            }
            item
        })
        .collect();

    let armed = app.selected.iter().filter(|s| **s).count();
    let title = if area.width > 40 {
        format!(" vectors  {armed}/{} ", ALL.len())
    } else {
        format!(" {armed}/{} ", ALL.len())
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .title(Span::styled(title, Style::default().fg(DIM)));
    f.render_widget(List::new(items).block(block), area);
}

fn draw_stats(f: &mut Frame, area: Rect, app: &App) {
    let (pkts, bytes, errs) = match &app.stats {
        Some(s) => (s.total_packets(), s.total_bytes(), s.errors()),
        None => (0, 0, 0),
    };
    let elapsed = app.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0);
    let mut spans = vec![
        Span::styled("rate ", Style::default().fg(DIM)),
        Span::styled(
            format!("{} pps", human_rate(app.pps)),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" bw ", Style::default().fg(DIM)),
        Span::styled(
            format!("{}/s", crate::stats::human_bytes(app.bps as u64)),
            Style::default().fg(ACCENT),
        ),
        Span::styled(" sent ", Style::default().fg(DIM)),
        Span::styled(format!("{pkts}"), Style::default().fg(Color::White)),
        Span::styled(" vol ", Style::default().fg(DIM)),
        Span::styled(crate::stats::human_bytes(bytes), Style::default().fg(Color::White)),
        Span::styled(" err ", Style::default().fg(DIM)),
        Span::styled(format!("{errs}"), Style::default().fg(if errs > 0 { BAD } else { DIM })),
        Span::styled(" up ", Style::default().fg(DIM)),
        Span::styled(format!("{elapsed}s"), Style::default().fg(Color::White)),
    ];
    if let Some(r) = app.remaining() {
        spans.push(Span::styled(" left ", Style::default().fg(DIM)));
        spans.push(Span::styled(
            format!("{}s", r),
            Style::default().fg(if r < 10 { BAD } else { WARN }),
        ));
    }
    if let Some(h) = &app.health {
        let (label, color) = match h.state() {
            health::UP => (format!("{}ms", h.avg_ms()), OK),
            health::DEGRADED => ("degraded".to_string(), WARN),
            health::DOWN => ("DOWN".to_string(), BAD),
            _ => ("-".to_string(), DIM),
        };
        spans.push(Span::styled(" health ", Style::default().fg(DIM)));
        spans.push(Span::styled(
            label,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
        if let Some(p) = h.success_pct() {
            spans.push(Span::styled(
                format!(" {:.0}%", p * 100.0),
                Style::default().fg(if p < 0.9 { BAD } else { DIM }),
            ));
        }
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);

    if area.height >= 3 {
        let ratio = if app.pps <= 0.0 {
            0.0
        } else {
            ((app.pps + 1.0).log10() / 7.0).clamp(0.0, 1.0)
        };
        let g = Gauge::default()
            .gauge_style(Style::default().fg(ACCENT).bg(Color::Rgb(28, 32, 36)))
            .ratio(ratio)
            .label(format!("{} pps", human_rate(app.pps)));
        f.render_widget(g, Rect { y: area.y + 1, height: 1, ..area });
    }
    if area.height >= 3 {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                app.message.clone(),
                Style::default().fg(WARN),
            ))),
            Rect { y: area.y + 2, height: 1, ..area },
        );
    }
}

fn draw_log(f: &mut Frame, area: Rect, app: &App) {
    let h = area.height.saturating_sub(2) as usize;
    let start = app.log.len().saturating_sub(h);
    let lines: Vec<Line> = app.log[start..]
        .iter()
        .map(|l| Line::from(Span::styled(l.clone(), Style::default().fg(DIM))))
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(60, 66, 72)))
        .title(Span::styled(" log ", Style::default().fg(DIM)));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let keys = match app.phase {
        Phase::Input | Phase::Scanning => "Tab field  Enter scan  Esc clear  ^C quit",
        Phase::Ready => "Space toggle  1-7 layer  m auto  o origin  Enter start",
        Phase::Running => "Enter/x stop  q quit",
        Phase::Stopped => "Enter restart  Esc edit  q quit",
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(keys, Style::default().fg(DIM)))),
        area,
    );
}
