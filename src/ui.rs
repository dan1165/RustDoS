//! Terminal rendering.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Phase};
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

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(10),
        Constraint::Length(4),
        Constraint::Length(8),
        Constraint::Length(1),
    ])
    .split(area);

    draw_header(f, rows[0], app);

    let cols = Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(rows[1]);
    draw_target(f, cols[0], app);
    draw_vectors(f, cols[1], app);

    draw_stats(f, rows[2], app);
    draw_log(f, rows[3], app);
    draw_footer(f, rows[4], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let (state, color) = match app.phase {
        Phase::Input => ("IDLE", DIM),
        Phase::Scanning => ("SCANNING", WARN),
        Phase::Ready => ("ARMED", ACCENT),
        Phase::Running => ("ATTACKING", BAD),
        Phase::Stopped => ("STOPPED", WARN),
    };
    let title = Line::from(vec![
        Span::styled("Rust", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("DoS", Style::default().fg(Color::Rgb(255, 90, 160)).add_modifier(Modifier::BOLD)),
        Span::styled("  L1-L7 stress tester", Style::default().fg(DIM)),
        Span::raw("   "),
        Span::styled(format!("[{state}]"), Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color));
    f.render_widget(Paragraph::new(title).block(block), area);
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

fn draw_target(f: &mut Frame, area: Rect, app: &App) {
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
        app.focus == 0 && matches!(app.phase, Phase::Input | Phase::Scanning),
        "example.com",
    );
    field(
        f,
        rows[1],
        "port (optional)",
        &app.port_input,
        app.focus == 1 && matches!(app.phase, Phase::Input | Phase::Scanning),
        "auto",
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
            Span::styled("port    ", Style::default().fg(DIM)),
            Span::styled(
                t.port.map(|p| p.to_string()).unwrap_or_else(|| "auto".into()),
                Style::default().fg(Color::White),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("tls     ", Style::default().fg(DIM)),
            Span::styled(
                if t.tls { "yes" } else { "no" },
                Style::default().fg(if app.is_tls() { OK } else { DIM }),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "no target scanned yet",
            Style::default().fg(DIM),
        )));
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
    let items: Vec<ListItem> = ALL
        .iter()
        .enumerate()
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
                    format!("{:<5}", spec.layer),
                    Style::default().fg(layer_color(spec.layer)),
                ),
                Span::styled(format!("{:<13}", spec.name), name_style),
                Span::styled(spec.desc, Style::default().fg(Color::Rgb(100, 108, 116))),
            ];
            if spec.needs_port {
                spans.push(Span::styled(" :port", Style::default().fg(Color::Rgb(80, 88, 96))));
            }
            if let Some(c) = &counts {
                let (_, pkts, _) = c[i];
                if pkts > 0 {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(
                        format!("{} p", human_rate(pkts as f64)),
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

    let title = format!(
        " vectors  {}/{} armed ",
        app.selected.iter().filter(|s| **s).count(),
        ALL.len()
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM))
        .title(Span::styled(title, Style::default().fg(DIM)));
    f.render_widget(List::new(items).block(block), area);
}

fn draw_stats(f: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)])
        .split(area);
    let (pkts, bytes, errs) = match &app.stats {
        Some(s) => (s.total_packets(), s.total_bytes(), s.errors()),
        None => (0, 0, 0),
    };
    let elapsed = app
        .started_at
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    let line = Line::from(vec![
        Span::styled("rate  ", Style::default().fg(DIM)),
        Span::styled(
            format!("{} pps", human_rate(app.pps)),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled("   bw  ", Style::default().fg(DIM)),
        Span::styled(
            format!("{}/s", crate::stats::human_bytes(app.bps as u64)),
            Style::default().fg(ACCENT),
        ),
        Span::styled("   sent  ", Style::default().fg(DIM)),
        Span::styled(format!("{pkts} pkts"), Style::default().fg(Color::White)),
        Span::styled("   vol  ", Style::default().fg(DIM)),
        Span::styled(crate::stats::human_bytes(bytes), Style::default().fg(Color::White)),
        Span::styled("   err  ", Style::default().fg(DIM)),
        Span::styled(format!("{errs}"), Style::default().fg(if errs > 0 { BAD } else { DIM })),
        Span::styled("   up  ", Style::default().fg(DIM)),
        Span::styled(format!("{elapsed}s"), Style::default().fg(Color::White)),
    ]);
    f.render_widget(Paragraph::new(line), rows[0]);

    // Log-scaled gauge of current packet rate.
    let ratio = if app.pps <= 0.0 {
        0.0
    } else {
        ((app.pps + 1.0).log10() / 7.0).clamp(0.0, 1.0)
    };
    let g = Gauge::default()
        .gauge_style(Style::default().fg(ACCENT).bg(Color::Rgb(28, 32, 36)))
        .ratio(ratio)
        .label(format!("{} pps", human_rate(app.pps)));
    f.render_widget(g, rows[1]);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            app.message.clone(),
            Style::default().fg(WARN),
        ))),
        rows[2],
    );
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
        Phase::Input | Phase::Scanning => "Tab switch  Enter scan  Esc clear  Ctrl-C quit",
        Phase::Ready => "Up/Down move  Space toggle  a all  n none  Enter start  Esc edit",
        Phase::Running => "Enter/x stop  q quit",
        Phase::Stopped => "Enter restart  Esc edit  q quit",
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(keys, Style::default().fg(DIM)))),
        area,
    );
}
