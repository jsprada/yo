//! Terminal output: small, colorful, and plain when piped or `NO_COLOR` is set.

use chrono::{Local, TimeZone};
use owo_colors::OwoColorize;
use owo_colors::Stream::{Stderr, Stdout};
use yo_store::{Direction, MessageKind, MessageRow};

pub fn accent(s: &str) -> String {
    s.if_supports_color(Stdout, |t| t.yellow()).if_supports_color(Stdout, |t| t.bold()).to_string()
}
pub fn name(s: &str) -> String {
    s.if_supports_color(Stdout, |t| t.bright_cyan()).if_supports_color(Stdout, |t| t.bold()).to_string()
}
pub fn me(s: &str) -> String {
    s.if_supports_color(Stdout, |t| t.green()).to_string()
}
pub fn dim(s: &str) -> String {
    s.if_supports_color(Stdout, |t| t.dimmed()).to_string()
}
pub fn bold(s: &str) -> String {
    s.if_supports_color(Stdout, |t| t.bold()).to_string()
}
pub fn red(s: &str) -> String {
    s.if_supports_color(Stdout, |t| t.red()).to_string()
}

pub fn ok(msg: &str) {
    println!("{} {msg}", "✔".if_supports_color(Stdout, |t| t.green()));
}
pub fn info(msg: &str) {
    println!("{} {msg}", "•".if_supports_color(Stdout, |t| t.cyan()));
}
pub fn warn(msg: &str) {
    eprintln!("{} {msg}", "⚠".if_supports_color(Stderr, |t| t.yellow()));
}
pub fn error(msg: &str) {
    eprintln!("{} {msg}", "✖".if_supports_color(Stderr, |t| t.red()));
}

pub fn banner() -> String {
    let art = [r" _   _  ___   _ ", r"| | | |/ _ \ | |", r"| |_| | (_) ||_|", r" \__, |\___/ (_)", r" |___/          "];
    art.iter().map(|l| accent(l)).collect::<Vec<_>>().join("\n")
}

/// "just now", "5m ago", "3h ago", "Mon 14:05", "Mar 3 14:05", "2023-03-03".
pub fn when(ts: u64) -> String {
    let now = yo_proto::now();
    let d = now.saturating_sub(ts);
    if d < 60 {
        return "just now".into();
    }
    if d < 3600 {
        return format!("{}m ago", d / 60);
    }
    if d < 6 * 3600 {
        return format!("{}h ago", d / 3600);
    }
    let Some(t) = Local.timestamp_opt(ts as i64, 0).single() else { return "?".into() };
    if d < 6 * 86400 {
        t.format("%a %H:%M").to_string()
    } else if d < 300 * 86400 {
        t.format("%b %-d %H:%M").to_string()
    } else {
        t.format("%Y-%m-%d").to_string()
    }
}

fn first_line(s: &str, max: usize) -> String {
    let line = s.lines().next().unwrap_or("");
    if line.chars().count() > max || s.lines().count() > 1 {
        let cut: String = line.chars().take(max).collect();
        format!("{cut}…")
    } else {
        line.to_string()
    }
}

/// A message card as shown by `yo read`.
pub fn card(row: &MessageRow, contact: &str, quote: Option<&MessageRow>, reply_hint: bool) -> String {
    let mut out = String::new();
    let num = accent(&format!("#{}", row.id));
    if row.msg.kind == MessageKind::Notice {
        out.push_str(&format!(" ┌ {num} {} · {}\n", accent("yo!"), dim(&when(row.msg.received_at))));
        for l in row.msg.body.lines() {
            out.push_str(&format!(" │ {}\n", red(l)));
        }
        out.push_str(" └\n");
        return out;
    }
    let who = match row.msg.direction {
        Direction::In => name(contact),
        Direction::Out => me(&format!("you → {contact}")),
    };
    out.push_str(&format!(" ┌ {num} {who} · {}\n", dim(&when(row.msg.sent_at))));
    if let Some(q) = quote {
        out.push_str(&format!(" │ {}\n", dim(&format!("↪ re #{}: {}", q.id, first_line(&q.msg.body, 50)))));
    }
    for l in row.msg.body.lines() {
        out.push_str(&format!(" │ {l}\n"));
    }
    if reply_hint && row.msg.direction == Direction::In {
        out.push_str(&format!(" └ {}\n", dim(&format!("↩ yo reply {} …", row.id))));
    } else {
        out.push_str(" └\n");
    }
    out
}

/// One line per message, as shown by `yo history`.
pub fn history_line(row: &MessageRow, contact: &str, quote: Option<&MessageRow>) -> String {
    let who = match row.msg.direction {
        Direction::In => name(contact),
        Direction::Out => me("you"),
    };
    let mut head = format!("{} {who} {}", accent(&format!("#{:<4}", row.id)), dim(&when(row.msg.sent_at)));
    if let Some(q) = quote {
        head.push_str(&format!(" {}", dim(&format!("↪ #{}", q.id))));
    }
    let mut out = format!(" {head}\n");
    for l in row.msg.body.lines() {
        out.push_str(&format!("       {l}\n"));
    }
    out
}

pub fn rule(title: &str) -> String {
    let width = 40usize.saturating_sub(title.chars().count() + 4);
    format!(" {} {} {}", dim("──"), bold(title), dim(&"─".repeat(width)))
}
