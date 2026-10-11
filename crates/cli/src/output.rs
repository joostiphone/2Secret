//! Terminal output helpers.

use serde::Serialize;

pub fn print_json<T: Serialize + ?Sized>(value: &T) {
    println!("{}", serde_json::to_string_pretty(value).expect("serializable"));
}

fn width(s: &str) -> usize {
    s.chars().count()
}

fn truncate(s: &str, max: usize) -> String {
    if width(s) <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Print an aligned table.
pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    let max_col = 48;
    let mut widths: Vec<usize> = headers.iter().map(|h| width(h)).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(width(cell).min(max_col));
            }
        }
    }
    let line = |cells: Vec<String>| {
        let parts: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let c = truncate(c, max_col);
                let pad = widths[i].saturating_sub(width(&c));
                format!("{c}{}", " ".repeat(pad))
            })
            .collect();
        println!("{}", parts.join("  ").trim_end());
    };
    line(headers.iter().map(|h| h.to_uppercase()).collect());
    for row in rows {
        line(row.clone());
    }
}

pub fn mask(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        "••••••••".into()
    }
}
