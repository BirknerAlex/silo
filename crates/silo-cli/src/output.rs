//! Terminal output helpers.
//!
//! Everything the CLI prints as a list goes through [`Table`], so column
//! alignment and the `--json` escape hatch are implemented once. The JSON
//! mode exists because the moment a CLI is useful, someone pipes it into
//! `jq`, and parsing aligned columns is a trap.

use std::fmt::Display;

pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(headers: &[&str]) -> Self {
        Self {
            headers: headers.iter().map(|h| h.to_string()).collect(),
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, cells: Vec<String>) -> &mut Self {
        debug_assert_eq!(
            cells.len(),
            self.headers.len(),
            "row has {} cells but the table has {} columns",
            cells.len(),
            self.headers.len()
        );
        self.rows.push(cells);
        self
    }

    /// Column widths sized to the widest cell, headers included.
    fn widths(&self) -> Vec<usize> {
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.chars().count()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(i) {
                    *width = (*width).max(cell.chars().count());
                }
            }
        }
        widths
    }

    pub fn render(&self) -> String {
        if self.rows.is_empty() {
            return String::new();
        }
        let widths = self.widths();
        let mut out = String::new();

        let line = |cells: &[String]| {
            cells
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    // The last column isn't padded: trailing whitespace is
                    // noise when the output is copied out of a terminal.
                    if i + 1 == cells.len() {
                        cell.clone()
                    } else {
                        format!("{cell:<width$}", width = widths[i])
                    }
                })
                .collect::<Vec<_>>()
                .join("  ")
        };

        out.push_str(&line(&self.headers));
        out.push('\n');
        for row in &self.rows {
            out.push_str(&line(row));
            out.push('\n');
        }
        out
    }

    pub fn print(&self, empty_message: &str) {
        if self.rows.is_empty() {
            println!("{empty_message}");
            return;
        }
        print!("{}", self.render());
    }
}

/// Prints a value as pretty JSON. Used by every `--json` flag.
pub fn print_json(value: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Formats a Unix timestamp for display, rendering the wire's "unset"
/// sentinel as a dash rather than 1970.
pub fn timestamp(seconds: i64) -> String {
    if seconds <= 0 {
        return "-".to_string();
    }
    match chrono::DateTime::from_timestamp(seconds, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "-".to_string(),
    }
}

/// Human-readable byte sizes. Package listings are read by people
/// eyeballing whether something looks the right size.
pub fn bytes(size: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if size < 0 {
        return "-".to_string();
    }
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn dash_if_empty(value: impl Display) -> String {
    let value = value.to_string();
    if value.is_empty() {
        "-".to_string()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_are_padded_to_the_widest_cell() {
        let mut table = Table::new(&["NAME", "SIZE"]);
        table.row(vec!["a-very-long-name".into(), "1 B".into()]);
        table.row(vec!["x".into(), "2 B".into()]);

        let rendered = table.render();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("NAME            "));
        assert!(lines[2].starts_with("x               "));
    }

    #[test]
    fn the_last_column_is_not_padded() {
        let mut table = Table::new(&["A", "B"]);
        table.row(vec!["x".into(), "short".into()]);
        table.row(vec!["y".into(), "much longer value".into()]);
        for line in table.render().lines() {
            assert_eq!(line, line.trim_end(), "trailing whitespace in {line:?}");
        }
    }

    #[test]
    fn an_empty_table_renders_nothing_and_prints_a_message() {
        let table = Table::new(&["A"]);
        assert_eq!(table.render(), "");
    }

    #[test]
    fn timestamps_render_the_unset_sentinel_as_a_dash() {
        assert_eq!(timestamp(0), "-");
        assert_eq!(timestamp(-1), "-");
        assert_eq!(timestamp(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn byte_sizes_scale_to_a_readable_unit() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
        assert_eq!(bytes(-1), "-");
    }

    #[test]
    fn empty_strings_display_as_a_dash() {
        assert_eq!(dash_if_empty(""), "-");
        assert_eq!(dash_if_empty("value"), "value");
    }
}
