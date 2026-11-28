//! Terminal user interface.
//!
//! Renders a keyboard-driven UI over a sanitized capture summary. Only
//! metadata is ever shown: no packet payloads, keys, or credentials.

use std::io::stdout;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Tabs,
    },
    Frame, Terminal,
};

use crate::domain::CaptureSummary;
use crate::error::Error;

/// Screens the user can navigate between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Summary,
    Frames,
    Help,
}

impl Screen {
    fn label(self) -> &'static str {
        match self {
            Screen::Summary => " Summary ",
            Screen::Frames => " Frames ",
            Screen::Help => " Help ",
        }
    }

    fn next(self) -> Self {
        match self {
            Screen::Summary => Screen::Frames,
            Screen::Frames => Screen::Help,
            Screen::Help => Screen::Summary,
        }
    }

    fn prev(self) -> Self {
        match self {
            Screen::Summary => Screen::Help,
            Screen::Frames => Screen::Summary,
            Screen::Help => Screen::Frames,
        }
    }
}

/// Application state for the TUI.
pub struct App {
    /// Parsed capture summary, if inspection succeeded.
    pub summary: Option<CaptureSummary>,
    /// Error message, if inspection failed.
    pub error: Option<String>,
    /// Currently active screen.
    pub screen: Screen,
    /// Index of the selected frame (Frames screen only).
    pub selected: usize,
    /// Whether the main loop should keep running.
    pub running: bool,
    /// Last status message shown to the user.
    pub status: Option<String>,
}

impl App {
    pub fn new(result: Result<CaptureSummary, Error>) -> Self {
        match result {
            Ok(summary) => Self {
                summary: Some(summary),
                error: None,
                screen: Screen::Summary,
                selected: 0,
                running: true,
                status: Some(
                    "Inspection complete. Press q to quit, ? for help.".to_string(),
                ),
            },
            Err(err) => Self {
                summary: None,
                error: Some(err.to_string()),
                screen: Screen::Summary,
                selected: 0,
                running: true,
                status: Some(format!("Inspection failed: {err}. Press q to quit.")),
            },
        }
    }

    pub fn frame_count(&self) -> usize {
        self.summary.as_ref().map(|s| s.frames.len()).unwrap_or(0)
    }

    pub fn select_next(&mut self) {
        let count = self.frame_count();
        if count == 0 {
            return;
        }
        self.selected = (self.selected + 1).min(count - 1);
    }

    pub fn select_previous(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }
}

/// Run the TUI over the result of an inspection.
pub fn run(result: Result<CaptureSummary, Error>) -> std::io::Result<()> {
    let mut app = App::new(result);

    let mut out = stdout();
    enable_raw_mode()?;
    execute!(
        out,
        EnterAlternateScreen,
        EnableMouseCapture,
        crossterm::cursor::Hide
    )?;

    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let result = loop {
        terminal.draw(|f| draw(f, &app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if handle_key(key, &mut app) {
                    break Ok(());
                }
            }
        }

        if !app.running {
            break Ok(());
        }
    };

    // Restore the terminal even on early exit. Writes go to the same stdout fd
    // the terminal was rendered through, so a fresh handle is sufficient.
    let mut out = stdout();
    execute!(
        out,
        DisableMouseCapture,
        LeaveAlternateScreen,
        crossterm::cursor::Show
    )?;
    disable_raw_mode()?;
    drop(terminal);

    result
}

fn handle_key(key: crossterm::event::KeyEvent, app: &mut App) -> bool {
    use KeyCode::*;

    match key.code {
        Char('q') | Char('Q') | Esc => {
            app.running = false;
            true // break the loop
        }
        Char('?') => {
            app.screen = Screen::Help;
            false
        }
        Char('1') => {
            app.screen = Screen::Summary;
            false
        }
        Char('2') => {
            app.screen = Screen::Frames;
            false
        }
        Char('3') => {
            app.screen = Screen::Help;
            false
        }
        KeyCode::Tab => {
            app.screen = app.screen.next();
            false
        }
        KeyCode::BackTab => {
            app.screen = app.screen.prev();
            false
        }
        Char('j') | Char('J') | Down => {
            app.select_next();
            false
        }
        Char('k') | Char('K') | Up => {
            app.select_previous();
            false
        }
        _ => false,
    }
}

fn draw(f: &mut Frame, app: &App) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title bar
            Constraint::Length(3), // status bar
            Constraint::Min(0),    // body
            Constraint::Length(1), // help hint
        ])
        .split(size);

    draw_title_bar(f, chunks[0], app);
    draw_status_bar(f, chunks[1], app);
    match app.screen {
        Screen::Summary => draw_summary(f, chunks[2], app),
        Screen::Frames => draw_frames(f, chunks[2], app),
        Screen::Help => draw_help_widget(f, chunks[2]),
    }
    draw_hint(f, chunks[3], app);
}

fn draw_title_bar(f: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let titles: Vec<ratatui::prelude::Line> = [
        Screen::Summary,
        Screen::Frames,
        Screen::Help,
    ]
    .iter()
    .map(|screen| {
        let (style, text) = if app.screen == *screen {
            (
                Style::default().fg(Color::Black).bg(Color::Cyan),
                screen.label().to_string(),
            )
        } else {
            (
                Style::default().fg(Color::White),
                format!(" {} ", screen.label().trim()),
            )
        };
        ratatui::prelude::Line::styled(text, style)
    })
    .collect();
    let tabs_widget = Tabs::new(titles)
        .select(app.screen as usize)
        .block(
            Block::default()
                .title(format!(" StreamCrack v{}", env!("CARGO_PKG_VERSION")))
                .borders(Borders::ALL),
        );
    f.render_widget(tabs_widget, area);
}

fn draw_status_bar(f: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let text = app.status.as_deref().unwrap_or("").to_string();
    let block = Block::default().borders(Borders::ALL).title(" Status ");
    let para = Paragraph::new(text).block(block).style(Style::default().fg(Color::Yellow));
    f.render_widget(para, area);
}

fn draw_summary(f: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let summary = match app.summary.as_ref() {
        Some(s) => s,
        None => {
            let err = app.error.as_deref().unwrap_or("unknown error");
            let block = Block::default().title(" Inspection result ").borders(Borders::ALL);
            let para = Paragraph::new(format!("Inspection failed:\n{err}"))
                .block(block)
                .alignment(Alignment::Left);
            f.render_widget(Clear, area);
            f.render_widget(para, area);
            return;
        }
    };

    let mut rows: Vec<Row> = Vec::new();
    rows.push(Row::new(vec![Cell::from("format"), Cell::from(format!("{:?}", summary.format))]));
    rows.push(Row::new(vec![
        Cell::from("packets"),
        Cell::from(summary.packet_count.to_string()),
    ]));
    rows.push(Row::new(vec![
        Cell::from("captured bytes"),
        Cell::from(summary.captured_bytes.to_string()),
    ]));
    rows.push(Row::new(vec![
        Cell::from("offered bytes"),
        Cell::from(summary.offered_bytes.to_string()),
    ]));
    rows.push(Row::new(vec![
        Cell::from("first timestamp"),
        Cell::from(
            summary
                .first_timestamp
                .map(|t| t.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
        ),
    ]));
    rows.push(Row::new(vec![
        Cell::from("last timestamp"),
        Cell::from(
            summary
                .last_timestamp
                .map(|t| t.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
        ),
    ]));
    rows.push(Row::new(vec![
        Cell::from("link types"),
        Cell::from(
            summary
                .link_types
                .iter()
                .map(|lt| crate::domain::link_type_name(*lt).to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
    ]));
    rows.push(Row::new(vec![
        Cell::from("diagnostics"),
        Cell::from(summary.diagnostics.len().to_string()),
    ]));

    let widths = [Constraint::Length(22), Constraint::Min(0)];
    let header_row = Row::new(vec![Cell::from(" Field "), Cell::from(" Value ")])
        .style(Style::default().fg(Color::Cyan));
    let table = Table::new(rows, widths)
        .header(header_row)
        .block(Block::default().title(" Capture summary ").borders(Borders::ALL))
        .column_spacing(1);

    f.render_widget(table, area);
}

fn draw_frames(f: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let summary = match app.summary.as_ref() {
        Some(s) => s,
        None => {
            let block = Block::default().title(" Frames ").borders(Borders::ALL);
            let para = Paragraph::new("No capture data available.")
                .block(block)
                .alignment(Alignment::Center);
            f.render_widget(para, area);
            return;
        }
    };

    let header = [
        " #",
        " timestamp",
        " caplen",
        " orig_len",
        " link type",
        " classification",
    ];
    let widths = [
        Constraint::Length(4),
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Min(0),
    ];

    let rows: Vec<Row> = summary
        .frames
        .iter()
        .enumerate()
        .map(|(i, frame)| {
            let selected = i == app.selected;
            let classification_label = match &frame.classification {
                crate::domain::FrameClassification::Decoded { frame } => {
                    format!("Decoded({:?})", frame.kind)
                }
                crate::domain::FrameClassification::DecoderPending { link_type } => {
                    format!("DecoderPending({link_type})")
                }
                crate::domain::FrameClassification::UnknownLinkType { link_type } => {
                    format!("Unknown({link_type})")
                }
            };
            let style = if selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(i.to_string()),
                Cell::from(frame.timestamp.to_string()),
                Cell::from(frame.caplen.to_string()),
                Cell::from(frame.orig_len.to_string()),
                Cell::from(crate::domain::link_type_name(frame.link_type).to_string()),
                Cell::from(classification_label),
            ])
            .style(style)
        })
        .collect();

    let header_row = Row::new(header.map(Cell::from))
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    let selected_label = if summary.frames.is_empty() {
        String::new()
    } else {
        format!("({}, {} selected) ", summary.frames.len(), app.selected + 1)
    };
    let table = Table::new(rows, widths)
        .header(header_row)
        .block(
            Block::default()
                .title(format!(
                    " Frames ({} total){}",
                    summary.frames.len(),
                    selected_label
                ))
                .borders(Borders::ALL),
        )
        .column_spacing(1);

    f.render_widget(table, area);
}

fn draw_help_widget(f: &mut Frame, area: ratatui::layout::Rect) {
    let lines = [
        ("q / Esc", "Quit the application"),
        ("Tab / Shift-Tab", "Switch screens (Summary, Frames, Help)"),
        ("1 / 2 / 3", "Jump to Summary / Frames / Help"),
        ("j / k / Up / Down", "Move frame selection (Frames screen)"),
        ("?", "Show this help screen"),
        ("", ""),
        ("All data shown is capture metadata only.", ""),
        ("No packet payloads, keys, or credentials are displayed.", ""),
    ];

    let items: Vec<ListItem> = lines
        .iter()
        .map(|(key, desc)| {
            let text = if key.is_empty() {
                desc.to_string()
            } else {
                format!("{:<24} {}", key, desc)
            };
            ListItem::new(text)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Help / key bindings ")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(list, area);
}

fn draw_hint(f: &mut Frame, area: ratatui::layout::Rect, _app: &App) {
    let hint = " q:quit  ?:help  Tab:screens  j/k:select frame  ";
    let block = Block::default().borders(Borders::ALL);
    let para = Paragraph::new(hint)
        .block(block)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(para, area);
}
