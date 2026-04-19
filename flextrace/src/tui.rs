use std::{collections::HashMap, time::Duration};

use crossterm::{event::{Event, EventStream, KeyCode}, style::Stylize};
use flextrace_common::PerfEventType;
use futures::StreamExt;
use flextrace::{Node, ProfileData, Tree};
use log::{debug, trace};
use ratatui::{Frame, Terminal, layout::{Constraint, Direction, Layout}, prelude::Backend, style::Style, text::{Line, Span, Text}, widgets::{Block, Borders, Paragraph}};
use crate::{Opt, perf::PerfManager};

const FRAMES_PER_SECOND: f32 = 60.0;

pub enum Screen {
    Main,
    Exiting,
}

pub struct State {
    pub nextid: u64,
    pub perf_manager: PerfManager,
    pub tree: Tree,
    pub focused_event: PerfEventType,
    pub profile_data: HashMap<u32, ProfileData>,
    pub screen: Screen,
    pub quitting: bool,
    pub opt: Opt,
}

impl State {
    pub fn new(pm: PerfManager, options: Opt) -> Self {
        let tree = Tree { nodes: vec![Node { counters: HashMap::new(), name: "root".to_string(), children: HashMap::new(), hits: 0, parent: 0 }], focused_event: PerfEventType::None, focused_node: 0, selected_node: 0, focused_children_sorted_cache: Vec::new() };
        State {
            nextid: 0,
            perf_manager: pm,
            tree: tree,
            focused_event: PerfEventType::None,
            profile_data: HashMap::new(),
            screen: Screen::Main,
            quitting: false,
            opt: options,
        }
    }
    pub fn handle_event(&mut self, event: &Event) {
        if let Some(key) = event.as_key_press_event() {
            match &self.screen {
                Screen::Main => {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.screen = Screen::Exiting;
                            return;
                        }
                        KeyCode::Down => {
                            if self.tree.selected_node + 1 < self.tree.focused_children_sorted_cache.len() {
                                self.tree.selected_node += 1;
                            }
                            return;
                        }
                        KeyCode::Up => {
                            if self.tree.selected_node > 0 {
                                self.tree.selected_node -= 1;
                            }
                            return;
                        }
                        KeyCode::Right => {
                            if self.tree.focused_children_sorted_cache.len() == 0 {return}
                            self.tree.focused_node = self.tree.focused_children_sorted_cache[self.tree.selected_node].2;
                            self.tree.selected_node = 0;
                            self.tree.update_sorted_cache();
                            return;
                        }
                        KeyCode::Left => {
                            self.tree.focused_node = self.tree.nodes[self.tree.focused_node].parent;
                            self.tree.update_sorted_cache();

                            // in the future somehow make this the old focused node
                            self.tree.selected_node = 0;
                            return;
                        }
                        _ => (),
                    }
                }
                Screen::Exiting => {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.quitting = true;
                            return;
                        }
                        KeyCode::Esc => {
                            self.screen = Screen::Main;
                            return;
                        }
                        _ => {
                            self.screen = Screen::Main;
                            return;
                        }
                    }
                }
            }
        }
    }
}

pub async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut State) -> anyhow::Result<()> {
    let period = Duration::from_secs_f32(1.0 / FRAMES_PER_SECOND);
    let mut interval = tokio::time::interval(period);
    let mut events: EventStream = EventStream::new();

    loop {
        tokio::select! {
            Some(recv) = app.perf_manager.event_rx.recv() => {
                if let Some(stackid) = recv.stack_id {
                    if stackid < 0 {
                        debug!("bpf_get_stackid() returned {stackid}, dropping stack trace");
                    }
                    else {
                        let trace = app.perf_manager.get_stack_fp(stackid)?;
                        trace!("generated stack trace from stackid {stackid}");

                        app.tree.update(app.perf_manager.symbolize_fp_trace(trace, recv.pid)?, recv.event_type);
                        app.tree.update_sorted_cache();
                    }
                }

                let event_type = recv.event_type;
                let pid = recv.pid;
                let recv_gid = recv.gid;

                let profile_data_entry = app.profile_data.entry(pid).or_insert_with(||
                    ProfileData {
                        events: HashMap::new(),
                        name: String::from_utf8_lossy(&recv.cmd).to_string(),
                        gid: 0,
                    }
                );
                
                // increment the counter for that event
                *profile_data_entry.events.entry(event_type).or_insert(0) += 1;
                profile_data_entry.gid = recv_gid;
            },
            Some(Ok(event)) = events.next() => app.handle_event(&event),
            _ = interval.tick() => { terminal.draw(|f| render(f, app)); }
        }

        if app.quitting {
            break;
        }
    }
    return Ok(());
}

pub fn render(f: &mut Frame, app: &mut State) {
    match app.screen {
        Screen::Main => {
            let layout_chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(3), Constraint::Fill(1)]).split(f.area());
            let title = Line::from(vec![
                Span::styled("   flextrace pre alpha   ", Style::new().red()),
                Span::styled("      stack trace tree            ", Style::new().cyan()),
                Span::raw("focused function: ".to_owned() + &app.tree.nodes[app.tree.focused_node].name),
            ]);

            f.render_widget(title, layout_chunks[0]);
            f.render_widget(&app.tree, layout_chunks[1]);
        },
        // in the future make this the focused tree node ^^^^^ this is temporary and does not allow traversal of the tree
        Screen::Exiting => {
            let span = Span::raw("are you sure you want to exit? (q)");
            f.render_widget(span, f.area());
        }
    }
}
