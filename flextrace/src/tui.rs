use std::{collections::HashMap, time::Duration};

use crossterm::event::{Event, EventStream, KeyCode};
use flextrace_common::{FlextraceError, PerfEventType};
use futures::StreamExt;
use flextrace::{Node, ProfileData, Tree};
use log::{debug, trace};
use ratatui::{Frame, Terminal, layout::{Constraint, Direction, Layout}, prelude::Backend, style::{Style, Styled, Stylize}, text::{Line, Span, Text}, widgets::{Block, Borders, Paragraph}};
use crate::{Opt, perf::PerfManager};

const FRAMES_PER_SECOND: f32 = 60.0;

pub enum Screen {
    Main,
    Exiting,
    NewEvent,
    Events,
}

pub struct State {
    pub nextid: u64,
    pub perf_manager: PerfManager,
    pub tree: Tree,
    pub profile_data: HashMap<u32, ProfileData>,
    pub screen: Screen,
    pub quitting: bool,
    pub selected_event_index: usize,
    pub available_events: Vec<PerfEventType>,
    pub opt: Opt,

    // new event screen
    pub selected_input: usize,
    pub new_event_index: usize,
    pub new_event_pid: String,
    pub new_event_period: String,

    pub attached_events: Vec<(u64, String)>,
    pub attached_events_scroller: usize,
    pub events_killer_prompt: bool,
    pub killid: String,
}

impl State {
    pub fn new(pm: PerfManager, options: Opt, event_list: Vec<PerfEventType>, attached_events: Vec<(u64, String)>, nxtid: u64) -> Self {
        let tree = Tree {
            nodes: vec![Node { counters: HashMap::new(), name: "root".to_string(), children: HashMap::new(), hits: 0, parent: 0 }],
            focused_event: PerfEventType::None,
            focused_node: 0, selected_node: 0,
            focused_children_sorted_cache: Vec::new(),
            display_head_node: 0,
        };

        State {
            nextid: nxtid,
            perf_manager: pm,
            tree: tree,
            profile_data: HashMap::new(),
            screen: Screen::Main,
            quitting: false,
            selected_event_index: 0,
            available_events: event_list,
            opt: options,

            selected_input: 0,
            new_event_index: 0,
            new_event_period: String::new(),
            new_event_pid: String::new(),

            attached_events: attached_events,
            attached_events_scroller: 0,
            events_killer_prompt: false,
            killid: String::new(),
        }
    }
    pub fn handle_event(&mut self, event: &Event) -> anyhow::Result<()>{
        if let Some(key) = event.as_key_press_event() {
            match &self.screen {
                Screen::Main => {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.screen = Screen::Exiting;
                        }
                        KeyCode::Down => {
                            if self.tree.selected_node + 1 < self.tree.focused_children_sorted_cache.len() {
                                self.tree.selected_node += 1;
                            }
                        }
                        KeyCode::Up => {
                            if self.tree.selected_node > 0 {
                                self.tree.selected_node -= 1;
                            }
                        }
                        KeyCode::Right => {
                            if self.tree.focused_children_sorted_cache.len() == 0 {return Ok(())}
                            if self.tree.nodes[self.tree.focused_children_sorted_cache[self.tree.selected_node].2].children.len() == 0 {return Ok(())}
                            self.tree.focused_node = self.tree.focused_children_sorted_cache[self.tree.selected_node].2;
                            self.tree.selected_node = 0;
                            self.tree.display_head_node = 0;
                            self.tree.update_sorted_cache();
                        }
                        KeyCode::Left => {
                            let old_node = self.tree.focused_node;
                            self.tree.focused_node = self.tree.nodes[self.tree.focused_node].parent;
                            self.tree.update_sorted_cache();
                            self.tree.display_head_node = 0;

                            // this is gonna make ts slow ill look into making it faster later, i have an idea but it uses a bit more ram
                            self.tree.selected_node = 0;
                            for i in 0..self.tree.focused_children_sorted_cache.len() - 1 {
                                if self.tree.focused_children_sorted_cache[i].2 == old_node {
                                    self.tree.selected_node = i;
                                    self.tree.display_head_node = i;
                                    break;
                                }
                            }
                        }
                        KeyCode::PageDown => {
                            if self.tree.display_head_node < self.tree.focused_children_sorted_cache.len() - 1 {
                                self.tree.display_head_node += 1;
                            }
                        }
                        KeyCode::PageUp => {
                            if self.tree.display_head_node > 0 {
                                self.tree.display_head_node -= 1;
                            }
                        }
                        KeyCode::Char('z') => {
                            if self.selected_event_index > 0 {
                                self.selected_event_index -= 1;
                                self.tree.focused_event = self.available_events[self.selected_event_index];
                                self.tree.update_sorted_cache();
                            }
                        }
                        KeyCode::Char('x') => {
                            if self.selected_event_index < self.available_events.len() - 1 {
                                self.selected_event_index += 1;
                                self.tree.focused_event = self.available_events[self.selected_event_index];
                                self.tree.update_sorted_cache();
                            }
                        }
                        KeyCode::Char('i') => {
                            self.screen = Screen::NewEvent;
                        }
                        KeyCode::Char('k') => { self.screen = Screen::Events; }
                        _ => (),
                    }
                }
                Screen::Exiting => {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.quitting = true;
                        }
                        KeyCode::Esc => {
                            self.screen = Screen::Main;
                        }
                        _ => {
                            self.screen = Screen::Main;
                        }
                    }
                }
                Screen::NewEvent => {
                    match key.code {
                        KeyCode::Esc => {
                            self.new_event_index = 0;
                            self.new_event_period = String::from("");
                            self.new_event_pid = String::from("");
                            self.selected_input = 0;

                            self.screen = Screen::Main;
                        }
                        KeyCode::Up => {
                            if self.selected_input > 0 {
                                self.selected_input -= 1;
                            }
                        }
                        KeyCode::Down => {
                            if self.selected_input < 2 {
                                self.selected_input += 1;
                            }
                        }
                        KeyCode::Char(c) => {
                            if c == 'q' {
                                self.new_event_index = 0;
                                self.new_event_period = String::from("");
                                self.new_event_pid = String::from("");

                                self.screen = Screen::Main;
                                return Ok(());
                            }

                            if c.is_numeric() {
                                match self.selected_input {
                                    0 => self.new_event_pid.push(c),
                                    1 => self.new_event_period.push(c),
                                    _ => (),
                                }
                            }
                            if c == 'x' {
                                if self.selected_event_index < self.perf_manager.event_list.len() - 1 { self.selected_event_index += 1; }
                            }
                            if c == 'z' {
                                if self.selected_event_index > 0 { self.selected_event_index -= 1; }
                            }
                        }
                        KeyCode::Backspace => {
                            match self.selected_input {
                                0 => { self.new_event_pid.pop(); },
                                1 => { self.new_event_period.pop(); },
                                _ => (),
                            }
                        }
                        KeyCode::Enter => {
                            if self.selected_input == 2 {
                                // attach the new perf event
                                let pid: Option<u32> = if let Ok(pid) = self.new_event_pid.parse::<u32>() { Some(pid) } else { None };
                                let period: Option<u64> = if let Ok(period) = self.new_event_period.parse::<u32>() { Some(period as u64) } else { None };

                                let perf_event_enum = PerfEventType::from_str(&self.perf_manager.event_list[self.new_event_index][6..].to_string())?;

                                self.perf_manager.attach_event(perf_event_enum, pid, period, self.nextid)?;
                                
                                self.attached_events.push((self.nextid, String::from("event type: ".to_owned() + &perf_event_enum.ebpf_from_self().unwrap() + " pid: all " + " period: " + &period.unwrap_or(100000).to_string())));

                                self.nextid += 1;
                                self.new_event_index = 0;
                                self.new_event_period = String::from("");
                                self.new_event_pid = String::from("");

                                let mut exists = false;

                                for event in &self.available_events {
                                    if *event == perf_event_enum { exists = true; }
                                }

                                if exists == false { self.available_events.push(perf_event_enum) }

                                self.screen = Screen::Main;
                            }
                        }
                        _ => (),
                    }
                }
                Screen::Events => {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => {
                            if self.events_killer_prompt {
                                self.killid = String::new();
                                self.events_killer_prompt = false;
                            }
                            else {
                                self.attached_events_scroller = 0;
                                self.screen = Screen::Main;
                            }
                        }
                        KeyCode::PageDown => {
                            if self.attached_events_scroller < self.attached_events.len() - 1 { self.attached_events_scroller += 1; }
                        }
                        KeyCode::PageUp => {
                            if self.attached_events_scroller > 0 { self.attached_events_scroller -= 1; }
                        }
                        KeyCode::Char('i') => {
                            self.attached_events_scroller = 0;
                            self.screen = Screen::NewEvent;
                        }
                        KeyCode::Char('d') => {
                            if self.events_killer_prompt {
                                if let Ok(id) = self.killid.parse::<u64>() {
                                    self.perf_manager.detach_event(id);

                                    for i in 0..self.attached_events.len() {
                                        if self.attached_events[i].0 == id {
                                            self.attached_events.remove(i);
                                            break;
                                        }
                                    }
                                }
                                self.events_killer_prompt = false;
                                self.killid = String::new();
                            }
                            else { self.events_killer_prompt = true; }
                        }
                        KeyCode::Char(c) => {
                            if c.is_numeric() && self.events_killer_prompt == true { self.killid.push(c) }
                        }
                        KeyCode::Backspace => {
                            self.killid.pop();
                        }
                        _ => (),
                    }
                }
            }
        }
        Ok(())
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
            Some(Ok(event)) = events.next() => app.handle_event(&event)?,
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
            let layout_chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(2), Constraint::Fill(1), Constraint::Length(2)]).split(f.area());
            let event_string = {
                if let Some(name) = app.available_events[app.selected_event_index].ebpf_from_self() {
                    name
                }
                else { "None".to_string() }
            };

            let title = Line::from(vec![
                Span::raw("  focused function: ".to_owned() + &app.tree.nodes[app.tree.focused_node].name),
                Span::raw("  # children: ".to_owned() + &app.tree.nodes[app.tree.focused_node].children.len().to_string()),
                Span::raw("  focused event: ".to_string() + &event_string),
                Span::raw("  selected: ".to_owned() + &app.tree.focused_children_sorted_cache[app.tree.selected_node].0)

            ]);

            let footer = Line::from(vec![
                Span::raw(" flextrace pre alpha ").red(),
                Span::raw(" stack trace tree ").blue(),
                Span::raw(" [quit: esc/q] [manage events: k] [add event: i] [scroll: pgup/pgdn] [select: up/down arrow]").light_magenta(),
            ]);

            f.render_widget(title, layout_chunks[0]);
            f.render_widget(&app.tree, layout_chunks[1]);
            f.render_widget(footer, layout_chunks[2]);
        },
        Screen::Exiting => {
            let span = Span::raw("are you sure you want to exit? (q)");
            f.render_widget(span, f.area());
        }
        Screen::Events => {
            let layout_chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Fill(1), Constraint::Length(2)]).split(f.area());

            let header = Span::raw("# events: ".to_string() + &app.attached_events.len().to_string());

            let footer = Line::from(vec![
                Span::raw(" flextrace pre alpha ").red(),
                Span::raw(" active perf events ").blue(),
                Span::raw(" [back/cancel: esc/q] [add event: i] [detach event: d (again to confirm)] [scroll: pgup/pgdn]").light_magenta(),
            ]);

            let mut lines: Vec<Line> = Vec::new();

            for event in &app.attached_events {
                lines.push(Line::from("id: [".to_owned() + &event.0.to_string() + "] " + &event.1));
            }

            let scrolled = lines[app.attached_events_scroller..].to_vec();

            let list = Text::from(scrolled);

            if app.events_killer_prompt {
                f.render_widget(Span::raw("detach event: ".to_owned() + &app.killid).red(), layout_chunks[1]);
            }

            f.render_widget(header, layout_chunks[0]);
            f.render_widget(list, layout_chunks[2]);
            f.render_widget(footer, layout_chunks[3]);

        }
        Screen::NewEvent => {
            let layout_chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(2), Constraint::Fill(1), Constraint::Length(2)]).split(f.area());

            let footer = Line::from(vec![
                Span::raw(" flextrace pre alpha ").red(),
                Span::raw( " attach new event ").blue(),
                Span::raw(" [back/cancel: esc/q] [select feild: up/down arrow] [confirm attach: enter]").light_magenta(),
            ]);

            let mut lines: Vec<Line> = vec![
                Line::from("event type: ".to_string() + &app.perf_manager.event_list[app.selected_event_index]),
                Line::from("pid (default all): ".to_string() + &app.new_event_pid),
                Line::from("event period: ".to_string() + &app.new_event_period),
                Line::from("[attach event]").light_blue().bold()
            ];

            lines[app.selected_input + 1] = lines[app.selected_input + 1].clone().green();

            let text = Text::from(lines);

            f.render_widget(text, layout_chunks[1]);
            f.render_widget(footer, layout_chunks[2]);
        }
    }
}
