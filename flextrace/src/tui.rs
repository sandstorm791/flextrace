use std::time::Duration;

use crossterm::event::{Event, EventStream, KeyCode};
use futures::StreamExt;
use flextrace::TreeNode;
use ratatui::{Terminal, prelude::Backend};
use crate::perf::PerfManager;

const FRAMES_PER_SECOND: f32 = 60.0;

pub enum Screen {
    Main,
    Exiting,
}

pub struct State {
    nextid: u64,
    perf_manager: PerfManager,
    tree: TreeNode,
    exit: bool,
    screen: Screen,
    quitting: bool,
}

impl State {
    pub fn handle_event(&mut self, event: &Event) {
        if let Some(key) = event.as_key_press_event() {
            match &self.screen {
                Screen::Main => {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.screen = Screen::Exiting;
                            return;
                        }
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
                todo!();
            },
            Some(Ok(event)) = events.next() => app.handle_event(&event),
            _ = interval.tick() => { terminal.draw(|f| render(f, app))?; }
        }
    }
    Ok(())
}

pub fn render() {
    todo!()
}