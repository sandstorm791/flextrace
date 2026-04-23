use std::io;

use clap::Parser;
use crossterm::{event::{DisableMouseCapture, EnableMouseCapture}, execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode}};
use flextrace::{SaveData, save_traces};
use flextrace_common::{PERF_EVENT_VARIANTS, PerfEventType};
//#[rustfmt::skip]
use log::{LevelFilter, info};

mod perf;
mod tui;

use perf::*;
use ratatui::{Terminal, prelude::CrosstermBackend};

use crate::tui::{State, run_app};
//use ratatui::{DefaultTerminal, crossterm::event};

#[derive(Debug, Parser, Clone)]
#[command(name = "flextrace", version = "0.1.0", about = "an efficient system profiler using ebpf", long_about = None, arg_required_else_help = false)]
struct Opt {
    //this way of taking in cli args is lowkey sketchy but idk i might change it later
    // just have to remind the user to enter everything IN order

    #[arg(short, long, default_value_t = false)]
    tui: bool,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[arg(short = 'V', long, default_value_t = false)]
    super_verbose: bool,

    #[arg(short, long, value_name = "PATH", help = "path to output profiling data after completing execution")]
    out: Option<String>,

    #[arg(short, long, value_parser = parse_events, help = "list of perf events to profile with optional period, event:period", default_value = "all")]
    events: Vec<(String, u64)>,

    #[arg(short = 'x', long, value_parser = parse_filter, help = "define events to ignore from certain processes: pid:event1,event2,event3\nor just the pid to drop everything from that process", default_value = "noarg")]
    filter_exclude: Vec<(u32, u32)>,

    #[arg(short = 'f', long, help = "specify processes to return stack traces from upon perf event hit based on frame pointers (program MUST be compiled without frame pointer omission)")]
    stack_trace_fp: Vec<u32>,

    #[arg(long, help = "list perf events supported by flextrace (remove the event_ when using as an argument)", default_value_t = false)]
    list: bool,
}

// im pretty sure clap automaticlly handles the vec<> part and we
// only have to worry about handling one str at a time
fn parse_filter(filter: &str) -> anyhow::Result<(u32, u32)> {
    if filter == "noarg" {
        return Ok((0, 0u32));
    }

    if let Some(colon_index) = filter.find(":") {
        let mut events_mask: u32 = 0;
        let mut events_index = 0;

        let mut to_process = &filter[colon_index + 1..];

        while let Some(comma_index) = to_process.find(",") {
            if events_index >= PERF_EVENT_VARIANTS { return Err(anyhow::Error::msg("too many perf events specified yo")); }
            
            events_mask |= 1 << PerfEventType::from_str(&to_process[..comma_index].to_string()).unwrap() as u8;

            if comma_index != to_process.len() {
                to_process = &to_process[comma_index + 1..];
            }
            else { to_process = ""; }

            events_index += 1;
        }

        if to_process != "" && events_index >= PERF_EVENT_VARIANTS {
            return Err(anyhow::Error::msg("too many perf events mr white!!!"));
        }
        events_mask |= 1 << PerfEventType::from_str(&to_process.to_string()).unwrap() as u8;

        let key = match filter[..colon_index].parse::<u32>() {
            Ok(thing) => thing,
            Err(_e) => return Err(anyhow::Error::msg("yo!!! mr white!! can't parse this u32 yo!!!")),
        };

        Ok((key, events_mask))
    }
    else { Ok((filter.parse()?, u32::MAX as u32)) }
}

fn parse_events(filter: &str) -> anyhow::Result<(String, u64)> {
    if filter == "all" {
        return Ok(("all".to_string(), 0u64))
    }

    let event: (String, u64);
    if let Some(colon_index) = filter.find(":") {
        event = (filter[0..colon_index].to_string(), filter[colon_index + 1..].parse()?);
    }
    else { event = (filter.to_string(), 0u64); }

    Ok(event)
}

// example:
// fir -gvl fir.log -e cache_miss,branch_miss,context_switch,fs_event,random_thing -x node[fs_event] -x docker[fs_event]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let loglevel: LevelFilter;

    if opt.super_verbose { loglevel = LevelFilter::Trace; }
    else if opt.verbose { loglevel = LevelFilter::Debug; }
    else { loglevel = LevelFilter::Info; }

    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        .filter_level(loglevel)
        .init();
    
    // (no need to bump the memlock rlimit cause we don't even support kernels that old)
    //include ebpf program at compile time, load at runtime

    let mut perf_manager = PerfManager::new()?;

    if opt.list {
        for name in &perf_manager.event_list {
            info!("{name}");
        }
        return Ok(())
    }

    // apply perf configuration to PERF_CONFIG map
    if (opt.filter_exclude.get(0).unwrap() != &(0, 0)) || (opt.stack_trace_fp.get(0) != None) {
        perf_manager.update_perf_config(&opt.filter_exclude, &opt.stack_trace_fp)?;
    }

    let mut nextid: u64 = 0;
    let mut event_list: Vec<PerfEventType> = Vec::new();

    event_list.push(PerfEventType::None);

    // load and attach perf events
    for event_arg in &opt.events {
        let period_arg: Option<u64>;
            match event_arg.1 {
                0 => period_arg = None,
                _ => period_arg = Some(event_arg.1),
            }

        if !(PerfEventType::from_str(&event_arg.0)? == PerfEventType::Any) {
            let perf_event_enum = PerfEventType::from_str(&event_arg.0)?;
            perf_manager.attach_event(perf_event_enum, None, period_arg, nextid)?;
            event_list.push(perf_event_enum);
        }
        else {
            info!("using all perf events\n");
            event_list = Vec::new();
            event_list.push(PerfEventType::None);

            let event_names = perf_manager.event_list.clone();

            for name in event_names {
                let perf_event_enum = PerfEventType::from_str(&name[6..].to_string())?;
                perf_manager.attach_event(perf_event_enum, None, period_arg, nextid)?;
                event_list.push(perf_event_enum);
                nextid += 1;
            }
            break;
        }
        nextid += 1;
    }

    enable_raw_mode()?;
    let mut stderr = io::stderr();
    execute!(stderr, EnterAlternateScreen, EnableMouseCapture)?;
    
    let backend = CrosstermBackend::new(stderr);
    let mut terminal = Terminal::new(backend)?;

    let mut app: State = State::new(perf_manager, opt.clone(), event_list);

    run_app(&mut terminal, &mut app).await?;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Some(path) = opt.out {
        let save_data = SaveData {tree: app.tree, data: app.profile_data};
        save_traces(path, save_data)?;
    }

    Ok(())
}
