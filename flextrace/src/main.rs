use std::{sync::{Arc, Mutex}, time::Duration};

use aya::{maps::stack, programs::{PerfEvent, Program}};
use clap::Parser;
use flextrace_common::{PERF_EVENT_VARIANTS, PerfEventType};
//#[rustfmt::skip]
use log::{debug, info, warn};

mod perf;
use perf::*;

use flextrace::*;

#[derive(Debug, Parser)]
#[command(name = "flextrace", version = "0.1.0", about = "an efficient system profiler using ebpf", long_about = None, arg_required_else_help = false)]
struct Opt {
    //this way of taking in cli args is lowkey sketchy but idk i might change it later
    // just have to remind the user to enter everything IN order

    #[arg(short, long, default_value_t = false)]
    gui: bool,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[arg(short, long, value_name = "PATH", help = "path to output profiling data after completing execution")]
    out: Option<String>,

    #[arg(short, long, value_name = "EVENTS", help = "list of perf events to profile", default_values_t = ["all".to_string()])]
    events: Vec<String>,

    #[arg(short = 'x', long, value_parser = parse_filter, help = "define events to ignore from certain processes: pid:event1,event2,event3\nor just the pid to drop everything from that process", default_value = "noarg")]
    filter_exclude: Vec<(u32, u32)>,

    #[arg(short = 'f', long, help = "list processes to return stack traces from upon perf event hit based on frame pointers (program MUST be compiled without frame pointer omission)")]
    stack_trace_fp: Vec<u32>,

    #[arg(long, alias = "list", help = "list perf events supported by flextrace (remove the event_ when using as an argument)", default_value_t = false)]
    list_events: bool,
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


// example:
// fir -gvl fir.log -e cache_miss,branch_miss,context_switch,fs_event,random_thing -x node[fs_event] -x docker[fs_event]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();
    
    // (no need to bump the memlock rlimit cause we don't even support kernels that old)
    //include ebpf program at compile time, load at runtime

    let mut perf_manager = PerfManager::new()?;

    if opt.list_events {
        for name in perf_manager.list_events() {
            info!("{name}");
            return Ok(())
        }
    }

    // apply perf configuration to PERF_CONFIG map
    if (opt.filter_exclude.get(0).unwrap() != &(0, 0)) || (opt.stack_trace_fp.get(0) != None) {
        perf_manager.update_perf_config(opt.filter_exclude, opt.stack_trace_fp)?;
    }


    let mut nextid: u64 = 0;

    // load and attach perf events
    for event_arg in opt.events {
        if !(PerfEventType::from_str(&event_arg)? == PerfEventType::Any) {
            let perf_event_enum = PerfEventType::from_str(&event_arg)?;
            perf_manager.attach_event(perf_event_enum, None, None, nextid)?;
        }
        else {
            info!("using all perf events\n");

            for name in perf_manager.list_events(){
                let perf_event_enum = PerfEventType::from_str(&name[6..].to_string())?;
                perf_manager.attach_event(perf_event_enum, None, None, nextid)?;
                nextid += 1;
            }
            break;
        }
        nextid += 1;
    }

    let mut profile_data: StdHashMap<u32, ProfileData> = StdHashMap::new(); 
    let mut stack_tree = TreeNode { counters: StdHashMap::new(), name: String::from("root"), children: Vec::new() };

    loop {
        if let Some(recv) = &perf_manager.event_rx.recv().await {

            if let Some(stackid) = recv.stack_id {
                if stackid < 0 {
                    debug!("bpf_get_stackid() returned {stackid}, dropping stack trace");
                }
                else {
                    let trace = perf_manager.get_stack_fp(stackid)?;
                    debug!("generated stack trace from stackid {stackid}");

                    stack_tree.update(perf_manager.symbolize_fp_trace(trace, recv.pid)?, recv.event_type);
                }
            }

            let event_type = recv.event_type;
            let pid = recv.pid;
            let recv_gid = recv.gid;

            let profile_data = profile_data.entry(pid).or_insert_with(||
                ProfileData {
                    events: StdHashMap::new(),
                    name: String::from_utf8_lossy(&recv.cmd).to_string(),
                    gid: 0,
                }
            );
            
            // increment the counter for that event
            *profile_data.events.entry(event_type).or_insert(0) += 1;
            profile_data.gid = recv_gid;
        }
    }
}
