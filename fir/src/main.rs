use anyhow::Error;
use aya::programs::perf_attach::PerfLinkId;
use aya::programs::perf_event::PerfEventLinkId;
use aya::programs::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy};
use aya::maps::{HashMap, MapData, RingBuf};
use aya::util::online_cpus;
use clap::{Parser};
use fir_common::{PERF_EVENT_VARIANTS, PerfEventType, PerfSample};
//#[rustfmt::skip]
use log::{debug, warn};
use tokio::io::unix::AsyncFd;
use std::sync::mpsc;
use std::ffi::CStr;

#[derive(Debug, Parser)]
#[command(name = "fir", version = "0.1.0", about = "an efficient system profiler using ebpf", long_about = None, arg_required_else_help = true)]
struct Opt {
    //this way of taking in cli args is lowkey sketchy but idk i might change it later
    // just have to remind the user to enter everything IN order
    #[arg(short, long, default_value_t = false)]
    gui: bool,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[arg(short, long, value_name = "PATH")]
    logfile: Option<String>,

    #[arg(short, long, required = true, value_name = "EVENTS", help = "list of perf events to profile")]
    events: Vec<String>,

    #[arg(short = 'x', long, value_parser = parse_filter, help = "define events to ignore from certain processes: pid:event1,event2,event3\nor just the pid to drop everything from that process")]
    filter_exclude: Vec<(u32, [PerfEventType; PERF_EVENT_VARIANTS])>,
}

// im pretty sure clap automaticlly handles the vec<> part and we
// only have to worry about handling one str at a time
fn parse_filter(filter: &str) -> anyhow::Result<(u32, [PerfEventType; PERF_EVENT_VARIANTS])> {
    if let Some(colon_index) = filter.find(":") {
        let mut events = [PerfEventType::None; PERF_EVENT_VARIANTS];
        let mut events_index = 0;

        let mut to_process = &filter[colon_index + 1..];

        while let Some(comma_index) = to_process.find(",") {
            if events_index >= PERF_EVENT_VARIANTS { return Err(anyhow::Error::msg("too many perf events specified yo")); }
            
            events[events_index] = PerfEventType::from_str(&to_process[..comma_index].to_string()).unwrap();

            if comma_index != events.len() {
                to_process = &to_process[comma_index + 1..];
            }
            else { to_process = ""; }

            events_index += 1;
        }

        if to_process != "" && events_index >= PERF_EVENT_VARIANTS {
            return Err(anyhow::Error::msg("too many perf events mr white!!!"));
        }
        events[events_index] = PerfEventType::from_str(&to_process.to_string()).unwrap();

        let key = match filter[..colon_index].parse::<u32>() {
            Ok(thing) => thing,
            Err(e) => return Err(anyhow::Error::msg("yo!!! mr white!! can't parse this u32 yo!!!")),
        };

        Ok((key, events))
    }
    else { Ok((filter.parse()?, [PerfEventType::Any; PERF_EVENT_VARIANTS])) }
}


// example:
// fir -gvl fir.log -e cache_miss,branch_miss,context_switch,fs_event,random_thing -x node[fs_event] -x docker[fs_event]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // include ebpf program at compile time, load at runtime
    let mut ebpf: aya::Ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fir"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    // i cant believe this actually works
    // forgive me
    for event_arg in opt.events {
        if let Some(event) = PerfEventType::ebpf_from_str(&event_arg) {
            let perf_event: &mut PerfEvent = ebpf.program_mut(&event).unwrap().try_into()?;
            let perf_event_enum = PerfEventType::from_str(&event_arg)?;
            
            load_attach_event(perf_event, perf_event_enum)?;
        }
        else if PerfEventType::from_str(&event_arg)? == PerfEventType::Any {
            println!("using all perf events\n");

            for (name, program) in ebpf.programs_mut() {
                let perf_event: &mut PerfEvent = program.try_into()?;
                let perf_event_enum = PerfEventType::from_str(&name[6..].to_string())?;
                
                load_attach_event(perf_event, perf_event_enum)?;
            }
            break;
        }
    }

    // maps
    // some of ts prob looks unnecessary rn, such as declaring stuff outside the
    // thread just to clone it and use it only in that thread (for now) but i promise theres a method here
    let perf_event_buf = RingBuf::try_from(ebpf.take_map("PERF_EVENTS").unwrap()).unwrap();
    let mut asyncfd_perf_buf = AsyncFd::new(perf_event_buf)?;
    let (perf_tx, perf_rx) = mpsc::channel::<PerfSample>();

    let mut filter_exclude_map: HashMap<_, u32, [u8; PERF_EVENT_VARIANTS]> = HashMap::try_from(ebpf.take_map("FILTER_PIDS").unwrap()).unwrap();

    for (key, value) in opt.filter_exclude {
        let mut value_parsed: [u8; PERF_EVENT_VARIANTS] = [0u8; PERF_EVENT_VARIANTS];

        for i in 0..2 {
            value_parsed[i] = value[i].into();
        }

        filter_exclude_map.insert(key, value_parsed, 0)?;
    }

    // poll and read the maps (non-blockingly :D)
    tokio::spawn(async move {
        loop {
            for i in ringbuf_read(&mut asyncfd_perf_buf).await.unwrap() {
                perf_tx.send(i).unwrap();
            }
        }
    });

    loop {
        let recv = &perf_rx.recv()?;

        let command_str = CStr::from_bytes_until_nul(&recv.cmd)
            .expect("CStr::from_bytes_until_nul failed")
            .to_string_lossy()
            .into_owned();

        let event_type = &recv.event_type.ebpf_from_self().unwrap();
        
        println!("{command_str}\n{event_type}\n");
    }

}

async fn ringbuf_read<T: Copy>(fd: &mut AsyncFd<RingBuf<MapData>>) -> Result<Vec<T>, Error> {
    let mut readguard = fd.readable_mut().await.unwrap();
    let mut items: Vec<T> = Vec::new();

    let count_processed = readguard.try_io(|inner|{
        let mut count: usize = 0;

        while let Some(event) = inner.get_mut().next() {
            // reserve/submit api guarantees an unmangled struct
            // but .next() still returns [u8] so we need to unsafe pointer cast

            let event_struct = unsafe {
                let ptr = event.as_ptr() as *const T;

                *ptr
            };

            items.push(event_struct);
            count += 1;
        }

        Ok(count)
    }).unwrap().unwrap();

        println!("ringbuf processed {} items", count_processed);

        readguard.clear_ready();
        Ok(items)
}

fn load_attach_event(perf_event: &mut PerfEvent, perf_event_enum: PerfEventType) -> anyhow::Result<Vec<PerfEventLinkId>> {
    let perf_event_category = perf_event_enum.perf_event_category()?;
    let perf_id: u64;

    match perf_event_category {
        PerfTypeId::Hardware => perf_id = perf_event_enum.perf_hw_id()? as u64,
        PerfTypeId::Software => perf_id = perf_event_enum.perf_sw_id()? as u64,
        _ => panic!("please fix this!!! add a handler for perf event types other\nthan hardware and software!!!!!\n\nif you're seeing this in prod i give you full permission to slap me in the face next time you see me"),
    }

    perf_event.load()?;

    let mut links: Vec<PerfEventLinkId> = Vec::new();

    for cpu in online_cpus().map_err(|(_, error)| error)? {
            match perf_event.attach(
                perf_event_category.clone(),
                perf_id,
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Period(1000000),
                true,
            ) {
                Ok(link_id) => links.push(link_id),
                Err(e) => {
                    println!("system does not support perf event {}", perf_event_enum.ebpf_from_self().unwrap_or(String::from("could not get the string version of this event i guess, weird...")));
                    break;
                },
            };
    }

    Ok(links)
}
