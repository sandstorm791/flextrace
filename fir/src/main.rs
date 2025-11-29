use anyhow::Error;
use aya::programs::{PerfEventScope, PerfTypeId, PerfEvent, SamplePolicy, perf_event::perf_hw_id::*};
use aya::maps::{MapData, RingBuf};
use aya::util::online_cpus;
use clap::{Parser};
use fir_common::{PerfSample, PerfEventType, PERF_EVENT_VARIANTS};
use libc::pid_t;
//#[rustfmt::skip]
use log::{debug, warn};
use tokio::io::{unix::AsyncFd};
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

    #[arg(short = 'x', long, help = "define events to ignore from certain processes: pid[event1,event2,event3]\nor just the pid to drop everything from that process")]
    filter_exclude: Option<Vec<String>>,
}

impl Opt {
    fn parse_filter(&self) -> anyhow::Result<()> {
        if let Some(filter) = &self.filter_exclude {
            for i in filter {
                let pid: pid_t;
                let events: [PerfEventType; PERF_EVENT_VARIANTS] = [PerfEventType::None; PERF_EVENT_VARIANTS];

                if let Some(pos) = i.find("[") {

                } else { return Err(anyhow::anyhow!("bad filter arguments, no [ found")); }
        }
        }

        Ok(())
    }
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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fir"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    // perf stuff

    //cache misses
    let perf_prog_cachemiss: &mut PerfEvent = ebpf.program_mut("cache_miss").unwrap().try_into()?;
    perf_prog_cachemiss.load()?;

    // attatching stuff
    //cache misses 

    for cpu in online_cpus().map_err(|(_, error)| error)? {
        perf_prog_cachemiss.attach(
            PerfTypeId::Hardware,
            PERF_COUNT_HW_CACHE_MISSES as u64,
            PerfEventScope::AllProcessesOneCpu { cpu },
            SamplePolicy::Period(1000000),
            true,
        )?;

        
    }
    // maps
    // some of ts prob looks unnecessary rn, such as declaring stuff outside the
    // thread just to clone it and use it only in that thread (for now) but i promise theres a method here
    let perf_event_buf = RingBuf::try_from(ebpf.take_map("PERF_EVENTS").unwrap()).unwrap();
    let mut asyncfd_perf_buf = AsyncFd::new(perf_event_buf)?;
    let (perf_tx, perf_rx) = mpsc::channel::<PerfSample>();

    // poll and read the maps (non-blockingly :D)
    tokio::spawn(async move {
        loop {
            for i in ringbuf_read(&mut asyncfd_perf_buf).await.unwrap() {
                perf_tx.send(i).unwrap();
            }
        }
    });

    loop {
        let command_str = CStr::from_bytes_until_nul(&perf_rx.recv().unwrap().cmd)
            .expect("CStr::from_bytes_until_nul failed")
            .to_string_lossy()
            .into_owned();
        
        println!("{command_str}\n");
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

        //debug
        if count_processed > 1 {
            println!("rate of ringbuf writing breifly surpassed userspace thread's ability to read");
        }

        println!("ringbuf processed {} items", count_processed);

        readguard.clear_ready();
        Ok(items)
}

