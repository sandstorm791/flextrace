use std::{collections::HashMap as StdHashMap, num::NonZero};

use anyhow::Result;
use aya::{Ebpf, maps::{MapData, RingBuf, StackTraceMap, stack_trace::{StackTrace}}, programs::{PerfEvent, Program, perf_event::{PerfEventLink, PerfEventScope, SamplePolicy}}, util::online_cpus};
use blazesym::{Pid, symbolize::{Input, Sym, Symbolized, Symbolizer, source::{Process, Source}}};
use aya::maps::HashMap as AyaHashMap;
use flextrace_common::{FlextraceError, PerfEventType, PerfProcessConfig, PerfSample};
use log::{debug, error, info};
use tokio::{io::unix::AsyncFd, sync::mpsc::{self, Receiver}};

pub struct PerfManager {
    ebpf: Ebpf,

    map_perf_config: AyaHashMap<MapData, u32, PerfProcessConfig>,
    map_stack_traces: StackTraceMap<MapData>,

    pub event_rx: Receiver<PerfSample>,
    symbolizer: Symbolizer,

    links: StdHashMap<u64, Vec<PerfEventLink>>,
    pub event_list: Vec<String>,
}

impl PerfManager {
    pub fn new() -> Result<Self> {
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flextrace"));

        let mut ebpf = aya::EbpfLoader::new().load(bytes)?;

        let mut prog_names: Vec<String> = Vec::new();
        /*
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/flextrace"
        )))?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        */

        // load ALL of the perf events into the kernel before we attach them so that the map fds know where to go
        for (name, program) in ebpf.programs_mut() {
            match program {
                Program::PerfEvent(p) => {
                    p.load()?;
                    debug!("loaded event {name}");
                    prog_names.push(name.to_string());
                },
                _ => continue,
            }
        }
        debug!("perf events loaded into kernel");

        // access the maps
        let config_map = { 
            let raw_map = ebpf.take_map("PERF_CONFIG").unwrap();
            AyaHashMap::try_from(raw_map).unwrap()
        };
        let event_map = {
            let raw_map = ebpf.take_map("PERF_EVENTS").unwrap();
            RingBuf::try_from(raw_map).unwrap()
        };
        let stack_traces = {
            let raw_map = ebpf.take_map("PERF_STACK_TRACES").unwrap();
            StackTraceMap::try_from(raw_map).unwrap()
        };
        debug!("maps initialized");

        let mut ringbuf_fd = AsyncFd::new(event_map)?;
        let (perf_tx, perf_rx) = mpsc::channel::<PerfSample>(100);

        tokio::spawn(async move {
            loop {
                for i in ringbuf_read::<PerfSample>(&mut ringbuf_fd).await.unwrap() {
                    if let Err(_) = perf_tx.send(i).await {
                        error!("ringbuf mpsc reciever dropped");
                        return
                    };
                }
            }
        });
        debug!("event poller started");

        Ok(Self {
            ebpf: ebpf,
            map_perf_config: config_map,
            map_stack_traces: stack_traces,
            links: StdHashMap::new(),
            event_rx: perf_rx,
            symbolizer: Symbolizer::new(),
            event_list: prog_names,
        })
    }

    pub fn attach_event(&mut self, perf_event_enum: PerfEventType, pid: Option<u32>, period: Option<u64>, id: u64) -> anyhow::Result<()> {
        let perf_config = perf_event_enum.perf_config()?;

        let perf_ebpf_name = match perf_event_enum.ebpf_from_self() {
            Some(name) => name,
            None => return Err(anyhow::Error::msg("no such valid perf event")),
        };

        let perf_event: &mut PerfEvent = self.ebpf.program_mut(&perf_ebpf_name)
            .ok_or(FlextraceError::NoSuchProgram(String::from(&perf_ebpf_name)))?
            .try_into()
            .map_err(|_| FlextraceError::Msg(String::from("failed to convert aya Program to PerfEvent? tell me about this bug")))?;

        let mut links: Vec<PerfEventLink> = Vec::new();

        let mut some_period: u64 = 100000;

        if let Some(period) = period {
            some_period = period;
        }

        let mut scope_info = String::from("all processes");

        for cpu in online_cpus().map_err(|(_, error)| error)? {
            match perf_event.attach(
                perf_config,
                match pid {
                    Some(some_pid) => {
                        scope_info = String::from("pid ") + &some_pid.to_string();
                        PerfEventScope::OneProcess { pid: some_pid, cpu: Some(cpu) }
                },
                    None => PerfEventScope::AllProcessesOneCpu { cpu },
                },
                SamplePolicy::Period(some_period),
                true,
            ) {
                Ok(link_id) => links.push(perf_event.take_link(link_id)?),
                Err(_e) => {
                    info!("system does not support perf event {}", perf_event_enum.ebpf_from_self().unwrap_or(String::from("could not get the string version of this event i guess, weird...")));
                    break;
                },
            };
        }
        debug!("attached perf event {perf_ebpf_name} with id: {id} sampling period: {some_period} scope: {scope_info}");

        self.links.insert(id, links);
        Ok(())
    }

    pub fn detach_event(&mut self, id: u64) {
        self.links.remove(&id);
        debug!("detached perf event with id {id}");
    }

    pub fn update_perf_config(&mut self, filter_exclude: &Vec<(u32, u32)>, stack_trace_fp: &Vec<u32>) -> Result<()> {
        let mut config_temp: StdHashMap<u32, PerfProcessConfig> = StdHashMap::new();

        for (key, mask) in filter_exclude {
            config_temp.insert(*key, PerfProcessConfig(*mask, false));
        }

        for key in stack_trace_fp {
            config_temp.entry(*key).and_modify(|config| config.1 = true).or_insert(PerfProcessConfig(0, true));
        }

        for (key, config) in config_temp {
            debug!("config for pid {key}: fp stack traces: {}, mask: {}", config.1, config.0);
            self.map_perf_config.insert(key, config, 0)?;
        }

        Ok(())
    }

    pub fn get_stack_fp(&mut self, id: i64) -> Result<StackTrace, aya::maps::MapError> {
        self.map_stack_traces.get(&(id as u32), 0)
    }

    pub fn symbolize_fp_trace(&mut self, trace: StackTrace, pid: u32) -> Result<Vec<String>> {
        let mut ips: Vec<u64> = Vec::new();

        for frame in trace.frames() {
            ips.push(frame.ip);
        }

        let syms = self.symbolizer.symbolize(&Source::Process(Process::new(Pid::Pid(NonZero::new(pid).unwrap()))), Input::AbsAddr(&ips))?;
        let mut trace_parsed: Vec<String> = Vec::new();

        for result in syms {
            match result {
                Symbolized::Sym(Sym {
                    name,
                    module,
                    ..
                }) => {
                    // im sorry about this
                    let namestr: String = module.unwrap().to_str().unwrap().to_string() + ":" + &name.to_string() + "(at)";
                    trace_parsed.push(namestr);
                }
                Symbolized::Unknown(..) =>  { trace_parsed.push(String::from("nosym_")) }
            }
        }

        for i in 0..trace_parsed.len() {
            trace_parsed[i].push_str(&ips[i].to_string());
        }

        Ok(trace_parsed)
    }
}

pub async fn ringbuf_read<T: Copy>(fd: &mut AsyncFd<RingBuf<MapData>>) -> Result<Vec<T>> {
    let mut readguard = fd.readable_mut().await?;
    let mut items: Vec<T> = Vec::new();

    readguard.try_io(|inner|{
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

        readguard.clear_ready();
        Ok(items)
}
