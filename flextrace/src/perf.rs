use std::{collections::HashMap as StdHashMap, sync::{Arc, Mutex}};

use anyhow::Result;
use aya::{Ebpf, maps::{MapData, RingBuf, StackTraceMap, stack_trace::StackTrace}, programs::{PerfEvent, Program, perf_event::{PerfEventLink, PerfEventScope, SamplePolicy}}, util::online_cpus};
use flextrace::{AyaHashMap, ringbuf_read};
use flextrace_common::{FlextraceError, PerfEventType, PerfProcessConfig, PerfSample};
use log::{debug, info, warn};
use tokio::{io::unix::AsyncFd, sync::mpsc::{self, Receiver}, task::JoinHandle};

pub struct PerfManager {
    ebpf: Ebpf,

    map_perf_config: AyaHashMap<MapData, u32, PerfProcessConfig>,
    map_stack_traces: StackTraceMap<MapData>,

    pub event_rx: Receiver<PerfSample>,
    event_polling_task: JoinHandle<anyhow::Result<()>>,

    links: StdHashMap<u64, Vec<PerfEventLink>>,
}

pub struct ProfileData {
    pub name: String,
    pub gid: u32,
    pub events: StdHashMap<PerfEventType, u32>,
}

impl PerfManager {
    pub fn new() -> Result<Self> {
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/flextrace"
        )))?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }

        // load ALL of the perf events into the kernel before we attach them so that the map fds know where to go
        for (name, program) in ebpf.programs_mut() {
            match program {
                Program::PerfEvent(p) => {
                    p.load()?;
                },
                _ => continue,
            }
        }
        info!("perf events loaded into kernel");

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
        info!("maps initialized");

        let mut ringbuf_fd = AsyncFd::new(event_map)?;
        let (perf_tx, perf_rx) = mpsc::channel::<PerfSample>(100);

        let polling_task = tokio::spawn(async move {
            loop {
                for i in ringbuf_read::<PerfSample>(&mut ringbuf_fd).await.unwrap() {
                    perf_tx.send(i).await.map_err(|_| anyhow::anyhow!("reciever closed?"))?;
                }
            }
        });
        info!("event poller started");

        Ok(Self {
            ebpf: ebpf,
            map_perf_config: config_map,
            map_stack_traces: stack_traces,
            links: StdHashMap::new(),
            event_polling_task: polling_task,
            event_rx: perf_rx,
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
        info!("attached perf event {perf_ebpf_name} with id: {id} sampling period: {some_period} scope: {scope_info}");

        self.links.insert(id, links);

        Ok(())
    }

    pub fn list_events(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for (name, prog) in self.ebpf.programs() {
            names.push(name.to_string());
        }
        names
    }

    pub fn detach_event(&mut self, id: u64) {
        self.links.remove(&id);
    }

    pub fn update_perf_config(&mut self, filter_exclude: Vec<(u32, u32)>, stack_trace_fp: Vec<u32>) -> Result<()> {
        let mut config_temp: StdHashMap<u32, PerfProcessConfig> = StdHashMap::new();

        for (key, mask) in filter_exclude {
            config_temp.insert(key, PerfProcessConfig(mask, false));
        }

        for key in stack_trace_fp {
            config_temp.entry(key).and_modify(|config| config.1 = true).or_insert(PerfProcessConfig(0, true));
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
}
