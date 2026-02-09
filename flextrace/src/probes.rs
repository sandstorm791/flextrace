use std::sync::{Arc, Mutex};
use aya::{maps::MapData, programs::uprobe::{UProbe, UProbeAttachPoint, UProbeLink, UProbeLinkId}, Ebpf};
use flextrace::{AyaHashMap, StdHashMap};
use flextrace_common::{FlextraceError, ProbeConfig};

pub struct ProbeLoader {
    // if you actually run out of cookies you better get out of the way of the sun before it swallows you
    next_probe_cookie: u64,

    ebpf: Arc<Mutex<Ebpf>>,
    config_map: AyaHashMap<MapData, u32, ProbeConfig>,
    links: StdHashMap<u64, UProbeLinkId>,
}

impl ProbeLoader {
    pub fn new(ebpf_shared: Arc<Mutex<Ebpf>>) -> Self{
        let typed_map: AyaHashMap<MapData, u32, ProbeConfig> = {
            let mut ebpf = ebpf_shared.lock().unwrap();
            let map = ebpf.take_map("PROBE_CONFIG").expect("map PROBE_CONFIG not found???");
            
            AyaHashMap::try_from(map).expect("could not convert map PROBE_CONFIG into typed map")
        };

        Self {
            next_probe_cookie: 0,
            ebpf: ebpf_shared,
            config_map: typed_map,
            links: StdHashMap::new(),
        }
    }

    pub fn attatch_probe(&mut self, func_name: &str, executable: &str, pid: Option<u32>) -> Result<(), FlextraceError> {
        let mut bpf = self.ebpf.lock().unwrap();

        let probe: &mut UProbe = bpf
            .program_mut("probe_handler")
            .ok_or(FlextraceError::NoSuchProgram(String::from("probe_handler")))?
            .try_into()
            .map_err(|_| FlextraceError::NoSuchProgram(String::from("probe_handler")))?;

        let link_id = probe
            // not a clue if this is gonna work right but we'll see
            .attach(UProbeAttachPoint {
                location: aya::programs::uprobe::UProbeAttachLocation::from(func_name),
                cookie: Some(self.next_probe_cookie)},
                executable,
                pid).unwrap();

                // ^^^ stop being lazy and map this to a FlextraceError

        self.links.insert(self.next_probe_cookie, link_id);

        self.next_probe_cookie += 1;
        Ok(())
    }
}
