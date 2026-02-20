use std::sync::{Arc, Mutex};
use aya::{maps::MapData, programs::uprobe::{UProbe, UProbeAttachPoint, UProbeLink, UProbeLinkId}, Ebpf};
use flextrace::{AyaHashMap, StdHashMap};
use flextrace_common::{FlextraceError, ProbeConfig};

pub struct ProbeLoader {
    // if you actually run out of cookies you better get out of the way of the sun before it swallows you
    next_probe_cookie: u64,

    ebpf: Arc<Mutex<Ebpf>>,
    config_map: AyaHashMap<MapData, u64, ProbeConfig>,
    links: StdHashMap<u64, UProbeLink>,
}

impl ProbeLoader {
    pub fn new(ebpf_shared: Arc<Mutex<Ebpf>>) -> Self{
        let typed_map: AyaHashMap<MapData, u64, ProbeConfig> = {
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
            .map_err(|_| FlextraceError::Msg(String::from("failed to convert Program struct to UProbe struct when attatching new probe")))?;

        let link_id = probe
            // not a clue if this is gonna work right but we'll see
            .attach(UProbeAttachPoint {
                location: aya::programs::uprobe::UProbeAttachLocation::from(func_name),
                cookie: Some(self.next_probe_cookie)},
                executable,
                pid).map_err(|e| FlextraceError::Msg(e.to_string()))?;

                // ^^^ stop being lazy and map this to a FlextraceError

        let link = probe.take_link(link_id).map_err(|_| FlextraceError::Msg("failed to take the link to the uprobe".to_string()))?;
        self.links.insert(self.next_probe_cookie, link);

        self.next_probe_cookie += 1;
        Ok(())
    }

    pub fn detach_probe(&mut self, id: u64) {
        self.links.remove(&id);
    }

    pub fn update_config(&mut self, cookie: u64, config: ProbeConfig) -> Result<(), FlextraceError> {
        self.config_map.insert(cookie, config, 0).map_err(|_| FlextraceError::Msg("failed to update uprobe configuration".to_string()))?;
        Ok(())
    }
}
