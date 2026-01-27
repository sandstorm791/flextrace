use std::sync::{Arc, Mutex};
use aya::{maps::MapData, programs::uprobe::{UProbe, UProbeLink}, Ebpf};
use flextrace::{AyaHashMap, StdHashMap};

use flextrace_common::{FlextraceError, ProbeConfig};

pub struct ProbeLoader {
    next_probe_cookie: u64,
    ebpf: Arc<Mutex<Ebpf>>,
    config_map: AyaHashMap<MapData, u32, ProbeConfig>,
    links: StdHashMap<u32, UProbeLink>,
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

    pub fn attatch_probe(&mut self, func_name: &str, executable: &str) -> Result<(), FlextraceError> {
        let mut bpf = self.ebpf.lock().unwrap();

        let probe: &mut UProbe = bpf
            .program_mut("probe_handler")
            .ok_or(FlextraceError::NoSuchProgram(String::from("probe_handler")))?
            .try_into()
            .map_err(|_| FlextraceError::NoSuchProgram(String::from("probe_handler")))?;

        let link_id = probe
            .attach(Some(func_name), 0, executable, None, self.next_probe_cookie)
        Ok(())
    }
}
