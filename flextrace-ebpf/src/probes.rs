use aya_ebpf::{macros::map, maps::{HashMap, RingBuf}};
use flextrace_common::ProbeConfig;

#[map]
pub static PROBE_EVENTS: RingBuf = RingBuf::with_byte_size(1000 * 3000, 0); // ~3MB, exact amount handled by aya

#[map]        // function cookie vvv
pub static PROBE_CONFIG: HashMap<u32, ProbeConfig> = HashMap::with_max_entries(300, 0);