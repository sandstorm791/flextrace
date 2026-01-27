pub use std::collections::HashMap as StdHashMap;
use flextrace_common::PerfEventType;
pub use aya::maps::HashMap as AyaHashMap;

pub struct ProfileData {
    pub name: String,
    pub gid: u32,
    pub events: StdHashMap<PerfEventType, u32>,
}
