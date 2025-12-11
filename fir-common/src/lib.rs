#![no_std]

use core::result::Result;

pub const PERF_EVENT_VARIANTS: usize = 2;

#[derive(Default, Copy, Clone, Debug)]
#[repr(C)]
pub struct PerfSample {
    pub event_type: PerfEventType,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cmd: [u8; 16],
}

// since we want to have one map for all types of perf events we'll use this internally
// instead of the aya generated perf ids that are category dependent
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PerfEventType {
    #[default]
    None,
    Any,
    CacheMiss,
}

impl PerfEventType {
    pub fn from_str(thing: &str) -> Result<PerfEventType, ()> {
        match thing {
            "none" => Ok(PerfEventType::None),
            "any" => Ok(PerfEventType::Any),
            "cache_miss" => Ok(PerfEventType::CacheMiss),
            _ => Err(()),
        }
    }
}
