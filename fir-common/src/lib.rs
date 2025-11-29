#![no_std]

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

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PerfEventType {
    #[default]
    None,
    Any,
    CacheMiss,
}
