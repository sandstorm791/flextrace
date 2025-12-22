#![no_std]
use core::{error::Error, fmt};

#[cfg(feature = "user")]
use aya_obj::generated::{perf_hw_id, perf_sw_ids};

#[cfg(feature = "user")]
use aya::programs::PerfTypeId;

pub const PERF_EVENT_VARIANTS: usize = 3;

#[derive(Debug)]
pub enum FlextraceError {
    TooManyEvents,
    BadArgument,
    NoSuchPerfEventType,
    NoPerfEventCategory,
    NoPerfHwId,
    NoPerfSwId,
}

impl fmt::Display for FlextraceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TooManyEvents => write!(f, "too many events for one process, max is {PERF_EVENT_VARIANTS}"),
            Self::BadArgument => write!(f, "bad arguments lol"),
            Self::NoSuchPerfEventType => write!(f, "the perf event type specified does not exist or is not currently supported"),
            _ => write!(f, "whatever error this is i was too lazy to write an error msg for it"),
        }
    }
}

impl Error for FlextraceError {}

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
pub enum PerfEventType {
    #[default]
    None,
    
    Any,
    CacheMiss,
}

impl PerfEventType {
    pub fn from_str(thing: &str) -> Result<PerfEventType, FlextraceError> {
        match thing {
            "none" => Ok(PerfEventType::None),
            "any" => Ok(PerfEventType::Any),
            "cache_miss" => Ok(PerfEventType::CacheMiss),
            _ => Err(FlextraceError::NoSuchPerfEventType),
        }
    }

    pub fn ebpf_from_self(&self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Any => Some("generic_perf_handler"),
            Self::CacheMiss => Some("cache_miss"),
        }
    }

    pub fn ebpf_from_str(thing: &str) -> Option<&str> {
        return PerfEventType::ebpf_from_self(&PerfEventType::from_str(thing).unwrap());
    }


    #[cfg(feature = "user")]
    pub fn perf_event_category(&self) -> Result<PerfTypeId, FlextraceError> {
        match self {
            PerfEventType::CacheMiss => Ok(PerfTypeId::Hardware),
            _ => Err(FlextraceError::NoPerfEventCategory),
        }
    }


    #[cfg(feature = "user")]
    // this function will return an error if the perf event is not a hardware event
    pub fn perf_hw_id(&self) -> Result<perf_hw_id, FlextraceError> {
        match self {
            PerfEventType::CacheMiss => Ok(perf_hw_id::PERF_COUNT_HW_CACHE_MISSES),
            _ => Err(FlextraceError::NoPerfHwId),
        }
    }

    #[cfg(feature = "user")]
    pub fn perf_sw_id(&self) -> Result<perf_sw_ids, FlextraceError> {
        match self {
            _ => Err(FlextraceError::NoPerfSwId),
        }
    }

}