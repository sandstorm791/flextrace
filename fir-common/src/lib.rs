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

    //hardware
    CacheMiss,
    CpuCycles,
    Instructions,
    CacheReferences,
    BranchInstructions,
    BranchMisses,
    BusCycles,
    StalledCyclesFront,
    StalledCyclesBack,
    RefCpuCycles,

    //software
    CpuClock,
    TaskClock,
    PageFaults,
    ContextSwitches,
    CpuMigrations,
    PageFaultsMin,
    PageFaultsMaj,
    AlignmentFaults,
    EmulationFaults,
    CgroupSwitches
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

            // hardware
            Self::CacheMiss => Some("event_cache_miss"),
            Self::CpuCycles => Some("event_cpu_cycles"),
            Self::Instructions => Some("event_instructions"),
            Self::CacheReferences => Some("event_cache_references"),
            Self::BranchInstructions => Some("event_branch_instructions"),
            Self::BranchMisses => Some("event_branch_misses"),
            Self::BusCycles => Some("event_bus_cycles"),
            Self::StalledCyclesFront => Some("event_stalled_cycles_front"),
            Self::StalledCyclesBack => Some("event_stalled_cycles_back"),
            Self::RefCpuCycles => Some("event_ref_cpu_cycles"),

            // software
            Self::CpuClock => Some("event_cpu_clock"),
            Self::TaskClock => Some("event_task_clock"),
            Self::PageFaults => Some("event_page_faults"),
            Self::ContextSwitches => Some("event_context_switches"),
            Self::CpuMigrations => Some("event_cpu_migrations"),
            Self::PageFaultsMaj => Some("event_page_faults_maj"),
            Self::PageFaultsMin => Some("event_page_faults_min"),
            Self::AlignmentFaults => Some("event_alignment_faults"),
            Self::EmulationFaults => Some("event_emulation_faults"),
            Self::CgroupSwitches => Some("event_cgroup_switches"),
        }
    }

    pub fn ebpf_from_str(thing: &str) -> Option<&str> {
        return PerfEventType::ebpf_from_self(&PerfEventType::from_str(thing).unwrap());
    }


    #[cfg(feature = "user")]
    pub fn perf_event_category(&self) -> Result<PerfTypeId, FlextraceError> {
        match self {
            Self::CacheMiss => Ok(PerfTypeId::Hardware),
            Self::CpuCycles => Ok(PerfTypeId::Hardware),
            Self::Instructions => Ok(PerfTypeId::Hardware),
            Self::CacheReferences => Ok(PerfTypeId::Hardware),
            Self::BranchInstructions => Ok(PerfTypeId::Hardware),
            Self::BranchMisses => Ok(PerfTypeId::Hardware),
            Self::BusCycles => Ok(PerfTypeId::Hardware),
            Self::StalledCyclesFront => Ok(PerfTypeId::Hardware),
            Self::StalledCyclesBack => Ok(PerfTypeId::Hardware),
            Self::RefCpuCycles => Ok(PerfTypeId::Hardware),

            Self::CpuClock => Ok(PerfTypeId::Software),
            Self::TaskClock => Ok(PerfTypeId::Software),
            Self::PageFaults => Ok(PerfTypeId::Software),
            Self::ContextSwitches => Ok(PerfTypeId::Software),
            Self::CpuMigrations => Ok(PerfTypeId::Software),
            Self::PageFaultsMaj => Ok(PerfTypeId::Software),
            Self::PageFaultsMin => Ok(PerfTypeId::Software),
            Self::AlignmentFaults => Ok(PerfTypeId::Software),
            Self::EmulationFaults => Ok(PerfTypeId::Software),
            Self::CgroupSwitches => Ok(PerfTypeId::Software),

            _ => Err(FlextraceError::NoPerfEventCategory),
        }
    }


    #[cfg(feature = "user")]
    // this function will return an error if the perf event is not a hardware event
    pub fn perf_hw_id(&self) -> Result<perf_hw_id, FlextraceError> {
        match self {
            Self::CacheMiss => Ok(perf_hw_id::PERF_COUNT_HW_CACHE_MISSES),
            Self::CpuCycles => Ok(perf_hw_id::PERF_COUNT_HW_CPU_CYCLES),
            Self::Instructions => Ok(perf_hw_id::PERF_COUNT_HW_INSTRUCTIONS),
            Self::CacheReferences => Ok(perf_hw_id::PERF_COUNT_HW_CACHE_REFERENCES),
            Self::BranchInstructions => Ok(perf_hw_id::PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
            Self::BranchMisses => Ok(perf_hw_id::PERF_COUNT_HW_BRANCH_MISSES),
            Self::BusCycles => Ok(perf_hw_id::PERF_COUNT_HW_BUS_CYCLES),
            Self::StalledCyclesFront => Ok(perf_hw_id::PERF_COUNT_HW_STALLED_CYCLES_FRONTEND),
            Self::StalledCyclesBack => Ok(perf_hw_id::PERF_COUNT_HW_STALLED_CYCLES_BACKEND),
            Self::RefCpuCycles => Ok(perf_hw_id::PERF_COUNT_HW_REF_CPU_CYCLES),
            _ => Err(FlextraceError::NoPerfHwId),
        }
    }

    #[cfg(feature = "user")]
    pub fn perf_sw_id(&self) -> Result<perf_sw_ids, FlextraceError> {
        match self {
            Self::CpuClock => Ok(perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK),
            Self::TaskClock => Ok(perf_sw_ids::PERF_COUNT_SW_TASK_CLOCK),
            Self::PageFaults => Ok(perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS),
            Self::ContextSwitches => Ok(perf_sw_ids::PERF_COUNT_SW_CONTEXT_SWITCHES),
            Self::CpuMigrations => Ok(perf_sw_ids::PERF_COUNT_SW_CPU_MIGRATIONS),
            Self::PageFaultsMaj => Ok(perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MAJ),
            Self::PageFaultsMin => Ok(perf_sw_ids::PERF_COUNT_SW_PAGE_FAULTS_MIN),
            Self::AlignmentFaults => Ok(perf_sw_ids::PERF_COUNT_SW_ALIGNMENT_FAULTS),
            Self::EmulationFaults => Ok(perf_sw_ids::PERF_COUNT_SW_EMULATION_FAULTS),
            Self::CgroupSwitches => Ok(perf_sw_ids::PERF_COUNT_SW_CGROUP_SWITCHES),
            _ => Err(FlextraceError::NoPerfSwId),
        }
    }

}