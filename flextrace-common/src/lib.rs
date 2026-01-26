#![cfg_attr(not(feature = "user"), no_std)]
#[cfg(feature = "user")]
use std::fmt::{self, Display};

#[cfg(feature = "user")]
use aya_obj::generated::{perf_hw_id, perf_sw_ids};

#[cfg(feature = "user")]
use aya::programs::PerfTypeId;
use num_enum::{IntoPrimitive, TryFromPrimitive};

pub const PERF_EVENT_VARIANTS: usize = 22;

#[cfg(feature = "user")]
#[derive(Debug)]
pub enum FlextraceError<E = ()> {
    TooManyEvents(String),
    BadArgument(String),
    NoSuchPerfEventType(String),
    NoPerfEventCategory(String),
    NoPerfHwId(String),
    NoPerfSwId(String),
    Msg(String),
    Inner(E),
}

#[cfg(feature = "user")]
impl<E> fmt::Display for FlextraceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TooManyEvents(ctx) => write!(f, "too many events for one process, max is {PERF_EVENT_VARIANTS}, context: {ctx}"),
            Self::BadArgument(ctx) => write!(f, "bad arguments lol, input was {ctx}"),
            Self::NoSuchPerfEventType(ctx) => write!(f, "the perf event type {ctx} does not exist or is not currently supported"),
            _ => write!(f, "whatever error this is i was too lazy to write an error msg for it"),
        }
    }
}

#[cfg(feature = "user")]
impl<E: std::fmt::Debug + Display> std::error::Error for FlextraceError<E> {}

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
#[derive(Hash, TryFromPrimitive, IntoPrimitive, Default, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PerfEventType {
    #[default]
    None = 22,
    
    Any = 21,

    //hardware
    CacheMiss = 1,
    CpuCycles = 2,
    Instructions = 3,
    CacheReferences = 4,
    BranchInstructions = 5,
    BranchMisses = 6,
    BusCycles = 7,
    StalledCyclesFront = 8,
    StalledCyclesBack = 9,
    RefCpuCycles = 10,

    //software
    CpuClock = 11,
    TaskClock = 12,
    PageFaults = 13,
    ContextSwitches = 14,
    CpuMigrations = 15,
    PageFaultsMin = 16,
    PageFaultsMaj = 17,
    AlignmentFaults = 18,
    EmulationFaults = 19,
    CgroupSwitches = 20,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProbeConfig {
    pub num_args: u32,
    pub ptr_depths: [u32; 32], // 32 arguments ought to be enough for anyone... right?
}

#[cfg(feature = "user")]
impl PerfEventType {
    pub fn from_str(thing: &String) -> Result<PerfEventType, FlextraceError<String>> {
        match thing.as_str() {
            //"none" => Ok(PerfEventType::None),
            "any" => Ok(PerfEventType::Any),
            "all" => Ok(PerfEventType::Any),
            "cache_miss" => Ok(PerfEventType::CacheMiss),
            "page_faults" => Ok(PerfEventType::PageFaults),
            "cpu_cycles" => Ok(PerfEventType::CpuCycles),
            "context_switches" => Ok(PerfEventType::ContextSwitches),
            "cpu_migrations" => Ok(PerfEventType::CpuMigrations),
            "page_faults_min" => Ok(PerfEventType::PageFaultsMin),
            "page_faults_maj" => Ok(PerfEventType::PageFaultsMaj),
            "alignment_faults" => Ok(PerfEventType::AlignmentFaults),
            "emulation_faults" => Ok(PerfEventType::EmulationFaults),
            "cgroup_switches" => Ok(PerfEventType::CgroupSwitches),
            "cpu_clock" => Ok(PerfEventType::CpuClock),
            "task_clock" => Ok(PerfEventType::TaskClock),
            "ref_cpu_cycles" => Ok(PerfEventType::RefCpuCycles),
            "stalled_cycles_backend" => Ok(PerfEventType::StalledCyclesBack),
            "stalled_cycles_frontend" => Ok(PerfEventType::StalledCyclesFront),
            "bus_cycles" => Ok(PerfEventType::BusCycles),
            "branch_misses" => Ok(PerfEventType::BranchMisses),
            "branch_instructions" => Ok(PerfEventType::BranchInstructions),
            "cache_references" => Ok(PerfEventType::CacheReferences),
            "instructions" => Ok(PerfEventType::Instructions),
            _ => Err(FlextraceError::NoSuchPerfEventType(thing.to_owned())),
        }
    }

    pub fn ebpf_from_self(&self) -> Option<String> {
        match self {
            Self::None => None,

            // hardware
            Self::CacheMiss => Some(String::from("event_cache_miss")),
            Self::CpuCycles => Some(String::from("event_cpu_cycles")),
            Self::Instructions => Some(String::from("event_instructions")),
            Self::CacheReferences => Some(String::from("event_cache_references")),
            Self::BranchInstructions => Some(String::from("event_branch_instructions")),
            Self::BranchMisses => Some(String::from("event_branch_misses")),
            Self::BusCycles => Some(String::from("event_bus_cycles")),
            Self::StalledCyclesFront => Some(String::from("event_stalled_cycles_frontend")),
            Self::StalledCyclesBack => Some(String::from("event_stalled_cycles_backend")),
            Self::RefCpuCycles => Some(String::from("event_ref_cpu_cycles")),

            // software
            Self::CpuClock => Some(String::from("event_cpu_clock")),
            Self::TaskClock => Some(String::from("event_task_clock")),
            Self::PageFaults => Some(String::from("event_page_faults")),
            Self::ContextSwitches => Some(String::from("event_context_switches")),
            Self::CpuMigrations => Some(String::from("event_cpu_migrations")),
            Self::PageFaultsMaj => Some(String::from("event_page_faults_maj")),
            Self::PageFaultsMin => Some(String::from("event_page_faults_min")),
            Self::AlignmentFaults => Some(String::from("event_alignment_faults")),
            Self::EmulationFaults => Some(String::from("event_emulation_faults")),
            Self::CgroupSwitches => Some(String::from("event_cgroup_switches")),
            _ => None,
        }
    }

    pub fn ebpf_from_str(thing: &String) -> Option<String> {
        return PerfEventType::ebpf_from_self(&PerfEventType::from_str(thing).ok()?);
    }

    pub fn perf_event_category(&self) -> Result<PerfTypeId, FlextraceError<String>> {
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

            _ => Err(FlextraceError::NoPerfEventCategory(self.ebpf_from_self().unwrap_or(String::from("")))),
        }
    }

    // this function will return an error if the perf event is not a hardware event
    pub fn perf_hw_id(&self) -> Result<perf_hw_id, FlextraceError<String>> {
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
            _ => Err(FlextraceError::NoPerfHwId(self.ebpf_from_self().unwrap_or(String::from("no printable version of this enum??? mysterious...")))),
        }
    }

    pub fn perf_sw_id(&self) -> Result<perf_sw_ids, FlextraceError<String>> {
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
            _ => Err(FlextraceError::NoPerfSwId(self.ebpf_from_self().unwrap_or(String::from("")))),
        }
    }

}