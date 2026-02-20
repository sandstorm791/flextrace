#![no_std]
#![no_main]
use core::panic;

use aya_ebpf::bindings::BPF_F_USER_STACK;
use aya_ebpf::cty::c_void;
use aya_ebpf::helpers::generated::bpf_get_stackid;
use aya_ebpf::{EbpfContext, bpf_printk};
use aya_ebpf::macros::{map, perf_event};
use aya_ebpf::programs::PerfEventContext;
use aya_ebpf::maps::{HashMap, RingBuf, StackTrace};
use flextrace_common::{PerfSample, PerfEventType};

#[map]
pub static PERF_EVENTS: RingBuf = RingBuf::with_byte_size(1000 * 3000, 0); // ~3MB, exact amount handled by aya

#[map]
pub static PERF_STACK_TRACES: StackTrace = StackTrace::with_max_entries(5000, 0); //~5MB i think? maybe in the future make this a runtime toggleable thing

#[map]
//10k processes ought to be enough for anybody
pub static PERF_CONFIG: HashMap<u32, (u32, bool)> = HashMap::with_max_entries(10000, 0);

fn handle_perf_event(ctx: PerfEventContext, e_type: u8) -> u32 {
    let mut stackid: Option<i64> = None;

    if let Some(config) = unsafe { PERF_CONFIG.get(&ctx.pid()) } {
        //check if we should filter this event out based on the event type and pid
        if config.0 & (1 << e_type) != 0 {
            return 0;
        }

        //do a stack trace if the frame pointer stack trace flag is true
        if config.1 {
            stackid = Some(unsafe {bpf_get_stackid(ctx.as_ptr() as *mut c_void, &PERF_STACK_TRACES as *const _ as *mut c_void, BPF_F_USER_STACK as u64) });
        }
    }

    let sample = PerfSample {
        event_type: PerfEventType::try_from(e_type).unwrap(),
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        uid: ctx.uid(),
        gid: ctx.gid(),
        cmd: ctx.command().unwrap_or([0u8; 16]),
        stack_id: stackid,
    };

    if let Some(mut buf) = PERF_EVENTS.reserve::<PerfSample>(0) {
        buf.write(sample);
        buf.submit(0);
    }
    else {
        unsafe { bpf_printk!(b" !!! could not reserve space in PERF_EVENTS buffer !!!"); }
    }

    0
}

//hardware events
#[perf_event]
pub fn event_cache_miss(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::CacheMiss.into());
}

#[perf_event]
pub fn event_cpu_cycles(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::CpuCycles.into());
}

#[perf_event]
pub fn event_instructions(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::Instructions.into());
}

#[perf_event]
pub fn event_cache_references(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::CacheReferences.into());
}

#[perf_event]
pub fn event_branch_instructions(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::BranchInstructions.into());
}

#[perf_event]
pub fn event_branch_misses(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::BranchMisses.into());
}

#[perf_event]
pub fn event_bus_cycles(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::BusCycles.into());
}

#[perf_event]
pub fn event_stalled_cycles_frontend(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::StalledCyclesFront.into());
}

#[perf_event]
pub fn event_stalled_cycles_backend(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::StalledCyclesBack.into());
}

#[perf_event]
pub fn event_ref_cpu_cycles(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::RefCpuCycles.into());
}

//software events
#[perf_event]
pub fn event_cpu_clock(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::CpuClock.into());
}

#[perf_event]
pub fn event_task_clock(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::TaskClock.into());
}

#[perf_event]
pub fn event_page_faults(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::PageFaults.into());
}

#[perf_event]
pub fn event_context_switches(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::ContextSwitches.into());
}

#[perf_event]
pub fn event_cpu_migrations(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::CpuMigrations.into());
}

#[perf_event]
pub fn event_page_faults_min(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::PageFaultsMin.into());
}

#[perf_event]
pub fn event_page_faults_maj(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::PageFaultsMaj.into());
}

#[perf_event]
pub fn event_alignment_faults(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::AlignmentFaults.into());
}

#[perf_event]
pub fn event_cgroup_switches(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::CgroupSwitches.into());
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";