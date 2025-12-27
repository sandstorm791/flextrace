#![no_std]
#![no_main]
use core::panic;

use aya_ebpf::{EbpfContext, bpf_printk};
use aya_ebpf::macros::{map, perf_event};
use aya_ebpf::programs::{PerfEventContext};
use aya_ebpf::maps::{HashMap, RingBuf};
use flextrace_common::{PerfSample, PerfEventType, PERF_EVENT_VARIANTS};

#[map]
pub static PERF_EVENTS: RingBuf = RingBuf::with_byte_size(1000 * 3000, 0); // ~3MB, exact amount handled by aya

#[map]
//10k (~640kb) processes should be enough for anyone but we can always update it
//could use BPF_F_NO_PREALLOC but that has more runtime overhead
pub static FILTER_PIDS: HashMap<u32, [u8; PERF_EVENT_VARIANTS]> = HashMap::with_max_entries(10000, 0);

fn handle_perf_event(ctx: PerfEventContext, e_type: u8) -> u32 {
    // filter out if the event is on a pid that filters that event
    if let Some(filter) = unsafe { FILTER_PIDS.get(&ctx.pid()) } {
        for i in filter {
            if i == &e_type || i == &PerfEventType::Any.into() {
                return 0;
            }
            // it would appear that we can guarantee order correctness such that once we stumble
            // across a single None it means there's only None's left
            if i == &PerfEventType::None.into() {
                break;
            }
        }
    }

    let sample = PerfSample {
        event_type: PerfEventType::try_from(e_type).unwrap(),
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        uid: ctx.uid(),
        gid: ctx.gid(),
        cmd: ctx.command().unwrap_or([0u8; 16]),
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