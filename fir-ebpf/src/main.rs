#![no_std]
#![no_main]
use aya_ebpf::{EbpfContext};
use aya_ebpf::macros::{map, perf_event};
use aya_ebpf::programs::{PerfEventContext};
use aya_ebpf::maps::{HashMap, RingBuf};
use fir_common::{PerfSample, PerfEventType, PERF_EVENT_VARIANTS};

#[map]
pub static PERF_EVENTS: RingBuf = RingBuf::with_byte_size(1000 * 3000, 0); // ~3MB, exact amount handled by aya

#[map]
//10k (~640kb) processes should be enough for anyone but we can always update it
//could use BPF_F_NO_PREALLOC but that has more runtime overhead
pub static FILTER_PIDS: HashMap<u32, [PerfEventType; PERF_EVENT_VARIANTS]> = HashMap::with_max_entries(10000, 0);

#[perf_event]
pub fn cache_miss(ctx: PerfEventContext) -> u32 {
    return handle_perf_event(ctx, PerfEventType::CacheMiss);
}

fn handle_perf_event(ctx: PerfEventContext, e_type: PerfEventType) -> u32 {
    // filter out if the event is on a pid that filters that event
    if let Some(filter) = unsafe { FILTER_PIDS.get(&ctx.pid()) } {
        for i in filter {
            if i == &e_type || i == &PerfEventType::Any {
                return 0;
            }
        }
    }

    let sample = PerfSample {
        event_type: e_type,
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

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";