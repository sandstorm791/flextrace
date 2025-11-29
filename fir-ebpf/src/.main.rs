#![no_std]
#![no_main]

use aya_ebpf::{helpers::bpf_get_current_pid_tgid, programs::ProbeContext};
use aya_ebpf::maps::RingBuf;
use fir_common::{KprobeEvent, UprobeEvent};

#[map]
pub static mut UPROBE_EVENTS: RingBuf<UprobeEvent> = RingBuf::with_byte_size(1000 * 3000, 0); // 3MB

#[map]
pub static mut KPROBE_EVENTS: RingBuf<KprobeEvent> = RingBuf::with_byte_size(1000 * 3000, 0);

// youre gonna see some weird shit in this code. discretion advised for good programmers and those who are mentally stable

#[uprobe]
pub fn fir_uprobe(ctx: ProbeContext) -> u32 {
    match fir_try_uprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn fir_try_uprobe(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    let timestamp: u64 = unsafe { bpf_ktime_get_ns() };

    let event = UprobeEvent { pid: pid, timestamp: timestamp, func: 0 };

    unsafe { UPROBE_EVENTS.output(&event, 0); }

    Ok(0)
}

pub fn fir_kprobe(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    let timestamp: u64 = unsafe { bpf_ktime_get_ns() };
    
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
