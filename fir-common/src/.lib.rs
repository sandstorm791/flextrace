#![no_std]

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct UprobeEvent {
    pub pid: u32,
    pub timestamp: u64,
    pub func: u32,

    // arguments maybe? well see what actually ends up in there
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub r8: u64,
    pub r9: u64,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct KprobeEvent {
    pub call: u32,
    pub timestamp: u64,

    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub r8: u64,
    pub r9: u64,
    
}
