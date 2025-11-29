use aya::programs::{UProbe, KProbe};
use aya::maps::RingBuf;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{signal, spawn};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, unix::AsyncFd};
use std::sync::mpsc::channel;

#[derive(Debug, Parser)]
struct Opt {
    //this way of taking in cli args is lowkey sketchy but idk i might change it later
    // just have to remind the user to enter everything IN order
    #[arg(long, alias = "uf")]
    uprobe_fn: Option<Vec<str>>,

    #[arg(long, alias = "uo")]
    uprobe_offset: Option<Vec<u64>>,

    #[arg(short, long)]
    target: Option<Vec<str>>,

    #[arg(short, long)]
    pid: Option<Vec<pid_t>>,

    kprobe_fn: Option<Vec<str>>,

    kprobe_offset: Option<Vec<u64>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // include ebpf program at compile time, load at runtime
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        //env!("OUT_DIR"),
        "/fir"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let Opt {uprobe_fn, uprobe_offset, target, pid, kprobe_fn, kprobe_offset} = opt;

    let fir_uprobe: &mut UProbe = ebpf.program_mut("fir_uprobe").unwrap().try_into()?;
    let fir_kprobe: &mut KProbe = ebpf.program_mut("fir_kprobe").unwrap().try_into()?;
    
    /* im pretty sure we should load the program before creating the map? this code is already
    too confusing for me to want to refactor and try it out so its whatever for now */
    fir_uprobe.load()?;
    fir_kprobe.load()?;

    let mut uevent_buf = RingBuf::try_from(ebpf.map_mut("UPROBE_EVENTS").unwrap()).unwrap();
    let mut asyncfd_uevent_buf = AsyncFd::new(uevent_buf);

    let mut kevent_buf = RingBuf::try_from(ebpf.map_mut("KPROBE_EVENTS").unwrap()).unwrap();
    let mut asyncfd_kevent_buf = AsyncFd::new(kevent_buf);

    fir_uprobe.attach(Some("fopen"), 0, "libc", pid)?;

    // i like my io non-blocking bruh
    // these are unbounded channels because i dont want to drop ANY events EVER.
    // the only thing is we need to be careful about runaway memory usage
    let (uprobe_tx, mut uprobe_rx) = mpsc::channel();
    let (kprobe_tx, mut kprobe_rx) = mpsc::channel();

    tokio::spawn(async move {
        loop {
            let mut uguard = asyncfd_uevent_buf.readable().await.unwrap();
            
            while let Some(uevent) = uevent_buf.next() {
                uprobe_tx.try_send(uevent).is_ok()?;
            }

            uguard.clear_ready();

        }
    });
    // no sense in having the kprobes sender wait for the uprobe array, lets make another thread
    tokio::spawn(async move {
        loop {
            let mut kguard = asyncfd_kevent_buf.readable().await().unwrap();

            while let Some(kevent) = kevent_buf.next() {
                kprobe_tx.try_send(kevent).is_ok()?;
            }

            kguard.clear_ready();
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
