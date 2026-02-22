pub use std::collections::HashMap as StdHashMap;
use aya::maps::{MapData, RingBuf};
pub use aya::maps::HashMap as AyaHashMap;
use tokio::io::unix::AsyncFd;
use anyhow::Result;

pub async fn ringbuf_read<T: Copy>(fd: &mut AsyncFd<RingBuf<MapData>>) -> Result<Vec<T>> {
    let mut readguard = fd.readable_mut().await?;
    let mut items: Vec<T> = Vec::new();

    readguard.try_io(|inner|{
        let mut count: usize = 0;

        while let Some(event) = inner.get_mut().next() {
            // reserve/submit api guarantees an unmangled struct
            // but .next() still returns [u8] so we need to unsafe pointer cast

            let event_struct = unsafe {
                let ptr = event.as_ptr() as *const T;

                *ptr
            };

            items.push(event_struct);
            count += 1;

        }

        Ok(count)
    }).unwrap().unwrap();

        readguard.clear_ready();
        Ok(items)
}
