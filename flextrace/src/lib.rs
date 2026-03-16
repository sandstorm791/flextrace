pub use std::collections::HashMap as StdHashMap;
use aya::maps::{MapData, RingBuf};
pub use aya::maps::HashMap as AyaHashMap;
use bincode_next::{Decode, Encode, config, decode_from_slice, encode_to_vec};
use flextrace_common::PerfEventType;
use log::trace;
use tokio::io::unix::AsyncFd;
use anyhow::Result;

use std::fs::{write, read};

#[derive(Debug, Encode, Decode)]
pub struct TreeNode {
    pub counters: StdHashMap<PerfEventType, u32>,
    pub name: String,
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    // we assume that we are included in the elements to be updated but not in the trace vec
    // we also assume that the front of the trace vec is the head of the trace
    pub fn update(&mut self, mut trace: Vec<String>, event: PerfEventType) {
        trace!("calling update on a tree node");
        self.counters.entry(event).and_modify(|c| *c += 1 ).or_insert(1);
        
        if trace.len() == 0 {
            trace!("trace update complete returning...");
            return;
        }

        let stack_highest = &trace[0].to_string();

        trace.pop();

        for node in &mut self.children {
            if &node.name == stack_highest {
                trace!("found a matching child for {stack_highest}!");
                node.update(trace, event);
                return;
            }
        }

        self.children.push(
            TreeNode {
                counters: StdHashMap::new(),
                name: stack_highest.to_string(),
                children: Vec::new(),
            }
        );

        self.children[0].update(trace, event);
    }
}

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

pub fn save_traces(path: String, trace: TreeNode) -> Result<()> {
    let ser = encode_to_vec(trace, config::standard())?;
    write(path, ser)?;
    Ok(())
}

pub fn read_traces_file(path: String) -> Result<TreeNode> {
    let bytes = read(path)?;
    let de: (TreeNode, usize) = decode_from_slice(&bytes, config::standard())?;
    Ok(de.0)
}
