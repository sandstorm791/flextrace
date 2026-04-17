pub use aya::maps::HashMap as AyaHashMap;
use bincode_next::{Decode, Encode, config, decode_from_slice, encode_to_vec};
use flextrace_common::PerfEventType;
use log::trace;
use ratatui::{buffer::Buffer, layout::Rect, widgets::{BarChart, Block, Widget}};
use anyhow::Result;

use std::{collections::HashMap, fs::{read, write}};

mod perf;

#[derive(Debug, Encode, Decode)]
pub struct TreeNode {
    pub counters: HashMap<PerfEventType, u32>,
    pub name: String,
    pub children: Vec<TreeNode>,
    pub focused_event: PerfEventType,
    pub hits: u32,
}

#[derive(Debug, Encode, Decode)]
pub struct ProfileData {
    pub name: String,
    pub gid: u32,
    pub events: HashMap<PerfEventType, u32>,
}

#[derive(Debug, Encode, Decode)]
pub struct SaveData {
    pub tree: TreeNode,
    pub data: HashMap<u32, ProfileData>,
}

impl TreeNode {
    pub fn focus(&mut self, focus: PerfEventType) -> &mut Self {
        self.focused_event = focus;
        self
    }

    // we assume that we are included in the elements to be updated but not in the trace vec
    // we also assume that the front of the trace vec is the head of the trace
    pub fn update(&mut self, mut trace: Vec<String>, event: PerfEventType) {
        trace!("calling update on a tree node");
        self.counters.entry(event).and_modify(|c| *c += 1 ).or_insert(1);
        self.hits += 1;
        
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
                counters: HashMap::new(),
                name: stack_highest.to_string(),
                children: Vec::new(),
                focused_event: PerfEventType::None,
                hits: 0,
            }
        );

        self.children[0].update(trace, event);
    }
}

impl Widget for &TreeNode {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // TODO: this is super inefficient to do every frame so fix this and add a cache
        let mut data: Vec<(&str, u64)> = Vec::new();

        for child in &self.children {
            data.push((&child.name, *child.counters.get(&self.focused_event).unwrap_or(&child.hits) as u64));
        }

        let chart = BarChart::default()
            .block(Block::bordered().title(" stack traces "))
            .bar_width(1)
            .bar_gap(5)
            .data(&data)
            .max(7);

        chart.render(area, buf);
    }
}

pub fn save_traces(path: String, data: SaveData) -> Result<()> {
    let ser = encode_to_vec(data, config::standard())?;
    write(path, ser)?;
    Ok(())
}

pub fn read_traces_file(path: String) -> Result<SaveData> {
    let bytes = read(path)?;
    let de: (SaveData, usize) = decode_from_slice(&bytes, config::standard())?;
    Ok(de.0)
}
