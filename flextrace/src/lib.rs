pub use aya::maps::HashMap as AyaHashMap;
use bincode_next::{Decode, Encode, config, decode_from_slice, encode_to_vec};
use flextrace_common::PerfEventType;
use log::trace;
use ratatui::{buffer::Buffer, layout::Rect, widgets::{BarChart, Block, Widget}};
use anyhow::Result;

use std::{collections::HashMap, fs::{read, write}};

mod perf;

#[derive(Debug, Encode, Decode)]
pub struct Tree {
    pub nodes: Vec<Node>,
    pub focused_event: PerfEventType,
    pub focused_node: usize,
}

#[derive(Debug, Encode, Decode)]
pub struct Node {
    pub counters: HashMap<PerfEventType, u32>,
    pub name: String,
    pub children: HashMap<String, usize>,
    pub hits: u32,
    pub parent: usize,
}

#[derive(Debug, Encode, Decode)]
pub struct ProfileData {
    pub name: String,
    pub gid: u32,
    pub events: HashMap<PerfEventType, u32>,
}

#[derive(Debug, Encode, Decode)]
pub struct SaveData {
    pub tree: Tree,
    pub data: HashMap<u32, ProfileData>,
}

impl Tree {
    pub fn update(&mut self, trace: Vec<String>, event: PerfEventType) {
        trace!("updating tree with new trace");
        let mut current_index = 0;

        for name in trace {
            let next_index = if let Some(&child_index) = self.nodes[current_index].children.get(&name) { child_index }
            else {
                trace!("adding new child to tree");
                let new_child_index = self.nodes.len();
                let new_node = Node {
                    name: name.clone(),
                    counters: HashMap::new(),
                    hits: 0,
                    children: HashMap::new(),
                    parent: current_index,
                };

                self.nodes.push(new_node);
                self.nodes[current_index].children.insert(name, new_child_index);
                new_child_index
            };

            current_index = next_index;
            self.nodes[current_index].hits += 1;
            self.nodes[current_index].counters.entry(event).and_modify(|c| *c += 1 ).or_insert(1);
        }
    }
}

impl Widget for &Tree {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // TODO: this is super inefficient to do every frame so fix this and add a cache
        let mut data: Vec<(&str, u64)> = Vec::new();

        for child in &self.nodes[self.focused_node].children {
            data.push((&child.0[child.0.find(":").unwrap()+1..], *self.nodes[*child.1].counters.get(&self.focused_event).unwrap_or(&self.nodes[*child.1].hits) as u64))
        }

        let chart = BarChart::default()
            .block(Block::bordered().title(" stack traces "))
            .bar_width(1)
            .bar_gap(5)
            .data(&data);

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
