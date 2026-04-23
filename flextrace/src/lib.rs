pub use aya::maps::HashMap as AyaHashMap;
use bincode_next::{Decode, Encode, config, decode_from_slice, encode_to_vec};
use flextrace_common::PerfEventType;
use log::trace;
use ratatui::{buffer::Buffer, layout::{Direction, Rect}, style::{Color, Style}, widgets::{Bar, BarChart, Block, Widget}};
use anyhow::Result;

use std::{cmp::Reverse, collections::HashMap, fs::{read, write}};

mod perf;

#[derive(Debug, Encode, Decode)]
pub struct Tree {
    pub nodes: Vec<Node>,
    pub focused_event: PerfEventType,
    pub focused_node: usize, // in nodes
    pub selected_node: usize, // in focused_children_sorted_cache
    pub focused_children_sorted_cache: Vec<(String, u64, usize)>,
    pub display_head_node: usize, // in focused_children_sorted_cache
}

#[derive(Debug, Encode, Decode)]
pub struct Node {
    pub counters: HashMap<PerfEventType, u32>,
    pub name: String,
    pub children: HashMap<String, usize>,
    pub hits: u32,
    pub parent: usize,
}

impl Node {
    pub fn counter(&self, event: PerfEventType) -> u32 {
        if event == PerfEventType::None { return self.hits }
        if let Some(hits) = self.counters.get(&event) { return *hits }
        else { 0 }
    }
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

    pub fn update_sorted_cache(&mut self) {
        let mut cache: Vec<(String, u64, usize)> = Vec::new();

        for child in &self.nodes[self.focused_node].children {
            cache.push((child.0[child.0.find(":").unwrap()+1..].to_string(), *self.nodes[*child.1].counters.get(&self.focused_event).unwrap_or(&self.nodes[*child.1].counter(self.focused_event)) as u64, *child.1))
        } // this looks so funny im leaving it in 🥀

        cache.sort_by_key(|item| Reverse(item.1));

        self.focused_children_sorted_cache = cache;
    }
}

impl Widget for &Tree {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if self.focused_children_sorted_cache.len() == 0 {return}
        let mut bars: Vec<Bar> = Vec::new();

        for i in (self.display_head_node..&self.focused_children_sorted_cache.len() - 1) {
            let mut bar = Bar::new(self.focused_children_sorted_cache[i].1).label("[".to_string() + &i.to_string() + "]  " + &*self.focused_children_sorted_cache[i].0);
            if &self.focused_children_sorted_cache[self.selected_node].0 == &self.focused_children_sorted_cache[i].0 {
                bar = bar.style(Color::Green);
            }
            bars.push(bar);
        }

        let chart = BarChart::horizontal(bars);

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
