use crate::trace_parser::{TraceRecord, RecordValue};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct DefectResults {
    pub dead_store_pairs: Vec<(usize, usize)>,
    pub silent_store_pairs: Vec<(usize, usize)>,
    pub silent_load_pairs: Vec<(usize, usize)>,
}

/// record the recent store info for an addr
#[derive(Debug, Clone)]
struct LastStore {
    idx: usize,
    value: RecordValue,
    /// if load between it and its previous store (for dead-store)
    seen_load_since: bool,
}

/// record the recent load info for an addr
#[derive(Debug, Clone)]
struct LastLoad {
    idx: usize,
    value: RecordValue,
}

#[inline]
fn addr_key(addr: u32, offset: u32) -> u64 {
    (addr as u64).wrapping_add(offset as u64)
}

pub fn analysis_trace(trace: &[TraceRecord]) -> DefectResults {
    let mut results = DefectResults::default();

    // map: address -> LastStore
    let mut last_store_map: HashMap<u64, LastStore> = HashMap::new();
    // map: address -> LastLoad
    let mut last_load_map: HashMap<u64, LastLoad> = HashMap::new();

    for (idx, rec) in trace.iter().enumerate() {
        match rec {
            TraceRecord::StoreRecord(s) => {
                let key = addr_key(s.addr, s.offset);

                // Silent store: compare with last store at this address (if any)
                if let Some(prev) = last_store_map.get(&key) {
                    if prev.value == s.value {
                        // silent store pair: (prev.idx, idx)
                        results.silent_store_pairs.push((prev.idx, idx));
                    }
                    // Dead store: if since prev store there was NO load -> dead
                    if prev.seen_load_since == false {
                        results.dead_store_pairs.push((prev.idx, idx));
                    }
                }

                // Update last_store: after this store, reset seen_load_since=false
                last_store_map.insert(
                    key,
                    LastStore {
                        idx,
                        value: s.value.clone(),
                        seen_load_since: false,
                    },
                );

                // Note: a store does not update last_load_map (loads tracked separately)
            }

            TraceRecord::LoadRecord(l) => {
                let key = addr_key(l.addr, l.offset);

                // Silent load: compare with last load at this address (if any)
                if let Some(prev) = last_load_map.get(&key) {
                    if prev.value == l.value {
                        results.silent_load_pairs.push((prev.idx, idx));
                    }
                }

                // Update last_load_map
                last_load_map.insert(
                    key,
                    LastLoad {
                        idx,
                        value: l.value.clone(),
                    },
                );

                // For dead-store tracking: mark that since last_store at this address, a load occurred
                if let Some(prev_store) = last_store_map.get_mut(&key) {
                    prev_store.seen_load_since = true;
                }
            }
        }
    }

    results
}