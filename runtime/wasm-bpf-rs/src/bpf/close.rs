//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::collections::hash_map::Entry;

use log::debug;

use crate::state::CallerType;

use super::BpfObjectType;

/// close and detach a bpf object
pub fn wasm_close_bpf_object(mut caller: CallerType, program: BpfObjectType) -> i32 {
    debug!("Close bpf object: {}", program);
    let state = caller.data_mut();
    match state.object_map.entry(program) {
        Entry::Occupied(v) => {
            v.remove();
            0
        }
        Entry::Vacant(_) => {
            debug!("Invalid bpf object id: {}", program);
            -1
        }
    }
}
