//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use log::debug;

use crate::{ensure_c_str, ensure_program_mut_by_caller, state::CallerType};

use super::{BpfObjectType, WasmString};

/// get map fd by name from a bpf object
pub fn wasm_bpf_map_fd_by_name(
    mut caller: CallerType,
    program: BpfObjectType,
    name: WasmString,
) -> i32 {
    debug!("map fd by name");
    let map_name = ensure_c_str!(caller, name);
    let object = ensure_program_mut_by_caller!(caller, program);
    let object_guard = object.get_object();
    let map = match object_guard.map(&map_name) {
        Some(v) => v,
        None => {
            debug!("Invalid map name: {}", map_name);
            return -1;
        }
    };

    map.fd()
}
