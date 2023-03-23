//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::os::fd::AsRawFd;

use log::debug;

use crate::{ensure_c_str, ensure_program_mut_by_state, state::CallerType};

use super::{BpfObjectType, WasmString};

/// attach a bpf program to hook points
pub fn wasm_attach_bpf_program(
    mut caller: CallerType,
    program: BpfObjectType,
    name: WasmString,
    attach_target: WasmString, // Allow null pointers
) -> i32 {
    debug!("wasm attach bpf program");
    let name_str = ensure_c_str!(caller, name);

    let attach_target_str = if attach_target == 0 {
        None
    } else {
        Some(ensure_c_str!(caller, attach_target))
    };
    let state = caller.data_mut();
    let object = ensure_program_mut_by_state!(state, program);

    let program = match object.get_object_mut().prog_mut(&name_str) {
        Some(v) => v,
        None => {
            debug!("No program named `{}` found", name_str);
            return -1;
        }
    };
    if let Some(attach_target) = attach_target_str {
        let section_name = program.section();
        // More attach types could be added
        if section_name == "sockops" {
            let cgroup_file = match std::fs::OpenOptions::new().read(true).open(&attach_target) {
                Ok(v) => v,
                Err(err) => {
                    debug!(
                        "Failed to open cgroup `{}` for attaching: {}",
                        attach_target, err
                    );
                    return -1;
                }
            };
            let fd = cgroup_file.as_raw_fd();
            state.opened_files.push(cgroup_file);
            let link = match program.attach_cgroup(fd) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to attach program to cgroup: {}", err);
                    return -1;
                }
            };
            state.opened_links.push(link);
            return 0;
        }
    }
    let link = match program.attach() {
        Ok(v) => v,
        Err(err) => {
            debug!("Failed to attach link: {}", err);
            return -1;
        }
    };
    state.opened_links.push(link);
    0
}
