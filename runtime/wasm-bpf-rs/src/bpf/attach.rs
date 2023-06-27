//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{ffi::CString, os::fd::AsRawFd};

use libc::if_nametoindex;
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
    let mut object_guard = object.get_object_mut();
    let program = match object_guard.prog_mut(&name_str) {
        Some(v) => v,
        None => {
            debug!("No program named `{}` found", name_str);
            return -1;
        }
    };
    if let Some(attach_target) = attach_target_str {
        let section_name = program.section();
        // More attach types could be added
        match section_name {
            "sockops" => {
                let cgroup_file = match std::fs::OpenOptions::new().read(true).open(&attach_target)
                {
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
                debug!("secops attached with link {:?}", link);
                state.opened_links.push(link);
                return 0;
            }
            "xdp" => {
                debug!("Processing xdp attach to {:?}", attach_target);
                let name_str = match CString::new(attach_target.as_bytes()) {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("Failed to convert xdp interface name to CStr: {}", e);
                        return -1;
                    }
                };
                // SAFETY: The input string is guaranteed to be correct
                let ifidx = unsafe { if_nametoindex(name_str.as_ptr()) };
                if ifidx == 0 {
                    let e = errno::errno();
                    debug!("Failed to get if idx, err={}, errno={}", e, e.0);
                    return -e.0;
                }
                let link = match program.attach_xdp(ifidx as i32) {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("Failed to attach xdp: {}", e);
                        return -1;
                    }
                };
                debug!("xdp attached with link {:?}", link);
                state.opened_links.push(link);
                return 0;
            }
            s => {
                debug!(
                    "Unsupported special attach type: {}, will try auto attaching",
                    s
                );
            }
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
