//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{ffi::CString, os::fd::AsRawFd};

use libc::if_nametoindex;
use log::debug;

use crate::{
    bpf::fd::resolve_guest_fd, ensure_c_str, ensure_program_mut_by_state, state::CallerType,
};

use super::{BpfObjectType, WasmString};

/// attach a bpf program to hook points
///
/// This is the interface-backed half of the attach ABI: a target named by a network interface
/// (`xdp`) belongs here, and a null `attach_target` auto-attaches, as does any section without
/// special handling. A target named by a file, such as the cgroup a `sockops` program attaches
/// to, belongs to `wasm_attach_bpf_program_fd`, which takes a descriptor the guest already holds
/// rather than a path the host has to open.
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

/// attach a bpf program to a hook point named by a file descriptor
///
/// This is the file-backed half of the attach ABI: `sockops` takes the descriptor of the cgroup
/// directory, which the guest must already hold and which resolves to the host descriptor the
/// runtime recorded when it preopened that directory, so no path from the guest is opened here.
/// A negative `target_fd` means no target and auto-attaches, as does any section without special
/// handling. An interface-backed target (`xdp`) is named by an interface rather than a file and
/// is rejected; it stays on `wasm_attach_bpf_program`.
pub fn wasm_attach_bpf_program_fd(
    mut caller: CallerType,
    program: BpfObjectType,
    name: WasmString,
    target_fd: i32, // Negative values mean no attach target
) -> i32 {
    debug!("wasm attach bpf program by fd");
    let name_str = ensure_c_str!(caller, name);
    // Resolving reads the WASI descriptor table out of the state, so it has to finish before the
    // bpf object is borrowed mutably out of that same state.
    let host_fd = if target_fd < 0 {
        None
    } else {
        match resolve_guest_fd(&mut caller, target_fd as u32) {
            Ok(v) => Some(v),
            Err(err) => {
                debug!("Failed to resolve attach fd {}: {}", target_fd, err);
                return -1;
            }
        }
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
    match program.section() {
        "sockops" => {
            if let Some(cgroup_fd) = host_fd {
                let link = match program.attach_cgroup(cgroup_fd) {
                    Ok(v) => v,
                    Err(err) => {
                        debug!("Failed to attach program to cgroup: {}", err);
                        return -1;
                    }
                };
                debug!("sockops attached with link {:?}", link);
                state.opened_links.push(link);
                return 0;
            }
            debug!(
                "No attach target given for sockops program `{}`, will try auto attaching",
                name_str
            );
        }
        "xdp" => {
            debug!(
                "`{}` is an xdp program; xdp attaches to a network interface rather than to a \
                 file, so it has no descriptor to resolve. Use wasm_attach_bpf_program with the \
                 interface name instead",
                name_str
            );
            return -1;
        }
        s => {
            debug!(
                "Unsupported special attach type: {}, will try auto attaching",
                s
            );
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
