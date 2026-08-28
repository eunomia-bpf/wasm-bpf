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

/// What [`wasm_attach_bpf_program_fd`] does for a program. The decision is made from the
/// section name before any descriptor is resolved.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FdAttachAction {
    /// Resolve the target descriptor and attach to the cgroup it names.
    AttachCgroupByFd,
    /// Refuse the attach: xdp targets an interface, not a file.
    RejectXdp,
    /// Attach without a target. A descriptor passed to such a section is not consulted.
    AutoAttach,
}

/// Pick the [`FdAttachAction`] for a section. Runs before any descriptor is resolved, so it
/// sees only whether a target was passed, never what it resolves to.
pub(crate) fn fd_attach_action(section: &str, has_target_fd: bool) -> FdAttachAction {
    match (section, has_target_fd) {
        ("sockops", true) => FdAttachAction::AttachCgroupByFd,
        ("xdp", _) => FdAttachAction::RejectXdp,
        _ => FdAttachAction::AutoAttach,
    }
}

/// attach a bpf program to a hook point named by a file descriptor
///
/// This is the file-backed half of the attach ABI: `sockops` takes the descriptor of the cgroup
/// directory, which the guest must already hold and which resolves to the host descriptor the
/// runtime recorded when it preopened that directory, so no path from the guest is opened here.
/// The section decides what happens before any descriptor is resolved: only a `sockops` program
/// with a target resolves one. A negative `target_fd` means no target and auto-attaches, as does
/// any section without special handling; a descriptor passed to such a section is ignored. An
/// interface-backed target (`xdp`) is named by an interface rather than a file and is rejected
/// without touching the descriptor; it stays on `wasm_attach_bpf_program`.
pub fn wasm_attach_bpf_program_fd(
    mut caller: CallerType,
    program: BpfObjectType,
    name: WasmString,
    target_fd: i32, // Negative values mean no attach target
) -> i32 {
    debug!("wasm attach bpf program by fd");
    let name_str = ensure_c_str!(caller, name);
    // Clone the object handle out of the state so no state borrow is held across the match:
    // the sockops arm resolves the descriptor, and resolving reads the state again.
    let object_rc = {
        let state = caller.data_mut();
        let object = ensure_program_mut_by_state!(state, program);
        object.get_object_rc()
    };
    let mut object_guard = object_rc.borrow_mut();
    let prog = match object_guard.prog_mut(&name_str) {
        Some(v) => v,
        None => {
            debug!("No program named `{}` found", name_str);
            return -1;
        }
    };
    match fd_attach_action(prog.section(), target_fd >= 0) {
        FdAttachAction::RejectXdp => {
            debug!(
                "`{}` is an xdp program; xdp attaches to a network interface rather than to a \
                 file, so it has no descriptor to resolve. Use wasm_attach_bpf_program with the \
                 interface name instead",
                name_str
            );
            -1
        }
        FdAttachAction::AttachCgroupByFd => {
            let host_fd = match resolve_guest_fd(&mut caller, target_fd as u32) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to resolve attach fd {}: {}", target_fd, err);
                    return -1;
                }
            };
            let link = match prog.attach_cgroup(host_fd) {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to attach program to cgroup: {}", err);
                    return -1;
                }
            };
            debug!("sockops attached with link {:?}", link);
            caller.data_mut().opened_links.push(link);
            0
        }
        FdAttachAction::AutoAttach => {
            if prog.section() == "sockops" {
                debug!(
                    "No attach target given for sockops program `{}`, will try auto attaching",
                    name_str
                );
            } else {
                debug!(
                    "Unsupported special attach type: {}, will try auto attaching",
                    prog.section()
                );
            }
            let link = match prog.attach() {
                Ok(v) => v,
                Err(err) => {
                    debug!("Failed to attach link: {}", err);
                    return -1;
                }
            };
            caller.data_mut().opened_links.push(link);
            0
        }
    }
}
