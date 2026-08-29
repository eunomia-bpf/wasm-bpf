//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
//! Tests for the dispatch of the fd-based attach ABI.
//!
//! They pin the section-to-action mapping of `fd_attach_action`, which
//! `wasm_attach_bpf_program_fd` consults before resolving any descriptor. That the resolver
//! runs only in the `AttachCgroupByFd` arm is enforced by the structure of that function,
//! not checked here. None of these tests load an eBPF program or need root.

use crate::bpf::attach::{fd_attach_action, FdAttachAction};

#[test]
fn test_xdp_rejected_with_and_without_fd() {
    assert_eq!(fd_attach_action("xdp", true), FdAttachAction::RejectXdp);
    assert_eq!(fd_attach_action("xdp", false), FdAttachAction::RejectXdp);
}

#[test]
fn test_sockops_with_fd_attaches_by_fd() {
    assert_eq!(
        fd_attach_action("sockops", true),
        FdAttachAction::AttachCgroupByFd
    );
}

#[test]
fn test_sockops_without_fd_auto_attaches() {
    assert_eq!(
        fd_attach_action("sockops", false),
        FdAttachAction::AutoAttach
    );
}

#[test]
fn test_other_sections_auto_attach_with_and_without_fd() {
    for section in ["kprobe/sys_clone", "socket", ""] {
        assert_eq!(fd_attach_action(section, true), FdAttachAction::AutoAttach);
        assert_eq!(fd_attach_action(section, false), FdAttachAction::AutoAttach);
    }
}
