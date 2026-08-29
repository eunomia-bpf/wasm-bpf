//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
//! Tests for the resolution of a guest file descriptor into a host one.
//!
//! Unlike the fixtures next to them, none of these load an eBPF program or need root, so they
//! run wherever the crate is tested. They are where two invariants are checked: a guest cannot
//! name a host directory the runtime did not preopen, and a preopened directory grants the
//! guest nothing but the descriptor it hands to attach.

use std::collections::HashMap;
use std::fs::{self, File};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use wasi_common::{dir::DirCaps, file::FileCaps};
use wasmtime::{Engine, Instance, Linker, Module, Store};
use wasmtime_wasi::{
    ambient_authority, sync::dir::Dir as WasiDirImpl, Dir as CapStdDir, WasiCtx, WasiCtxBuilder,
};

use crate::bpf::fd::resolve_guest_fd_in_state;
use crate::handle::ProgramOperation;
use crate::runner::preopen_config_dirs;
use crate::state::AppState;

/// A directory that exists on every machine these tests run on, which keeps them from having to
/// create anything.
fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Build the state a host function sees, with `dirs` preopened through the same code the runtime
/// runs, and return the descriptor the guest holds for each of them in ascending order.
fn state_with_preopens(dirs: &[PathBuf]) -> (AppState, Vec<u32>) {
    let mut wasi = WasiCtxBuilder::new().build();
    let mapping = dirs
        .iter()
        .enumerate()
        .map(|(idx, dir)| (dir.clone(), PathBuf::from(format!("/preopen{idx}"))))
        .collect::<Vec<_>>();
    let preopen_dirs = preopen_config_dirs(&mut wasi, &mapping).unwrap();
    let mut guest_fds = preopen_dirs.keys().copied().collect::<Vec<_>>();
    guest_fds.sort_unstable();
    let (_operation_tx, operation_rx) = mpsc::channel::<ProgramOperation>();
    let state = AppState::new(wasi, String::default(), operation_rx, preopen_dirs);
    (state, guest_fds)
}

/// Put a directory in the guest's descriptor table without recording a host handle for it, which
/// is what a directory the guest opened for itself looks like to the resolver.
fn push_unrecorded_dir(wasi: &mut WasiCtx, path: &Path) -> u32 {
    let cap_dir = CapStdDir::open_ambient_dir(path, ambient_authority()).unwrap();
    let dir = Box::new(WasiDirImpl::from_cap_std(cap_dir));
    let caps = DirCaps::all();
    let file_caps = FileCaps::all();
    wasi.push_dir(dir, caps, file_caps, path.into()).unwrap()
}

/// What the kernel calls whatever `fd` names, so a resolved descriptor can be compared against
/// the directory it is supposed to be.
fn dev_and_inode(fd: RawFd) -> (libc::dev_t, libc::ino_t) {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fstat` writes only the `stat` it is handed, and `fd` is owned by the caller for
    // the duration of the call.
    let ret = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    assert_eq!(ret, 0, "fstat on fd {fd} failed");
    let stat = unsafe { stat.assume_init() };
    (stat.st_dev, stat.st_ino)
}

/// A guest that pokes at a directory descriptor with the raw WASI calls, compiled from WAT so
/// the test needs no wasm toolchain. Each export takes the descriptor and returns the errno.
/// The memory export is required: wiggle writes out-params through it.
const CAPS_PROBE_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_readdir"
    (func $fd_readdir (param i32 i32 i32 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_prestat_get"
    (func $fd_prestat_get (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; scratch: 0 prestat out, 8 opened-fd out, 16 readdir size out, 32 readdir buffer
  (data (i32.const 512) "present.txt")
  (data (i32.const 528) "made-by-guest.txt")
  (func (export "prestat_get") (param $fd i32) (result i32)
    (call $fd_prestat_get (local.get $fd) (i32.const 0)))
  ;; open the file that exists beneath the preopen: oflags 0, rights fd_read
  (func (export "try_open_existing") (param $fd i32) (result i32)
    (call $path_open (local.get $fd) (i32.const 0) (i32.const 512) (i32.const 11)
      (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 8)))
  ;; create a file that does not exist: oflags creat|excl, rights fd_write
  (func (export "try_create") (param $fd i32) (result i32)
    (call $path_open (local.get $fd) (i32.const 0) (i32.const 528) (i32.const 17)
      (i32.const 5) (i64.const 64) (i64.const 0) (i32.const 0) (i32.const 8)))
  (func (export "try_readdir") (param $fd i32) (result i32)
    (call $fd_readdir (local.get $fd) (i32.const 32) (i32.const 256) (i64.const 0)
      (i32.const 16))))
"#;

/// Instantiate [`CAPS_PROBE_WAT`] against `wasi`, wired up the way the runtime wires a module:
/// the same linker registration and the same state type.
fn instantiate_caps_probe(
    wasi: WasiCtx,
    preopen_dirs: HashMap<u32, File>,
) -> (Store<AppState>, Instance) {
    let engine = Engine::default();
    let module = Module::new(&engine, CAPS_PROBE_WAT).unwrap();
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::add_to_linker(&mut linker, |s: &mut AppState| &mut s.wasi).unwrap();
    let (_operation_tx, operation_rx) = mpsc::channel::<ProgramOperation>();
    let state = AppState::new(wasi, String::default(), operation_rx, preopen_dirs);
    let mut store = Store::new(&engine, state);
    let instance = linker.instantiate(&mut store, &module).unwrap();
    (store, instance)
}

#[test]
fn test_resolve_preopened_dir_fd() {
    let dir = crate_dir();
    let (state, guest_fds) = state_with_preopens(&[dir.clone()]);
    // wasi-common hands out descriptors above stdio, so the only preopen is the guest's fd 3.
    assert_eq!(guest_fds, vec![3]);

    let host_fd = resolve_guest_fd_in_state(&state, guest_fds[0]).unwrap();
    // SAFETY: `F_GETFD` only reads the descriptor table entry of `host_fd`.
    let flags = unsafe { libc::fcntl(host_fd, libc::F_GETFD) };
    assert_ne!(flags, -1, "resolved fd {host_fd} is not open in the host");
    let expected = File::open(dir).unwrap();
    assert_eq!(
        dev_and_inode(host_fd),
        dev_and_inode(expected.as_raw_fd()),
        "resolved fd does not name the preopened directory"
    );
}

#[test]
fn test_resolve_rejects_unopened_fd() {
    let (state, _) = state_with_preopens(&[crate_dir()]);
    assert!(resolve_guest_fd_in_state(&state, 999999).is_err());
}

#[test]
fn test_resolve_rejects_non_directory_fd() {
    let (state, _) = state_with_preopens(&[crate_dir()]);
    // stdio is always seated at 0, 1 and 2: open in the guest, yet nothing the host preopened.
    for fd in 0..=2 {
        assert!(
            resolve_guest_fd_in_state(&state, fd).is_err(),
            "stdio fd {fd} resolved to a host descriptor"
        );
    }
}

#[test]
fn test_resolve_rejects_dir_the_host_did_not_preopen() {
    let (mut state, guest_fds) = state_with_preopens(&[crate_dir()]);
    let guest_opened = push_unrecorded_dir(&mut state.wasi, &crate_dir().join("tests"));
    assert!(!guest_fds.contains(&guest_opened));
    assert!(
        resolve_guest_fd_in_state(&state, guest_opened).is_err(),
        "a directory the guest opened itself resolved to a host descriptor"
    );
    // The preopen is still resolvable, so the rejection above is about that descriptor and not
    // about the state having gone bad.
    assert!(resolve_guest_fd_in_state(&state, guest_fds[0]).is_ok());
}

#[test]
fn test_resolve_rejects_closed_fd() {
    let (mut state, guest_fds) = state_with_preopens(&[crate_dir()]);
    let guest_fd = guest_fds[0];
    assert!(resolve_guest_fd_in_state(&state, guest_fd).is_ok());
    // Dropping the table entry is what closing the descriptor does. The host handle recorded at
    // preopen time outlives it, and must not keep answering for a number the guest no longer
    // holds.
    state.wasi.table().delete(guest_fd);
    assert!(resolve_guest_fd_in_state(&state, guest_fd).is_err());
}

#[test]
fn test_resolve_answers_every_fd_without_panicking() {
    let (state, guest_fds) = state_with_preopens(&[crate_dir(), crate_dir().join("tests")]);
    for fd in (0..64).chain([999999, u32::MAX - 1, u32::MAX]) {
        assert_eq!(
            resolve_guest_fd_in_state(&state, fd).is_ok(),
            guest_fds.contains(&fd),
            "fd {fd} resolved against expectation"
        );
    }
}

#[test]
fn test_preopen_grants_no_filesystem_rights() {
    let unique = format!("wasm-bpf-preopen-caps-{}", std::process::id());
    let dir = std::env::temp_dir().join(unique);
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("present.txt"), b"present").unwrap();

    // The preopen under test goes through preopen_config_dirs, the code the runtime runs.
    let mut wasi = WasiCtxBuilder::new().build();
    let preopen_dirs =
        preopen_config_dirs(&mut wasi, &[(dir.clone(), PathBuf::from("/preopen0"))]).unwrap();
    let guest_fd = *preopen_dirs.keys().next().unwrap();
    let (mut store, instance) = instantiate_caps_probe(wasi, preopen_dirs);
    let mut probe = |name: &str| {
        instance
            .get_typed_func::<i32, i32>(&mut store, name)
            .unwrap()
            .call(&mut store, guest_fd as i32)
            .unwrap()
    };

    // Discovery works without any rights, so the guest still finds the preopen and can pass
    // its number to attach. The denials assert only that the operation fails; the exact errno
    // is a wasi-common detail not worth pinning.
    assert_eq!(probe("prestat_get"), 0);
    assert_ne!(probe("try_open_existing"), 0);
    assert_ne!(probe("try_readdir"), 0);
    assert_ne!(probe("try_create"), 0);
    assert!(resolve_guest_fd_in_state(store.data(), guest_fd).is_ok());
    assert!(
        !dir.join("made-by-guest.txt").exists(),
        "the denied create still made a file on the host"
    );

    // Control: the same probe against the same directory pushed with full capabilities, so the
    // denials above come from the capability check and not from broken plumbing.
    let mut control_wasi = WasiCtxBuilder::new().build();
    let control_fd = push_unrecorded_dir(&mut control_wasi, &dir);
    let (mut control_store, control_instance) =
        instantiate_caps_probe(control_wasi, HashMap::new());
    let mut control_probe = |name: &str| {
        control_instance
            .get_typed_func::<i32, i32>(&mut control_store, name)
            .unwrap()
            .call(&mut control_store, control_fd as i32)
            .unwrap()
    };
    assert_eq!(control_probe("try_open_existing"), 0);
    assert_eq!(control_probe("try_readdir"), 0);
    assert_eq!(control_probe("try_create"), 0);

    fs::remove_dir_all(&dir).ok();
}
