//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

// Do we really need `unsafe` on FFI functions? I don't think :)
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::{
    ffi::{c_char, c_int, c_ulonglong, CStr},
    slice,
    thread::JoinHandle,
};

use wasm_bpf_rs::{handle::WasmProgramHandle, Config};
unsafe fn dump_strings_from_argv(argv: *const *const c_char, argc: c_int) -> Vec<String> {
    let mut args_vec = vec![];
    for i in 0..argc {
        let curr = { *argv.offset(i as isize) };
        let curr = { CStr::from_ptr(curr) }.to_string_lossy().to_string();
        args_vec.push(curr);
    }
    args_vec
}

#[no_mangle]
/// Run a module sync
/// error_callback will be called if any error happened
pub extern "C" fn wasm_bpf_module_run(
    module_binary: *const u8,
    module_binary_size: c_ulonglong,
    argv: *const *const c_char,
    argc: c_int,
    error_callback: Option<unsafe extern "C" fn(*const c_char)>,
) -> i32 {
    let module_binary =
        unsafe { slice::from_raw_parts(module_binary, module_binary_size as usize) };
    let args_vec = unsafe { dump_strings_from_argv(argv, argc) };
    if let Err(e) = wasm_bpf_rs::run_wasm_bpf_module(module_binary, &args_vec, Config::default()) {
        if let Some(cb) = error_callback {
            let ptr = e.to_string().as_ptr() as *const c_char;

            unsafe { cb(ptr) };
        }
        return -1;
    }
    0
}

#[no_mangle]
/// Run a module async
/// error_callback will be called if any error happened
/// returns a handle to control the program, if succeeded; else returns null
pub extern "C" fn wasm_bpf_module_run_async(
    module_binary: *const u8,
    module_binary_size: c_ulonglong,
    argv: *const *const c_char,
    argc: c_int,
    error_callback: Option<unsafe extern "C" fn(*const c_char)>,
) -> Option<Box<WrappedHandle>> {
    let module_binary =
        unsafe { slice::from_raw_parts(module_binary, module_binary_size as usize) };
    let args_vec = unsafe { dump_strings_from_argv(argv, argc) };
    let (prog_hd, join_hd) =
        match wasm_bpf_rs::run_wasm_bpf_module_async(module_binary, &args_vec, Config::default()) {
            Ok(v) => v,
            Err(e) => {
                if let Some(cb) = error_callback {
                    let ptr = e.to_string().as_ptr() as *const c_char;

                    unsafe { cb(ptr) };
                }
                return None;
            }
        };
    Some(Box::new(WrappedHandle {
        prog_handle: Some(prog_hd),
        join_handle: Some(join_hd),
    }))
}

#[repr(C)]
/// A wrapped handle
pub struct WrappedHandle {
    prog_handle: Option<WasmProgramHandle>,
    join_handle: Option<JoinHandle<anyhow::Result<()>>>,
}
#[no_mangle]
/// Destroy the handle
/// Destroying the handle will not terminate the running program
pub extern "C" fn wasm_bpf_handle_destroy(handle: Box<WrappedHandle>) {
    drop(handle);
}
#[no_mangle]
/// Pause the program
pub extern "C" fn wasm_bpf_handle_pause_prog(handle: *mut WrappedHandle) -> i32 {
    let handle = unsafe { &mut *handle };
    if let Some(hd) = &mut handle.prog_handle {
        if hd.pause().is_err() {
            return -1;
        }
    } else {
        return -1;
    }
    0
}

#[no_mangle]
/// Resume the program
pub extern "C" fn wasm_bpf_handle_resume_prog(handle: *mut WrappedHandle) -> i32 {
    let handle = unsafe { &mut *handle };
    if let Some(hd) = &mut handle.prog_handle {
        if  hd.resume().is_err() {
            return -1;
        }
    } else {
        return -2;
    }
    0
}

#[no_mangle]
/// Terminate the program
pub extern "C" fn wasm_bpf_handle_terminate_prog(handle: *mut WrappedHandle) -> i32 {
    let handle = unsafe { &mut *handle };
    if let Some(hd) = handle.prog_handle.take() {
        if hd.terminate().is_err() {
            return -1;
        }
    } else {
        return -2;
    }
    0
}

#[no_mangle]
/// Wait for the program's exiting
pub extern "C" fn wasm_bpf_handle_join_prog(handle: *mut WrappedHandle) -> i32 {
    let handle = unsafe { &mut *handle };
    if let Some(hd) = handle.join_handle.take() {
        if hd.join().is_err() {
            return -1;
        }
    } else {
        return -2;
    }
    0
}
