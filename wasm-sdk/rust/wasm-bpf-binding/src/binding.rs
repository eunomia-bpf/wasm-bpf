//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
pub type Uint64T = u64;
pub type Uint32T = u32;
pub type Int32T = i32;
pub type BpfObjectSkel = Uint64T;
pub fn wasm_bpf_map_operate(
    fd: i32,
    cmd: i32,
    key: u64,
    value: u64,
    next_key: u64,
    flags_s: Uint64T,
) -> i32 {
    unsafe {
        #[link(wasm_import_module = "wasm_bpf")]
        extern "C" {
            #[link_name = "wasm_bpf_map_operate"]
            fn wit_import(_: i32, _: i32, _: i64, _: i64, _: i64, _: i64) -> i32;
        }
        wit_import(
            fd as i32,
            cmd as i32,
            key as i64,
            value as i64,
            next_key as i64,
            flags_s as i64,
        )
    }
}
pub fn wasm_bpf_buffer_poll(
    program: BpfObjectSkel,
    fd: i32,
    sample_func: Int32T,
    ctx: Uint32T,
    data: u32,
    max_size: i32,
    timeout_ms: i32,
) -> i32 {
    unsafe {
        #[link(wasm_import_module = "wasm_bpf")]
        extern "C" {
            #[link_name = "wasm_bpf_buffer_poll"]
            fn wit_import(_: i64, _: i32, _: i32, _: i32, _: i32, _: i32, _: i32) -> i32;
        }
        let ret = wit_import(
            program as i64,
            fd as i32,
            sample_func as i32,
            ctx as i32,
            data as i32,
            max_size as i32,
            timeout_ms as i32
        );
        ret
    }
}
pub fn wasm_attach_bpf_program(
    obj: BpfObjectSkel,
    name: u32,
    attach_target: u32,
) -> i32 {
    unsafe {
        #[link(wasm_import_module = "wasm_bpf")]
        extern "C" {
            #[link_name = "wasm_attach_bpf_program"]
            fn wit_import(_: i64, _: i32, _: i32) -> i32;
        }
        let ret = wit_import(
            obj as i64,
            name as i32,
            attach_target as i32
        );
        ret
    }
}
pub fn wasm_load_bpf_object(obj_buf: u32, obj_buf_sz: i32) -> BpfObjectSkel {
    unsafe {
        #[link(wasm_import_module = "wasm_bpf")]
        extern "C" {
            #[link_name = "wasm_load_bpf_object"]
            fn wit_import(_: i32, _: i32) -> i64;
        }
        let ret = wit_import(
            obj_buf as i32,
            obj_buf_sz as i32
        );
        ret as u64
    }
}
pub fn wasm_close_bpf_object(obj: BpfObjectSkel) -> i32 {
    unsafe {
        #[link(wasm_import_module = "wasm_bpf")]
        extern "C" {
            #[link_name = "wasm_close_bpf_object"]
            fn wit_import(_: i64) -> i32;
        }
        let ret = wit_import(obj as i64);
        ret
    }
}
pub fn wasm_bpf_map_fd_by_name(obj: BpfObjectSkel, name: u32) -> i32 {
    unsafe {
        #[link(wasm_import_module = "wasm_bpf")]
        extern "C" {
            #[link_name = "wasm_bpf_map_fd_by_name"]
            fn wit_import(_: i64, _: i32) -> i32;
        }
        let ret = wit_import(
            obj as i64,
            name as i32
        );
        ret
    }
}
