//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{collections::HashMap, fs::File, ptr::null, sync::mpsc};

use libbpf_rs::{
    libbpf_sys::{self, bpf_map, bpf_map__fd, bpf_object__next_map},
    Link, Map, Object, Program,
};
use wasmtime::Caller;
use wasmtime_wasi::WasiCtx;

use crate::{bpf::poll::BpfBuffer, handle::ProgramOperation};

const FIRST_OBJECT_ID: u64 = 1;

pub struct WrapperObject {
    pub object: Object,
    pub buffer: Option<BpfBuffer>,
}

impl WrapperObject {
    pub fn get_object(&self) -> &Object {
        &self.object
    }
    pub fn get_object_mut(&mut self) -> &mut Object {
        &mut self.object
    }
}

pub struct AppState {
    pub wasi: WasiCtx,
    pub next_object_id: u64,
    pub object_map: HashMap<u64, WrapperObject>,
    pub opened_files: Vec<File>,
    pub opened_links: Vec<Link>,
    pub callback_func_name: String,
    pub wrapper_called: bool,
    pub operation_rx: mpsc::Receiver<ProgramOperation>,
}

#[allow(unused)]
struct MyObject {
    pub ptr: *mut libbpf_sys::bpf_object,
    _maps: HashMap<String, Map>,
    _progs: HashMap<String, Program>,
}

impl AppState {
    pub fn new(
        wasi: WasiCtx,
        callback_func_name: String,
        operation_rx: mpsc::Receiver<ProgramOperation>,
    ) -> Self {
        Self {
            wasi,
            next_object_id: FIRST_OBJECT_ID,
            object_map: HashMap::default(),
            opened_files: vec![],
            opened_links: vec![],
            callback_func_name,
            wrapper_called: false,
            operation_rx,
        }
    }
    pub fn get_map_ptr_by_fd(&self, fd: i32) -> Option<*const bpf_map> {
        for prog in self.object_map.values() {
            unsafe {
                let ptr = prog.get_object() as *const Object as *const MyObject;
                let bpf_object_ptr = (*ptr).ptr;
                let mut pos = bpf_object__next_map(bpf_object_ptr, null());
                while !pos.is_null() {
                    if bpf_map__fd(pos) == fd {
                        return Some(pos);
                    }
                    pos = bpf_object__next_map(bpf_object_ptr, pos);
                }
            }
        }
        None
    }
}

pub type CallerType<'a> = Caller<'a, AppState>;
