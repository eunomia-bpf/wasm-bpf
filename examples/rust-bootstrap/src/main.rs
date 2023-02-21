#![no_main]

wit_bindgen_guest_rust::generate!("host");
use std::{ffi::CStr, slice};

use wasm_bpf_binding::binding;
#[export_name = "__main_argc_argv"]
fn main(_env_json: u32, _str_len: i32) -> i32 {
    // embed and open the bpf object
    let bpf_object = include_bytes!("../bootstrap.bpf.o");

    // load the object
    let obj_ptr =
        binding::wasm_load_bpf_object(bpf_object.as_ptr() as u32, bpf_object.len() as i32);
    if obj_ptr == 0 {
        println!("Failed to load bpf object");
        return 1;
    }
    // attach bpf program to func
    let attach_result = binding::wasm_attach_bpf_program(
        obj_ptr,
        "handle_exec\0".as_ptr() as u32,
        "\0".as_ptr() as u32,
    );
    if attach_result < 0 {
        println!("Attach handle_exit failed: {}", attach_result);
        return 1;
    }
    // attach bpf program to func
    let attach_result = binding::wasm_attach_bpf_program(
        obj_ptr,
        "handle_exit\0".as_ptr() as u32,
        "\0".as_ptr() as u32,
    );
    if attach_result < 0 {
        println!("Attach handle_exit failed: {}", attach_result);
        return 1;
    }
    // get the map fd for ring buffer
    let map_fd = binding::wasm_bpf_map_fd_by_name(obj_ptr, "rb\0".as_ptr() as u32);
    if map_fd < 0 {
        println!("Failed to get map fd: {}", map_fd);
        return 1;
    }
    // binding::wasm
    let buffer = [0u8; 256];
    loop {
        // polling the buffer
        binding::wasm_bpf_buffer_poll(
            obj_ptr,
            map_fd,
            handle_event as i32,
            0,
            buffer.as_ptr() as u32,
            buffer.len() as i32,
            100,
        );
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Event {
    pid: i32,
    ppid: i32,
    exit_code: u32,
    __pad0: [u8; 4],
    duration_ns: u64,
    comm: [u8; 16],
    filename: [u8; 127],
    exit_event: u8,
}

/// handle ring buffer events
extern "C" fn handle_event(_ctx: u32, data: u32, _data_sz: u32) {
    let event_slice = unsafe { slice::from_raw_parts(data as *const Event, 1) };
    let event = &event_slice[0];
    let pid = event.pid;
    let ppid = event.ppid;
    let exit_code = event.exit_code;
    if event.exit_event == 1 {
        print!(
            "{:<8} {:<5} {:<16} {:<7} {:<7} [{}]",
            "TIME",
            "EXIT",
            unsafe { CStr::from_ptr(event.comm.as_ptr() as *const i8) }
                .to_str()
                .unwrap(),
            pid,
            ppid,
            exit_code
        );
        if event.duration_ns != 0 {
            print!(" ({}ms)", event.duration_ns / 1000000);
        }
        println!("");
    } else {
        println!(
            "{:<8} {:<5} {:<16} {:<7} {:<7} {}",
            "TIME",
            "EXEC",
            unsafe { CStr::from_ptr(event.comm.as_ptr() as *const i8) }
                .to_str()
                .unwrap(),
            pid,
            ppid,
            unsafe { CStr::from_ptr(event.filename.as_ptr() as *const i8) }
                .to_str()
                .unwrap()
        );
    }
}
