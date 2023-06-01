use std::{ffi::CStr, slice, time::Duration};

use anyhow::{anyhow, Context, Result};
use wasm_bpf_libbpf_rs::{object::ObjectBuilder, poll::PollBuilder};

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

fn main() -> Result<()> {
    let bpf_object = include_bytes!("../bootstrap.bpf.o");
    let obj = ObjectBuilder::default()
        .open_memory(bpf_object)
        .with_context(|| anyhow!("Failed to open"))?
        .load()
        .with_context(|| anyhow!("Failed to load"))?;
    obj.prog("handle_exec").unwrap().attach()?;
    let map = obj.map("rb").unwrap();
    let mut buf = [0u8; 2048];
    let poll = PollBuilder::new(&map, &mut buf)
        .sample_cb(|v| {
            let event_slice = unsafe { slice::from_raw_parts(v.as_ptr() as *const Event, 1) };
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
                println!();
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
            0
        })
        .build();
    loop {
        poll.poll(Duration::from_millis(100))?;
    }
}
