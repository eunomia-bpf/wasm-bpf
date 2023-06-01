use anyhow::{anyhow, Context};
use plain::Plain;
use std::ffi::c_char;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use std::{ffi::CStr, fmt::Debug};
use wasm_bpf_libbpf_rs::{object::ObjectBuilder, poll::PollBuilder};

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

fn main() -> anyhow::Result<()> {
    let bpf_object = include_bytes!("../tcpconnlat.bpf.o");
    let obj = ObjectBuilder::default()
        .open_memory(&bpf_object[..])
        .with_context(|| anyhow!("Failed to open object"))?
        .load()
        .with_context(|| anyhow!("Failed to load object"))?;
    obj.prog("fentry_tcp_v4_connect").unwrap().attach()?;
    obj.prog("fentry_tcp_v6_connect").unwrap().attach()?;
    obj.prog("fentry_tcp_rcv_state_process").unwrap().attach()?;
    obj.prog("tcp_destroy_sock").unwrap().attach()?;
    let map = obj.map("events").unwrap();
    let mut data_buf = [0u8; 2048];
    let mut start_ts = 0;
    let poll = PollBuilder::new(&map, &mut data_buf)
        .sample_cb(|v| handle_event(v, &mut start_ts))
        .build();
    println!(
        "{:<9} {:<6} {:<12} {:<2} {:<16} {:<6} {:<16} {:<5} LAT(ms)",
        "TIME(s)", "PID", "COMM", "IP", "SADDR", "LPORT", "DADDR", "DPORT"
    );
    loop {
        poll.poll(Duration::from_millis(100))?;
    }
}

fn handle_event(data: &[u8], start_ts: &mut u64) -> i32 {
    let event = Event::from_bytes(data).unwrap();
    if *start_ts == 0 {
        *start_ts = event.ts_us;
    }
    let (sddr, daddr) = match event.af {
        AF_INET => (
            Ipv4Addr::from(unsafe { event.saddr.v4 }.to_ne_bytes()).to_string(),
            Ipv4Addr::from(unsafe { event.daddr.v4 }.to_ne_bytes()).to_string(),
        ),
        AF_INET6 => (
            Ipv6Addr::from(unsafe { event.saddr.v6 }).to_string(),
            Ipv6Addr::from(unsafe { event.daddr.v6 }).to_string(),
        ),
        s => {
            eprintln!("Invalid AF: {}", s);
            return 0;
        }
    };
    print!("{:<9.3} ", (event.ts_us - *start_ts) as f64 / 1000000.0);
    println!(
        "{:<6} {:<12} {:<2} {:<16} {:<6} {:<16} {:<5} {:.2}",
        event.tgid,
        unsafe { CStr::from_ptr(event.comm.as_ptr() as *const c_char) }.to_string_lossy(),
        if event.af == AF_INET { "v4" } else { "v6" },
        sddr,
        event.lport,
        daddr,
        u16::from_be(event.dport),
        event.delta_us as f64 / 1000.0
    );

    0
}

#[repr(C)]
#[derive(Default, Debug)]
struct Event {
    saddr: Addr,
    daddr: Addr,
    comm: [u8; 16],
    delta_us: u64,
    ts_us: u64,
    tgid: u32,
    af: i32,
    lport: u16,
    dport: u16,
}

// SAFE: Event satisfies all the requirements of `Plain`.
unsafe impl Plain for Event {}

#[repr(C)]
union Addr {
    v4: u32,
    v6: [u8; 16],
}

impl Default for Addr {
    fn default() -> Self {
        Self {
            v6: Default::default(),
        }
    }
}

impl Debug for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v4 = unsafe { self.v4 };
        let v6 = unsafe { self.v6 };
        write!(f, "v4: {}, v6:{:?}", v4, v6)
    }
}
