//! This module contains tests for the runtime.
//!
use flexi_logger::Logger;

use crate::handle::WasmProgramHandle;
use crate::pipe::ReadableWritePipe;
use crate::runner::GetWasmExitCodeHelper;
use crate::state::CallerType;

use super::*;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

/// This function is only needed when running tests, so I put it here.
pub fn get_test_file_path(name: impl AsRef<str>) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push(name.as_ref());
    path
}

enum WaitPolicy<'a> {
    NoWait(&'a mut Option<WasmProgramHandle>),
    WaitUntilTimedOut(u64),
}

fn test_example_and_wait(name: &str, config: Config, wait_policy: WaitPolicy) {
    // Enable epoch interruption, so the wasm program can terminate after timeout_sec seconds.

    let path = get_test_file_path(name);
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    let args = vec!["test".to_string()];
    if let WaitPolicy::NoWait(handle_out) = wait_policy {
        let (wasm_handle, _) = run_wasm_bpf_module_async(&buffer, &args, config).unwrap();
        *handle_out = Some(wasm_handle);
    } else if let WaitPolicy::WaitUntilTimedOut(timeout_sec) = wait_policy {
        let (wasm_handle, join_handle) = run_wasm_bpf_module_async(&buffer, &args, config).unwrap();
        thread::sleep(Duration::from_secs(timeout_sec));
        // What if the wasm programs ends before the timeout_sec? If that happened, terminate will be failing.
        // So there shouldn't be `unwrap`
        wasm_handle.terminate().ok();

        if let Err(e) = join_handle.join().unwrap() {
            if let Some(exit_code) = e.get_wasm_exit_code() {
                // When the wasm program exits abnormally..
                panic!("Wasm program exited abnormally: exit code = {}", exit_code);
            }
            // It was trapped. Right?
            println!("{}", e.to_string());
        }
    }
}

fn test_example(name: &str, config: Config, timeout_sec: u64) {
    test_example_and_wait(name, config, WaitPolicy::WaitUntilTimedOut(timeout_sec));
}

#[test]
fn test_run_tracing_wasm_bpf_module() {
    test_example("execve.wasm", Config::default(), 3);
    test_example("bootstrap.wasm", Config::default(), 3);
    test_example("opensnoop.wasm", Config::default(), 3);
    test_example("rust-bootstrap.wasm", Config::default(), 3);
}

#[test]
fn test_run_network_wasm_bpf_module() {
    test_example("sockfilter.wasm", Config::default(), 3);
    test_example("sockops.wasm", Config::default(), 3);
}

#[test]
fn test_run_lsm_wasm_bpf_module() {
    test_example("lsm.wasm", Config::default(), 3);
}

#[test]
fn test_run_wasm_bpf_module_maps() {
    test_example("runqlat.wasm", Config::default(), 3);
}

#[test]
fn test_run_wasm_bpf_module_with_callback() {
    if let Ok(l) = Logger::try_with_str("debug") {
        l.start().ok();
    }
    let mut config = Config::default();
    config.set_callback_values(
        String::from("go-callback"),
        String::from("callback-wrapper"),
    );
    thread::spawn(move || {
        test_example("go-execve.wasm", config, 3);
    });
    thread::sleep(Duration::from_secs(3));
}

#[test]
fn test_receive_wasm_bpf_module_output() {
    let stdout = ReadableWritePipe::new_vec_buf();
    let stderr = ReadableWritePipe::new_vec_buf();
    let config = Config::new(
        String::from("go-callback"),
        String::from("callback-wrapper"),
        Box::new(stdio::stdin()),
        Box::new(stdout.clone()),
        Box::new(stderr.clone()),
    );
    let mut handle = None;
    test_example_and_wait("execve.wasm", config, WaitPolicy::NoWait(&mut handle));
    let mut already_read_length = 0;
    // Wait for 5s to wait the program warmup
    thread::sleep(Duration::from_secs(5));
    for _ in 0..3 {
        {
            let guard = stdout.get_read_lock();
            let vec_ref = guard.get_ref();
            if vec_ref.len() > already_read_length {
                std::io::stdout()
                    .write_all(&vec_ref[already_read_length..])
                    .unwrap();
                already_read_length = vec_ref.len();
            }
        }
        // Wait 3s, then continue to poll
        thread::sleep(Duration::from_millis(3000));
    }

    // Terminate the wasm program
    handle.unwrap().terminate().unwrap();
}

#[test]
fn test_pause_and_resume_wasm_program() {
    let stdout = ReadableWritePipe::new_vec_buf();
    let stderr = ReadableWritePipe::new_vec_buf();
    let config = Config::new(
        String::from("go-callback"),
        String::from("callback-wrapper"),
        Box::new(stdio::stdin()),
        Box::new(stdout.clone()),
        Box::new(stderr.clone()),
    );
    // Count how many ticks do we have now
    let count_tick = || {
        stdout
            .borrow()
            .get_ref()
            .iter()
            .filter(|v| **v == b'\n')
            .count() as i64
    };
    let mut handle = None;
    test_example_and_wait("tick.wasm", config, WaitPolicy::NoWait(&mut handle));
    // Wait for the program to warmup
    thread::sleep(Duration::from_secs(3));
    let tick_count_1 = count_tick();
    println!("Tick count 1: {}", tick_count_1);
    handle.as_mut().unwrap().pause().unwrap();
    thread::sleep(Duration::from_secs(3));
    handle.as_mut().unwrap().resume().unwrap();
    let tick_count_2 = count_tick();
    println!("Tick count 2: {}", tick_count_2);
    // Tick count should not differ than 1.
    // if the program was paused at 3.9999999s. And the resume function will take 0.0001s, we may got another tick.
    assert!((tick_count_1 - tick_count_2).abs() < 1);
    thread::sleep(Duration::from_secs(3));
    let tick_count_3 = count_tick();
    println!("Tick count 3: {}", tick_count_3);
    assert!(tick_count_3 - tick_count_2 >= 2);
    handle.take().unwrap().terminate().unwrap();
}

#[test]
fn test_custom_host_function() {
    let module_binary = std::fs::read(get_test_file_path("custom_host_func.wasm")).unwrap();
    let args = vec!["test".to_string()];
    let mut runner =
        WasmBpfModuleRunner::new(&module_binary[..], &args[..], Config::default()).unwrap();
    runner
        .register_host_function("host_func_test", "plus_i32", host_func_plus_i32)
        .unwrap();
    let (_, wrapper) = runner.into_engine_and_entry_func().unwrap();
    wrapper.run().unwrap();
}

fn host_func_plus_i32(_caller: CallerType, a: i32, b: i32) -> i32 {
    a + b
}

fn very_long_host_func() {
    println!("Sleeping started..");
    std::thread::sleep(Duration::from_secs(10));
    println!("Sleeping done");
}

#[test]
fn test_interruption_in_host_function() {
    Logger::try_with_str("debug").unwrap().start().unwrap();
    let module_binary = std::fs::read(get_test_file_path("interruption_in_hostfunc.wasm")).unwrap();
    let args = vec!["test".to_string()];

    let (tx, rx) = mpsc::channel::<WasmProgramHandle>();
    std::thread::spawn(move || {
        let mut runner =
            WasmBpfModuleRunner::new(&module_binary[..], &args[..], Config::default()).unwrap();
        runner
            .register_host_function("test", "long_sleep", very_long_host_func)
            .unwrap();
        let (wasm_handle, func_wrapper) = runner.into_engine_and_entry_func().unwrap();
        tx.send(wasm_handle).unwrap();
        func_wrapper.run().unwrap();
    });
    let handle = rx.recv().unwrap();
    std::thread::sleep(Duration::from_secs(2));
    handle.terminate().unwrap();
}

#[test]
fn test_interruption_in_wasm_callback() {
    let module_binary = std::fs::read(get_test_file_path("interruption_in_callback.wasm")).unwrap();
    let args = vec!["test".to_string()];
    let (handle, _) =
        run_wasm_bpf_module_async(&module_binary[..], &args[..], Config::default()).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    handle.terminate().unwrap();
}

#[test]
#[should_panic(expected = "Wasm program exited abnormally")]
fn test_abnormally_exited_wasm_program() {
    test_example_and_wait(
        "abnormal_exit.wasm",
        Config::default(),
        WaitPolicy::WaitUntilTimedOut(5),
    );
}

#[test]
fn test_normally_exited_wasm_program() {
    test_example_and_wait(
        "normal_exit.wasm",
        Config::default(),
        WaitPolicy::WaitUntilTimedOut(5),
    );
}

#[test]
fn test_exit_code_of_interruped_wasm_program() {
    test_example_and_wait(
        "long_sleep.wasm",
        Config::default(),
        WaitPolicy::WaitUntilTimedOut(2),
    );
}
