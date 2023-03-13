
use crate::pipe::ReadableWritePipe;

use super::*;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;


// This function is only needed when running tests, so I put it here.
pub fn get_test_file_path(name: impl AsRef<str>) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push(name.as_ref());
    path
}

enum WaitPolicy<'a> {
    NoWait(&'a mut Option<Engine>),
    WaitUntilTimedOut(u64),
}

fn test_example_and_wait(name: &str, config: Config, wait_policy: WaitPolicy) {
    // Enable epoch interruption, so the wasm program can terminate after timeout_sec seconds.
    let config = config.set_epoch_interruption(true);

    let path = get_test_file_path(name);
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    let args = vec!["test".to_string()];
    if let WaitPolicy::NoWait(engine_out) = wait_policy {
        // If we don't want to wait, then just open a new thread to run the wasm program
        // and return the engine, which can be used to increase epoch
        // So that the user can terminate the wasm program manually
        let (tx, rx) = std::sync::mpsc::channel::<Engine>();
        thread::spawn(move || {
            let (engine, func) = WasmBpfModuleRunner::new(&buffer, &args, config)
                .unwrap()
                .into_engine_and_entry_func()
                .unwrap();
            tx.send(engine).unwrap();
            let result = func.run();
            if let Err(e) = result {
                // We can't distinguish epoch trap and other errors easily...
                println!("{}", e.to_string());
            }
        });

        *engine_out = Some(rx.recv().unwrap());
    } else if let WaitPolicy::WaitUntilTimedOut(timeout_sec) = wait_policy {
        // If we are going to wait for `timeout_sec` and terminate the wasm program
        // Then we just spawn a new thread to sleep and increase epoch
        // The original thread is used to run the wasm program
        let (engine, func) = WasmBpfModuleRunner::new(&buffer, &args, config)
            .unwrap()
            .into_engine_and_entry_func()
            .unwrap();
        // Run the Wasm module for 3 seconds in another thread
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_secs(timeout_sec));
            // kill the thread
            // There will be an epoch interruption in the wasm program.
            engine.increment_epoch();
        });
        let result = func.run();
        if let Err(e) = result {
            // We can't distinguish epoch trap and other errors easily...
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
    test_example("lsm.wasm", Config::default(), 3);
    test_example("rust-bootstrap.wasm", Config::default(), 3);
}

#[test]
fn test_run_network_wasm_bpf_module() {
    test_example("sockfilter.wasm", Config::default(), 3);
    test_example("sockops.wasm", Config::default(), 3);
}

#[test]
fn test_run_wasm_bpf_module_maps() {
    test_example("runqlat.wasm", Config::default(), 3);
}

#[test]
fn test_run_wasm_bpf_module_with_callback() {
    let mut config = Config::default();
    config.set_callback_values(
        String::from("go-callback"),
        String::from("callback-wrapper"),
    );
    test_example("go-execve.wasm", config, 3);
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
        true,
    );
    let mut engine = None;
    test_example_and_wait("execve.wasm", config, WaitPolicy::NoWait(&mut engine));
    let mut already_read_length = 0;
    // Wait for 5s to wait the program warmup
    thread::sleep(Duration::from_secs(5));
    for _ in 0..30 {
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
        // Wait 0.1s, then continue to poll
        thread::sleep(Duration::from_millis(100));
    }

    // Terminate the wasm program
    engine.unwrap().increment_epoch();
}
