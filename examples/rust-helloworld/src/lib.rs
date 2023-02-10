wit_bindgen_guest_rust::generate!("host");

#[export_name = "bpf_main"]
fn bpf_main(env_json: u32, str_len: i32) -> i32 {
    println!("Hello world!");
    println!("{} {}", env_json, str_len);
    return 0;
}
