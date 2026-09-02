set(sources
    src/wasm-bpf.cpp
)

set(exe_sources
		src/main.cpp
		${sources}
)

set(headers
    include/
)

EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )

set(third_party_headers
    third_party/includes/
    third_party/bpftool/libbpf/include/uapi
    third_party/bpftool/libbpf/
)

set(skel_includes
)

set(test_sources
    src/attach_dispatch_test.cpp
    src/attach_fd_e2e_test.cpp
    src/bpf_api_test.cpp
    src/hostile_init_e2e_test.cpp
    src/memory_check_test_driver.cpp
)
