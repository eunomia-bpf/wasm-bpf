#include "bpf-api.h"

#include <assert.h>
#include <fstream>
#include <iostream>
#include <string>
struct TestModule {
    const char* file_name;
    const char* desc;
};

static TestModule TEST_MODULES[] = {
    {.file_name = "memory_test_1.wasm",
     .desc = "Test that if wasm-bpf an handle a buffer of invalid length when "
             "loading bpf program"},
    {.file_name = "memory_test_2.wasm",
     .desc = "Test that if wasm-bpf can handle an invalid string"}};

int main() {
    for (const auto& item : TEST_MODULES) {
        using namespace std;
        cout << "Performing test for `" << item.file_name << "`" << endl;
        cout << "Desc: " << item.desc << endl;
        ifstream module_file(string("../../test/wasm-apps/") + item.file_name);
        assert((bool)module_file);
        vector<uint8_t> wasm_module((istreambuf_iterator<char>(module_file)),
                                    istreambuf_iterator<char>());
        const char* args[] = {"wasm-bpf", item.file_name};
        int ret = wasm_main(wasm_module.data(),
                            (unsigned int)wasm_module.size(), 2, (char**)args);
        cout << "exit code = " << ret << endl;
        assert(ret == 0);
        cout << "Test for " << item.file_name << " done" << endl;
        cout << endl;
        cout << endl;
    }
    return 0;
}