#! /usr/bin/env bash

# Usage: ./clang-format.sh /usr/bin/clang-format(version >= 10.0) [-f]
# Specify -f to format all c/cxx files, instead of check if the files satisfy the format file

lint() {
    local targets="examples wasm-sdk runtime/cpp/include runtime/cpp/test runtime/cpp/src"
    local clang_format="${1}"

    if [ "$#" -lt 1 ]; then
        echo "please provide clang-format command. Usage ${0} `which clang-format`"
        exit 1
    fi

    if [ ! -f "${clang_format}" ]; then
        echo "clang-format not found. Please install clang-format first"
        exit 1
    fi
    local ext_args="-Werror --dry-run"
    if [ "${2}" = "-f" ]; then
        ext_args=""
    fi
    find ${targets} -type f -iname *.[ch] -o -iname *.cpp -o -iname *.[ch]xx \
        | xargs -n1 ${clang_format} -i -style=file ${ext_args}

    exit $?
}

lint $@
