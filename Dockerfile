FROM ubuntu:22.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY ./runtime/rust/target/release/wasm-bpf-rs /root/wasm-bpf

WORKDIR /root

ENTRYPOINT ["./wasm-bpf"]
