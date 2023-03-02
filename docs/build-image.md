## Docker image

build the docker images

```sh
make build-rust
docker build -t ghcr.io/eunomia-bpf/wasm-bpf:latest .
```

```sh
docker run --rm -it --privileged -p 9435:9435 \
  -v $(pwd)/examples:/examples \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  ghcr.io/eunomia-bpf/wasm-bpf:latest /examples/bootstrap/bootstrap.wasm
```
