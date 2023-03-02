## Docker image

build the docker images

```sh
make build-rust
docker build -t ghcr.io/eunomia-bpf/wasm-bpf:latest .
```

```sh
wget https://eunomia-bpf.github.io/wasm-bpf/examples/bootstrap/bootstrap.wasm
docker run --rm -it --privileged \
  -v $(pwd):/examples \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  ghcr.io/eunomia-bpf/wasm-bpf:latest /examples/bootstrap.wasm
```
