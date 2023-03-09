.PHONY: build clean
build:
	cargo build --release
clean:
	cargo clean

.PHONY: test
test:
	cargo install clippy-sarif sarif-fmt grcov
	rustup component add llvm-tools-preview
	CARGO_INCREMENTAL=0 RUSTFLAGS="-Cinstrument-coverage -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off" RUSTDOCFLAGS="-Cpanic=abort" cargo test
	grcov . --binary-path ../target/debug/ --llvm -s . -t html --branch --ignore-not-existing -o ./coverage/
	grcov . --binary-path ../target/debug/ --llvm -s . -t lcov --branch --ignore-not-existing -o ./lcov.info
	cargo clippy --all-features --message-format=json | clippy-sarif | tee rust-clippy-results.sarif | sarif-fmt
	cargo fmt --check