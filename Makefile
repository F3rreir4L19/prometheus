.PHONY: fmt lint test check-all shadow-demo build-fx6300 build-note10

fmt:
	cargo fmt --all --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

check-all: fmt lint test

shadow-demo:
	cargo run -p prometheus-worker -- shadow-mode --scope examples/lab-scope.yaml --targets examples/shadow-targets.txt --action http

build-fx6300:
	cargo build --release --target x86_64-unknown-linux-gnu -p prometheus-worker

build-note10:
	rustup target add aarch64-unknown-linux-musl
	cargo build --release --target aarch64-unknown-linux-musl -p prometheus-control
