.PHONY: check fmt clippy test deny build bench-smoke

check: fmt clippy test deny

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

deny:
	cargo deny check

build:
	cargo build --release -p telltale

# REQ: NFR-001 — quick benchmark gate run before finishing hot-path tasks (AGENTS.md rule 4).
bench-smoke:
	./bench/run.sh smoke
