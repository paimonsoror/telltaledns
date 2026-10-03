.PHONY: check fmt clippy test deny build bench-smoke bench-proto udp-scaling fuzz

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

# Wire-layer micro-benchmarks (criterion).
bench-proto:
	cargo bench -p telltale-proto --bench hot_path

# T1.2 AC: UDP worker scaling (≥ 3.2× at 4 workers vs 1). Args: per-query work µs, seconds.
udp-scaling:
	cargo run --release -p telltale-net --example udp_scaling -- 20 3

# REQ: NFR-004 — fuzz every target for FUZZ_SECS seconds (needs nightly + cargo-fuzz).
FUZZ_SECS ?= 600
fuzz:
	cd fuzz && for t in parse_query parse_response differential; do \
		cargo +nightly fuzz run $$t -- -max_total_time=$(FUZZ_SECS) -max_len=1500 || exit 1; \
	done
