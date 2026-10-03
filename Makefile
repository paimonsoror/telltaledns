.PHONY: check fmt clippy test deny build bench-smoke bench-full image image-all bench-proto udp-scaling fuzz

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

# Nightly / release set: every corpus with inputs present, 3 runs, 25-50-75% load points.
bench-full:
	./bench/run.sh full

# REQ: OPS-001 — host-arch image, then the hardened smoke test (read-only, caps dropped, non-root).
image:
	docker buildx build --load -t telltale:dev .
	deploy/image/smoke.sh telltale:dev

# All three platforms into an OCI tarball, then the 15 MiB-per-arch size gate.
image-all:
	docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 --output type=oci,dest=target/telltale-oci.tar .
	python3 deploy/image/size.py --oci target/telltale-oci.tar

# Wire-layer micro-benchmarks (criterion).
bench-proto:
	cargo bench -p telltale-proto --bench hot_path

# T1.2 AC: UDP worker scaling (≥ 3.2× at 4 workers vs 1). Args: per-query work µs, seconds.
udp-scaling:
	cargo run --release -p telltale-net --example udp_scaling -- 20 3

# REQ: NFR-004 — fuzz every target for FUZZ_SECS seconds (needs nightly + cargo-fuzz).
FUZZ_SECS ?= 600
fuzz:
	cd fuzz && for t in parse_query parse_response differential parse_list; do \
		cargo +nightly fuzz run $$t -- -max_total_time=$(FUZZ_SECS) -max_len=1500 || exit 1; \
	done
