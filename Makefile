.PHONY: help build build-ebpf run clean

EBPF_DIR := dnsblk-ebpf
RUST_STABLE ?= +stable
RUST_NIGHTLY ?= +nightly
IFACE ?= enp4s0
DENY_FILE ?= /etc/deny.txt
help:
	@echo "Targets:"
	@echo "  make build        Build eBPF (nightly) + CLI binary (stable)"
	@echo "  make build-ebpf   Build eBPF object (nightly)"
	@echo "  make run          Build CLI, then run with IFACE and DENY_FILE"
	@echo "  make clean        Clean userspace and eBPF build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  IFACE=<iface>     Network interface (default: enp4s0)"
	@echo "  DENY_FILE=<path>  Deny list path (default: /etc/deny.txt)"

build-ebpf:
	cd $(EBPF_DIR) && cargo $(RUST_NIGHTLY) build --release --target bpfel-unknown-none -Z build-std=core

build: build-ebpf
	cargo $(RUST_STABLE) build -p dnsblk

run: build
	cargo $(RUST_STABLE) run -p dnsblk -- --interface $(IFACE) $(DENY_FILE)

clean:
	cargo clean
	cd $(EBPF_DIR) && cargo clean
