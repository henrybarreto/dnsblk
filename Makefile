.PHONY: help build build-ebpf run clean

EBPF_DIR := dnsblk-ebpf
RUST_STABLE ?= +stable
RUST_NIGHTLY ?= +nightly
IFACE ?= enp4s0
DENY_FILE ?= /etc/deny.txt
CARGO_TARGET_DIR ?= /tmp/dnsblk-target-0

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

build: build-ebpf
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR)/user 	cargo $(RUST_STABLE) build -p dnsblk

build-ebpf:
	cd $(EBPF_DIR) && CARGO_TARGET_DIR=$(CARGO_TARGET_DIR)/ebpf \
		cargo $(RUST_NIGHTLY) build --release --target bpfel-unknown-none -Z build-std=core
	mkdir -p $(EBPF_DIR)/target/bpfel-unknown-none/release
	cp $(CARGO_TARGET_DIR)/ebpf/bpfel-unknown-none/release/libdnsblk_ebpf.so \
	   $(EBPF_DIR)/target/bpfel-unknown-none/release/libdnsblk_ebpf.so

run: build
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR)/user 	cargo $(RUST_STABLE) run -p dnsblk -- --interface $(IFACE) $(DENY_FILE)

clean:
	CARGO_TARGET_DIR=$(CARGO_TARGET_DIR)/user 	cargo clean -p dnsblk
	cd $(EBPF_DIR) && CARGO_TARGET_DIR=$(CARGO_TARGET_DIR)/ebpf cargo clean
	rm -rf $(EBPF_DIR)/target
