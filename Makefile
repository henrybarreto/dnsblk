.PHONY: help build build-ebpf run clean

EBPF_DIR := ebpf
IFACE ?= enp4s0
DENY_FILE ?= /etc/deny.txt
help:
	@echo "Targets:"
	@echo "  make build        Build userspace binary (build script builds eBPF)"
	@echo "  make build-ebpf   Build eBPF object (nightly)"
	@echo "  make run          Build CLI, then run with IFACE and DENY_FILE"
	@echo "  make clean        Clean userspace and eBPF build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  IFACE=<iface>     Network interface (default: enp4s0)"
	@echo "  DENY_FILE=<path>  Deny list path (default: /etc/deny.txt)"

build-ebpf:
	cargo build --release --target bpfel-unknown-none -Z build-std=core --manifest-path $(EBPF_DIR)/Cargo.toml

build: build-ebpf
	cargo build -p dnsblk

run: build
	cargo run -p dnsblk -- --interface $(IFACE) $(DENY_FILE)

clean:
	cargo clean
	cargo clean --manifest-path $(EBPF_DIR)/Cargo.toml
