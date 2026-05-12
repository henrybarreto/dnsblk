# dnsblk

![rust edition](https://img.shields.io/badge/rust-2021-black)
![eBPF](https://img.shields.io/badge/eBPF-TC-orange)
![status](https://img.shields.io/badge/status-experimental-orange)

`dnsblk` is an **eBPF learning project** that blocks DNS queries to domains on
a deny list by attaching a TC (traffic control) classifier to a network
interface. The eBPF program inspects UDP/53 packets, hashes the domain name
using FNV-1a, and drops queries that match entries loaded from a deny file.

## Installation

Build the eBPF object and CLI binary with the provided Makefile:

```bash
make build
```

Run the benchmark suite:

```bash
cargo test
```

## Quick Start

```bash
make run IFACE=eth0 DENY_FILE=/etc/deny.txt
```

Or with Cargo directly:

```bash
mkdir -p /tmp/dnsblk-target
cargo build --release --manifest-path dnsblk-ebpf/Cargo.toml \
    --target-dir /tmp/dnsblk-target/ebpf
cp /tmp/dnsblk-target/ebpf/bpfel-unknown-none/release/libdnsblk_ebpf.so \
    dnsblk-ebpf/target/bpfel-unknown-none/release/libdnsblk_ebpf.so
CARGO_TARGET_DIR=/tmp/dnsblk-target/user cargo run -- \
    --interface eth0 /etc/deny.txt
```

## CLI

```
dnsblk <LIST>                        # default interface eth0
dnsblk -i <IFACE> <LIST>             # explicit interface
dnsblk --interface <IFACE> <LIST>    # long form
dnsblk --help                        # usage
```

- `<LIST>`: deny list file path (required positional, one domain per line).
- `-i`/`--interface`: network interface (default: `eth0`).
- Log level controlled via `LOG` env var (defaults to `info`).
- Press Ctrl+C for graceful shutdown.

## Requirements

- Linux kernel with BPF support
- Rust nightly (for eBPF compilation) and stable (for userspace)
- Elevated privileges for eBPF attach

## License

MIT License. See [LICENSE](LICENSE) for details.
