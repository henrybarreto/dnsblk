//! Core dnsblk logic: helpers, eBPF management, and the blocking worker.
//! This module has no UI dependency and is shared between CLI and GUI modes.

use std::{
    collections::HashMap,
    fs,
    hash::BuildHasher,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, MapData, RingBuf},
    programs::tc::{SchedClassifier, TcAttachType},
    Ebpf,
};

/// Embedded eBPF object bytes.
pub const BPF_BYTES: &[u8] = include_bytes_aligned!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../dnsblk-ebpf/target/bpfel-unknown-none/release/libdnsblk_ebpf.so"
));

/// FNV-1a 64-bit offset basis.
pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime.
pub const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
/// Maximum domain name length in wire format.
pub const MAX_DOMAIN_LEN: usize = 128;
/// Deduplication window for log suppression.
pub const LOG_DEDUP_WINDOW: Duration = Duration::from_millis(1200);
/// DNS query type A (IPv4 address).
pub const DNS_TYPE_A: u16 = 1;
/// DNS query type AAAA (IPv6 address).
pub const DNS_TYPE_AAAA: u16 = 28;

/// Event produced by the eBPF program when a DNS query is blocked.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockEvent {
    /// Source IPv4 address (0 for IPv6).
    pub src_addr: u32,
    /// Destination IPv4 address (0 for IPv6).
    pub dst_addr: u32,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// DNS query type (A, AAAA, etc.).
    pub qtype: u16,
    /// Alignment padding.
    _pad: [u8; 2],
    /// Domain name in wire format (null-terminated, up to `MAX_DOMAIN_LEN` bytes).
    pub domain: [u8; MAX_DOMAIN_LEN],
}

/// Handle to a running worker thread.
pub struct WorkerHandle {
    /// Stop flag shared with the worker thread.
    pub stop: Arc<AtomicBool>,
    /// Join handle for the worker thread.
    pub join: std::thread::JoinHandle<()>,
}

/// Messages sent from the worker thread to the event consumer.
pub enum WorkerMsg {
    /// Informational status message.
    Info(String),
    /// Error message from the worker.
    Error(String),
    /// A DNS query was blocked (contains formatted message).
    Blocked(String),
    /// Worker has stopped (clean shutdown).
    Stopped,
}

/// Validate that the Rust-side `BlockEvent` matches the eBPF-side layout.
#[must_use]
pub const fn validate_block_event() -> bool {
    std::mem::size_of::<BlockEvent>() == 4 + 4 + 2 + 2 + 2 + 2 + MAX_DOMAIN_LEN
}

/// Convert a domain name string to wire format.
#[must_use]
pub fn domain_to_wire(domain: &str) -> Vec<u8> {
    let mut wire = Vec::with_capacity(256);
    let domain = domain.trim().to_lowercase();
    let domain = domain.trim_end_matches('.');
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len();
        if len > 63 {
            continue;
        }
        wire.push(u8::try_from(len).unwrap_or(63));
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire
}

/// Compute FNV-1a 64-bit hash of a wire-format domain name.
#[must_use]
pub fn fnv1a_64(wire: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &byte in wire {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
        if byte == 0 {
            break;
        }
    }
    hash
}

/// Convert a wire-format domain name back to a human-readable string.
#[must_use]
pub fn wire_to_domain(wire: &[u8]) -> String {
    let mut s = String::new();
    let mut i: usize = 0;
    while i < wire.len() {
        let byte = match wire.get(i) {
            Some(&0) | None => break,
            Some(&b) => b,
        };
        let label_len = usize::from(byte);
        i += 1;
        if i.checked_add(label_len).is_none_or(|end| end > wire.len()) || label_len == 0 {
            break;
        }
        if !s.is_empty() {
            s.push('.');
        }
        let end = i + label_len;
        if let Some(slice) = wire.get(i..end) {
            s.push_str(std::str::from_utf8(slice).unwrap_or("?"));
        }
        i = end;
    }
    s
}

/// Return a human-readable name for a DNS query type.
#[must_use]
pub const fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        DNS_TYPE_A => "A",
        DNS_TYPE_AAAA => "AAAA",
        _ => "OTHER",
    }
}

/// List available network interfaces (excluding loopback).
#[must_use]
pub fn list_interfaces() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name != "lo" {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    names
}

/// Load deny list entries from a file into the eBPF deny map.
///
/// Returns `(loaded, skipped)` counts.
///
/// # Errors
///
/// Returns an error if the file cannot be read or if a deny entry cannot be inserted.
pub fn load_deny_map(
    path: &Path,
    deny_map: &mut AyaHashMap<MapData, [u8; 8], u8>,
) -> Result<(u64, u64)> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read deny file: {}", path.display()))?;

    let mut loaded = 0u64;
    let mut skipped = 0u64;
    for (line_no, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let wire = domain_to_wire(line);
        if wire.len() > 255 {
            skipped += 1;
            continue;
        }
        let hash = fnv1a_64(&wire);
        deny_map
            .insert(hash.to_be_bytes(), 1u8, 0)
            .with_context(|| {
                format!(
                    "Failed to insert deny entry at line {}: {line}",
                    line_no + 1
                )
            })?;
        loaded += 1;
    }

    Ok((loaded, skipped))
}

/// Check if a domain was recently seen and return suppression count.
///
/// Returns `None` if the event should be suppressed (deduplicated within the window),
/// `Some(count)` otherwise. `count > 0` indicates previously suppressed events.
#[must_use]
pub fn check_domain<S: BuildHasher>(
    seen: &mut HashMap<String, (Instant, u32), S>,
    domain: &str,
    now: Instant,
) -> Option<u32> {
    if let Some((last, suppressed)) = seen.get_mut(domain) {
        if now.duration_since(*last) < LOG_DEDUP_WINDOW {
            *suppressed += 1;
            *last = now;
            None
        } else {
            let count = *suppressed;
            *last = now;
            *suppressed = 0;
            let keep_after = now.checked_sub(LOG_DEDUP_WINDOW).map_or(now, |t| t);
            seen.retain(|_, (ts, _)| *ts >= keep_after);
            Some(count)
        }
    } else {
        seen.insert(domain.to_string(), (now, 0));
        let keep_after = now.checked_sub(LOG_DEDUP_WINDOW).map_or(now, |t| t);
        seen.retain(|_, (ts, _)| *ts >= keep_after);
        Some(0)
    }
}

/// Check if the current process is running as root (euid 0).
#[must_use]
pub fn is_root() -> bool {
    // SAFETY: geteuid is a simple libc call with no side effects.
    unsafe { libc::geteuid() == 0 }
}

/// Run the eBPF blocker worker in the current thread.
///
/// Attaches the tc classifier to the given interfaces, loads the deny map from
/// `deny_file`, then reads ringbuf events and sends messages through `tx` until
/// `stop` is set to `true`.
///
/// # Errors
///
/// Returns an error if eBPF loading, map operations, or ringbuf access fails.
pub fn run_blocker(
    ifaces: &[String],
    deny_file: &Path,
    tx: mpsc::Sender<WorkerMsg>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let mut bpf = Ebpf::load(BPF_BYTES).context("Failed to load embedded eBPF program")?;

    let program: &mut SchedClassifier = bpf
        .program_mut("dnsblk")
        .context("eBPF program 'dnsblk' not found")?
        .try_into()
        .context("Failed to cast to SchedClassifier")?;

    let attach_type = TcAttachType::Egress;
    program.load().context("Failed to load tc classifier")?;

    for iface in ifaces {
        program
            .attach(iface, attach_type)
            .with_context(|| format!("Failed to attach eBPF program to interface {iface}"))?;
    }

    let _ = tx.send(WorkerMsg::Info(format!(
        "Attached to {}",
        ifaces.join(", ")
    )));

    let mut deny_map: AyaHashMap<MapData, [u8; 8], u8> =
        AyaHashMap::try_from(bpf.take_map("DENY_MAP").context("DENY_MAP not found")?)?;

    let (loaded, skipped) = load_deny_map(deny_file, &mut deny_map)?;
    let _ = tx.send(WorkerMsg::Info(format!(
        "Loaded {loaded} deny entries from {} (skipped: {skipped})",
        deny_file.display()
    )));

    let ring = RingBuf::try_from(bpf.take_map("EVENTS").context("EVENTS map not found")?)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .context("Failed to create runtime")?;

    runtime.block_on(async move {
        let async_ring =
            tokio::io::unix::AsyncFd::new(ring).context("Failed to open ringbuf fd")?;
        let mut async_ring = async_ring;

        while !stop.load(Ordering::Relaxed) {
            let mut guard =
                match tokio::time::timeout(Duration::from_millis(500), async_ring.readable_mut())
                    .await
                {
                    Ok(Ok(guard)) => guard,
                    Ok(Err(e)) => return Err(anyhow::anyhow!("RingBuf wait failed: {e}")),
                    Err(_) => continue,
                };

            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                if item.len() < std::mem::size_of::<BlockEvent>() {
                    continue;
                }
                let ev: BlockEvent =
                    unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<BlockEvent>()) };
                let domain = wire_to_domain(&ev.domain);
                let msg = format!("Blocked ({}) : {domain}", qtype_name(ev.qtype));
                let _ = tx.send(WorkerMsg::Blocked(msg));
            }

            guard.clear_ready();
        }

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}
