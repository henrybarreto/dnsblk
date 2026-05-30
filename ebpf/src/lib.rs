#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{HashMap, RingBuf},
    programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};

// NOTE: Maximum length in bytes for a domain name copied into the BlockEvent (truncated beyond this).
const MAX_DOMAIN_LEN: usize = 128;
// NOTE: Standard Ethernet header size: 6 bytes dst MAC + 6 bytes src MAC + 2 bytes EtherType = 14.
const ETH_HDR_LEN: usize = 14;
// NOTE: DNS message header is 12 bytes: 2 ID + 2 flags + 4×2 counts = 12.
const DNS_HDR_LEN: usize = 12;
// NOTE: IANA well-known port for DNS over UDP.
const DNS_PORT: u16 = 53;

// NOTE: FNV-1a 64-bit constants — used for fast, non-cryptographic hashing of domain names.
// NOTE: FNV_OFFSET is the initial hash value (the "offset basis").
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
// NOTE: FNV_PRIME is the multiplication constant used in each FNV-1a iteration.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

// NOTE: Map keyed by FNV-1a 64-bit hash of the domain name (in wire format).
// NOTE: The value is a dummy u8 (1 = present). When a domain exceeds 128 bytes, we still match by hash.
// NOTE: Supports up to 1 million entries loaded from the deny list by userspace.
const DENY_MAP_MAX_ENTRIES: u32 = 1_000_000;

#[map]
// NOTE: Declares a BPF hash map that userspace populates with domain hashes to block.
// NOTE: Key is the big-endian bytes of the FNV-1a 64-bit hash. Value is a placeholder u8.
static DENY_MAP: HashMap<[u8; 8], u8> =
    HashMap::<[u8; 8], u8>::with_max_entries(DENY_MAP_MAX_ENTRIES, 0);

#[map]
// NOTE: Declares a BPF ring buffer (256 KB) for sending BlockEvent structs to userspace.
// NOTE: Userspace reads from this ring buffer to log which domains were blocked.
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// NOTE: Ensures the struct has C-compatible memory layout (no field reordering). Required for ring buffer serialization.
#[repr(C)]
// NOTE: Auto-derives Copy and Clone traits so the struct can be passed by value to the ring buffer.
#[derive(Copy, Clone)]
struct BlockEvent {
    // NOTE: Source IP address (IPv4, network byte order). Set to 0 for IPv6 (not logged in current format).
    src_addr: u32,
    // NOTE: Destination IP address (IPv4, network byte order). Set to 0 for IPv6.
    dst_addr: u32,
    // NOTE: Source port (UDP, network byte order).
    src_port: u16,
    // NOTE: Destination port (UDP, network byte order).
    dst_port: u16,
    // NOTE: DNS query type (e.g., 1 = A record, 28 = AAAA). Network byte order.
    qtype: u16,
    // NOTE: Padding to align the following `domain` field to a natural boundary (keeps struct layout predictable).
    _pad: [u8; 2],
    // NOTE: The raw wire-format domain name bytes copied from the DNS question section (null-terminated, truncated at MAX_DOMAIN_LEN).
    domain: [u8; MAX_DOMAIN_LEN],
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // eBPF programs must not unwind; treat panic as unreachable.
    unsafe { core::hint::unreachable_unchecked() }
}

#[classifier]
// NOTE: TC classifier entry point. Called by the kernel for every packet on the attached interface.
// NOTE: Returns TC_ACT_OK (pass) or TC_ACT_SHOT (drop / -1).
pub fn dnsblk(ctx: TcContext) -> i32 {
    // NOTE: Load the entire Ethernet header (14 bytes) to get both source/destination MAC and
    // EtherType in one load.
    let Ok(eth_hdr) = ctx.load::<EthHdr>(0) else {
        // NOTE: If loading fails (packet too short or malformed), pass it through unchanged.
        return TC_ACT_OK;
    };

    // NOTE: Branch on EtherType to parse either IPv4 or IPv6. Each arm returns the UDP header offset, src IP, and dst IP.
    let (udp_off, src_addr, dst_addr) = match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let Ok(ipv4) = ctx.load::<Ipv4Hdr>(ETH_HDR_LEN) else {
                return TC_ACT_OK;
            };
            if ipv4.proto != IpProto::Udp {
                return TC_ACT_OK;
            }
            (
                ETH_HDR_LEN + (ipv4.ihl() as usize) * 4,
                u32::from_be(ipv4.src_addr),
                u32::from_be(ipv4.dst_addr),
            )
        }
        EtherType::Ipv6 => {
            let Ok(ipv6) = ctx.load::<Ipv6Hdr>(ETH_HDR_LEN) else {
                return TC_ACT_OK;
            };
            if ipv6.next_hdr != IpProto::Udp {
                return TC_ACT_OK;
            }
            (ETH_HDR_LEN + Ipv6Hdr::LEN, 0, 0)
        }
        _ => return TC_ACT_OK,
    };

    // NOTE: Load the UDP header at the calculated offset.
    let Ok(udp) = ctx.load::<UdpHdr>(udp_off) else {
        // NOTE: If the UDP header can't be loaded, pass the packet through.
        return TC_ACT_OK;
    };

    // NOTE: Convert UDP source port from network byte order to host byte order.
    let src_port = u16::from_be(udp.source);
    // NOTE: Convert UDP destination port from network byte order to host byte order.
    let dst_port = u16::from_be(udp.dest);

    // NOTE: DNS runs on port 53. If neither source nor destination port is 53, this is not DNS traffic — pass it through.
    if src_port != DNS_PORT && dst_port != DNS_PORT {
        return TC_ACT_OK;
    }

    // NOTE: Calculate the byte offset where the DNS header begins (right after the UDP header).
    let dns_off = udp_off + UdpHdr::LEN;
    // NOTE: Load the 12-byte DNS message header from the computed offset.
    let Ok(dns_hdr) = ctx.load::<[u8; DNS_HDR_LEN]>(dns_off) else {
        // NOTE: If the DNS header can't be loaded (packet truncated), pass the packet through.
        return TC_ACT_OK;
    };

    // NOTE: DNS header byte 2 contains flags. Bit 7 (0x80) is the QR (Query/Response) bit.
    // NOTE: If set (= 1), this is a DNS response. We only care about blocking queries, so pass responses through.
    if (dns_hdr[2] & 0x80) != 0 {
        return TC_ACT_OK;
    }

    // NOTE: DNS header bytes 4–5 are QDCOUNT (question count) in big-endian.
    // NOTE: If QDCOUNT is 0, there's no question section to inspect — pass the packet through.
    if u16::from_be_bytes([dns_hdr[4], dns_hdr[5]]) == 0 {
        return TC_ACT_OK;
    }

    // NOTE: Parse domain, compute FNV-1a hash, copy wire bytes into the event.
    // NOTE: Initialize the BlockEvent with the IP/port info we've already parsed. Domain and hash are filled in next.
    let mut event = BlockEvent {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        // NOTE: Query type starts at 0; will be filled in after we skip past the domain name.
        qtype: 0,
        // NOTE: Zero-initialize the padding bytes to avoid leaking stack data into userspace.
        _pad: [0u8; 2],
        // NOTE: Zero-initialize the domain buffer; wire-format bytes will be copied in during the loop below.
        domain: [0u8; MAX_DOMAIN_LEN],
    };

    // NOTE: Initialize the FNV-1a hash accumulator with the offset basis constant.
    let mut hash: u64 = FNV_OFFSET;
    // NOTE: `di` tracks how many domain bytes we've copied into `event.domain` (truncated at MAX_DOMAIN_LEN).
    let mut di: usize = 0;
    // NOTE: `pos` is the current byte offset into the packet, starting right after the DNS header (start of the question section).
    let mut pos: usize = dns_off + DNS_HDR_LEN;
    // NOTE: `pkt_end` is the total length of the packet in bytes. Used to prevent reading past the packet boundary.
    let pkt_end: usize = ctx.len() as usize;

    // NOTE: Iterate through the wire-format domain name, up to MAX_DOMAIN_LEN bytes.
    for _ in 0..MAX_DOMAIN_LEN {
        // NOTE: Stop if we've read past the packet end or already copied the max domain bytes into the event.
        if pos >= pkt_end || di >= MAX_DOMAIN_LEN {
            break;
        }

        // NOTE: Load a single byte from the packet at the current position in the question section.
        let Ok(byte) = ctx.load::<u8>(pos) else {
            // NOTE: If the byte can't be loaded (out of bounds), pass the packet through (safer than dropping unknown traffic).
            return TC_ACT_OK;
        };
        // NOTE: Advance the read position by one byte.
        pos += 1;

        // NOTE: DNS name compression detection — bytes with both high bits set (0xC0) indicate a pointer/compression.
        // NOTE: We don't support name compression; encountering it means the domain is complex. Pass the packet through.
        if byte & 0xC0 == 0xC0 {
            return TC_ACT_OK;
        }

        // NOTE: Copy to event (best-effort, truncated silently if beyond 128 bytes).
        // NOTE: Only write into `event.domain` if we haven't exceeded the buffer capacity.
        if di < MAX_DOMAIN_LEN {
            event.domain[di] = byte;
        }
        // NOTE: Always increment the domain index, even if we're past the buffer — used for the loop guard above.
        di += 1;

        // NOTE: Update hash (always, so long domains match too — the hash covers the entire wire-format name).
        // NOTE: FNV-1a step: XOR the byte into the hash, then multiply by FNV_PRIME (wrapping to avoid panics in no_std).
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);

        // NOTE: A zero byte in DNS wire format terminates the domain name (the root label). Stop reading.
        if byte == 0 {
            break;
        }
    }

    // NOTE: After parsing the domain, we need at least 2 more bytes (QCLASS + QTYPE) to read the query type.
    // NOTE: If there aren't enough bytes remaining, pass the packet through.
    if pos + 1 >= pkt_end {
        return TC_ACT_OK;
    }

    // NOTE: Load the high byte of the query type (QTYPE field follows the domain name in the question section).
    let Ok(qtype_hi) = ctx.load::<u8>(pos) else {
        // NOTE: If loading the byte fails, pass the packet through.
        return TC_ACT_OK;
    };

    // NOTE: Load the low byte of the query type.
    let Ok(qtype_lo) = ctx.load::<u8>(pos + 1) else {
        // NOTE: If loading the byte fails, pass the packet through.
        return TC_ACT_OK;
    };

    // NOTE: Reconstruct the 16-bit QTYPE in host byte order from the two big-endian bytes.
    let qtype = u16::from_be_bytes([qtype_hi, qtype_lo]);

    // NOTE: Store the query type into the event for userspace logging.
    event.qtype = qtype;

    // NOTE: Convert the final FNV-1a hash to big-endian bytes to use as the deny-map lookup key.
    let hash_key = hash.to_be_bytes();
    // NOTE: SAFETY: `DENY_MAP.get()` is marked unsafe in aya because BPF map lookups can theoretically fail
    // NOTE: at runtime. In practice, if the map exists and the key is the correct size, this is sound.
    // NOTE: Look up the domain hash in the deny map. If found (Some), the domain is on the blocklist.
    if unsafe { DENY_MAP.get(&hash_key) }.is_some() {
        info!(
            &ctx,
            "blocked dns qtype={} hash={:x} src_port={} dst_port={}",
            qtype,
            hash,
            src_port,
            dst_port
        );
        // NOTE: Send the BlockEvent to userspace via the ring buffer. The `0` flag means no special behavior.
        // NOTE: `let _ =` ignores the Result — if the ring buffer is full, the event is silently dropped (non-blocking).
        let _ = EVENTS.output(&event, 0);
        // NOTE: Drop the packet (TC_ACT_SHOT = -1). The DNS query never reaches its destination.
        TC_ACT_SHOT
    } else {
        // NOTE: Domain not found in the deny map — allow the packet to pass through normally.
        TC_ACT_OK
    }
}
