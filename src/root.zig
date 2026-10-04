//! EtherIP tunnel over IPv6 — library root.
//!
//! This package implements the EtherIP wire format defined by **RFC 3378** (Informational,
//! September 2002) and carries it over IPv6 with Next Header 97, performing IPv6 *source*
//! fragmentation (RFC 8200 Section 4.5) so that a jumbo overlay frame can traverse a small
//! underlay.
//!
//! ## What this package is, and is not
//!
//! * RFC 3378 is **Informational**, not Standards Track. It describes a data format and assigns no
//!   security. This package therefore makes **no claim** that EtherIP provides confidentiality,
//!   integrity, or authentication, and adds none.
//! * RFC 3378 says nothing about IPv6: it names only the IPv4 Protocol field. Using protocol 97 as
//!   an IPv6 Next Header is a transport adaptation justified by IANA's shared *IP Protocol Numbers*
//!   registry and RFC 8200 Section 4, and it changes **no EtherIP header field**. See
//!   `docs/RFC-ANALYSIS.md` Section 2.
//! * RFC 3378 Section 1 states EtherIP "does not provide protection against infinite loops". Neither
//!   does this implementation; loop avoidance is a topology concern.
//!
//! ## Module map
//!
//! | Module | Responsibility | Primary RFCs |
//! |---|---|---|
//! | [`etherip`] | EtherIP header encode/decode, strict validation | RFC 3378 |
//! | [`ethernet`] | Ethernet II / 802.1Q / 802.1ad frame validation | DIX, IEEE 802.1Q/ad |
//! | [`ipv6`] | IPv6 header, extension-header chain, addresses | RFC 8200, RFC 4291 |
//! | [`fragment`] | MTU arithmetic and source fragmentation | RFC 8200 4.5, 5 |
//! | [`reassembly`] | Bounded fragment reassembly | RFC 8200 4.5 |
//! | [`icmpv6`] | Packet Too Big, and the errors a destination node must send | RFC 4443, RFC 8201 |
//! | [`mss_clamp`] | Optional TCP MSS clamping | implementation feature |
//! | [`checksum`] | RFC 1071 checksum and pseudo-headers | RFC 1071, RFC 9293, RFC 8200 8.1 |
//! | [`config`] | Configuration and startup validation | derived from the above |
//! | [`tunnel`] | Encapsulation, decapsulation, PMTUD, statistics | all of the above |
//! | [`overlay`] | L2 interface binding | RFC 3378 4 step 3 |
//! | [`platform`] | Raw-IPv6 transport abstraction | — |
//!
//! ## Quick start
//!
//! ```zig
//! var cfg: config.Config = .{
//!     .local_ipv6 = try ipv6.Address.parse("2001:db8:100::1"),
//!     .remote_ipv6 = try ipv6.Address.parse("2001:db8:200::1"),
//!     .underlay_mtu = 1500,
//!     .overlay_mtu = 9000,
//! };
//! try cfg.validate();
//! // A 9000-octet frame now leaves as 7 outer packets of at most 1496 octets.
//! ```

const std = @import("std");

pub const config = @import("config.zig");
pub const checksum = @import("checksum.zig");
pub const etherip = @import("etherip.zig");
pub const ethernet = @import("ethernet.zig");
pub const fragment = @import("fragment.zig");
pub const icmpv6 = @import("icmpv6.zig");
pub const ipv6 = @import("ipv6.zig");
pub const mss_clamp = @import("mss_clamp.zig");
pub const overlay = @import("overlay.zig");
pub const platform = @import("platform.zig");
pub const reassembly = @import("reassembly.zig");
pub const stats = @import("stats.zig");
pub const tunnel = @import("tunnel.zig");

/// IANA protocol number / IPv6 Next Header for EtherIP.
pub const protocol_number: u8 = etherip.ip_protocol_number;

/// Largest Ethernet frame this tunnel can carry: a 16-bit IPv6 Payload Length (RFC 8200 Section 3)
/// minus the 2-octet EtherIP header.
pub const max_overlay_mtu: usize = ipv6.max_payload_len - etherip.header_len;

pub const Config = config.Config;
pub const Address = ipv6.Address;
pub const Tunnel = tunnel.Tunnel;
pub const Statistics = stats.Snapshot;

/// Every module's tests, plus the cross-module suite in `tests/`.
pub const tests = @import("tests/tests.zig");

test {
    _ = config;
    _ = checksum;
    _ = etherip;
    _ = ethernet;
    _ = fragment;
    _ = icmpv6;
    _ = ipv6;
    _ = mss_clamp;
    _ = overlay;
    _ = platform;
    _ = reassembly;
    _ = stats;
    _ = tunnel;
    _ = tests;
}

test "protocol constants" {
    try std.testing.expectEqual(@as(u8, 97), protocol_number);
    try std.testing.expectEqual(@as(usize, 65533), max_overlay_mtu);
}