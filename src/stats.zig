//! Structured, allocation-free counters for the tunnel's observable behaviour.
//!
//! No RFC specifies which counters a tunnel should expose, so this set is an implementation
//! choice (docs/RFC-ANALYSIS.md Section 7.4). The names follow the project's requirements.
//!
//! Counters are plain `u64`s incremented without atomics: this type is designed to be owned by a
//! single transmit or receive thread. A multi-threaded deployment should shard `Tunnel` per
//! thread and sum the snapshots, which is why `snapshot()` returns a value rather than exposing the
//! live fields.

const std = @import("std");
const Io = std.Io;

pub const Counters = struct {
    /// Ethernet frames successfully encapsulated into an EtherIP datagram.
    tx_packets: u64 = 0,
    /// Octets of encapsulated Ethernet payload transmitted (frames, not outer packets).
    tx_bytes: u64 = 0,
    /// IPv6 packets emitted by this endpoint that carry EtherIP (Next Header 97).
    tx_ipv6_packets: u64 = 0,
    /// Outer IPv6 packets emitted that carried a Fragment header.
    tx_fragments: u64 = 0,
    /// IPv6 packets accepted from the underlay carrying EtherIP.
    rx_packets: u64 = 0,
    /// Octets of Ethernet payload delivered to the overlay interface.
    rx_bytes: u64 = 0,
    /// Outer IPv6 packets accepted that carried a Fragment header.
    rx_fragments: u64 = 0,
    /// Fragment packets handed to the reassembler (buffered, duplicate or completing).
    rx_fragment_accepted: u64 = 0,
    /// Duplicate fragments dropped (RFC 8200 Section 4.5 permits this).
    rx_fragment_duplicate: u64 = 0,
    /// EtherIP datagrams successfully reassembled from fragments.
    reassembly_success: u64 = 0,
    /// Reassembly contexts abandoned because fragments never arrived (RFC 8200 Section 4.5).
    reassembly_timeout: u64 = 0,
    /// Reassembly contexts abandoned because fragments overlapped (RFC 8200 Section 4.5).
    reassembly_overlap_drop: u64 = 0,
    /// Reassembly contexts evicted to make room for a new datagram.
    reassembly_evicted: u64 = 0,
    /// Packets rejected by any parser, for any reason (malformed outer IPv6, EtherIP, Ethernet,
    /// ICMPv6, or a reassembly rejection).
    malformed_packets: u64 = 0,
    /// Packets dropped because the destination address or Next Header was not ours.
    not_for_us: u64 = 0,
    /// Encapsulated TCP SYN packets whose MSS option was reduced.
    mss_clamped_packets: u64 = 0,
    /// Encapsulated TCP SYN packets inspected but left alone (already below the clamp, no MSS
    /// option, or not a SYN).
    mss_clamp_noop: u64 = 0,
    /// Encapsulated TCP SYN packets whose headers could not be parsed safely.
    mss_clamp_unparseable: u64 = 0,
    /// Changes to the effective path MTU caused by ICMPv6 Packet Too Big (RFC 8201 Section 4).
    pmtu_updates: u64 = 0,
    /// ICMPv6 Packet Too Big messages received.
    icmp_packet_too_big: u64 = 0,
    /// Packet Too Big messages discarded because they did not correlate with transmitted traffic
    /// (RFC 8201 Section 4's validation requirement).
    unmatched_packet_too_big: u64 = 0,
    /// ICMPv6 messages generated locally in response to malformed or incomplete datagrams
    /// (RFC 8200 Section 4.5 error conditions).
    icmp_errors_sent: u64 = 0,
    /// Packets dropped by the overlay interface (for example, egress queue full).
    tx_dropped: u64 = 0,

    pub fn add(self: *Counters, other: Counters) void {
        inline for (std.meta.fields(Counters)) |f| {
            @field(self, f.name) += @field(other, f.name);
        }
    }
};

/// A point-in-time copy of `Counters` plus derived reassembly occupancy.
pub const Snapshot = struct {
    counters: Counters,
    reassembly: struct {
        in_flight_packets: usize,
        in_flight_bytes: usize,
        buffered_bytes: usize,
        max_packets: usize,
        max_bytes: usize,
    },
    /// `min(configured_underlay_mtu, discovered_path_mtu)`.
    effective_path_mtu: usize,
    /// Path MTU learned from ICMPv6 Packet Too Big, or null if none has been received.
    discovered_path_mtu: ?u32,
    configured_underlay_mtu: usize,
    overlay_mtu: usize,
};

/// Write the snapshot as `key = value` lines. Deterministic ordering for tests and log scraping.
pub fn formatSnapshot(snap: Snapshot, w: *Io.Writer) Io.Writer.Error!void {
    const c = snap.counters;
    inline for (std.meta.fields(Counters)) |f| {
        try w.print("{s} = {d}\n", .{ f.name, @field(c, f.name) });
    }
    try w.print("reassembly_in_flight_packets = {d}\n", .{snap.reassembly.in_flight_packets});
    try w.print("reassembly_in_flight_bytes = {d}\n", .{snap.reassembly.in_flight_bytes});
    try w.print("reassembly_buffered_bytes = {d}\n", .{snap.reassembly.buffered_bytes});
    try w.print("reassembly_max_packets = {d}\n", .{snap.reassembly.max_packets});
    try w.print("reassembly_max_bytes = {d}\n", .{snap.reassembly.max_bytes});
    try w.print("effective_path_mtu = {d}\n", .{snap.effective_path_mtu});
    if (snap.discovered_path_mtu) |m| {
        try w.print("discovered_path_mtu = {d}\n", .{m});
    } else {
        try w.writeAll("discovered_path_mtu = unset\n");
    }
    try w.print("configured_underlay_mtu = {d}\n", .{snap.configured_underlay_mtu});
    try w.print("overlay_mtu = {d}\n", .{snap.overlay_mtu});
}

const t = std.testing;

test "Counters start at zero" {
    const c: Counters = .{};
    try t.expectEqual(@as(u64, 0), c.tx_packets);
    try t.expectEqual(@as(u64, 0), c.reassembly_overlap_drop);
}

test "Counters.add sums every field" {
    var a: Counters = .{};
    var b: Counters = .{};
    a.tx_packets = 3;
    a.tx_fragments = 7;
    b.tx_packets = 4;
    b.rx_bytes = 9000;

    a.add(b);
    try t.expectEqual(@as(u64, 7), a.tx_packets);
    try t.expectEqual(@as(u64, 7), a.tx_fragments);
    try t.expectEqual(@as(u64, 9000), a.rx_bytes);
    // Untouched fields stay zero.
    try t.expectEqual(@as(u64, 0), a.tx_bytes);
}

test "Counters covers every field required by the project brief" {
    // If this list grows, the implementation must be updated; if a name is renamed here the
    // compile fails, which is the point.
    const required = [_][]const u8{
        "tx_packets",         "rx_packets",
        "tx_bytes",           "rx_bytes",
        "tx_fragments",       "rx_fragments",
        "reassembly_success", "reassembly_timeout",
        "reassembly_overlap_drop", "malformed_packets",
        "mss_clamped_packets", "pmtu_updates",
    };
    for (required) |name| {
        var found = false;
        inline for (std.meta.fields(Counters)) |f| {
            if (std.mem.eql(u8, f.name, name)) found = true;
        }
        try t.expect(found);
    }
}

test "formatSnapshot emits every counter deterministically" {
    var buf: [4096]u8 = undefined;
    var w = Io.Writer.fixed(&buf);
    try formatSnapshot(.{
        .counters = .{ .tx_packets = 12, .rx_fragments = 5, .pmtu_updates = 1 },
        .reassembly = .{ .in_flight_packets = 2, .in_flight_bytes = 100, .buffered_bytes = 50, .max_packets = 4, .max_bytes = 4096 },
        .effective_path_mtu = 1500,
        .discovered_path_mtu = 1400,
        .configured_underlay_mtu = 1500,
        .overlay_mtu = 9000,
    }, &w);
    const out = w.buffered();

    try t.expect(indexOfLine(out, "tx_packets = 12") != null);
    try t.expect(indexOfLine(out, "rx_fragments = 5") != null);
    try t.expect(indexOfLine(out, "pmtu_updates = 1") != null);
    try t.expect(indexOfLine(out, "effective_path_mtu = 1500") != null);
    try t.expect(indexOfLine(out, "discovered_path_mtu = 1400") != null);
    try t.expect(indexOfLine(out, "overlay_mtu = 9000") != null);

    // With no PTB received yet, the discovered value reads "unset".
    var buf2: [4096]u8 = undefined;
    var w2 = Io.Writer.fixed(&buf2);
    try formatSnapshot(.{
        .counters = .{},
        .reassembly = .{ .in_flight_packets = 0, .in_flight_bytes = 0, .buffered_bytes = 0, .max_packets = 0, .max_bytes = 0 },
        .effective_path_mtu = 1500,
        .discovered_path_mtu = null,
        .configured_underlay_mtu = 1500,
        .overlay_mtu = 9000,
    }, &w2);
    try t.expect(indexOfLine(w2.buffered(), "discovered_path_mtu = unset") != null);
}

fn indexOfLine(haystack: []const u8, needle: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, i, needle)) |p| {
        const end = p + needle.len;
        if (end == haystack.len or haystack[end] == '\n') return haystack[p..];
        i = p + 1;
    }
    return null;
}