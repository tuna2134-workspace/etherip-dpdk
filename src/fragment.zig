//! IPv6 source fragmentation of an EtherIP datagram, plus the MTU arithmetic it depends on.
//!
//! RFC: RFC 8200 Section 4.5 ("Fragment Header") and Section 5 ("Packet Size Issues").
//!
//! ## Why EtherIP datagrams are fragmented at all
//!
//! RFC 3378 describes EtherIP only for IP datagrams that fit; it says nothing about oversized
//! frames. RFC 8200 Section 4.5 defines how *any* IPv6 source splits a packet that exceeds the
//! path MTU. This module applies those rules to the EtherIP datagram, so that a 9000-octet
//! Ethernet frame can cross a 1500-octet IPv6 underlay.
//!
//! ## The original-packet model (RFC 8200 Section 4.5 as corrected by Errata ID 5945)
//!
//! ```text
//! original packet:
//! +------------------+-----------------------------//----------------+
//! |  Per-Fragment    |               Fragmentable                    |
//! |    Headers       |                   Part                        |
//! +------------------+-----------------------------//----------------+
//! ```
//!
//! We insert no en-route-processed extension headers, so:
//!
//!   * Per-Fragment Headers = the 40-octet IPv6 header (Next Header = 44, Payload Length per
//!     fragment).
//!   * Upper-Layer header  = the 16-bit **EtherIP** header.
//!   * **Fragmentable Part = `EtherIP header || Ethernet frame`.**
//!
//! This is the justification for treating the EtherIP header as part of the fragmented data: it is
//! the upper-layer header, and the upper-layer header is the first thing inside the Fragmentable
//! Part. Fragment Offset 0 therefore addresses the first nibble of the EtherIP Version field.
//!
//! ## Alignment
//!
//! RFC 8200 Section 4.5: "Each complete fragment, except possibly the last ('rightmost') one, is
//! an integer multiple of 8 octets long." Non-final fragment payloads are therefore rounded down
//! to an 8-octet multiple of whatever space remains under the path MTU.

const std = @import("std");
const ipv6 = @import("ipv6.zig");
const etherip = @import("etherip.zig");

/// RFC 8200 Section 4.5: Fragment Offset is expressed in 8-octet units.
pub const fragment_alignment: usize = 8;

/// Length of the IPv6 Fragment header (RFC 8200 Section 4.5).
pub const fragment_header_len: usize = 8;

pub const MtuError = error{
    /// The path MTU is too small to hold the IPv6 header plus the Fragment header plus at least
    /// one aligned unit of Fragmentable Part.
    PathMtuTooSmall,
    /// The resulting fragment payload would not fit the 16-bit IPv6 Payload Length field
    /// (RFC 8200 Section 3).
    PayloadLengthOverflow,
};

// ---------------------------------------------------------------------------
// MTU arithmetic
// ---------------------------------------------------------------------------

/// Every input to the MTU calculation. Nothing here is hard-coded to 1500: the caller supplies the
/// path MTU and the per-header overheads, so 1280, 1500, 9000 and jumbo underlays all work.
pub const MtuParams = struct {
    /// The effective path MTU: `min(configured_underlay_mtu, discovered_path_mtu)`, floored at
    /// the IPv6 minimum link MTU of 1280 (RFC 8200 Section 5, RFC 8201 Section 4).
    path_mtu: usize,
    /// Length of the outer IPv6 header. Always 40 (RFC 8200 Section 3).
    ipv6_header_len: usize = ipv6.header_len,
    /// Octets reserved in the Per-Fragment Headers region for en-route-processed extension
    /// headers (RFC 8200 Section 4.5). No RFC mandates a value; default 0 because this
    /// implementation inserts none.
    ///
    /// When non-zero the caller MUST also supply the actual header octets and their Next Header
    /// type through `EmitParams.per_fragment_ext` / `EmitParams.per_fragment_ext_next_header`.
    /// RFC 8200 Section 4.5 requires the IPv6 header's Next Header field to name the *first*
    /// Per-Fragment header, so zero-filling this region while still announcing 44 would produce
    /// packets the receiver itself must reject. `per_fragment_ext_len` is therefore only an MTU
    /// accounting parameter when used standalone; `Tunnel` never sets it without the headers.
    per_fragment_ext_len: usize = 0,
};

/// Octets of wire overhead carried by *every* packet this tunnel emits.
///
/// `tunnel_overhead(fragmenting = true)` is what the fragmenter must leave room for; with
/// `fragmenting = false` there is no Fragment header.
///
/// Note that the 2-octet EtherIP header is deliberately **not** counted here: it is part of the
/// fragmentable payload, not of the outer headers. That is precisely why a 9000-octet Ethernet
/// frame can be carried by 1496-octet outer packets.
pub fn tunnelOverhead(params: MtuParams, fragmenting: bool) usize {
    const frag_bytes = if (fragmenting) fragment_header_len else 0;
    return params.ipv6_header_len + params.per_fragment_ext_len + frag_bytes;
}

/// Largest legal length of the Fragmentable Part carried in one fragment packet.
///
/// Returns a multiple of 8 (RFC 8200 Section 4.5), or `error.PathMtuTooSmall` if the path MTU
/// cannot accommodate the headers plus at least one aligned unit.
///
/// For the mandatory scenario (path_mtu 1500, no extension headers):
/// ```text
/// 1500 - 40 (IPv6) - 8 (Fragment) = 1452
/// floor(1452 / 8) * 8             = 1448
/// 40 + 8 + 1448                   = 1496  <= 1500
/// ```
pub fn calculateFragmentPayloadSize(params: MtuParams) MtuError!usize {
    const overhead = tunnelOverhead(params, true);
    // Guard against `path_mtu < overhead` producing an underflow.
    if (params.path_mtu <= overhead) return error.PathMtuTooSmall;
    const available = params.path_mtu - overhead;
    const aligned = (available / fragment_alignment) * fragment_alignment;
    if (aligned == 0) return error.PathMtuTooSmall;
    if (aligned > ipv6.max_payload_len) return error.PayloadLengthOverflow;
    return aligned;
}

/// Number of fragments `datagram_len` will be split into at the given fragment payload size.
pub fn fragmentCount(datagram_len: usize, fragment_payload_size: usize) MtuError!usize {
    if (fragment_payload_size == 0) return error.PathMtuTooSmall;
    if (datagram_len == 0) return error.PathMtuTooSmall;
    const n = (datagram_len + fragment_payload_size - 1) / fragment_payload_size;
    // Each fragment carries 8 octets of Fragment header; the reassembled Payload Length must stay
    // within the 16-bit field (RFC 8200 Section 4.5 error condition 3).
    if (n > 8192) return error.PayloadLengthOverflow;
    return n;
}

/// Smallest datagram length that will be split into more than one fragment.
///
/// Useful for the "frame just below / exactly at / just above the fragment threshold" tests.
pub fn fragmentationThreshold(fragment_payload_size: usize) usize {
    return fragment_payload_size + 1;
}

// ---------------------------------------------------------------------------
// Fragment emission
// ---------------------------------------------------------------------------

/// Largest outer packet this fragmenter will ever produce, given the caller's scratch buffer.
pub fn maxPacketSize(params: MtuParams) usize {
    return tunnelOverhead(params, true) + ipv6.max_payload_len;
}

/// The only failure a `FragmentSink` may report. A sink either accepts a fragment or aborts the
/// whole emission; transport-specific failures map onto `error.Abort`.
pub const SinkError = error{Abort};

/// Receives each assembled fragment packet. Implementations decide whether to transmit it, buffer
/// it, or count it.
pub const FragmentSink = struct {
    context: *anyopaque,
    emit: *const fn (context: *anyopaque, packet: []const u8, meta: FragmentMeta) SinkError!void,

    pub fn call(self: FragmentSink, packet: []const u8, meta: FragmentMeta) SinkError!void {
        return self.emit(self.context, packet, meta);
    }
};

/// Metadata describing one emitted fragment packet.
pub const FragmentMeta = struct {
    /// Index of this fragment, 0-based.
    index: u32,
    /// Number of fragments in the datagram.
    count: u32,
    /// Fragment Offset field value (in 8-octet units).
    fragment_offset: u13,
    /// M flag: true for every fragment except the last.
    more_fragments: bool,
    /// RFC 8200 Section 4.5 Identification, shared by all fragments of one datagram.
    identification: u32,
    /// Total octets on the wire for this fragment packet.
    wire_len: usize,
};

pub const EmitParams = struct {
    mtu: MtuParams,
    /// Source of the outer IPv6 header.
    source: ipv6.Address,
    /// Destination of the outer IPv6 header.
    destination: ipv6.Address,
    /// Traffic Class / Flow Label / Hop Limit for every fragment (RFC 8200 Section 3).
    write_options: ipv6.WriteOptions,
    /// Identification for the whole datagram (RFC 8200 Section 4.5).
    identification: u32,
    /// Actual Per-Fragment extension header octets to place between the IPv6 header and the
    /// Fragment header. Must be exactly `mtu.per_fragment_ext_len` octets and a whole number of
    /// extension headers. Empty when no such headers are used.
    ///
    /// RFC 8200 Section 4.5: these are the headers "that must be processed by nodes en route to the
    /// destination", so they precede the Fragment header in every fragment and are counted in the
    /// reassembled packet's Payload Length.
    per_fragment_ext: []const u8 = &.{},
    /// Next Header value for the IPv6 header, naming the first header in `per_fragment_ext`. Must be
    /// 44 (Fragment) when `per_fragment_ext` is empty.
    per_fragment_ext_next_header: u8 = ipv6.next_header_fragment,
};

/// Caller-owned scratch buffer for fragment serialisation.
///
/// Holding the buffer here (rather than inside `emitFragments`) is what keeps the fast path
/// allocation-free: one caller-provided buffer is reused for every fragment of every datagram.
pub const Fragmenter = struct {
    scratch: []u8,
    /// Largest wire size `emitFragments` will write; validated up front so `emitFragments` cannot
    /// fail for lack of space.
    capacity: usize,

    pub const InitError = MtuError || error{ScratchTooSmall};

    pub fn init(scratch: []u8, params: MtuParams) InitError!Fragmenter {
        const max_frag = try calculateFragmentPayloadSize(params);
        const needed = tunnelOverhead(params, true) + max_frag;
        if (scratch.len < needed) return error.ScratchTooSmall;
        return .{ .scratch = scratch[0..needed], .capacity = needed };
    }

    pub fn deinit(self: *Fragmenter) void {
        self.scratch = self.scratch[0..0];
    }

    /// Split `datagram` (a complete EtherIP datagram: 16-bit EtherIP header + Ethernet frame) into
    /// RFC 8200 Section 4.5 fragment packets and hand each to `sink`.
    ///
    /// `datagram` is the **Fragmentable Part**: its first `etherip.header_len` octets are the
    /// EtherIP header, so the first fragment carries the EtherIP header plus the leading frame
    /// octets and every subsequent fragment is raw frame data.
    ///
    /// Errors:
    ///   * `error.NotFragmentable` — the datagram already fits and should not have been
    ///     fragmented (the caller must send it whole).
    ///   * `error.DatagramTooLarge` — reassembling it would exceed the 16-bit Payload Length
    ///     field, which RFC 8200 Section 4.5 error condition 3 forbids.
    pub fn emitFragments(
        self: *Fragmenter,
        params: EmitParams,
        datagram: []const u8,
        sink: FragmentSink,
    ) EmitError!u32 {
        const max_frag = calculateFragmentPayloadSize(params.mtu) catch |e| return e;

        // `init` sized `scratch` for the MTU it was given, but `emitFragments` takes its MTU per
        // call. A caller that inits with one MTU and emits with a larger one would otherwise write
        // past `scratch`, so re-check here rather than trusting the init-time invariant.
        const per_fragment_ext = params.mtu.per_fragment_ext_len;
        const overhead = params.mtu.ipv6_header_len + per_fragment_ext + fragment_header_len;
        if (self.scratch.len < overhead + max_frag) return error.ScratchTooSmall;
        if (self.scratch.len < overhead) return error.PathMtuTooSmall;

        if (datagram.len <= max_frag) return error.NotFragmentable;
        // RFC 8200 Section 4.5: the reassembled Payload Length must fit the 16-bit field. The
        // Per-Fragment extension headers count towards it alongside the Fragmentable Part.
        const reserved = params.mtu.per_fragment_ext_len;
        if (std.math.add(usize, datagram.len, reserved) catch std.math.maxInt(usize) > ipv6.max_payload_len) {
            return error.DatagramTooLarge;
        }
        // RFC 8200 Section 4.5: the IPv6 header's Next Header names the first Per-Fragment header.
        if (params.per_fragment_ext.len != reserved) return error.PerFragmentExtLengthMismatch;
        if (reserved != 0 and params.per_fragment_ext_next_header == ipv6.next_header_fragment) {
            // Non-empty reserved region but the Next Header still claims Fragment: that would make
            // the reserved octets look like a Fragment header to the receiver.
            return error.PerFragmentExtNextHeaderMismatch;
        }
        if (reserved == 0 and params.per_fragment_ext_next_header != ipv6.next_header_fragment) {
            return error.PerFragmentExtNextHeaderMismatch;
        }
        // RFC 8200 Section 4.5: "Extension headers, if any, and the Upper-Layer header ... must be
        // in the first fragment." The EtherIP header is the Upper-Layer header here, so the first
        // fragment must be able to hold it.
        if (max_frag < etherip.header_len) return error.PathMtuTooSmall;

        const count = (datagram.len + max_frag - 1) / max_frag;
        const first_data_off = params.mtu.ipv6_header_len + per_fragment_ext;

        var offset: usize = 0;
        var index: u32 = 0;
        while (offset < datagram.len) : (offset += max_frag) {
            const remaining = datagram.len - offset;
            const chunk_len = @min(remaining, max_frag);
            const is_last = offset + chunk_len == datagram.len;
            // RFC 8200 Section 4.5: every fragment except the last is a multiple of 8 octets.
            std.debug.assert(is_last or chunk_len % fragment_alignment == 0);

            // (1) Per-Fragment headers: the IPv6 header followed by the reserved extension
            // octets. RFC 8200 Section 4.5 counts those octets in Payload Length, so they must be
            // written (as zero) rather than left holding whatever was in the scratch buffer.
            const payload_len = fragment_header_len + chunk_len;
            @memset(
                self.scratch[ipv6.header_len..first_data_off],
                0,
            );
            ipv6.writeHeader(
                self.scratch[0..first_data_off],
                // The last Per-Fragment header's Next Header becomes 44.
                ipv6.next_header_fragment,
                payload_len + per_fragment_ext,
                .{
                    .traffic_class = params.write_options.traffic_class,
                    .flow_label = params.write_options.flow_label,
                    .hop_limit = params.write_options.hop_limit,
                    .source = params.source,
                    .destination = params.destination,
                },
            ) catch return error.PathMtuTooSmall;

            // (2) Fragment header.
            const fh = self.scratch[first_data_off..][0..fragment_header_len];
            // The Fragment header's Next Header identifies the first header of the
            // Fragmentable Part: EtherIP, in every fragment. RFC 8200 Section 4.5 notes these
            // values "may differ" across fragments and that only the offset-zero fragment's value
            // is used, so writing 97 everywhere is the conformant and simplest choice.
            fh[0] = etherip.ip_protocol_number;
            fh[1] = 0; // Reserved: "Initialized to zero for transmission; ignored on reception."
            const unit_offset: u32 = @intCast(offset / fragment_alignment);
            std.debug.assert(unit_offset <= std.math.maxInt(u13));
            const of_and_flags: u16 = (@as(u16, @intCast(unit_offset)) << 3) |
                (if (is_last) @as(u16, 0) else @as(u16, 1));
            std.mem.writeInt(u16, fh[2..4], of_and_flags, .big);
            std.mem.writeInt(u32, fh[4..8], params.identification, .big);

            // (3) The fragment itself. (No extension headers or Upper-Layer header beyond the
            // EtherIP header, which is already part of `datagram` for the first fragment.)
            @memcpy(self.scratch[first_data_off + fragment_header_len ..][0..chunk_len], datagram[offset..][0..chunk_len]);

            const wire_len = first_data_off + payload_len;
            std.debug.assert(wire_len <= self.scratch.len);
            try sink.call(self.scratch[0..wire_len], .{
                .index = index,
                .count = @intCast(count),
                .fragment_offset = @intCast(unit_offset),
                .more_fragments = !is_last,
                .identification = params.identification,
                .wire_len = wire_len,
            });
            index += 1;
        }
        return index;
    }
};

pub const EmitError = MtuError || SinkError || error{
    /// `EmitParams.per_fragment_ext.len` differs from `MtuParams.per_fragment_ext_len`, so the
    /// reserved region cannot be filled consistently (RFC 8200 Section 4.5).
    PerFragmentExtLengthMismatch,
    /// The announced Per-Fragment Next Header does not match the supplied extension headers
    /// (RFC 8200 Section 4.5).
    PerFragmentExtNextHeaderMismatch,
    /// `MtuParams.ipv6_header_len` is not the fixed IPv6 header length (RFC 8200 Section 3).
    Ipv6HeaderLenMismatch,
    /// The datagram already fits within `max_frag`; it must be sent unfragmented.
    NotFragmentable,
    /// The Fragmenter's scratch buffer is too small for the MTU supplied to this call.
    ScratchTooSmall,
    /// Reassembling the datagram would overflow the 16-bit IPv6 Payload Length field
    /// (RFC 8200 Section 4.5, error condition 3).
    DatagramTooLarge,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

/// Captures every emitted fragment packet for inspection.
const Collector = struct {
    packets: std.ArrayList(u8) = .empty,
    metas: std.ArrayList(FragmentMeta) = .empty,
    gpa: std.mem.Allocator,

    fn sink(ctx: *anyopaque, packet: []const u8, meta: FragmentMeta) SinkError!void {
        const self: *Collector = @ptrCast(@alignCast(ctx));
        self.packets.appendSlice(self.gpa, packet) catch return error.Abort;
        self.metas.append(self.gpa, meta) catch return error.Abort;
    }

    fn deinit(self: *Collector) void {
        self.packets.deinit(self.gpa);
        self.metas.deinit(self.gpa);
    }

    /// Packets are stored back to back, so packet `i` starts after the sum of all earlier
    /// packets' wire lengths.
    fn fragment(self: *const Collector, i: usize) []const u8 {
        var off: usize = 0;
        for (self.metas.items[0..i]) |m| off += m.wire_len;
        return self.packets.items[off..][0..self.metas.items[i].wire_len];
    }
};

test "MTU arithmetic: the mandatory 1500-byte underlay case (RFC 8200 4.5 / 5)" {
    const params = MtuParams{ .path_mtu = 1500 };
    try t.expectEqual(@as(usize, 40 + 8), tunnelOverhead(params, true));
    try t.expectEqual(@as(usize, 40), tunnelOverhead(params, false));

    // 1500 - 40 - 8 = 1452, rounded down to an 8-octet multiple = 1448.
    const payload = try calculateFragmentPayloadSize(params);
    try t.expectEqual(@as(usize, 1448), payload);
    try t.expectEqual(@as(usize, 0), payload % fragment_alignment);

    // The largest resulting fragment packet is 40 + 8 + 1448 = 1496 <= 1500.
    const wire = tunnelOverhead(params, true) + payload;
    try t.expectEqual(@as(usize, 1496), wire);
    try t.expect(wire <= params.path_mtu);
}

test "MTU arithmetic: no 1500 is hard-coded anywhere" {
    // IPv6 minimum link MTU (RFC 8200 Section 5).
    try t.expectEqual(@as(usize, 1280), ipv6.min_link_mtu);
    const at_min = try calculateFragmentPayloadSize(.{ .path_mtu = 1280 });
    // 1280 - 48 = 1232, already a multiple of 8.
    try t.expectEqual(@as(usize, 1232), at_min);
    try t.expectEqual(@as(usize, 1280), tunnelOverhead(.{ .path_mtu = 1280 }, true) + at_min);

    // 9000-octet underlay.
    const jumbo = try calculateFragmentPayloadSize(.{ .path_mtu = 9000 });
    try t.expectEqual(@as(usize, 8952), jumbo); // 9000 - 48 = 8952
    try t.expectEqual(@as(usize, 0), jumbo % 8);

    // An MTU that is not a multiple of 8 (measured from after the headers) loses the remainder to
    // the RFC 8200 Section 4.5 alignment requirement.
    try t.expectEqual(@as(usize, 1448), try calculateFragmentPayloadSize(.{ .path_mtu = 1497 }));
    try t.expectEqual(@as(usize, 1440), try calculateFragmentPayloadSize(.{ .path_mtu = 1491 }));
    try t.expectEqual(@as(usize, 1432), try calculateFragmentPayloadSize(.{ .path_mtu = 1483 }));

    // Reserved extension-header octets reduce the payload budget.
    const with_hbh = try calculateFragmentPayloadSize(.{ .path_mtu = 1500, .per_fragment_ext_len = 16 });
    try t.expectEqual(@as(usize, 1432), with_hbh); // 1500 - 40 - 16 - 8 = 1436 -> 1432
    try t.expectEqual(@as(usize, 64), tunnelOverhead(.{ .path_mtu = 1500, .per_fragment_ext_len = 16 }, true)); // 40 + 16 + 8
}

test "MTU arithmetic: rejects an unusable path MTU" {
    // No room for the IPv6 header alone.
    try t.expectError(error.PathMtuTooSmall, calculateFragmentPayloadSize(.{ .path_mtu = 48 }));
    try t.expectError(error.PathMtuTooSmall, calculateFragmentPayloadSize(.{ .path_mtu = 47 }));
    // Room for the headers but not for one aligned unit.
    try t.expectError(error.PathMtuTooSmall, calculateFragmentPayloadSize(.{ .path_mtu = 55 }));
    // Exactly the headers with zero payload is also unusable.
    try t.expectError(error.PathMtuTooSmall, calculateFragmentPayloadSize(.{ .path_mtu = 48 }));
}

test "fragmentCount and fragmentationThreshold" {
    const max_frag: usize = 1448;
    try t.expectEqual(@as(usize, 1), try fragmentCount(1448, max_frag));
    try t.expectEqual(@as(usize, 2), try fragmentCount(1449, max_frag));
    try t.expectEqual(@as(usize, 2), try fragmentCount(2896, max_frag));
    try t.expectEqual(@as(usize, 3), try fragmentCount(2897, max_frag));
    try t.expectEqual(@as(usize, 7), try fragmentCount(9002, max_frag));
    try t.expectEqual(@as(usize, 1449), fragmentationThreshold(max_frag));
    try t.expectError(error.PathMtuTooSmall, fragmentCount(10, 0));
    try t.expectError(error.PathMtuTooSmall, fragmentCount(0, 1448));
}

fn testFrame(gpa: std.mem.Allocator, len: usize) ![]u8 {
    const frame = try gpa.alloc(u8, len);
    // A deterministic, recognisable pattern so corruption is obvious in assertions.
    for (frame, 0..) |*b, i| b.* = @truncate(i *% 251 +% 17);
    return frame;
}

test "Fragmenter.init validates the scratch buffer" {
    const params = MtuParams{ .path_mtu = 1500 };
    var scratch: [1496]u8 = undefined;
    var f = try Fragmenter.init(&scratch, params);
    try t.expectEqual(@as(usize, 1496), f.capacity);
    f.deinit();

    var small: [100]u8 = undefined;
    try t.expectError(error.ScratchTooSmall, Fragmenter.init(&small, params));

    var tiny: [10]u8 = undefined;
    try t.expectError(error.PathMtuTooSmall, Fragmenter.init(&tiny, .{ .path_mtu = 20 }));
}

test "emitFragments: 9000-octet Ethernet frame over a 1500-octet underlay" {
    const gpa = std.testing.allocator;
    const params = MtuParams{ .path_mtu = 1500 };
    var scratch: [1496]u8 = undefined;
    var frag = try Fragmenter.init(&scratch, params);
    defer frag.deinit();

    const frame = try testFrame(gpa, 9000);
    defer gpa.free(frame);

    const datagram = try gpa.alloc(u8, etherip.header_len + frame.len);
    defer gpa.free(datagram);
    _ = try etherip.encapsulate(frame, datagram);

    var c = Collector{ .gpa = gpa };
    defer c.deinit();

    const src = try ipv6.Address.parse("2001:db8:100::1");
    const dst = try ipv6.Address.parse("2001:db8:200::1");
    const count = try frag.emitFragments(.{
        .mtu = params,
        .source = src,
        .destination = dst,
        .write_options = .{ .source = src, .destination = dst, .hop_limit = 64 },
        .identification = 0xCAFEBABE,
    }, datagram, .{ .context = &c, .emit = Collector.sink });

    // Fragmentable Part is 9002 octets: 6 * 1448 + 914 = 7 fragments.
    try t.expectEqual(@as(u32, 7), count);

    const reassembled = try gpa.alloc(u8, datagram.len);
    defer gpa.free(reassembled);
    var filled: usize = 0;

    for (0..count) |i| {
        const m = c.metas.items[i];
        const pkt = c.fragment(i);

        // RFC 8200 Section 4.5: the packet must fit the path MTU.
        try t.expect(pkt.len <= params.path_mtu);
        try t.expectEqual(m.wire_len, pkt.len);

        // Outer IPv6 header.
        const h = try ipv6.parseHeader(pkt);
        try t.expectEqual(@as(u16, @intCast(m.wire_len - ipv6.header_len)), h.payload_length);
        try t.expectEqual(ipv6.next_header_fragment, h.next_header);
        try t.expect(src.eql(h.source));
        try t.expect(dst.eql(h.destination));

        // Fragment header.
        const chain = try ipv6.parseExtensionChain(h);
        const f = chain.fragment.?;
        try t.expectEqual(etherip.ip_protocol_number, f.next_header);
        try t.expectEqual(@as(u8, 0), f.reserved);
        try t.expectEqual(@as(u2, 0), f.res);
        try t.expectEqual(@as(u32, 0xCAFEBABE), f.identification);
        try t.expectEqual(m.more_fragments, f.more_fragments);
        try t.expectEqual(m.fragment_offset, f.fragment_offset);
        // RFC 8200 Section 4.5: every non-final fragment is a multiple of 8 octets.
        if (m.more_fragments) try t.expectEqual(@as(usize, 0), f.data.len % 8);

        // The first fragment must begin with the EtherIP header (RFC 8200 Section 4.5: the
        // Upper-Layer header must be in the first fragment).
        const at: usize = f.byteOffset();
        try t.expect(@as(usize, f.data.len) + at <= reassembled.len);
        @memcpy(reassembled[at..][0..f.data.len], f.data);
        filled += f.data.len;
    }
    try t.expectEqual(datagram.len, filled);
    try t.expectEqualSlices(u8, datagram, reassembled);
    // And the EtherIP payload is the original frame, byte for byte.
    try t.expectEqualSlices(u8, frame, reassembled[etherip.header_len..]);
}

test "emitFragments: refuses to fragment something that already fits" {
    const gpa = std.testing.allocator;
    const params = MtuParams{ .path_mtu = 1500 };
    var scratch: [1496]u8 = undefined;
    var frag = try Fragmenter.init(&scratch, params);

    // 2 (EtherIP) + 1446 (frame) == exactly one aligned fragment payload.
    const datagram = try gpa.alloc(u8, 1448);
    defer gpa.free(datagram);
    @memset(datagram, 0xAB);

    var c = Collector{ .gpa = gpa };
    defer c.deinit();
    try t.expectError(
        error.NotFragmentable,
        frag.emitFragments(.{
            .mtu = params,
            .source = ipv6.Address.any,
            .destination = ipv6.Address.any,
            .write_options = .{ .source = ipv6.Address.any, .destination = ipv6.Address.any },
            .identification = 1,
        }, datagram, .{ .context = &c, .emit = Collector.sink }),
    );
}

test "emitFragments: rejects a datagram beyond the 16-bit Payload Length limit" {
    const gpa = std.testing.allocator;
    const params = MtuParams{ .path_mtu = 9000 };
    var scratch: [9000]u8 = undefined;
    var frag = try Fragmenter.init(&scratch, params);

    // 65533 is the largest Fragmentable Part that still fits a 16-bit Payload Length.
    const big = try gpa.alloc(u8, 65536);
    defer gpa.free(big);
    @memset(big, 0);

    var c = Collector{ .gpa = gpa };
    defer c.deinit();
    try t.expectError(
        error.DatagramTooLarge,
        frag.emitFragments(.{
            .mtu = params,
            .source = ipv6.Address.any,
            .destination = ipv6.Address.any,
            .write_options = .{ .source = ipv6.Address.any, .destination = ipv6.Address.any },
            .identification = 1,
        }, big, .{ .context = &c, .emit = Collector.sink }),
    );
}

test "emitFragments: exactly two fragments, boundary at the alignment limit" {
    const gpa = std.testing.allocator;
    const params = MtuParams{ .path_mtu = 1500 };
    var scratch: [1496]u8 = undefined;
    var frag = try Fragmenter.init(&scratch, params);

    // 1448 + 1448 = 2896 exactly: the second (final) fragment is also a multiple of 8.
    const datagram = try gpa.alloc(u8, 2896);
    defer gpa.free(datagram);
    for (datagram, 0..) |*b, i| b.* = @truncate(i);

    var c = Collector{ .gpa = gpa };
    defer c.deinit();
    const count = try frag.emitFragments(.{
        .mtu = params,
        .source = ipv6.Address.any,
        .destination = ipv6.Address.any,
        .write_options = .{ .source = ipv6.Address.any, .destination = ipv6.Address.any },
        .identification = 0x1234,
    }, datagram, .{ .context = &c, .emit = Collector.sink });

    try t.expectEqual(@as(u32, 2), count);
    try t.expect(c.metas.items[0].more_fragments);
    try t.expect(!c.metas.items[1].more_fragments);
    try t.expectEqual(@as(u13, 0), c.metas.items[0].fragment_offset);
    try t.expectEqual(@as(u13, 181), c.metas.items[1].fragment_offset); // 1448 / 8
    try t.expectEqual(@as(usize, 1496), c.metas.items[0].wire_len);
    try t.expectEqual(@as(usize, 40 + 8 + 1448), c.metas.items[1].wire_len);
}

test "emitFragments: a larger MTU than the Fragmenter was built for is refused, not overflowed" {
    const gpa = std.testing.allocator;
    var scratch: [1496]u8 = undefined;
    var frag = try Fragmenter.init(&scratch, .{ .path_mtu = 1500 });
    defer frag.deinit();

    const datagram = try gpa.alloc(u8, 5000);
    defer gpa.free(datagram);
    @memset(datagram, 0x11);

    var c = Collector{ .gpa = gpa };
    defer c.deinit();
    // A 4000-octet path MTU needs 4048 + 4000 scratch; this Fragmenter only has 1496.
    try t.expectError(
        error.ScratchTooSmall,
        frag.emitFragments(.{
            .mtu = .{ .path_mtu = 4000 },
            .source = ipv6.Address.any,
            .destination = ipv6.Address.any,
            .write_options = .{ .source = ipv6.Address.any, .destination = ipv6.Address.any },
            .identification = 1,
        }, datagram, .{ .context = &c, .emit = Collector.sink }),
    );
}
