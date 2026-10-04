//! Optional TCP MSS clamping for encapsulated frames.
//!
//! ## This is an implementation feature, not a protocol requirement
//!
//! No RFC in this project mandates MSS clamping for EtherIP. RFC 3378 is silent (it is an
//! Informational document describing a data format), and RFC 8201 Section 5.1 merely encourages
//! packetization layers to *"avoid sending messages that will require source fragmentation"*. MSS
//! clamping is a well-known technique for exactly that (RFC 6691 in general terms), offered here as
//! an opt-in feature that reduces fragmentation incidence. It is **never** a substitute for the
//! IPv6 source fragmentation the tunnel depends on: a 9000-octet Ethernet frame has no TCP MSS to
//! shrink, so fragmentation remains the mechanism that carries jumbo traffic.
//!
//! ## Scope, deliberately narrow
//!
//!   * Only Ethernet II, with any 802.1Q / 802.1ad tags.
//!   * Only IPv4 or IPv6 as the inner network layer.
//!   * Only TCP as the transport.
//!   * Only packets with SYN set and ACK clear. RFC 9293 Section 3.1 makes the MSS option
//!     meaningful only in a SYN; rewriting it elsewhere would be wrong.
//!   * Only when a TCP MSS option is present and larger than the computed target. A SYN without an
//!     MSS option is left alone, as is a SYN whose MSS already fits.
//!   * Every unrelated TCP option is preserved byte for byte; only the 2 octets of the MSS option
//!     change, and the TCP checksum is recomputed over the correct pseudo-header.
//!
//! ## How the safe MSS is computed
//!
//! Nothing is hard-coded:
//!
//! ```text
//! effective_path_mtu  = min(configured_underlay_mtu, discovered_path_mtu)   [RFC 8201 5.2]
//! effective_inner_mtu = effective_path_mtu - 40 (outer IPv6) - 2 (EtherIP)
//! clamp               = effective_inner_mtu - inner_ip_header_len - inner_tcp_header_len
//! ```
//!
//! With `effective_path_mtu = 1500` that gives 1418 for IPv4/TCP and 1398 for IPv6/TCP. With the
//! IPv6 minimum link MTU of 1280 they become 1198 and 1178. The result is further limited by
//! `overlay_mtu` and by any explicitly configured clamp value.

const std = @import("std");
const ipv6 = @import("ipv6.zig");
const etherip = @import("etherip.zig");
const ethernet = @import("ethernet.zig");
const checksum = @import("checksum.zig");

/// IANA EtherType for IPv4.
pub const ether_type_ipv4: u16 = ethernet.ether_type_ipv4;
/// IANA EtherType for IPv6.
pub const ether_type_ipv6: u16 = ethernet.ether_type_ipv6;

/// IANA protocol number 6 (TCP).
pub const ip_proto_tcp: u8 = 6;
/// Minimum length of an IPv4 header with no options (RFC 791).
pub const ipv4_min_header_len: usize = 20;
/// Minimum length of an IPv6 header (RFC 8200 Section 3).
pub const ipv6_header_len: usize = 40;
/// Minimum length of a TCP header (RFC 9293 Section 3.1: Data Offset of 5 words).
pub const tcp_min_header_len: usize = 20;

/// TCP flag bits we care about (RFC 9293 Section 3.1).
pub const tcp_flag_fin: u8 = 0x01;
pub const tcp_flag_syn: u8 = 0x02;
pub const tcp_flag_rst: u8 = 0x04;
pub const tcp_flag_psh: u8 = 0x08;
pub const tcp_flag_ack: u8 = 0x10;

/// Why a frame was not modified.
pub const SkipReason = enum {
    /// Not a TCP frame (EtherType is neither IPv4 nor IPv6, or the L3 protocol is not TCP).
    NotTcp,
    /// TCP header present but SYN is not set, or ACK is set: not a handshake.
    NotSyn,
    /// A SYN with no TCP MSS option. RFC 9293 Section 3.1 makes the option optional, and RFC 768
    /// (UDP) and RFC 793 predecessors defaulted to 536, so leaving it alone is correct: the peer
    /// chose not to advertise an MSS and we have no business inventing one.
    NoMssOption,
    /// The advertised MSS already fits the computed target.
    AlreadyWithinTarget,
};

pub const Outcome = union(enum) {
    /// The advertised MSS exceeded the target and was reduced.
    clamped: struct { from: u16, to: u16 },
    /// The frame was left untouched.
    skipped: SkipReason,
    /// The frame could not be parsed far enough to decide safely, so it was left untouched.
    unparseable,
};

pub const ParseError = error{
    /// Not enough octets to decide.
    Truncated,
    /// Structurally invalid: impossible header lengths, a TCP option that runs off the end, etc.
    Malformed,
};

/// Everything needed to decide whether and how to clamp, plus the resulting numbers.
pub const Budget = struct {
    /// `min(configured_underlay_mtu, discovered_path_mtu)`.
    effective_path_mtu: usize,
    /// Largest Ethernet frame the tunnel will carry.
    overlay_mtu: usize,
    /// An operator-specified clamp, or null for automatic derivation.
    configured_mss: ?u16 = null,
};

/// Compute the MSS this tunnel is willing to accept on an inner TCP connection.
///
/// Returns null when the budget is too small to host even a minimal TCP/IP packet, which the
/// caller treats as "do not clamp".
pub fn computeTargetMss(budget: Budget, ip_header_len: usize, tcp_header_len: usize) ?u16 {
    // RFC 8200 Section 3: 40-octet outer IPv6 header.
    // RFC 3378 Section 2: 2-octet EtherIP header, which is part of the tunnel overhead here because
    // we are budgeting for a packet that will NOT be fragmented.
    const tunnel_overhead = ipv6_header_len + etherip.header_len;
    if (budget.effective_path_mtu <= tunnel_overhead) return null;
    const effective_inner_mtu = budget.effective_path_mtu - tunnel_overhead;
    if (effective_inner_mtu <= ip_header_len + tcp_header_len) return null;

    const computed = effective_inner_mtu - ip_header_len - tcp_header_len;
    // Never exceed what the tunnel can actually carry.
    var target: usize = @min(computed, budget.overlay_mtu);
    if (budget.configured_mss) |configured| {
        target = @min(target, configured);
    }
    if (target == 0 or target > std.math.maxInt(u16)) return null;
    return @intCast(target);
}

/// Convenience wrappers for the two inner-IP flavours.
pub fn computeTargetMssIpv4(budget: Budget, tcp_header_len: usize) ?u16 {
    return computeTargetMss(budget, ipv4_min_header_len, tcp_header_len);
}

pub fn computeTargetMssIpv6(budget: Budget, tcp_header_len: usize) ?u16 {
    return computeTargetMss(budget, ipv6_header_len, tcp_header_len);
}

/// Locate the TCP MSS option inside a TCP header and return its offset in `segment`.
///
/// * `segment` must be the complete TCP header plus data.
/// * `header_len` is the TCP Data Offset in octets (RFC 9293 Section 3.1: the upper four bits of
///   octet 12, in 32-bit words).
///
/// Returns the offset of the 2 MSS octets, `error.Malformed` if the option block is inconsistent
/// (RFC 9293 requires padding with EOL rather than a zero length), or null when no MSS option is
/// present.
pub fn findMssOption(segment: []const u8, header_len: usize) ParseError!?usize {
    if (segment.len < tcp_min_header_len) return error.Truncated;
    if (header_len < tcp_min_header_len or header_len > segment.len) return error.Malformed;

    var i: usize = tcp_min_header_len;
    while (i < header_len) {
        const kind = segment[i];
        if (kind == 0) return null; // End of Option List (RFC 9293).
        if (kind == 1) { // NOP
            i += 1;
            continue;
        }
        if (i + 1 >= header_len) return error.Malformed;
        const len = segment[i + 1];
        // Every option except NOP and EOL has a length octet that must cover itself.
        if (len < 2 or i + len > header_len) return error.Malformed;
        if (kind == 2) { // MSS, RFC 9293 Section 3.1
            if (len != 4) return error.Malformed;
            return i + 2;
        }
        i += len;
    }
    return null;
}

/// Inspect, and if warranted clamp, the MSS advertised by a TCP SYN inside an Ethernet frame.
///
/// `frame` is modified in place (it is the overlay interface's buffer). Returns an `Outcome`;
/// `.unparseable` and `.skipped` both leave `frame` byte-for-byte unchanged.
pub fn clampFrame(frame: []u8, budget: Budget) Outcome {
    const eth = ethernet.parse(frame) catch return .unparseable;

    const ip_off = @as(usize, eth.payload.ptr - frame.ptr);
    const l3 = switch (eth.ether_type) {
        ether_type_ipv4 => L3.ipv4,
        ether_type_ipv6 => L3.ipv6,
        else => return .{ .skipped = .NotTcp },
    };

    // --- inner IP header ---
    const L3Info = struct {
        header_len: usize,
        src_off: usize,
        dst_off: usize,
        protocol: u8,
        addr_len: usize,
    };
    const info: L3Info = switch (l3) {
        .ipv4 => blk: {
            const p = eth.payload;
            if (p.len < ipv4_min_header_len) return .unparseable;
            const version: u4 = @truncate(p[0] >> 4);
            if (version != 4) return .unparseable;
            const ihl: usize = @as(usize, p[0] & 0x0f) * 4;
            // RFC 791: IHL must be at least 5 and must fit inside the captured octets.
            if (ihl < ipv4_min_header_len or ihl > p.len) return .unparseable;
            break :blk .{
                .header_len = ihl,
                .src_off = 12,
                .dst_off = 16,
                .protocol = p[9],
                .addr_len = 4,
            };
        },
        .ipv6 => blk: {
            const p = eth.payload;
            if (p.len < ipv6_header_len) return .unparseable;
            if ((p[0] >> 4) != 6) return .unparseable;
            // Walk the inner extension headers in order (RFC 8200 Section 4). A fragment header is
            // rejected: a fragmented SYN cannot be safely rewritten.
            var next_header = p[6];
            var off: usize = ipv6_header_len;
            var hops: usize = 0;
            while (true) {
                switch (next_header) {
                    ipv6.next_header_tcp => break,
                    ipv6.next_header_fragment => return .unparseable,
                    ipv6.next_header_hop_by_hop,
                    ipv6.next_header_destination_options,
                    ipv6.next_header_routing,
                    => {
                        if (p.len < off + 8) return .unparseable;
                        const hdr_ext_len = p[off + 1];
                        const total = (@as(usize, hdr_ext_len) + 1) * 8;
                        if (off + total > p.len) return .unparseable;
                        next_header = p[off];
                        off += total;
                        hops += 1;
                        if (hops > 8) return .unparseable;
                        continue;
                    },
                    else => return .{ .skipped = .NotTcp },
                }
                break;
            }
            break :blk .{
                .header_len = off,
                .src_off = 8,
                .dst_off = 24,
                .protocol = next_header,
                .addr_len = 16,
            };
        },
    };

    if (info.protocol != ip_proto_tcp) return .{ .skipped = .NotTcp };

    // --- inner TCP header ---
    const tcp_off = ip_off + info.header_len;
    const tcp = frame[tcp_off..];
    if (tcp.len < tcp_min_header_len) return .unparseable;

    const data_offset_words: u8 = tcp[12] >> 4;
    if (data_offset_words < 5) return .unparseable;
    const tcp_header_len: usize = @as(usize, data_offset_words) * 4;
    if (tcp_header_len > tcp.len) return .unparseable;

    const flags = tcp[13];
    const is_syn = (flags & tcp_flag_syn) != 0;
    const is_ack = (flags & tcp_flag_ack) != 0;
    // RFC 9293 Section 3.1: the MSS option is only sent in a SYN. ACK-clear SYN identifies the
    // handshake, so a simultaneous-open SYN-ACK is intentionally left alone.
    if (!is_syn or is_ack) return .{ .skipped = .NotSyn };

    const mss_off = findMssOption(tcp[0..tcp_header_len], tcp_header_len) catch return .unparseable;
    const mss_field_off = tcp_off + (mss_off orelse return .{ .skipped = .NoMssOption });
    const advertised = std.mem.readInt(u16, frame[mss_field_off..][0..2], .big);
    // RFC 9293 Section 3.1: the Checksum field is the 16 bits at octet 16 of the TCP header.
    const tcp_checksum_offset: usize = 16;

    const target: u16 = computeTargetMss(budget, info.header_len, tcp_header_len) orelse
        return .unparseable;
    if (advertised <= target) return .{ .skipped = .AlreadyWithinTarget };

    std.mem.writeInt(u16, frame[mss_field_off..][0..2], target, .big);

    // Recompute the TCP checksum over the correct pseudo-header. Only the 2 MSS octets changed, so
    // every other option and every other header octet is preserved exactly.
    const ip_version: checksum.IpVersion = switch (l3) {
        .ipv4 => .ipv4,
        .ipv6 => .ipv6,
    };
    checksum.recomputeTcpChecksum(
        tcp,
        tcp_checksum_offset,
        ip_version,
        frame[ip_off + info.src_off ..][0..info.addr_len],
        frame[ip_off + info.dst_off ..][0..info.addr_len],
    ) catch return .unparseable;

    return .{ .clamped = .{ .from = advertised, .to = target } };
}

const L3 = enum { ipv4, ipv6 };

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

const dst_mac = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
const src_mac = [6]u8{ 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };

/// Build an Ethernet II frame carrying an inner TCP SYN with the given MSS option value.
/// `null` omits the MSS option entirely.
fn buildSynTcpSyn(
    gpa: std.mem.Allocator,
    l3: L3,
    vlan: ?u16,
    mss: ?u16,
) ![]u8 {
    const vlan_bytes: usize = if (vlan != null) ethernet.vlan_tag_len else 0;

    const l3_ether_type: u16 = switch (l3) {
        .ipv4 => ethernet.ether_type_ipv4,
        .ipv6 => ethernet.ether_type_ipv6,
    };
    const ip_len: usize = switch (l3) {
        .ipv4 => ipv4_min_header_len,
        .ipv6 => ipv6_header_len,
    };

    // Options: MSS (kind 2, len 4) plus NOP/NOP/SACK-permitted and EOL, the classic Linux SYN.
    var options: [12]u8 = .{ 2, 4, 0x05, 0xb4, 1, 1, 4, 2, 0, 0, 0, 0 };
    if (mss == null) {
        // No MSS: a timestamp option occupies the same space, ending with EOL padding.
        options = .{ 8, 10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0 };
    }
    const tcp_len = tcp_min_header_len + options.len;

    const total = ethernet.header_len + vlan_bytes + ip_len + tcp_len;
    const frame = try gpa.alloc(u8, total);
    @memset(frame, 0);

    // Ethernet II header. With a VLAN tag the outer type is the TPID and the inner type follows
    // the 4-octet tag (IEEE 802.1Q on the wire).
    var n: usize = 0;
    try ethernet.writeHeader(
        frame[n..],
        dst_mac,
        src_mac,
        if (vlan != null) ethernet.ether_type_vlan else l3_ether_type,
    );
    n += ethernet.header_len;
    if (vlan) |vlan_id| {
        ethernet.writeVlanTci(frame[n..][0..2], .{
            .priority = 5,
            .drop_eligible = false,
            .vlan_id = @truncate(vlan_id),
        });
        writeEtherType(frame[n + 2 ..][0..2], l3_ether_type);
        n += ethernet.vlan_tag_len;
    }

    switch (l3) {
        .ipv4 => {
            const ip = frame[n..][0..ip_len];
            ip[0] = 0x45; // Version 4, IHL 5 (no options).
            ip[2] = @truncate((ip_len + tcp_len) >> 8);
            ip[3] = @truncate(ip_len + tcp_len);
            ip[8] = 64; // TTL
            ip[9] = ip_proto_tcp;
            @memcpy(ip[12..16], &[_]u8{ 192, 0, 2, 1 });
            @memcpy(ip[16..20], &[_]u8{ 198, 51, 100, 7 });
            // A plausible IPv4 header checksum so the frame looks real in a capture.
            const hc = checksum.checksum(ip);
            std.mem.writeInt(u16, ip[10..12], if (hc == 0) 0xffff else hc, .big);
        },
        .ipv6 => {
            const src6 = ipv6.Address.parse("2001:db8::1") catch unreachable;
            const dst6 = ipv6.Address.parse("2001:db8::2") catch unreachable;
            try ipv6.writeHeader(frame[n..][0..ip_len], ip_proto_tcp, tcp_len, .{
                .hop_limit = 64,
                .source = src6,
                .destination = dst6,
            });
        },
    }
    n += ip_len;

    const tcp = frame[n..];
    std.mem.writeInt(u16, tcp[0..2], 12345, .big); // source port
    std.mem.writeInt(u16, tcp[2..4], 443, .big); // destination port
    tcp[12] = @intCast((tcp_len / 4) << 4); // Data Offset, in 32-bit words
    tcp[13] = tcp_flag_syn; // SYN set, ACK clear.
    @memcpy(tcp[tcp_min_header_len..][0..options.len], &options);
    if (mss) |v| std.mem.writeInt(u16, tcp[22..24], v, .big);

    // Seed a correct TCP checksum so the clamping test can prove it stays correct.
    checksum.recomputeTcpChecksum(
        tcp[0..tcp_len],
        16,
        switch (l3) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
        },
        frame[n - ip_len + infoSrcOff(l3) ..][0..infoSrcLen(l3)],
        frame[n - ip_len + infoDstOff(l3) ..][0..infoDstLen(l3)],
    ) catch unreachable;

    return frame;
}

fn infoSrcOff(l3: L3) usize {
    return switch (l3) {
        .ipv4 => 12,
        .ipv6 => 8,
    };
}
fn infoDstOff(l3: L3) usize {
    return switch (l3) {
        .ipv4 => 16,
        .ipv6 => 24,
    };
}
fn infoSrcLen(l3: L3) usize {
    return switch (l3) {
        .ipv4 => 4,
        .ipv6 => 16,
    };
}
fn infoDstLen(l3: L3) usize {
    return switch (l3) {
        .ipv4 => 4,
        .ipv6 => 16,
    };
}

fn writeEtherType(out: *[2]u8, v: u16) void {
    std.mem.writeInt(u16, out[0..2], v, .big);
}

/// Verify the TCP checksum of a frame built by `buildSynTcpSyn`.
fn tcpChecksumValid(frame: []const u8, l3: L3) bool {
    const eth = ethernet.parse(frame) catch return false;
    const ip_off = @as(usize, eth.payload.ptr - frame.ptr);
    const ip_len: usize = switch (l3) {
        .ipv4 => @as(usize, frame[ip_off] & 0x0f) * 4,
        .ipv6 => ipv6_header_len,
    };
    const tcp = frame[ip_off + ip_len ..];
    const sum = checksum.accumulatePseudoHeader(
        0,
        switch (l3) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
        },
        frame[ip_off + infoSrcOff(l3) ..][0..infoSrcLen(l3)],
        frame[ip_off + infoDstOff(l3) ..][0..infoDstLen(l3)],
        ip_proto_tcp,
        tcp.len,
    ) catch return false;
    return checksum.fold(checksum.accumulate(sum, tcp)) == 0xffff;
}

const budget_1500: Budget = .{ .effective_path_mtu = 1500, .overlay_mtu = 9000 };

test "computeTargetMss: derived from the effective path MTU, never hard-coded" {
    // IPv4: 1500 - 40 (outer IPv6) - 2 (EtherIP) - 20 (IPv4) - 20 (TCP) = 1418
    try t.expectEqual(@as(?u16, 1418), computeTargetMssIpv4(budget_1500, 20));
    // IPv6: 1500 - 40 - 2 - 40 - 20 = 1398
    try t.expectEqual(@as(?u16, 1398), computeTargetMssIpv6(budget_1500, 20));

    // A 24-octet TCP header (options present) reduces the IPv4 target by 4.
    try t.expectEqual(@as(?u16, 1414), computeTargetMssIpv4(budget_1500, 24));

    // The IPv6 minimum link MTU (RFC 8200 Section 5) as the effective path MTU.
    const at_min: Budget = .{ .effective_path_mtu = 1280, .overlay_mtu = 9000 };
    try t.expectEqual(@as(?u16, 1198), computeTargetMssIpv4(at_min, 20));
    try t.expectEqual(@as(?u16, 1178), computeTargetMssIpv6(at_min, 20));

    // A 9000-octet effective path MTU raises the budget but never past the overlay MTU.
    const jumbo: Budget = .{ .effective_path_mtu = 9000, .overlay_mtu = 9000 };
    try t.expectEqual(@as(?u16, 8918), computeTargetMssIpv4(jumbo, 20));

    // An explicit operator clamp wins when it is lower.
    const capped: Budget = .{ .effective_path_mtu = 1500, .overlay_mtu = 9000, .configured_mss = 1200 };
    try t.expectEqual(@as(?u16, 1200), computeTargetMssIpv4(capped, 20));
    // ...but a clamp above the computed target does not raise it.
    const raised: Budget = .{ .effective_path_mtu = 1500, .overlay_mtu = 9000, .configured_mss = 9000 };
    try t.expectEqual(@as(?u16, 1418), computeTargetMssIpv4(raised, 20));

    // A path MTU that cannot host the tunnel headers yields no target at all.
    const tiny: Budget = .{ .effective_path_mtu = 64, .overlay_mtu = 9000 };
    try t.expectEqual(@as(?u16, null), computeTargetMssIpv4(tiny, 20));
    const zero: Budget = .{ .effective_path_mtu = 42, .overlay_mtu = 9000 };
    try t.expectEqual(@as(?u16, null), computeTargetMssIpv4(zero, 20));
}

test "findMssOption: RFC 9293 option layout" {
    // MSS, kind 2 length 4, value 1460, then SACK-permitted, then EOL.
    var tcp = [_]u8{0} ** 28;
    const opts = [_]u8{ 2, 4, 0x05, 0xb4, 4, 2, 0, 0 };
    @memcpy(tcp[20..28], &opts);
    try t.expectEqual(@as(?usize, 22), try findMssOption(&tcp, 28));
    try t.expectEqual(@as(u16, 1460), std.mem.readInt(u16, tcp[22..24], .big));

    // NOP padding before the MSS option.
    var padded = [_]u8{0} ** 27;
    const opts2 = [_]u8{ 1, 1, 2, 4, 0x05, 0xb4, 0 };
    @memcpy(padded[20..27], &opts2);
    try t.expectEqual(@as(?usize, 24), try findMssOption(&padded, 27));

    // No MSS option: EOL terminates the list.
    var none = [_]u8{0} ** 24;
    const opts3 = [_]u8{ 1, 1, 1, 0 }; // NOP, NOP, NOP, End of Option List
    @memcpy(none[20..24], &opts3);
    try t.expectEqual(@as(?usize, null), try findMssOption(&none, 24));

    // Empty option block.
    try t.expectEqual(@as(?usize, null), try findMssOption(&[_]u8{0} ** 20, 20));
}

test "findMssOption: malformed option blocks are rejected, not guessed at" {
    // Zero-length option: RFC 9293 requires EOL (0) or NOP (1) instead.
    var zero_len = [_]u8{0} ** 24;
    zero_len[20] = 4;
    zero_len[21] = 0;
    try t.expectError(error.Malformed, findMssOption(&zero_len, 24));

    // Option length of 1: too short to cover the length octet.
    var short_opt = [_]u8{0} ** 24;
    short_opt[20] = 4;
    short_opt[21] = 1;
    try t.expectError(error.Malformed, findMssOption(&short_opt, 24));

    // Option runs past the end of the header.
    var overrun = [_]u8{0} ** 24;
    overrun[20] = 4;
    overrun[21] = 40;
    try t.expectError(error.Malformed, findMssOption(&overrun, 24));

    // MSS option with the wrong length field.
    var wrong_len = [_]u8{0} ** 24;
    wrong_len[20] = 2;
    wrong_len[21] = 6;
    wrong_len[22] = 0x05;
    wrong_len[23] = 0xb4;
    try t.expectError(error.Malformed, findMssOption(&wrong_len, 24));

    // Data Offset below the minimum header size.
    try t.expectError(error.Malformed, findMssOption(&[_]u8{0} ** 20, 16));
    // Data Offset beyond the segment.
    try t.expectError(error.Malformed, findMssOption(&[_]u8{0} ** 20, 24));
    // Truncated segment.
    try t.expectError(error.Truncated, findMssOption(&[_]u8{0} ** 12, 20));
}

test "clampFrame: IPv4 TCP SYN above the target is clamped and the checksum fixed" {
    const gpa = t.allocator;
    const frame = try buildSynTcpSyn(gpa, .ipv4, null, 1460);
    defer gpa.free(frame);

    try t.expect(tcpChecksumValid(frame, .ipv4));
    const before = try gpa.dupe(u8, frame);
    defer gpa.free(before);

    switch (clampFrame(frame, budget_1500)) {
        .clamped => |c| {
            // 1500 - 40 (outer IPv6) - 2 (EtherIP) - 20 (IPv4) - 32 (TCP header with options)
            try t.expectEqual(@as(u16, 1460), c.from);
            try t.expectEqual(@as(u16, 1406), c.to);
        },
        else => return error.TestUnexpectedResult,
    }

    // The MSS option now advertises the target.
    const eth = try ethernet.parse(frame);
    const tcp = eth.payload[ipv4_min_header_len..];
    try t.expectEqual(@as(u16, 1406), std.mem.readInt(u16, tcp[22..24], .big));
    try t.expect(tcpChecksumValid(frame, .ipv4));

    // Nothing outside the 2-octet MSS option and the 2-octet TCP Checksum field may change: that
    // is the strongest available statement that "all unrelated TCP options are preserved".
    const ip_off = ethernet.header_len;
    const tcp_off = ip_off + ipv4_min_header_len;
    const mss_lo = tcp_off + 22;
    const mss_hi = mss_lo + 2;
    const csum_lo = tcp_off + 16;
    const csum_hi = csum_lo + 2;
    for (before, frame, 0..) |x, y, i| {
        if (x == y) continue;
        const in_mss = i >= mss_lo and i < mss_hi;
        const in_csum = i >= csum_lo and i < csum_hi;
        if (!in_mss and !in_csum) {
            std.debug.print("octet {d} changed unexpectedly: 0x{X:0>2} -> 0x{X:0>2}\n", .{ i, x, y });
            return error.TestUnexpectedResult;
        }
    }
    try t.expect(before[mss_lo] != frame[mss_lo] or before[mss_lo + 1] != frame[mss_lo + 1]);
}

test "clampFrame: IPv6 TCP SYN above the target is clamped" {
    const gpa = t.allocator;
    const frame = try buildSynTcpSyn(gpa, .ipv6, null, 1440);
    defer gpa.free(frame);
    try t.expect(tcpChecksumValid(frame, .ipv6));

    switch (clampFrame(frame, budget_1500)) {
        .clamped => |c| {
            // 1500 - 40 - 2 - 40 (inner IPv6) - 32 (TCP header with options)
            try t.expectEqual(@as(u16, 1440), c.from);
            try t.expectEqual(@as(u16, 1386), c.to);
        },
        else => return error.TestUnexpectedResult,
    }
    try t.expect(tcpChecksumValid(frame, .ipv6));
}

test "clampFrame: VLAN-tagged IPv4 TCP SYN" {
    const gpa = t.allocator;
    const frame = try buildSynTcpSyn(gpa, .ipv4, 100, 1460);
    defer gpa.free(frame);

    const eth = try ethernet.parse(frame);
    try t.expectEqual(@as(usize, 1), eth.tags.len);
    try t.expectEqual(@as(u12, 100), eth.tags.innermostVlanId().?);

    switch (clampFrame(frame, budget_1500)) {
        .clamped => |c| try t.expectEqual(@as(u16, 1406), c.to),
        else => return error.TestUnexpectedResult,
    }
    try t.expect(tcpChecksumValid(frame, .ipv4));
    // The VLAN tag survives untouched.
    const after = try ethernet.parse(frame);
    try t.expectEqual(@as(u12, 100), after.tags.innermostVlanId().?);
}

test "clampFrame: VLAN-tagged IPv6 TCP SYN" {
    const gpa = t.allocator;
    const frame = try buildSynTcpSyn(gpa, .ipv6, 4094, 1440);
    defer gpa.free(frame);
    try t.expect(tcpChecksumValid(frame, .ipv6));

    switch (clampFrame(frame, budget_1500)) {
        .clamped => |c| try t.expectEqual(@as(u16, 1386), c.to),
        else => return error.TestUnexpectedResult,
    }
    try t.expect(tcpChecksumValid(frame, .ipv6));
}

test "clampFrame: an MSS already below the clamp is left alone" {
    const gpa = t.allocator;
    const frame = try buildSynTcpSyn(gpa, .ipv4, null, 1200);
    defer gpa.free(frame);
    const before = try gpa.dupe(u8, frame);
    defer gpa.free(before);

    switch (clampFrame(frame, budget_1500)) {
        .skipped => |r| try t.expectEqual(SkipReason.AlreadyWithinTarget, r),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqualSlices(u8, before, frame);
    try t.expect(tcpChecksumValid(frame, .ipv4));

    // Exactly at the target is also left alone.
    const exact = try buildSynTcpSyn(gpa, .ipv4, null, 1406);
    defer gpa.free(exact);
    switch (clampFrame(exact, budget_1500)) {
        .skipped => |r| try t.expectEqual(SkipReason.AlreadyWithinTarget, r),
        else => return error.TestUnexpectedResult,
    }
}

test "clampFrame: a SYN with no MSS option is left alone" {
    const gpa = t.allocator;
    const frame = try buildSynTcpSyn(gpa, .ipv4, null, null);
    defer gpa.free(frame);
    const before = try gpa.dupe(u8, frame);
    defer gpa.free(before);

    switch (clampFrame(frame, budget_1500)) {
        .skipped => |r| try t.expectEqual(SkipReason.NoMssOption, r),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqualSlices(u8, before, frame);
}

test "clampFrame: non-SYN TCP packets are never modified" {
    const gpa = t.allocator;
    var frame = try buildSynTcpSyn(gpa, .ipv4, null, 1460);
    defer gpa.free(frame);
    // Turn it into an ACK and into a bare ACK data segment.
    frame[14 + 20 + 13] = tcp_flag_ack;
    const before = try gpa.dupe(u8, frame);
    defer gpa.free(before);
    switch (clampFrame(frame, budget_1500)) {
        .skipped => |r| try t.expectEqual(SkipReason.NotSyn, r),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqualSlices(u8, before, frame);

    // SYN+ACK (simultaneous open) is also left alone.
    frame[14 + 20 + 13] = tcp_flag_syn | tcp_flag_ack;
    switch (clampFrame(frame, budget_1500)) {
        .skipped => |r| try t.expectEqual(SkipReason.NotSyn, r),
        else => return error.TestUnexpectedResult,
    }
}

test "clampFrame: non-TCP and malformed frames are left alone" {
    const gpa = t.allocator;

    // ARP frame.
    var arp: [64]u8 = @splat(0);
    try ethernet.writeHeader(&arp, dst_mac, src_mac, ethernet.ether_type_arp);
    const before_arp = try gpa.dupe(u8, &arp);
    defer gpa.free(before_arp);
    switch (clampFrame(&arp, budget_1500)) {
        .skipped => |r| try t.expectEqual(SkipReason.NotTcp, r),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqualSlices(u8, before_arp, &arp);

    // IPv4 carrying UDP, not TCP.
    var udp: [64]u8 = @splat(0);
    try ethernet.writeHeader(&udp, dst_mac, src_mac, ethernet.ether_type_ipv4);
    udp[14] = 0x45;
    udp[14 + 9] = 17; // UDP
    switch (clampFrame(&udp, budget_1500)) {
        .skipped => |r| try t.expectEqual(SkipReason.NotTcp, r),
        else => return error.TestUnexpectedResult,
    }

    // Truncated frames of every length never panic.
    var junk: [16]u8 = @splat(0xEE);
    var len: usize = 0;
    while (len <= junk.len) : (len += 1) {
        _ = clampFrame(junk[0..len], budget_1500);
    }
}

test "clampFrame: malformed TCP options leave the frame untouched" {
    const gpa = t.allocator;
    const frame = try buildSynTcpSyn(gpa, .ipv4, null, 1460);
    defer gpa.free(frame);
    const before = try gpa.dupe(u8, frame);
    defer gpa.free(before);

    // Corrupt the option block: a zero-length option is illegal (RFC 9293).
    frame[14 + 20 + 20] = 4;
    frame[14 + 20 + 21] = 0;
    const after_corrupt = try gpa.dupe(u8, frame);
    defer gpa.free(after_corrupt);

    switch (clampFrame(frame, budget_1500)) {
        .unparseable => {},
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqualSlices(u8, after_corrupt, frame);
    try t.expectEqualSlices(u8, before[0 .. 14 + 20 + 20], frame[0 .. 14 + 20 + 20]);
}

test "clampFrame: a fragmented inner IPv6 SYN is refused rather than mis-clamped" {
    const gpa = t.allocator;
    const frame = try buildSynTcpSyn(gpa, .ipv6, null, 1440);
    defer gpa.free(frame);
    const before = try gpa.dupe(u8, frame);
    defer gpa.free(before);

    // Claim the inner IPv6 header is followed by a Fragment header without actually placing one:
    // the chain walk must notice the inconsistency instead of treating the TCP header bytes as a
    // Fragment header.
    frame[ethernet.header_len + 6] = ipv6.next_header_fragment;
    _ = clampFrame(frame, budget_1500);

    // Now place a real Fragment header. Because the offset-0 fragment still holds the whole TCP
    // header this could technically be rewritten, but a fragment offset other than zero means the
    // TCP header may be split across fragments, so clamping must be refused.
    const ip_off = ethernet.header_len;
    const tcp_off = ip_off + ipv6_header_len;
    var with_frag = try gpa.alloc(u8, frame.len + 8);
    defer gpa.free(with_frag);
    @memcpy(with_frag[0..tcp_off], frame[0..tcp_off]);
    @memset(with_frag[tcp_off..][0..8], 0);
    with_frag[tcp_off] = ip_proto_tcp;
    with_frag[tcp_off + 1] = 0;
    @memcpy(with_frag[tcp_off + 8 ..][0 .. frame.len - tcp_off], frame[tcp_off..]);
    // Fragment Offset = 1 (octet 8), M = 1: the TCP header starts in the *next* fragment.
    std.mem.writeInt(u16, with_frag[tcp_off + 2 ..][0..2], (1 << 3) | 1, .big);
    const payload_len = std.mem.readInt(u16, with_frag[ip_off + 4 ..][0..2], .big) + 8;
    std.mem.writeInt(u16, with_frag[ip_off + 4 ..][0..2], payload_len, .big);
    with_frag[ip_off + 6] = ipv6.next_header_fragment;

    const frag_before = try gpa.dupe(u8, with_frag);
    defer gpa.free(frag_before);
    switch (clampFrame(with_frag, budget_1500)) {
        .unparseable => {},
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqualSlices(u8, frag_before, with_frag);
}

test "clampFrame: inner IPv6 extension headers are walked in order (RFC 8200 Section 4)" {
    const gpa = t.allocator;
    // Build the frame, then splice an 8-octet Hop-by-Hop header between the IPv6 header and TCP.
    const base = try buildSynTcpSyn(gpa, .ipv6, null, 1440);
    defer gpa.free(base);

    const ip_off = ethernet.header_len;
    const tcp_off = ip_off + ipv6_header_len;

    var frame = try gpa.alloc(u8, base.len + 8);
    defer gpa.free(frame);
    @memcpy(frame[0..tcp_off], base[0..tcp_off]);
    // Hop-by-Hop header: Next Header = TCP, Hdr Ext Len = 0, PadNop trailing.
    @memset(frame[tcp_off..][0..8], 0);
    frame[tcp_off] = ip_proto_tcp;
    frame[tcp_off + 1] = 0;
    @memcpy(frame[tcp_off + 8 ..][0 .. base.len - tcp_off], base[tcp_off..]);
    // IPv6 Payload Length and Next Header must now account for the extra 8 octets.
    const payload_len = std.mem.readInt(u16, frame[ip_off + 4 ..][0..2], .big) + 8;
    std.mem.writeInt(u16, frame[ip_off + 4 ..][0..2], payload_len, .big);
    frame[ip_off + 6] = ipv6.next_header_hop_by_hop;
    // Re-seed a correct TCP checksum for the new layout.
    checksum.recomputeTcpChecksum(
        frame[tcp_off + 8 ..],
        16,
        .ipv6,
        frame[ip_off + 8 ..][0..16],
        frame[ip_off + 24 ..][0..16],
    ) catch unreachable;

    try t.expect(tcpChecksumValidWithHopByHop(frame));
    switch (clampFrame(frame, budget_1500)) {
        .clamped => |c| {
            // The inner IPv6 header is now 40 + 8 = 48 octets:
            // 1500 - 40 - 2 - 48 - 32 = 1378.
            try t.expectEqual(@as(u16, 1378), c.to);
        },
        else => return error.TestUnexpectedResult,
    }
}

fn tcpChecksumValidWithHopByHop(frame: []const u8) bool {
    const eth = ethernet.parse(frame) catch return false;
    const ip_off = @as(usize, eth.payload.ptr - frame.ptr);
    const tcp = frame[ip_off + ipv6_header_len + 8 ..];
    const sum = checksum.accumulatePseudoHeader(
        0,
        .ipv6,
        frame[ip_off + 8 ..][0..16],
        frame[ip_off + 24 ..][0..16],
        ip_proto_tcp,
        tcp.len,
    ) catch return false;
    return checksum.fold(checksum.accumulate(sum, tcp)) == 0xffff;
}

test "fuzz: clampFrame never panics and never corrupts unparseable input" {
    const Fuzz = struct {
        fn fuzzer(_: void, smith: *std.testing.Smith) anyerror!void {
            const gpa = std.testing.allocator;
            const frame = try gpa.alloc(u8, 128);
            defer gpa.free(frame);
            const n: usize = smith.slice(frame);
            const budget: Budget = .{
                .effective_path_mtu = smith.valueRangeAtMost(u32, 42, 9000),
                .overlay_mtu = smith.valueRangeAtMost(u32, 60, 9000),
                .configured_mss = if (smith.value(bool))
                    @as(?u16, @intCast(smith.value(u16)))
                else
                    null,
            };
            switch (clampFrame(frame[0..n], budget)) {
                .clamped => |c| try std.testing.expect(c.to < c.from),
                else => {},
            }
        }
    };
    try t.fuzz({}, Fuzz.fuzzer, .{});
}