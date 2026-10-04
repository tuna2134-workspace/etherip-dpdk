//! ICMPv6 Packet Too Big parsing and the ICMPv6 error messages an EtherIP endpoint must originate.
//!
//! RFCs:
//!   * [RFC 4443] *ICMPv6 for IPv6*, Section 2 (general rules), Section 3.1 (Destination
//!     Unreachable), Section 3.2 (Packet Too Big), Section 3.4 (Parameter Problem).
//!   * [RFC 8201] *Path MTU Discovery for IP version 6*, Section 4 (protocol requirements),
//!     Section 5.2 (storing PMTU information).
//!   * [RFC 8200] *IPv6 Specification*, Section 4.5 (the reassembly error conditions this endpoint,
//!     acting as the *destination*, must report).
//!
//! ## Why an EtherIP endpoint originates ICMPv6
//!
//! RFC 8200 Section 4.5 lists five error conditions, four of which require the node performing
//! reassembly to send an ICMPv6 message. Our endpoint is the destination of every fragment it
//! accepts, so those are host obligations, not router obligations. This module builds them so the
//! tunnel can queue them for the platform to transmit; nothing in the tunnel *requires* it to,
//! which matters because RFC 4443 Section 2.4 (e) forbids generating errors for other error
//! messages.

const std = @import("std");
const ipv6 = @import("ipv6.zig");
const checksum = @import("checksum.zig");

/// RFC 4443 Section 3: ICMPv6 Destination Unreachable error message type.
pub const type_destination_unreachable: u8 = 1;
/// RFC 4443 Section 3.2: Packet Too Big.
pub const type_packet_too_big: u8 = 2;
/// RFC 4443 Section 3.3: Time Exceeded.
pub const type_time_exceeded: u8 = 3;
/// RFC 4443 Section 3.4: Parameter Problem.
pub const type_parameter_problem: u8 = 4;

/// RFC 4443 Section 3.3 Code 1: "Fragment Reassembly Time Exceeded".
pub const code_fragment_reassembly_time_exceeded: u8 = 1;

/// RFC 4443 Section 3.4 Code 0: "Erroneous header field encountered".
pub const code_erroneous_header_field: u8 = 0;
/// RFC 4443 Section 3.4 Code 1: "Unrecognized Next Header type encountered" (RFC 8200 Section 4).
pub const code_unrecognized_next_header: u8 = 1;
/// RFC 4443 Section 3.4 Code 3: "IPv6 Header Error".
pub const code_ipv6_header_error: u8 = 3;

/// RFC 4443 Section 3.1: fixed part of an ICMPv6 error message before the quoted packet.
pub const error_header_len: usize = 8;

// ---------------------------------------------------------------------------
// Packet Too Big
// ---------------------------------------------------------------------------

pub const ParseError = error{
    /// Fewer than 8 octets: not a complete ICMPv6 error header.
    Truncated,
    /// The payload was not an ICMPv6 error message.
    NotAnErrorMessage,
    /// The checksum did not verify. RFC 4443 Section 2.1 requires it be computed over the
    /// ICMPv6 pseudo-header.
    BadChecksum,
};

/// A parsed ICMPv6 Packet Too Big message (RFC 4443 Section 3.2).
pub const PacketTooBig = struct {
    /// RFC 4443 Section 3.2: "MTU  The Maximum Transmission Unit of the next-hop link."
    ///
    /// This is the link MTU as-is. Unlike IPv4's RFC 1191, **no header length is subtracted**,
    /// and unlike RFC 1191's 576-octet floor there is no separate minimum: the floor is the IPv6
    /// minimum link MTU of 1280 (RFC 8200 Section 5), applied by RFC 8201 Section 4.
    mtu: u32,
    /// RFC 4443 Section 2.4 (c): "as much of the invoking packet as possible without making the
    /// error message packet exceed the minimum IPv6 MTU". Zero-copy sub-slice of the input.
    invoking_packet: []const u8,
};

/// Parse an ICMPv6 Packet Too Big message body (everything after the outer IPv6 header).
///
/// `outer_source` / `outer_destination` are the ICMPv6 packet's own IPv6 header addresses, needed
/// to verify the checksum per RFC 4443 Section 2.1 ("a node that originates an ICMPv6 message has
/// to determine both the Source and Destination IPv6 Addresses in the IPv6 header before
/// calculating the checksum").
pub fn parsePacketTooBig(
    body: []const u8,
    outer_source: ipv6.Address,
    outer_destination: ipv6.Address,
) ParseError!PacketTooBig {
    if (body.len < error_header_len) return error.Truncated;
    if (body[0] >= 128) return error.NotAnErrorMessage;
    if (body[0] != type_packet_too_big) return error.NotAnErrorMessage;

    // RFC 4443 Section 3.2: "Code  Set to 0 (zero) by the originator and ignored by the receiver."
    // So the Code is deliberately NOT validated.
    if (!checksumValid(body, outer_source, outer_destination)) return error.BadChecksum;

    return .{
        .mtu = std.mem.readInt(u32, body[4..8], .big),
        .invoking_packet = body[error_header_len..],
    };
}

/// Verify the ICMPv6 checksum over the pseudo-header + body (RFC 4443 Section 2.1, RFC 8200
/// Section 8.1).
pub fn checksumValid(
    body: []const u8,
    outer_source: ipv6.Address,
    outer_destination: ipv6.Address,
) bool {
    const sum = checksum.accumulatePseudoHeader(
        0,
        .ipv6,
        &outer_source.bytes(),
        &outer_destination.bytes(),
        ipv6.next_header_icmpv6,
        body.len,
    ) catch return false;
    // A correct body sums, together with its pseudo-header, to all ones.
    return checksum.fold(checksum.accumulate(sum, body)) == 0xffff;
}

/// Offset of the IPv6 Payload Length field within the fixed IPv6 header (RFC 8200 Section 3).
/// RFC 8200 Section 4.5 error condition 2 requires the Pointer of a Parameter Problem Code 0
/// message to name this field.
pub const pointer_payload_length: u32 = 4;
/// Offset of the Fragment Offset field of the Fragment header (RFC 8200 Section 4.5 error
/// condition 3 requires the Pointer to name it).
///
/// RFC 8200 Section 4.5 error condition 2 says "pointing to the Payload Length field of the
/// fragment packet" and condition 3 says "pointing to the Fragment Offset field of the fragment
/// packet". The Fragment header is the first extension header in our packets, so its offset from
/// the start of the packet is 40 (the IPv6 header length). Its own 16-bit offset/M/Res field is at
/// byte 2 of that header.
pub const pointer_fragment_offset: u32 = ipv6.header_len + 2;

/// Apply a received Packet Too Big to a path-MTU estimate, following RFC 8201 Section 4 and
/// Section 5.2 exactly.
///
/// Returns the new estimate and whether it changed.
///
/// Rules implemented:
///   * RFC 8201 Section 4: "If a node receives a Packet Too Big message reporting a next-hop MTU
///     that is less than the IPv6 minimum link MTU, it must discard it. A node must not reduce its
///     estimate of the Path MTU below the IPv6 minimum link MTU."
///   * RFC 8201 Section 5.2: the tentative PMTU is the MTU field, or the IPv6 minimum link MTU if
///     that is larger; if it is less than the existing estimate it replaces it.
///   * RFC 8201 Section 4: "A node must not increase its estimate of the Path MTU in response to
///     the contents of a Packet Too Big message." That is enforced by `allow_increase` being false
///     here: the caller never passes a larger value.
pub fn applyPacketTooBig(current: ?u32, reported: u32, allow_increase: bool) ?u32 {
    if (reported < ipv6.min_link_mtu) return current; // discard, per RFC 8201 Section 4
    const tentative = if (reported > ipv6.min_link_mtu) reported else @as(u32, ipv6.min_link_mtu);
    const existing = current orelse return tentative;
    if (tentative < existing) return tentative;
    if (allow_increase and tentative > existing) return tentative;
    return existing;
}

// ---------------------------------------------------------------------------
// Originating the ICMPv6 errors RFC 8200 Section 4.5 requires of a destination node
// ---------------------------------------------------------------------------

/// A message the tunnel wants the platform to transmit.
pub const ErrorToSend = struct {
    /// Destination IPv6 address: RFC 4443 Section 3.2 for Packet Too Big, and for every other
    /// error "Copied from the Source Address field of the invoking packet" (RFC 4443 Sections 3.1,
    /// 3.3 and 3.4).
    destination: ipv6.Address,
    /// Serialised ICMPv6 message, including its checksum.
    message: []const u8,
};

/// A caller-owned destination for a dequeued ICMPv6 message. The tunnel's own queue is compacted on
/// the next enqueue, so handing out a slice into it would dangle; this copies instead.
pub const Outgoing = struct {
    destination: ipv6.Address = .any,
    len: u16 = 0,
    /// 8 octets of ICMPv6 header plus as much of the invoking packet as fits under the IPv6 minimum
    /// link MTU (RFC 4443 Section 2.4 (c), RFC 8200 Section 5).
    buffer: [ipv6.min_link_mtu - ipv6.header_len]u8 = undefined,

    pub fn message(self: *const Outgoing) []const u8 {
        return self.buffer[0..self.len];
    }
};

/// What an ICMPv6 error message should say. `invoking_packet` must be the original datagram
/// starting at its IPv6 header (RFC 4443 Section 2.4 (c)).
pub const ErrorRequest = union(enum) {
    /// RFC 8200 Section 4.5 error condition 2: M = 1 but the fragment length is not a multiple of
    /// 8 octets. Parameter Problem Code 0, Pointer = Payload Length field.
    fragment_length_not_aligned: struct { invoking_packet: []const u8 },
    /// RFC 8200 Section 4.5 error condition 3: length and offset would push the reassembled
    /// Payload Length past 65 535. Parameter Problem Code 0, Pointer = Fragment Offset field.
    fragment_exceeds_payload_length: struct { invoking_packet: []const u8 },
    /// RFC 8200 Section 4.5 error condition 4: the first fragment did not include all headers
    /// through an Upper-Layer header. Parameter Problem Code 3, Pointer = 0.
    first_fragment_incomplete: struct { invoking_packet: []const u8 },
    /// RFC 8200 Section 4.5 error condition 1: reassembly timed out. Time Exceeded Code 1.
    reassembly_time_exceeded: struct { invoking_packet: []const u8 },
    /// RFC 8200 Section 4: an unrecognised Next Header type. Parameter Problem Code 1, Pointer =
    /// offset of the unrecognised value within the original packet.
    unrecognized_next_header: struct {
        invoking_packet: []const u8,
        pointer: u32,
    },
    /// An extension header that is malformed, truncated, repeated, or out of the order RFC 8200
    /// Section 4 requires. Parameter Problem **Code 0** ("Erroneous header field encountered"),
    /// Pointer = offset of the header that could not be processed.
    malformed_extension_header: struct {
        invoking_packet: []const u8,
        pointer: u32,
    },
};

/// Write an ICMPv6 error message per RFC 4443 Sections 3.3 and 3.4.
///
/// `out` receives `error_header_len` octets of ICMPv6 header followed by as much of the invoking
/// packet as fits, which is exactly RFC 4443 Section 2.4 (c)'s rule
/// ("as much of the invoking packet as possible without making the error message packet exceed the
/// minimum IPv6 MTU"). Returns the number of octets written.
pub fn writeError(
    out: []u8,
    source: ipv6.Address,
    destination: ipv6.Address,
    request: ErrorRequest,
) error{BufferTooSmall}!usize {
    const spec: struct {
        msg_type: u8,
        code: u8,
        rest: u32,
        pointer: u32,
        has_pointer: bool,
        quoted: []const u8,
    } = switch (request) {
        .fragment_length_not_aligned => |v| .{
            .msg_type = type_parameter_problem,
            .code = code_erroneous_header_field,
            .rest = 0,
            .pointer = pointer_payload_length,
            .has_pointer = true,
            .quoted = v.invoking_packet,
        },
        .fragment_exceeds_payload_length => |v| .{
            .msg_type = type_parameter_problem,
            .code = code_erroneous_header_field,
            .rest = 0,
            .pointer = pointer_fragment_offset,
            .has_pointer = true,
            .quoted = v.invoking_packet,
        },
        .first_fragment_incomplete => |v| .{
            .msg_type = type_parameter_problem,
            .code = code_ipv6_header_error,
            .rest = 0,
            // RFC 8200 Section 4.5: "with the Pointer field set to zero".
            .pointer = 0,
            .has_pointer = true,
            .quoted = v.invoking_packet,
        },
        .reassembly_time_exceeded => |v| .{
            .msg_type = type_time_exceeded,
            .code = code_fragment_reassembly_time_exceeded,
            .rest = 0,
            .pointer = 0,
            .has_pointer = false,
            .quoted = v.invoking_packet,
        },
        .unrecognized_next_header => |v| .{
            .msg_type = type_parameter_problem,
            .code = code_unrecognized_next_header,
            .rest = 0,
            .pointer = v.pointer,
            .has_pointer = true,
            .quoted = v.invoking_packet,
        },
        .malformed_extension_header => |v| .{
            .msg_type = type_parameter_problem,
            .code = code_erroneous_header_field,
            .rest = 0,
            .pointer = v.pointer,
            .has_pointer = true,
            .quoted = v.invoking_packet,
        },
    };

    if (out.len < error_header_len) return error.BufferTooSmall;
    out[0] = spec.msg_type;
    out[1] = spec.code;
    std.mem.writeInt(u16, out[2..4], 0, .big); // Checksum, filled in below.
    // Octets 4..7 are the Parameter Problem Pointer (RFC 4443 Section 3.4) or the Time Exceeded
    // "Unused" field (RFC 4443 Section 3.3). Both are 32 bits; `rest` is kept separate from
    // `pointer` only so the union cases read clearly.
    if (spec.has_pointer) {
        std.mem.writeInt(u32, out[4..8], spec.pointer, .big);
    } else {
        std.mem.writeInt(u32, out[4..8], spec.rest, .big);
    }

    // RFC 4443 Section 2.4 (c): quote as much as fits.
    const quoted = @min(requestQuoted(request).len, out.len - error_header_len);
    @memcpy(out[error_header_len..][0..quoted], requestQuoted(request)[0..quoted]);

    const total = error_header_len + quoted;
    // RFC 4443 Section 2.1: the checksum covers the pseudo-header.
    const sum = checksum.accumulatePseudoHeader(
        0,
        .ipv6,
        &source.bytes(),
        &destination.bytes(),
        ipv6.next_header_icmpv6,
        total,
    ) catch return error.BufferTooSmall;
    const c: u16 = ~checksum.fold(checksum.accumulate(sum, out[0..total]));
    std.mem.writeInt(u16, out[2..4], if (c == 0) 0xffff else c, .big);
    return total;
}

fn requestQuoted(request: ErrorRequest) []const u8 {
    return switch (request) {
        .fragment_length_not_aligned => |v| v.invoking_packet,
        .fragment_exceeds_payload_length => |v| v.invoking_packet,
        .first_fragment_incomplete => |v| v.invoking_packet,
        .reassembly_time_exceeded => |v| v.invoking_packet,
        .unrecognized_next_header => |v| v.invoking_packet,
        .malformed_extension_header => |v| v.invoking_packet,
    };
}

const t = std.testing;

/// Build a syntactically valid Packet Too Big message for tests, with a correct checksum.
fn buildPtb(
    out: []u8,
    src: ipv6.Address,
    dst: ipv6.Address,
    mtu: u32,
    quoted: []const u8,
) usize {
    out[0] = type_packet_too_big;
    out[1] = 0; // Code: set to 0 by the originator, ignored by the receiver.
    std.mem.writeInt(u16, out[2..4], 0, .big);
    std.mem.writeInt(u32, out[4..8], mtu, .big);
    const n = error_header_len + @min(quoted.len, out.len - error_header_len);
    @memcpy(out[error_header_len..n], quoted[0 .. n - error_header_len]);
    const sum = checksum.accumulatePseudoHeader(
        0,
        .ipv6,
        &src.bytes(),
        &dst.bytes(),
        ipv6.next_header_icmpv6,
        n,
    ) catch unreachable;
    const c: u16 = ~checksum.fold(checksum.accumulate(sum, out[0..n]));
    std.mem.writeInt(u16, out[2..4], if (c == 0) 0xffff else c, .big);
    return n;
}

test "parsePacketTooBig: RFC 4443 Section 3.2 field extraction" {
    const src = try ipv6.Address.parse("2001:db8::1");
    const dst = try ipv6.Address.parse("2001:db8::2");
    var buf: [128]u8 = undefined;
    const quoted = [_]u8{0x60} ++ [_]u8{0} ** 39 ++ [_]u8{ 0x30, 0x03 };
    const n = buildPtb(&buf, src, dst, 1400, &quoted);

    const ptb = try parsePacketTooBig(buf[0..n], src, dst);
    try t.expectEqual(@as(u32, 1400), ptb.mtu);
    try t.expectEqualSlices(u8, &quoted, ptb.invoking_packet);
}

test "parsePacketTooBig: rejects truncated, informational and bad-checksum input" {
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    var buf: [128]u8 = undefined;
    const n = buildPtb(&buf, src, dst, 1400, &[_]u8{0x60} ++ [_]u8{0} ** 39);

    try t.expectError(error.Truncated, parsePacketTooBig(buf[0..7], src, dst));
    try t.expectError(error.Truncated, parsePacketTooBig(&[_]u8{}, src, dst));

    // Echo Request (128) is informational, not an error message.
    var informational: [8]u8 = @splat(0);
    informational[0] = 128;
    try t.expectError(error.NotAnErrorMessage, parsePacketTooBig(&informational, src, dst));

    // A different error type is not a Packet Too Big.
    var du: [8]u8 = @splat(0);
    du[0] = type_destination_unreachable;
    try t.expectError(error.NotAnErrorMessage, parsePacketTooBig(&du, src, dst));

    // A corrupted MTU field breaks the checksum.
    var corrupted = buf[0..n];
    corrupted[4] ^= 0xff;
    try t.expectError(error.BadChecksum, parsePacketTooBig(corrupted, src, dst));
}

test "parsePacketTooBig: the Code field is ignored on receipt (RFC 4443 Section 3.2)" {
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    var buf: [64]u8 = undefined;
    const n = buildPtb(&buf, src, dst, 1500, &[_]u8{0x60} ++ [_]u8{0} ** 39);
    // Rewrite the code and recompute the checksum; the receiver must still accept it.
    buf[1] = 42;
    std.mem.writeInt(u16, buf[2..4], 0, .big);
    const sum = checksum.accumulatePseudoHeader(
        0,
        .ipv6,
        &src.bytes(),
        &dst.bytes(),
        ipv6.next_header_icmpv6,
        n,
    ) catch unreachable;
    const c: u16 = ~checksum.fold(checksum.accumulate(sum, buf[0..n]));
    std.mem.writeInt(u16, buf[2..4], c, .big);

    const ptb = try parsePacketTooBig(buf[0..n], src, dst);
    try t.expectEqual(@as(u32, 1500), ptb.mtu);
}

test "applyPacketTooBig: RFC 8201 Section 4 rules" {
    // Unknown estimate: adopt the reported value.
    try t.expectEqual(@as(?u32, 1400), applyPacketTooBig(null, 1400, false));
    // Lower the estimate.
    try t.expectEqual(@as(?u32, 1300), applyPacketTooBig(1400, 1300, false));
    // Never raise in response to a PTB (RFC 8201 Section 4).
    try t.expectEqual(@as(?u32, 1400), applyPacketTooBig(1400, 1500, false));
    try t.expectEqual(@as(?u32, 1500), applyPacketTooBig(1400, 1500, true));
    // Discard a report below the IPv6 minimum link MTU of 1280 (RFC 8201 Section 4).
    try t.expectEqual(@as(?u32, 1400), applyPacketTooBig(1400, 1279, false));
    try t.expectEqual(@as(?u32, null), applyPacketTooBig(null, 1279, false));
    // A report of exactly 1280 clamps to the minimum, never below it.
    try t.expectEqual(@as(?u32, 1280), applyPacketTooBig(1500, 1280, false));
    try t.expectEqual(@as(?u32, 1280), applyPacketTooBig(null, 1280, false));
    // Zero is still "less than the minimum", so it is discarded rather than clamped.
    try t.expectEqual(@as(?u32, null), applyPacketTooBig(null, 0, false));
}

test "writeError: Parameter Problem Code 0 pointing at the Payload Length field" {
    // RFC 8200 Section 4.5 error condition 2.
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    const invoked = [_]u8{0x60} ++ [_]u8{0} ** 63;
    var out: [256]u8 = undefined;
    const n = try writeError(&out, src, dst, .{ .fragment_length_not_aligned = .{ .invoking_packet = &invoked } });

    try t.expectEqual(type_parameter_problem, out[0]);
    try t.expectEqual(code_erroneous_header_field, out[1]);
    try t.expectEqual(pointer_payload_length, std.mem.readInt(u32, out[4..8], .big));
    try t.expectEqual(@as(usize, error_header_len + invoked.len), n);
    try t.expect(checksumValid(out[0..n], src, dst));
    try t.expectEqualSlices(u8, &invoked, out[error_header_len..n]);
}

test "writeError: Parameter Problem Code 0 pointing at the Fragment Offset field" {
    // RFC 8200 Section 4.5 error condition 3.
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    const invoked = [_]u8{0x60} ++ [_]u8{0} ** 63;
    var out: [256]u8 = undefined;
    const n = try writeError(&out, src, dst, .{ .fragment_exceeds_payload_length = .{ .invoking_packet = &invoked } });
    try t.expectEqual(code_erroneous_header_field, out[1]);
    try t.expectEqual(pointer_fragment_offset, std.mem.readInt(u32, out[4..8], .big));
    try t.expect(checksumValid(out[0..n], src, dst));
}

test "writeError: Parameter Problem Code 3 with Pointer 0 for an incomplete first fragment" {
    // RFC 8200 Section 4.5 error condition 4.
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    const invoked = [_]u8{0x60} ++ [_]u8{0} ** 63;
    var out: [256]u8 = undefined;
    const n = try writeError(&out, src, dst, .{ .first_fragment_incomplete = .{ .invoking_packet = &invoked } });
    try t.expectEqual(type_parameter_problem, out[0]);
    try t.expectEqual(code_ipv6_header_error, out[1]);
    try t.expectEqual(@as(u32, 0), std.mem.readInt(u32, out[4..8], .big));
    try t.expect(checksumValid(out[0..n], src, dst));
}

test "writeError: Time Exceeded Code 1 for reassembly timeout (RFC 8200 Section 4.5 error 1)" {
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    const invoked = [_]u8{0x60} ++ [_]u8{0} ** 63;
    var out: [256]u8 = undefined;
    const n = try writeError(&out, src, dst, .{ .reassembly_time_exceeded = .{ .invoking_packet = &invoked } });
    try t.expectEqual(type_time_exceeded, out[0]);
    try t.expectEqual(code_fragment_reassembly_time_exceeded, out[1]);
    try t.expect(checksumValid(out[0..n], src, dst));
}

test "writeError: Parameter Problem Code 1 for an unrecognised Next Header (RFC 8200 Section 4)" {
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    const invoked = [_]u8{0x60} ++ [_]u8{0xFE} ++ [_]u8{0} ** 62;
    var out: [256]u8 = undefined;
    const n = try writeError(&out, src, dst, .{ .unrecognized_next_header = .{
        .invoking_packet = &invoked,
        .pointer = 6, // offset of the Next Header field in the IPv6 header
    } });
    try t.expectEqual(type_parameter_problem, out[0]);
    try t.expectEqual(code_unrecognized_next_header, out[1]);
    try t.expectEqual(@as(u32, 6), std.mem.readInt(u32, out[4..8], .big));
    try t.expect(checksumValid(out[0..n], src, dst));
}

test "writeError: quotes only as much as fits (RFC 4443 Section 2.4 (c))" {
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    const invoked = [_]u8{0xAB} ** 300;
    var out: [64]u8 = undefined;
    const n = try writeError(&out, src, dst, .{ .reassembly_time_exceeded = .{ .invoking_packet = &invoked } });
    try t.expectEqual(@as(usize, out.len), n);
    try t.expectEqualSlices(u8, invoked[0 .. n - error_header_len], out[error_header_len..n]);
}

test "writeError: rejects an undersized output buffer" {
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    var out: [4]u8 = undefined;
    try t.expectError(
        error.BufferTooSmall,
        writeError(&out, src, dst, .{ .reassembly_time_exceeded = .{ .invoking_packet = &[_]u8{0x60} } }),
    );
}

test "ICMPv6 type and code constants match RFC 4443" {
    try t.expectEqual(@as(u8, 2), type_packet_too_big);
    try t.expectEqual(@as(u8, 1), code_fragment_reassembly_time_exceeded);
    try t.expectEqual(@as(u8, 0), code_erroneous_header_field);
    try t.expectEqual(@as(u8, 3), code_ipv6_header_error);
    try t.expectEqual(@as(u8, 4), pointer_payload_length);
    try t.expectEqual(@as(usize, 40 + 2), pointer_fragment_offset);
}

test "fuzz: parsePacketTooBig never panics on arbitrary input" {
    const Fuzz = struct {
        fn fuzzer(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [128]u8 = undefined;
            const n: usize = smith.slice(&buf);
            _ = parsePacketTooBig(buf[0..n], ipv6.Address.loopback, ipv6.Address.any) catch {};
            _ = checksumValid(buf[0..n], ipv6.Address.loopback, ipv6.Address.any);
            _ = applyPacketTooBig(smith.value(?u32), smith.value(u32), smith.value(bool));
        }
    };
    try t.fuzz({}, Fuzz.fuzzer, .{});
}

test "writeError: Parameter Problem Code 0 for a malformed extension header" {
    // Distinct from Code 1: an unprocessable header is an erroneous header field, not an
    // unrecognised Next Header type.
    const src = ipv6.Address.loopback;
    const dst = ipv6.Address.any;
    const invoked = [_]u8{0x60} ++ [_]u8{0} ** 63;
    var out: [256]u8 = undefined;
    const n = try writeError(&out, src, dst, .{ .malformed_extension_header = .{
        .invoking_packet = &invoked,
        .pointer = 40,
    } });
    try t.expectEqual(type_parameter_problem, out[0]);
    try t.expectEqual(code_erroneous_header_field, out[1]);
    try t.expectEqual(@as(u32, 40), std.mem.readInt(u32, out[4..8], .big));
    try t.expect(checksumValid(out[0..n], src, dst));
}

test "Outgoing owns its message bytes" {
    var o = Outgoing{};
    @memset(o.buffer[0..8], 0xAB);
    o.len = 8;
    try t.expectEqual(@as(usize, 8), o.message().len);
    try t.expectEqual(@as(u8, 0xAB), o.message()[0]);
}
