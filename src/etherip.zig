//! RFC 3378 EtherIP header: encoding, decoding, and strict validation.
//!
//! RFC 3378 ("EtherIP: Tunneling Ethernet Frames in IP Datagrams", **Informational**, September
//! 2002) Section 2 defines the entire EtherIP header as 16 bits:
//!
//! ```text
//!  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |               |                                               |
//! |    VERSION    |                   RESERVED                    |
//! |               |                                               |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! * Bits 0-3  `Version`  — RFC 3378 Section 2: "The value of the version field MUST be 3".
//! * Bits 4-15 `Reserved` — RFC 3378 Section 2: "The value of the reserved field MUST be 0".
//!
//! RFC 3378 Section 4 step 1 (receiving) is normative and unambiguous:
//!
//! > "Examine the 16-bit EtherIP header. Confirm that the value of the version field is 3
//! >  (three), and that the value of the Reserved field is 0 (zero). **Frames with other values
//! >  MUST be discarded.**"
//!
//! This module therefore implements *only* strict validation. There is deliberately no lenient
//! mode and no fallback interpretation of the header as a legacy 8-bit Xerox Ethernet Tunnel
//! (XET) header, even though RFC 3378 Section 2 records that XET "employed the 8-bit header",
//! because RFC 3378 mandates discard. See docs/RFC-ANALYSIS.md Section 5.1.

const std = @import("std");

/// Size of the EtherIP header, in octets (RFC 3378 Section 2: "a 16-bit header").
pub const header_len: usize = 2;

/// RFC 3378 Section 2: "The value of the version field MUST be 3 (three, '0011' binary)."
pub const version: u4 = 3;

/// IANA *Assigned Internet Protocol Numbers*: 97 = `ETHERIP`, "Ethernet-within-IP
/// Encapsulation", reference RFC 3378. RFC 3378 Section 5: "IANA has assigned IP protocol value
/// 97 (decimal) for EtherIP."
///
/// EtherIP is registered with an EMPTY "IPv6 Extension Header" column, i.e. it is an upper-layer
/// protocol and may be used directly as an IPv6 Next Header. See docs/RFC-ANALYSIS.md Section 2.
pub const ip_protocol_number: u8 = 97;

/// Highest legal Reserved value, for range checks and documentation.
pub const reserved_max: u12 = 0xfff;

pub const Error = error{
    /// Fewer than `header_len` octets were supplied.
    TruncatedHeader,
    /// RFC 3378 Section 2: the Version field is not 3.
    UnsupportedVersion,
    /// RFC 3378 Section 4 step 1: "Frames with other values MUST be discarded."
    ReservedNotZero,
    /// RFC 3378 Section 2: "The encapsulated Ethernet frame field contains a complete Ethernet or
    /// IEEE 802.3 frame" — an EtherIP datagram with no frame after the header is malformed.
    MissingEthernetFrame,
    /// The caller-provided output buffer cannot hold the EtherIP datagram.
    BufferTooSmall,
};

/// A decoded RFC 3378 EtherIP header.
///
/// `frame` is a zero-copy sub-slice of the buffer this was parsed from.
pub const Header = struct {
    /// Always 3 for a datagram that passed validation.
    version: u4,
    /// Always 0 for a datagram that passed validation.
    reserved: u12,
    /// The encapsulated Ethernet / IEEE 802.3 frame, **without** an FCS.
    ///
    /// RFC 3378 Section 2: "a complete Ethernet or IEEE 802.3 frame of any type less the frame
    /// check sequence (FCS) value". VLAN and QinQ tags are part of `frame` and are never
    /// stripped, rewritten, or inspected by the EtherIP layer.
    frame: []const u8,

    /// Encode this header into 2 octets, network byte order.
    ///
    /// RFC 3378 Section 3 step 1: "The EtherIP Version field MUST be set to 3 (three), and the
    /// EtherIP Reserved field MUST be set to 0 (zero)."
    pub fn encode(self: Header, out: *[header_len]u8) void {
        std.debug.assert(self.version == version);
        std.debug.assert(self.reserved == 0);
        out[0] = (@as(u8, self.version) << 4) | @as(u8, @truncate(self.reserved >> 8));
        out[1] = @truncate(self.reserved);
    }

    /// Total EtherIP datagram size: header + encapsulated frame.
    pub fn datagramLen(self: Header) usize {
        return header_len + self.frame.len;
    }
};

/// Serialise the EtherIP header for an outbound datagram. Always emits Version 3 / Reserved 0.
pub fn encodeHeader(out: *[header_len]u8) void {
    std.debug.assert(out.len >= header_len);
    // 0x30 0x00 == Version 3 in the high nibble, Reserved zero elsewhere.
    out[0] = @as(u8, version) << 4;
    out[1] = 0;
}

/// Parse and strictly validate an EtherIP datagram.
///
/// `datagram` is the complete EtherIP datagram: the 16-bit EtherIP header immediately followed
/// by the encapsulated Ethernet frame. Per RFC 3378 Section 4 step 1, a Version other than 3 or a
/// non-zero Reserved field causes the datagram to be discarded; it is never reinterpreted as a
/// different protocol.
pub fn parse(datagram: []const u8) Error!Header {
    if (datagram.len < header_len) return error.TruncatedHeader;

    const word = std.mem.readInt(u16, datagram[0..2], .big);
    const ver: u4 = @truncate(word >> 12);
    const reserved: u12 = @truncate(word);

    if (ver != version) return error.UnsupportedVersion;
    // RFC 3378 Section 4 step 1: "…and that the value of the Reserved field is 0 (zero). Frames
    // with other values MUST be discarded."
    if (reserved != 0) return error.ReservedNotZero;

    const frame = datagram[header_len..];
    // RFC 3378 Section 2 requires "a complete Ethernet or IEEE 802.3 frame". The smallest legal
    // frame is a 14-octet Ethernet II header plus at least one octet of payload, enforced
    // structurally by the caller (`ethernet.parse`); here we only require a non-empty frame so
    // that a zero-length payload is still forwarded to the L2 layer for diagnosis.
    if (frame.len == 0) return error.MissingEthernetFrame;

    return .{ .version = ver, .reserved = reserved, .frame = frame };
}

/// RFC 3378 Section 3 step 1: "Prepend the 16-bit EtherIP header to the MAC frame. … The MAC
/// frame MUST NOT include the FCS."
///
/// `frame` is the Ethernet frame as received from the overlay L2 interface and MUST NOT contain
/// an FCS. This function performs no inspection, stripping, or rewriting of the frame: it is
/// copied verbatim so that destination MAC, source MAC, any 802.1Q/802.1ad tags, EtherType, and
/// payload survive byte-for-byte (docs/RFC-ANALYSIS.md Section 5.13).
///
/// On success `datagram` receives the complete EtherIP datagram. Returns the number of octets
/// written.
///
/// No heap allocation: `datagram` is caller-provided.
pub fn encapsulate(frame: []const u8, datagram: []u8) Error!usize {
    const total = header_len + frame.len;
    if (datagram.len < total) return error.BufferTooSmall;
    encodeHeader(datagram[0..header_len]);
    @memcpy(datagram[header_len..][0..frame.len], frame);
    return total;
}

const t = std.testing;

test "header_len and protocol number match RFC 3378 / IANA" {
    try t.expectEqual(@as(usize, 2), header_len);
    try t.expectEqual(@as(u4, 3), version);
    try t.expectEqual(@as(u8, 97), ip_protocol_number);
    try t.expectEqual(@as(usize, 16), header_len * 8);
}

test "encodeHeader emits Version 3 and Reserved 0 (RFC 3378 Section 3 step 1)" {
    var buf: [header_len]u8 = undefined;
    encodeHeader(&buf);
    // 0b0011_0000_0000_0000
    try t.expectEqual(@as(u8, 0x30), buf[0]);
    try t.expectEqual(@as(u8, 0x00), buf[1]);
}

test "parse: Version 3 / Reserved 0 is accepted" {
    var datagram: [2 + 20]u8 = undefined;
    @memset(&datagram, 0xAB);
    encodeHeader(datagram[0..2]);

    const h = try parse(&datagram);
    try t.expectEqual(@as(u4, 3), h.version);
    try t.expectEqual(@as(u12, 0), h.reserved);
    try t.expectEqual(@as(usize, 20), h.frame.len);
    try t.expectEqualSlices(u8, datagram[2..], h.frame);
    try t.expectEqual(@as(usize, 22), h.datagramLen());
}

test "parse: every unsupported Version is rejected (RFC 3378 Section 4 step 1)" {
    var datagram: [2 + 8]u8 = undefined;
    @memset(&datagram, 0);

    // Version 0 is the legacy 8-bit Xerox Ethernet Tunnel (XET) header per RFC 3378 Section 2.
    // RFC 3378 requires discard, so it must not parse as EtherIP.
    for (0..16) |v| {
        datagram[0] = @as(u8, @intCast(v)) << 4;
        datagram[1] = 0;
        if (v == 3) {
            _ = try parse(&datagram);
        } else {
            try t.expectError(error.UnsupportedVersion, parse(&datagram));
        }
    }
}

test "parse: every non-zero Reserved value is rejected (RFC 3378 Section 4 step 1)" {
    var datagram: [2 + 8]u8 = undefined;
    @memset(&datagram, 0);
    datagram[0] = 0x30;

    datagram[1] = 0x01;
    try t.expectError(error.ReservedNotZero, parse(&datagram));

    datagram[0] = 0x3f; // Version 3, Reserved high 4 bits = 0xf
    datagram[1] = 0x00;
    try t.expectError(error.ReservedNotZero, parse(&datagram));

    datagram[0] = 0x30;
    datagram[1] = 0xff;
    try t.expectError(error.ReservedNotZero, parse(&datagram));
}

test "parse: truncated and empty input never panics" {
    var datagram: [2 + 4]u8 = undefined;
    encodeHeader(datagram[0..2]);
    try t.expectError(error.TruncatedHeader, parse(datagram[0..0]));
    try t.expectError(error.TruncatedHeader, parse(datagram[0..1]));
    // A valid header with no encapsulated frame.
    try t.expectError(error.MissingEthernetFrame, parse(datagram[0..2]));
}

test "Header.encode round trips through parse" {
    const frame: [16]u8 = @splat(0x5A);
    var datagram: [header_len + frame.len]u8 = undefined;
    const n = try encapsulate(&frame, &datagram);
    try t.expectEqual(@as(usize, header_len + frame.len), n);

    const h = try parse(datagram[0..n]);
    try t.expectEqual(@as(u4, 3), h.version);
    try t.expectEqualSlices(u8, &frame, h.frame);

    var reencoded: [header_len]u8 = undefined;
    h.encode(&reencoded);
    try t.expectEqualSlices(u8, datagram[0..2], &reencoded);
}

test "encapsulate: frame is preserved byte for byte (RFC 3378 Section 2)" {
    // dst MAC, src MAC, EtherType, payload; no FCS.
    const frame = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // destination MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // source MAC
        0x08, 0x00,                         // EtherType IPv4
        0xde, 0xad, 0xbe, 0xef,             // payload
    };
    var datagram: [header_len + frame.len]u8 = undefined;
    const n = try encapsulate(&frame, &datagram);

    try t.expectEqual(@as(u8, 0x30), datagram[0]);
    try t.expectEqual(@as(u8, 0x00), datagram[1]);
    try t.expectEqualSlices(u8, &frame, datagram[header_len..n]);

    const h = try parse(datagram[0..n]);
    try t.expectEqualSlices(u8, &frame, h.frame);
}

test "encapsulate: refuses to overflow the caller buffer" {
    const frame = [_]u8{0} ** 40;
    var small: [header_len + 39]u8 = undefined;
    try t.expectError(error.BufferTooSmall, encapsulate(&frame, &small));
}

test "parse: does not read past the supplied slice" {
    // A datagram with a valid header and a single frame octet.
    var datagram: [header_len + 1]u8 = undefined;
    encodeHeader(datagram[0..2]);
    datagram[2] = 0xEE;
    const h = try parse(&datagram);
    try t.expectEqual(@as(usize, 1), h.frame.len);
    try t.expectEqual(@as(u8, 0xEE), h.frame[0]);
}

test "fuzz: parse never panics on arbitrary input" {
    const Fuzz = struct {
        fn fuzzer(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [64]u8 = undefined;
            const n: usize = smith.slice(&buf);
            _ = parse(buf[0..n]) catch {};
        }
    };
    try t.fuzz({}, Fuzz.fuzzer, .{});
}