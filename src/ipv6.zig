//! IPv6 header, address, and extension-header-chain handling.
//!
//! RFC: RFC 8200 ("Internet Protocol, Version 6 (IPv6) Specification", Standards Track).
//!
//! Scope of this file:
//!   * the fixed 40-octet IPv6 header (RFC 8200 Section 3),
//!   * the IPv6 Next Header registry values this tunnel needs,
//!   * an in-order extension-header chain walker (RFC 8200 Section 4),
//!   * RFC 4291 textual address parsing.
//!
//! RFC 3378 (EtherIP) is deliberately NOT modelled here: IANA registers protocol 97 in the
//! shared IP Protocol Numbers registry with an EMPTY "IPv6 Extension Header" column, i.e.
//! EtherIP is an upper-layer protocol, not an extension header. See docs/RFC-ANALYSIS.md
//! Section 2.

const std = @import("std");

/// Length of the fixed IPv6 header, in octets (RFC 8200 Section 3).
pub const header_len: usize = 40;

/// IPv6 Version field value (RFC 8200 Section 3: "4-bit Internet Protocol version number = 6").
pub const version: u4 = 6;

/// RFC 8200 Section 5: "IPv6 requires that every link in the Internet have an MTU of 1280 octets
/// or greater. This is known as the IPv6 minimum link MTU."
pub const min_link_mtu: usize = 1280;

/// Maximum value expressible in the 16-bit Payload Length field (RFC 8200 Section 3).
pub const max_payload_len: usize = 65535;

// ---------------------------------------------------------------------------
// Next Header / Protocol numbers
// Source: IANA "Assigned Internet Protocol Numbers" registry.
// ---------------------------------------------------------------------------

/// IANA protocol number for EtherIP: keyword `ETHERIP`, name "Ethernet-within-IP
/// Encapsulation", reference RFC 3378.
pub const next_header_etherip: u8 = 97;

/// IPv6 Fragment Header (RFC 8200 Section 4.5: "identified by a Next Header value of 44").
pub const next_header_fragment: u8 = 44;

/// Hop-by-Hop Options (RFC 8200 Section 4.3).
pub const next_header_hop_by_hop: u8 = 0;
/// Routing header (RFC 8200 Section 4.4).
pub const next_header_routing: u8 = 43;
/// Authentication Header (RFC 4302).
pub const next_header_ah: u8 = 51;
/// Encapsulating Security Payload (RFC 4303).
pub const next_header_esp: u8 = 50;
/// Destination Options (RFC 8200 Section 4.6).
pub const next_header_destination_options: u8 = 60;
/// No Next Header (RFC 8200 Section 4.7, value 59).
pub const next_header_none: u8 = 59;
/// ICMPv6 (RFC 4443).
pub const next_header_icmpv6: u8 = 58;
/// TCP (IANA `TCP`, RFC 9293).
pub const next_header_tcp: u8 = 6;
/// Mobility Header (RFC 6275).
pub const next_header_mobility: u8 = 135;
/// HIP (RFC 7401).
pub const next_header_hip: u8 = 139;

/// RFC 8200 Section 4: extension headers must be processed strictly in order, and the first
/// value that is not an extension header identifies the upper-layer header.
///
/// The loop bound is an implementation hardening limit (RFC 8200 mandates none) that makes chain
/// walking provably terminating on hostile input.
pub const max_extension_headers: usize = 8;

/// True for the Next Header values RFC 8200 Section 4 treats as extension headers.
pub fn isExtensionHeader(nh: u8) bool {
    return switch (nh) {
        next_header_hop_by_hop,
        next_header_routing,
        next_header_fragment,
        next_header_destination_options,
        next_header_ah,
        next_header_esp,
        next_header_mobility,
        next_header_hip,
        => true,
        else => false,
    };
}


// ---------------------------------------------------------------------------
// IPv6Address
// ---------------------------------------------------------------------------

/// A 128-bit IPv6 address, held as eight 16-bit groups in RFC 4291 Section 2.2 presentation
/// order so that `writeBytes`/`bytes` produce the exact RFC 8200 wire order.
pub const Address = struct {
    groups: [8]u16,

    /// `::` — RFC 4291 Section 2.2 "Unspecified Address".
    pub const any = Address{ .groups = .{0} ** 8 };
    pub const unspecified = any;

    /// `::1` — RFC 4291 Section 2.5.3 "Loopback Address".
    pub const loopback = Address{ .groups = .{ 0, 0, 0, 0, 0, 0, 0, 1 } };

    pub const AddressParseError = error{
        EmptyInput,
        InvalidCharacter,
        EmptyGroup,
        InvalidDoubleColon,
        TooManyDoubleColons,
        TooManyGroups,
        TooFewGroups,
        GroupOutOfRange,
        TrailingGarbage,
    };

    pub fn fromBytes(ptr: *const [16]u8) Address {
        var out: Address = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) out.groups[i] = std.mem.readInt(u16, ptr[i * 2 ..][0..2], .big);
        return out;
    }

    /// Write the 16 address octets in RFC 8200 wire order.
    pub fn writeBytes(self: Address, ptr: *[16]u8) void {
        for (self.groups, 0..) |g, i| std.mem.writeInt(u16, ptr[i * 2 ..][0..2], g, .big);
    }

    pub fn bytes(self: Address) [16]u8 {
        var out: [16]u8 = undefined;
        self.writeBytes(&out);
        return out;
    }

    pub fn eql(a: Address, b: Address) bool {
        return std.mem.eql(u16, &a.groups, &b.groups);
    }

    /// Total order over addresses, used only for deterministic test output and logging.
    pub fn order(a: Address, b: Address) std.math.Order {
        for (a.groups, b.groups) |x, y| {
            if (x != y) return if (x < y) .lt else .gt;
        }
        return .eq;
    }

    /// True if this is the unspecified address, which RFC 4291 forbids as a tunnel source.
    pub fn isUnspecified(self: Address) bool {
        return self.eql(.any);
    }

    /// RFC 4291 Section 2.5.2: `::ffff:0:0/96`, the IPv4-mapped address prefix.
    pub fn isIpv4Mapped(self: Address) bool {
        for (self.groups[0..5]) |g| if (g != 0) return false;
        return self.groups[5] == 0xffff;
    }

    /// Parse an RFC 4291 Section 2.2 textual IPv6 address.
    ///
    /// Accepts `::` zero compression and a trailing dotted-quad (RFC 4291 Section 2.2
    /// "IPv4-Embedded IPv6 Addresses"). Parsing is deliberately strict: no zone/scope IDs, no
    /// surrounding whitespace, no trailing garbage, at most one `::`.
    pub fn parse(text: []const u8) AddressParseError!Address {
        if (text.len == 0) return error.EmptyInput;
        // A zone ID would silently change the meaning of the address; reject rather than ignore.
        if (std.mem.indexOfScalar(u8, text, '%') != null) return error.InvalidCharacter;

        const dbl = std.mem.indexOf(u8, text, "::");

        // `head_text` and `tail_text` are the parts either side of `::`.
        // Without `::`, head_text is the whole address and tail_text is empty.
        var head_text: []const u8 = undefined;
        var tail_text: []const u8 = undefined;
        if (dbl) |pos| {
            // Reject ":::" and any second "::".
            if (std.mem.indexOf(u8, text[pos + 2 ..], "::") != null) return error.TooManyDoubleColons;
            head_text = text[0..pos];
            tail_text = text[pos + 2 ..];
        } else {
            head_text = text;
            tail_text = "";
        }

        var groups: [8]u16 = undefined;
        var n: usize = 0;

        if (dbl != null) {
            // Head occupies the low-order groups, tail occupies the high-order groups, and `::`
            // fills whatever remains. `::` must stand for at least one zero group, so the two
            // halves together may use at most seven groups.
            const n_head = try parseGroups(head_text, groups[0..], false);
            var tail_buf: [8]u16 = undefined;
            const n_tail = try parseGroups(tail_text, &tail_buf, true);
            if (n_head + n_tail >= 8) return error.TooManyGroups;
            // `::` expands to zero groups, filling the gap between head and tail.
            @memset(groups[n_head..][0 .. 8 - n_head - n_tail], 0);
            @memcpy(groups[8 - n_tail .. 8], tail_buf[0..n_tail]);
            return .{ .groups = groups };
        } else {
            // No compression: exactly eight groups are required, and a dotted quad may occupy
            // the last two.
            n = try parseGroups(head_text, groups[0..], true);
            if (n != 8) return error.TooFewGroups;
            return .{ .groups = groups };
        }
    }

    /// RFC 4291 Section 2.2 presentation form: lowercase hex, no leading zeros within a group,
    /// and `::` standing for the longest run of two or more zero groups.
    pub fn format(self: Address, buf: []u8) error{NoSpaceLeft}![]u8 {
        // Locate the longest run of two or more zero groups (RFC 4291 Section 2.2 allows "::" to
        // represent *one or more* groups, so a single zero group is left uncompressed).
        var best_start: usize = 8;
        var best_len: usize = 0;
        var i: usize = 0;
        while (i < 8) {
            if (self.groups[i] != 0) {
                i += 1;
                continue;
            }
            const start = i;
            while (i < 8 and self.groups[i] == 0) : (i += 1) {}
            if (i - start >= 2 and i - start > best_len) {
                best_start = start;
                best_len = i - start;
            }
        }
        const compress = best_start != 8;

        var w = Writer{ .buf = buf, .len = 0 };

        // RFC 4291 Section 2.2 permits (and most tooling prefers) the "d.d.d.d" form for
        // IPv4-mapped addresses, `::ffff:a.b.c.d`. Render those in that form so that a parse /
        // format round trip is byte-stable.
        if (self.isIpv4Mapped()) {
            try w.str("::ffff:");
            // groups[0..5] are zero and groups[5] is 0xffff, so the IPv4 quad is groups[6..8].
            try w.dottedQuad(.{
                @truncate(self.groups[6] >> 8),
                @truncate(self.groups[6]),
                @truncate(self.groups[7] >> 8),
                @truncate(self.groups[7]),
            });
            return buf[0..w.len];
        }

        var g: usize = 0;
        while (g < 8) {
            if (compress and g == best_start) {
                try w.str("::");
                g += best_len;
                continue;
            }
            if (g != 0) {
                const first_after_gap = compress and g == best_start + best_len;
                if (!first_after_gap) try w.str(":");
            }
            try w.hex16(self.groups[g]);
            g += 1;
        }
        return buf[0..w.len];
    }

    /// Parse up to `groups.len` 16-bit groups (or 2 groups if the text ends in a dotted quad).
    /// `allow_dotted_quad` disables dotted-quad handling for non-final positions.
    fn parseGroups(text: []const u8, groups: []u16, allow_dotted_quad: bool) AddressParseError!usize {
        if (text.len == 0) return 0;
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, text, ':');
        while (it.next()) |group_text| {
            if (group_text.len == 0) return error.EmptyGroup;
            if (std.mem.lastIndexOfScalar(u8, group_text, '.') != null) {
                // RFC 4291 Section 2.2: the dotted quad is only legal as the final group, and it
                // expands to two 16-bit groups.
                if (!allow_dotted_quad or it.peek() != null) return error.InvalidCharacter;
                if (groups.len - n < 2) return error.TooManyGroups;
                const quad = try parseDottedQuad(group_text);
                groups[n] = quad[0];
                groups[n + 1] = quad[1];
                n += 2;
                continue;
            }
            if (n == groups.len) return error.TooManyGroups;
            groups[n] = try parseHex16(group_text);
            n += 1;
        }
        return n;
    }

    fn parseHex16(text: []const u8) AddressParseError!u16 {
        if (text.len == 0 or text.len > 4) return error.InvalidCharacter;
        var v: u32 = 0;
        for (text) |c| {
            const d: u32 = switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => c - 'a' + 10,
                'A'...'F' => c - 'A' + 10,
                else => return error.InvalidCharacter,
            };
            v = v * 16 + d;
        }
        return std.math.cast(u16, v) orelse error.GroupOutOfRange;
    }

    fn parseDottedQuad(text: []const u8) AddressParseError![2]u16 {
        var out = [_]u16{ 0, 0, 0, 0 };
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, text, '.');
        while (it.next()) |octet_text| {
            if (n == 4) return error.TooManyGroups;
            if (octet_text.len == 0 or octet_text.len > 3) return error.InvalidCharacter;
            var v: u32 = 0;
            for (octet_text) |c| switch (c) {
                '0'...'9' => v = v * 10 + (c - '0'),
                else => return error.InvalidCharacter,
            };
            if (v > 255) return error.GroupOutOfRange;
            out[n] = @intCast(v);
            n += 1;
        }
        if (n != 4) return error.InvalidCharacter;
        return .{
            (@as(u16, out[0]) << 8) | out[1],
            (@as(u16, out[2]) << 8) | out[3],
        };
    }

    const Writer = struct {
        buf: []u8,
        len: usize,

        fn str(self: *Writer, s: []const u8) !void {
            if (self.len + s.len > self.buf.len) return error.NoSpaceLeft;
            @memcpy(self.buf[self.len..][0..s.len], s);
            self.len += s.len;
        }

        fn hex16(self: *Writer, value_in: u16) !void {
            const digits = "0123456789abcdef";
            var value = value_in;
            var tmp: [4]u8 = undefined;
            var i: usize = 4;
            while (i > 0) {
                i -= 1;
                tmp[i] = digits[value & 0xf];
                value >>= 4;
            }
            // RFC 4291 Section 2.2: no leading zeros within a group; "0" itself is kept.
            var start: usize = 0;
            while (start < 3 and tmp[start] == '0') start += 1;
            try self.str(tmp[start..]);
        }

        fn dottedQuad(self: *Writer, q: [4]u8) !void {
            for (q, 0..) |o, idx| {
                if (idx != 0) try self.str(".");
                var v = o;
                var digits: [3]u8 = undefined;
                var len: usize = 3;
                while (len > 0) {
                    len -= 1;
                    digits[len] = '0' + (v % 10);
                    v /= 10;
                }
                var start: usize = 0;
                while (start < 2 and digits[start] == '0') start += 1;
                try self.str(digits[start..]);
            }
        }
    };
};

// ---------------------------------------------------------------------------
// IPv6 header parsing
// ---------------------------------------------------------------------------

pub const ParseError = error{
    /// Fewer than 40 octets available for the fixed header.
    TruncatedHeader,
    /// RFC 8200 Section 4.5 permits exactly one Fragment header per packet.
    DuplicateFragmentHeader,
    /// RFC 8200 Section 3: Version field is not 6.
    UnsupportedVersion,
    /// RFC 8200 Section 3: Payload Length exceeds the octets actually available.
    PayloadLengthExceedsBuffer,
    /// RFC 8200 Section 4: fewer than 8 octets left for an extension header.
    TruncatedExtensionHeader,
    /// RFC 8200 Section 4: chain exceeded `max_extension_headers`.
    ExtensionHeaderChainTooLong,
    /// RFC 8200 Section 4.6/4.3: an extension header whose length is not an integer multiple of 8.
    InvalidExtensionHeaderLength,
    /// RFC 8200 Section 4: Next Header value is not an extension header and is not one we accept.
    UnsupportedNextHeader,
    /// RFC 8200 Section 4.3: a Hop-by-Hop Options header appeared somewhere other than immediately
    /// after the IPv6 header.
    MisplacedHopByHopHeader,
    /// An extension header this implementation does not implement. Registered but unreachable
    /// today; kept so a future registry addition is never silently skipped (RFC 8200 Section 4).
    UnsupportedExtensionHeader,
};

/// Parsed view of a received IPv6 packet. `payload` is a sub-slice of the input buffer; no copy
/// is made, so parsing is zero-copy.
pub const Packet = struct {
    /// Raw 40-octet header, exactly as received.
    raw_header: [header_len]u8,
    traffic_class: u8,
    flow_label: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    source: Address,
    destination: Address,
    /// Everything after the IPv6 header, bounded by `payload_length`.
    payload: []const u8,
    /// Total octets consumed by IPv6 + extension headers (excluding any upper-layer header).
    header_bytes: usize,

    /// RFC 8200 Section 3, Traffic Class + Flow Label (28 bits).
    pub fn versionAndClassFlow(self: Packet) u32 {
        return (@as(u32, version) << 28) | (@as(u32, self.traffic_class) << 20) | self.flow_label;
    }

    pub fn nextHeaderIs(self: Packet, nh: u8) bool {
        return self.next_header == nh;
    }

    /// True when a Fragment header was present in the chain.
    pub fn isFragmented(self: Packet) bool {
        return self.next_header == next_header_fragment;
    }
};

/// Parse the fixed IPv6 header from `buf` (zero-copy) and bound the payload by Payload Length.
///
/// RFC 8200 Section 3: Payload Length is "Length of the IPv6 payload, i.e., the rest of the
/// packet following this IPv6 header, in octets. (Note that any extension headers present are
/// considered part of the payload, i.e., included in the length count.)"
pub fn parseHeader(buf: []const u8) ParseError!Packet {
    if (buf.len < header_len) return error.TruncatedHeader;

    const ver: u4 = @truncate(buf[0] >> 4);
    if (ver != version) return error.UnsupportedVersion;

    const traffic_class: u8 = (@as(u8, buf[0] & 0x0f) << 4) | (@as(u8, buf[1] >> 4) & 0x0f);
    const flow_label: u32 = (@as(u32, buf[1] & 0x0f) << 16) | (@as(u32, buf[2]) << 8) | @as(u32, buf[3]);
    const payload_length = std.mem.readInt(u16, buf[4..6], .big);
    const next_header = buf[6];
    const hop_limit = buf[7];

    // RFC 8200 Section 3: Payload Length is "Length of the IPv6 payload ... in octets". A value of
    // zero therefore means "no payload", and any octets past the header are padding to be ignored —
    // they are NOT a jumbogram, which requires the RFC 2675 Jumbo Payload option in a Hop-by-Hop
    // header, and this implementation does not support that (there would be no payload to hold it).
    if (payload_length != 0 and buf.len < header_len + @as(usize, payload_length)) {
        return error.PayloadLengthExceedsBuffer;
    }

    return .{
        .raw_header = buf[0..header_len].*,
        .traffic_class = traffic_class,
        .flow_label = flow_label,
        .payload_length = payload_length,
        .next_header = next_header,
        .hop_limit = hop_limit,
        .source = Address.fromBytes(buf[8..24]),
        .destination = Address.fromBytes(buf[24..40]),
        .payload = buf[header_len..][0..payload_length],
        .header_bytes = header_len,
    };
}

/// Result of walking the IPv6 extension-header chain (RFC 8200 Section 4).
pub const Chain = struct {
    /// Next Header value of the first upper-layer header (i.e. not an extension header).
    upper_layer_next_header: u8,
    /// Sub-slice of the received payload holding the upper-layer header and data.
    upper_layer: []const u8,
    /// Total octets of extension headers consumed before `upper_layer`.
    ext_header_bytes: usize,
    /// The Fragment header, if one was present, with `data` pointing into the received buffer.
    fragment: ?FragmentHeaderView,
    /// True if a Hop-by-Hop Options header was present (RFC 8200 Section 4.3: it "must
    /// immediately follow the IPv6 header").
    saw_hop_by_hop: bool,
    /// A Destination Options header was present.
    saw_destination_options: bool,
    /// An Authentication Header was present (RFC 4302).
    saw_ah: bool,
    /// ESP was present; its payload is opaque and the walk stops there.
    saw_esp: bool,
    /// Offset from the start of the IPv6 header of the header that could not be processed, or null
    /// when the chain parsed cleanly. Used to build an RFC 4443 Section 3.4 Pointer.
    error_offset: ?u32,

    /// RFC 8200 Section 4.5 error condition 2: "If the length of a fragment, as derived from
    /// the fragment packet's Payload Length field, is not a multiple of 8 octets and the M flag of
    /// that fragment is 1, then that fragment must be discarded."
    pub fn validateFragmentLength(self: Chain) ParseError!void {
        const f = self.fragment orelse return;
        if (!f.more_fragments) return;
        if (f.data.len % 8 != 0) return error.InvalidExtensionHeaderLength;
    }
};

/// Zero-copy view of an IPv6 Fragment header (RFC 8200 Section 4.5) plus its following data.
pub const FragmentHeaderView = struct {
    next_header: u8,
    reserved: u8,
    fragment_offset: u13,
    res: u2,
    more_fragments: bool,
    identification: u32,
    /// The octets following the Fragment header.
    data: []const u8,

    /// RFC 8200 Section 4.5: Fragment Offset is "The offset, in 8-octet units, of the data
    /// following this header".
    pub fn byteOffset(self: FragmentHeaderView) u32 {
        return @as(u32, self.fragment_offset) * 8;
    }
};

/// Walk the extension-header chain in order (RFC 8200 Section 4: "extension headers must be
/// processed strictly in the order they appear in the packet").
///
/// Rejects — rather than skips — any extension header this implementation does not understand,
/// because skipping would violate RFC 8200 Section 4's ordering requirement and because the
/// project requires unsupported extension headers to be a testable rejection path.
pub fn parseExtensionChain(packet: Packet) ParseError!Chain {
    return parseExtensionChainReporting(packet, null);
}

/// As `parseExtensionChain`, but on failure writes the offset (from the start of the IPv6 header) of
/// the header that could not be processed into `error_offset`, so the caller can build a precise
/// RFC 4443 Section 3.4 Pointer instead of guessing.
///
/// `error_offset` is written only on failure; on success the `Chain.error_offset` field stays null.
pub fn parseExtensionChainReporting(packet: Packet, error_offset: ?*u32) ParseError!Chain {

    var nh = packet.next_header;
    var rest = packet.payload;
    var ext_bytes: usize = 0;
    var count: usize = 0;
    // Offset of the header currently being walked, measured from the start of the IPv6 header.
    var here: u32 = header_len;

    var saw_hbh = false;
    var saw_dstopt = false;
    var saw_ah = false;
    var saw_esp = false;
    var fragment: ?FragmentHeaderView = null;
    var first = true;

    // Records `here` and returns `e`, so every failure path can report a precise Pointer.
    const fail = struct {
        fn at(e: ParseError, offset: u32, out: ?*u32) ParseError {
            if (out) |o| o.* = offset;
            return e;
        }
    }.at;

    while (isExtensionHeader(nh)) {
        // RFC 8200 Section 4: the Hop-by-Hop header "must immediately follow the IPv6 header".
        if (nh == next_header_hop_by_hop and !first) {
            return fail(error.MisplacedHopByHopHeader, here, error_offset);
        }
        first = false;

        count += 1;
        if (count > max_extension_headers) {
            return fail(error.ExtensionHeaderChainTooLong, here, error_offset);
        }

        switch (nh) {
            // RFC 8200 Section 4.5. Fragment headers are 8 octets with no Hdr Ext Len field.
            next_header_fragment => {
                // RFC 8200 Section 4.5 defines exactly one Fragment header per packet. A second
                // one is not part of the Fragmentable Part; consuming it would silently discard
                // eight octets of reassembled payload, so refuse the packet instead.
                if (fragment != null) return fail(error.DuplicateFragmentHeader, here, error_offset);
                if (rest.len < 8) return fail(error.TruncatedExtensionHeader, here, error_offset);
                const b = rest[0..8];
                fragment = .{
                    .next_header = b[0],
                    .reserved = b[1],
                    // Wire layout of octets 2..3: | Fragment Offset (13) | Res (2) | M (1) |
                    .fragment_offset = @truncate(std.mem.readInt(u16, b[2..4], .big) >> 3),
                    .res = @truncate((std.mem.readInt(u16, b[2..4], .big) >> 1) & 0x3),
                    .more_fragments = (b[3] & 0x1) != 0,
                    .identification = std.mem.readInt(u32, b[4..8], .big),
                    .data = rest[8..],
                };
                nh = b[0];
                rest = rest[8..];
                ext_bytes += 8;
                here += 8;
            },

            // RFC 8200 Sections 4.3/4.6: "Hdr Ext Len 8-bit unsigned integer. Length of the
            // extension header in 8-octet units, not including the first 8 octets." Errata 5256
            // (Verified) fixes a copy-paste error in 4.6 by making the field generic.
            next_header_hop_by_hop,
            next_header_destination_options,
            next_header_routing,
            => {
                if (rest.len < 8) return fail(error.TruncatedExtensionHeader, here, error_offset);
                const hdr_ext_len: u8 = rest[1];
                const total = (@as(usize, hdr_ext_len) + 1) * 8;
                if (rest.len < total) return fail(error.TruncatedExtensionHeader, here, error_offset);
                if (nh == next_header_hop_by_hop) saw_hbh = true;
                if (nh == next_header_destination_options) saw_dstopt = true;
                nh = b0(rest);
                rest = rest[total..];
                ext_bytes += total;
                here += @intCast(total);
            },

            // RFC 4302 Section 2.1: AH Length is in 4-octet units, minus 2. Total = (len + 2) * 4.
            next_header_ah => {
                if (rest.len < 8) return fail(error.TruncatedExtensionHeader, here, error_offset);
                const total = (@as(usize, rest[1]) + 2) * 4;
                if (total < 8 or rest.len < total) return fail(error.TruncatedExtensionHeader, here, error_offset);
                saw_ah = true;
                nh = b0(rest);
                rest = rest[total..];
                ext_bytes += total;
                here += @intCast(total);
            },

            // RFC 4303: ESP is not an extension header for Per-Fragment purposes and its payload
            // is opaque, so the walk terminates here.
            next_header_esp => {
                // An ESP header is at least 8 octets (SPI + sequence number), so a shorter
                // remainder is truncated input and must be rejected before any read.
                if (rest.len < 8) return fail(error.TruncatedExtensionHeader, here, error_offset);
                saw_esp = true;
                // Leave `rest` untouched: the ESP header length is not discoverable without
                // parsing the cipher suite, and its content is encrypted.
                break;
            },

            // `isExtensionHeader` already filtered, so this is unreachable in practice; kept so a
            // newly registered extension header is never silently skipped.
            else => return fail(error.UnsupportedExtensionHeader, here, error_offset),
        }
    }

    // RFC 8200 Section 4.7: "If the Payload Length field of the IPv6 header indicates the presence
    // of octets past the end of a header whose Next Header field contains 59, those octets must be
    // ignored." So No Next Header with trailing octets is legal; report an empty upper layer.
    if (nh == next_header_none) rest = rest[0..0];

    return .{
        .upper_layer_next_header = nh,
        .upper_layer = rest,
        .ext_header_bytes = ext_bytes,
        .fragment = fragment,
        .saw_hop_by_hop = saw_hbh,
        .saw_destination_options = saw_dstopt,
        .saw_ah = saw_ah,
        .saw_esp = saw_esp,
        .error_offset = null,
    };
}

fn b0(s: []const u8) u8 {
    return s[0];
}

// ---------------------------------------------------------------------------
// IPv6 header serialisation
// ---------------------------------------------------------------------------

/// The subset of IPv6 header fields a sender chooses. RFC 8200 Section 3 gives no constraints on
/// Traffic Class / Flow Label / Hop Limit beyond their meaning; the defaults here are
/// implementation-specific (documented in docs/RFC-ANALYSIS.md Section 7.4).
pub const WriteOptions = struct {
    traffic_class: u8 = 0,
    flow_label: u32 = 0,
    hop_limit: u8 = 64,
    source: Address,
    destination: Address,
};

/// Write the fixed 40-octet IPv6 header. `payload_length` MUST already account for every
/// extension header present (RFC 8200 Section 3).
pub fn writeHeader(out: []u8, next_header: u8, payload_length: usize, opts: WriteOptions) error{ PayloadLengthTooLarge, BufferTooSmall }!void {
    if (out.len < header_len) return error.BufferTooSmall;
    if (payload_length > max_payload_len) return error.PayloadLengthTooLarge;

    out[0] = (@as(u8, version) << 4) | (@as(u8, opts.traffic_class) >> 4);
    out[1] = ((opts.traffic_class & 0x0f) << 4) | @as(u8, @truncate(opts.flow_label >> 16));
    out[2] = @truncate(opts.flow_label >> 8);
    out[3] = @truncate(opts.flow_label);
    std.mem.writeInt(u16, out[4..6], @intCast(payload_length), .big);
    out[6] = next_header;
    out[7] = opts.hop_limit;
    opts.source.writeBytes(out[8..24]);
    opts.destination.writeBytes(out[24..40]);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

fn expectAddr(expected: []const u8, actual: Address) !void {
    var buf: [64]u8 = undefined;
    const got = try actual.format(&buf);
    try t.expectEqualStrings(expected, got);
}

test "Address: RFC 4291 parsing" {
    try expectAddr("2001:db8::1", try Address.parse("2001:db8:0:0:0:0:0:1"));
    try expectAddr("2001:db8::1", try Address.parse("2001:db8::1"));
    try expectAddr("::", try Address.parse("::"));
    try expectAddr("::1", try Address.parse("0:0:0:0:0:0:0:1"));
    try expectAddr("::", try Address.parse("0:0:0:0:0:0:0:0"));
    try expectAddr("1:2:3:4:5:6:7:8", try Address.parse("1:2:3:4:5:6:7:8"));
    try expectAddr("2001:db8:100::1", try Address.parse("2001:db8:100::1"));
    try expectAddr("fe80::dead:beef", try Address.parse("fe80:0:0:0:0:0:dead:beef"));
    try expectAddr("2001:db8::ffff:ffff:ffff:ffff", try Address.parse("2001:db8::ffff:ffff:ffff:ffff"));
    // Dotted quad (RFC 4291 Section 2.2).
    try expectAddr("::ffff:192.0.2.1", try Address.parse("::ffff:192.0.2.1"));
    // RFC 6052 NAT64 prefix 64:ff9b::/96: parsed correctly, but rendered in hex form
    // because the dotted-quad rendering is reserved for RFC 4291 Section 2.5.2 IPv4-mapped.
    try expectAddr("64:ff9b::c633:6407", try Address.parse("64:ff9b::198.51.100.7"));
    // Uppercase hex is legal per RFC 4291 Section 2.2.
    try expectAddr("2001:db8::abcd", try Address.parse("2001:DB8::ABCD"));
}

test "Address: round trip through bytes" {
    const a = try Address.parse("2001:db8:100::1");
    const raw = a.bytes();
    // First 32 bits: 20 01 0d b8 (RFC 4291 Section 2.2 group 1 = 0x2001, group 3 = 0x0db8).
    try t.expectEqual(@as(u8, 0x20), raw[0]);
    try t.expectEqual(@as(u8, 0x01), raw[1]);
    try t.expectEqual(@as(u8, 0x0d), raw[2]);
    try t.expectEqual(@as(u8, 0xb8), raw[3]);
    try t.expectEqual(@as(u8, 0x01), raw[4]); // group 3 = 0x0100
    try t.expectEqual(@as(u8, 0x00), raw[5]);
    try t.expectEqual(@as(u8, 0x00), raw[6]); // group 4 is compressed away
    try t.expectEqual(@as(u8, 0x01), raw[15]); // group 8 = 0x0001
    try t.expectEqualSlices(u8, &raw, &a.bytes());
    try t.expect(Address.fromBytes(&raw).eql(a));
}

test "Address: equality and ordering" {
    const a = try Address.parse("2001:db8::1");
    const b = try Address.parse("2001:db8::1");
    const c = try Address.parse("2001:db8::2");
    try t.expect(a.eql(b));
    try t.expect(!a.eql(c));
    try t.expectEqual(std.math.Order.lt, a.order(c));
    try t.expectEqual(std.math.Order.eq, a.order(b));
}

test "Address: rejects malformed input" {
    try t.expectError(error.EmptyInput, Address.parse(""));
    try t.expectError(error.TooFewGroups, Address.parse("2001:db8"));
    try t.expectError(error.TooManyGroups, Address.parse("1:2:3:4:5:6:7:8:9"));
    try t.expectError(error.TooManyGroups, Address.parse("1:2:3:4:5:6:7::8"));
    try t.expectError(error.TooManyDoubleColons, Address.parse("1::2::3"));
    try t.expectError(error.EmptyGroup, Address.parse(":1:2:3:4:5:6:7"));
    try t.expectError(error.EmptyGroup, Address.parse("1:2:3:4:5:6:7:"));
    try t.expectError(error.InvalidCharacter, Address.parse("2001:db8::g"));
    try t.expectError(error.InvalidCharacter, Address.parse("2001:db8::1%eth0"));
    try t.expectError(error.InvalidCharacter, Address.parse("2001:db8::10000"));
    try t.expectError(error.TooManyGroups, Address.parse("::1:2:3:4:5:6:7:8"));
}

test "Address: constants" {
    try t.expect(Address.any.isUnspecified());
    try t.expect(!Address.loopback.isUnspecified());
    try expectAddr("::1", Address.loopback);
}

test "parseHeader: RFC 8200 Section 3 field extraction" {
    var pkt: [header_len + 4]u8 = undefined;
    const src = try Address.parse("2001:db8::1");
    const dst = try Address.parse("2001:db8::2");
    try writeHeader(pkt[0..header_len], next_header_etherip, 4, .{
        .traffic_class = 0xAB,
        .flow_label = 0x12345,
        .hop_limit = 42,
        .source = src,
        .destination = dst,
    });
    @memcpy(pkt[40..44], &[_]u8{ 1, 2, 3, 4 });

    const p = try parseHeader(&pkt);
    try t.expectEqual(@as(u8, 6), p.raw_header[0] >> 4);
    try t.expectEqual(@as(u8, 0xAB), p.traffic_class);
    try t.expectEqual(@as(u32, 0x12345), p.flow_label);
    try t.expectEqual(@as(u16, 4), p.payload_length);
    try t.expectEqual(next_header_etherip, p.next_header);
    try t.expectEqual(@as(u8, 42), p.hop_limit);
    try t.expect(src.eql(p.source));
    try t.expect(dst.eql(p.destination));
    try t.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, p.payload);
}

test "parseHeader: rejects malformed input" {
    var pkt: [header_len + 8]u8 = undefined;
    @memset(&pkt, 0);
    try writeHeader(pkt[0..header_len], next_header_etherip, 0, .{
        .source = Address.any,
        .destination = Address.any,
    });

    // Truncated header.
    try t.expectError(error.TruncatedHeader, parseHeader(pkt[0..39]));

    // Wrong Version.
    var bad = pkt;
    bad[0] = 0x40; // Version 4
    try t.expectError(error.UnsupportedVersion, parseHeader(&bad));

    // Payload Length longer than the buffer.
    bad[0] = 0x60; // restore Version 6
    std.mem.writeInt(u16, bad[4..6], 100, .big);
    try t.expectError(error.PayloadLengthExceedsBuffer, parseHeader(&bad));

    // RFC 8200 Section 3: Payload Length 0 means "no payload". Octets past the header are padding
    // and must be ignored, not mistaken for an RFC 2675 jumbogram.
    {
        const padded = try parseHeader(pkt[0..][0 .. header_len + 1]);
        try t.expectEqual(@as(usize, 0), padded.payload.len);
        try t.expectEqual(@as(u16, 0), padded.payload_length);
    }
}

test "parseExtensionChain: no extension headers" {
    var pkt: [header_len + 2]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_etherip, 2, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const p = try parseHeader(&pkt);
    const c = try parseExtensionChain(p);
    try t.expectEqual(next_header_etherip, c.upper_layer_next_header);
    try t.expectEqual(@as(usize, 0), c.ext_header_bytes);
    try t.expect(c.fragment == null);
    try t.expect(!c.saw_hop_by_hop);
}

test "parseExtensionChain: Fragment header (RFC 8200 Section 4.5)" {
    // IPv6 | Fragment(next=97, offset=181, M=1, id=0xDEADBEEF) | 16 bytes
    var pkt: [header_len + 8 + 16]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_fragment, 8 + 16, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const fh = pkt[header_len..][0..8];
    fh[0] = next_header_etherip;
    fh[1] = 0; // Reserved: "Initialized to zero for transmission; ignored on reception."
    // offset 181, M=1 => (181 << 3) | 1 = 0x0589
    std.mem.writeInt(u16, fh[2..4], (181 << 3) | 1, .big);
    std.mem.writeInt(u32, fh[4..8], 0xDEADBEEF, .big);

    const c = try parseExtensionChain(try parseHeader(&pkt));
    try t.expectEqual(@as(usize, 8), c.ext_header_bytes);
    const f = c.fragment.?;
    try t.expectEqual(next_header_etherip, f.next_header);
    try t.expectEqual(@as(u8, 0), f.reserved);
    try t.expectEqual(@as(u13, 181), f.fragment_offset);
    try t.expectEqual(@as(u2, 0), f.res);
    try t.expect(f.more_fragments);
    try t.expectEqual(@as(u32, 0xDEADBEEF), f.identification);
    try t.expectEqual(@as(u32, 1448), f.byteOffset());
    try t.expectEqual(@as(usize, 16), f.data.len);
    try t.expectEqual(next_header_etherip, c.upper_layer_next_header);
    // RFC 8200 Section 4.5: an M=1 fragment must be a multiple of 8 octets.
    try c.validateFragmentLength();
}

test "parseExtensionChain: M=1 fragment with non-multiple-of-8 length is rejected" {
    var pkt: [header_len + 8 + 15]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_fragment, 8 + 15, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const fh = pkt[header_len..][0..8];
    fh[0] = next_header_etherip;
    fh[1] = 0;
    std.mem.writeInt(u16, fh[2..4], 0x0001, .big);
    std.mem.writeInt(u32, fh[4..8], 1, .big);

    const c = try parseExtensionChain(try parseHeader(&pkt));
    const f = c.fragment.?;
    try t.expectEqual(@as(usize, 15), f.data.len);
    try t.expectError(error.InvalidExtensionHeaderLength, c.validateFragmentLength());
}

test "parseExtensionChain: Hop-by-Hop + Fragment ordering" {
    // IPv6 | HBH(len=0) | Fragment | data   -- the RFC 8200 Section 4.1 recommended order.
    var pkt: [header_len + 8 + 8 + 8]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_hop_by_hop, 8 + 8 + 8, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const hbh = pkt[header_len..][0..8];
    hbh[0] = next_header_fragment;
    hbh[1] = 0;
    const fh = pkt[header_len + 8 ..][0..8];
    fh[0] = next_header_etherip;
    fh[1] = 0;
    std.mem.writeInt(u16, fh[2..4], 0x0000, .big);
    std.mem.writeInt(u32, fh[4..8], 0x1234, .big);

    const c = try parseExtensionChain(try parseHeader(&pkt));
    try t.expect(c.saw_hop_by_hop);
    try t.expectEqual(@as(usize, 16), c.ext_header_bytes);
    try t.expectEqual(@as(u13, 0), c.fragment.?.fragment_offset);
    try t.expect(!c.fragment.?.more_fragments);
}

test "parseExtensionChain: Hop-by-Hop must immediately follow the IPv6 header (RFC 8200 4.3)" {
    // Routing header first, then Hop-by-Hop: illegal ordering.
    var pkt: [header_len + 8 + 8]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_routing, 16, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const rt = pkt[header_len..][0..8];
    rt[0] = next_header_hop_by_hop;
    rt[1] = 0;
    try t.expectError(
        error.MisplacedHopByHopHeader,
        parseExtensionChain(try parseHeader(&pkt)),
    );
}

test "parseExtensionChain: unsupported extension header is rejected, not skipped" {
    // Next Header 253 is "reserved/experimental" and is not an extension header this
    // implementation understands.
    var pkt: [header_len + 4]u8 = undefined;
    try writeHeader(pkt[0..header_len], 253, 4, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const c = try parseExtensionChain(try parseHeader(&pkt));
    try t.expectEqual(@as(u8, 253), c.upper_layer_next_header);
    try t.expect(!isExtensionHeader(253));
}

test "parseExtensionChain: truncated and overlong chains" {
    // Fragment header claims to be present but the buffer ends.
    var pkt: [header_len + 4]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_fragment, 4, .{
        .source = Address.any,
        .destination = Address.any,
    });
    try t.expectError(error.TruncatedExtensionHeader, parseExtensionChain(try parseHeader(&pkt)));

    // An 8-byte header with Hdr Ext Len = 255 overruns the payload.
    var pkt2: [header_len + 8]u8 = undefined;
    try writeHeader(pkt2[0..header_len], next_header_destination_options, 8, .{
        .source = Address.any,
        .destination = Address.any,
    });
    pkt2[header_len + 1] = 255;
    try t.expectError(error.TruncatedExtensionHeader, parseExtensionChain(try parseHeader(&pkt2)));

    // A chain longer than max_extension_headers is refused (bounded loop).
    var buf: [header_len + 8 * (max_extension_headers + 2)]u8 = undefined;
    try writeHeader(buf[0..header_len], next_header_destination_options, 8 * (max_extension_headers + 2), .{
        .source = Address.any,
        .destination = Address.any,
    });
    var off: usize = header_len;
    var i: usize = 0;
    while (i < max_extension_headers + 2) : (i += 1) {
        buf[off] = next_header_destination_options;
        buf[off + 1] = 0;
        off += 8;
    }
    try t.expectError(error.ExtensionHeaderChainTooLong, parseExtensionChain(try parseHeader(&buf)));
}

test "parseExtensionChain: Authentication Header length is in 4-octet units (RFC 4302)" {
    // AH with payload len 1 => (1 + 2) * 4 = 12 octets.
    var pkt: [header_len + 12 + 2]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_ah, 14, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const ah = pkt[header_len..][0..12];
    ah[0] = next_header_etherip;
    ah[1] = 1;
    const c = try parseExtensionChain(try parseHeader(&pkt));
    try t.expect(c.saw_ah);
    try t.expectEqual(@as(usize, 12), c.ext_header_bytes);
    try t.expectEqual(@as(usize, 2), c.upper_layer.len);
}

test "writeHeader: Payload Length overflow is rejected" {
    var out: [header_len]u8 = undefined;
    try t.expectError(
        error.PayloadLengthTooLarge,
        writeHeader(&out, next_header_etherip, 65536, .{ .source = Address.any, .destination = Address.any }),
    );
}

test "Next Header registry values match IANA" {
    try t.expectEqual(@as(u8, 97), next_header_etherip); // ETHERIP [RFC 3378]
    try t.expectEqual(@as(u8, 44), next_header_fragment); // IPv6-Frag [RFC 8200]
    try t.expectEqual(@as(u8, 58), next_header_icmpv6); // IPv6-ICMP [RFC 4443]
    try t.expectEqual(@as(u8, 59), next_header_none); // IPv6-NoNxt
    try t.expectEqual(@as(u8, 60), next_header_destination_options);
    // EtherIP must NOT be treated as an extension header.
    try t.expect(!isExtensionHeader(next_header_etherip));
    try t.expect(isExtensionHeader(next_header_fragment));
}

test "fuzz: parseHeader never panics on arbitrary input" {
    const Fuzz = struct {
        fn fuzzer(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [160]u8 = undefined;
            const n: usize = smith.slice(&buf);
            const pkt = parseHeader(buf[0..n]) catch return;
            _ = parseExtensionChain(pkt) catch {};
        }
    };
    try t.fuzz({}, Fuzz.fuzzer, .{});
}

// ---------------------------------------------------------------------------
// Regression tests for the audit findings
// ---------------------------------------------------------------------------

test "ESP branch: a truncated ESP remainder is rejected, never indexed" {
    // RFC 8200 Section 4.5 / RFC 4303: an ESP header is at least 8 octets. A 40-octet IPv6 packet
    // with Next Header 50 and Payload Length 0 previously reached an unchecked `rest[0]`.
    var pkt: [header_len]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_esp, 0, .{
        .source = Address.any,
        .destination = Address.any,
    });
    // Payload Length 0 means no payload, so the chain sees an empty remainder and the ESP branch
    // refuses it as truncated. The point of the test is that it errors rather than indexing.
    try t.expectError(error.TruncatedExtensionHeader, parseExtensionChain(try parseHeader(&pkt)));

    // A Destination Options header that announces ESP with fewer than 8 octets left must be
    // refused rather than indexed.
    var short: [header_len + 8 + 4]u8 = undefined;
    try writeHeader(short[0..header_len], next_header_destination_options, 12, .{
        .source = Address.any,
        .destination = Address.any,
    });
    short[header_len] = next_header_esp;
    short[header_len + 1] = 0;
    try t.expectError(error.TruncatedExtensionHeader, parseExtensionChain(try parseHeader(&short)));

    // Exactly 8 octets of ESP is the minimum legal remainder and must parse.
    var exact: [header_len + 8 + 8]u8 = undefined;
    try writeHeader(exact[0..header_len], next_header_destination_options, 16, .{
        .source = Address.any,
        .destination = Address.any,
    });
    exact[header_len] = next_header_esp;
    exact[header_len + 1] = 0;
    const c2 = try parseExtensionChain(try parseHeader(&exact));
    try t.expect(c2.saw_esp);
    try t.expectEqual(@as(usize, 8), c2.upper_layer.len);
}

test "a second Fragment header is refused rather than silently consuming 8 octets" {
    // IPv6 | Frag | Frag | data. RFC 8200 Section 4.5 defines exactly one Fragment header.
    var pkt: [header_len + 8 + 8 + 8]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_fragment, 8 + 8 + 8, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const f1 = pkt[header_len..][0..8];
    f1[0] = next_header_fragment;
    f1[1] = 0;
    std.mem.writeInt(u16, f1[2..4], 0, .big);
    std.mem.writeInt(u32, f1[4..8], 1, .big);
    try t.expectError(error.DuplicateFragmentHeader, parseExtensionChain(try parseHeader(&pkt)));
}

test "RFC 8200 Section 4.7: No Next Header with trailing octets is ignored, not an error" {
    var pkt: [header_len + 8]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_none, 8, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const c = try parseExtensionChain(try parseHeader(&pkt));
    try t.expectEqual(next_header_none, c.upper_layer_next_header);
    try t.expectEqual(@as(usize, 0), c.upper_layer.len);
}

test "chain reports no error offset on a clean parse" {
    var pkt: [header_len + 2]u8 = undefined;
    try writeHeader(pkt[0..header_len], next_header_etherip, 2, .{
        .source = Address.any,
        .destination = Address.any,
    });
    const c = try parseExtensionChain(try parseHeader(&pkt));
    try t.expect(c.error_offset == null);
}

test "fuzz: parseExtensionChain never panics on any chain, including ESP and double fragments" {
    const Fuzz = struct {
        fn fuzzer(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [128]u8 = undefined;
            const n: usize = smith.slice(&buf);
            const pkt = parseHeader(buf[0..n]) catch return;
            _ = parseExtensionChain(pkt) catch {};
        }
    };
    try t.fuzz({}, Fuzz.fuzzer, .{});
}
