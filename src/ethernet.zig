//! Ethernet II / IEEE 802.1Q / IEEE 802.1ad frame parsing.
//!
//! RFCs:
//!   * [DIX] — *The Ethernet ... A Local Area Network: Data Link Layer and Physical Layer
//!     Specifications*, December 1982 (Ethernet II, referenced by RFC 3378 Section 1).
//!   * IEEE 802.3 — *Carrier Sense Multiple Access with Collision Detection ...*
//!   * IEEE 802.1Q — *Virtual LANs*, referenced by RFC 3378 Sections 1 and 2.
//!   * IEEE 802.1ad — *Provider Bridges*, the QinQ outer tag.
//!
//! Why this module exists: RFC 3378 Sections 1 and 2 explicitly put IEEE 802.1Q VLAN datagrams
//! in scope, and RFC 3378 Section 2 requires the tunnelled payload to be "a complete Ethernet or
//! IEEE 802.3 frame of any type less the frame check sequence (FCS) value". So the EtherIP layer
//! must carry VLAN and QinQ tags **verbatim inside the payload** and must never strip, rewrite or
//! otherwise reinterpret them.
//!
//! This module is a *validator/reader* only. It never adds an FCS, never removes one, and never
//! modifies the frame. FCS generation belongs to the L2 driver on egress, per RFC 3378
//! Section 4 step 3 ("The FCS MUST be calculated and appended to the frame as part of the data
//! link layer transmission processing"). See docs/RFC-ANALYSIS.md Section 5.13.

const std = @import("std");

/// Ethernet II type/length field (IEEE 802.3 Length field, DIX EtherType field).
pub const EtherType = u16;

pub const ether_type_ipv4: EtherType = 0x0800;
pub const ether_type_arp: EtherType = 0x0806;
pub const ether_type_vlan: EtherType = 0x8100;
/// IEEE 802.1ad QinQ outer tag. Carried transparently through an EtherIP tunnel exactly like a
/// 802.1Q tag.
pub const ether_type_qinq: EtherType = 0x88a8;
pub const ether_type_ipv6: EtherType = 0x86dd;
pub const ether_type_eapol: EtherType = 0x888e;

/// Destination address octets.
pub const mac_len: usize = 6;
/// Ethernet II header: 6 (dst) + 6 (src) + 2 (type) = 14 octets (DIX).
pub const header_len: usize = 14;
/// One IEEE 802.1Q / 802.1ad tag adds 4 octets.
pub const vlan_tag_len: usize = 4;
/// RFC 3378 has no minimum Ethernet frame size of its own. 64 octets is the 802.3 minimum
/// including FCS, i.e. 60 octets without: 14 header + 46 payload.
pub const min_frame_len: usize = 60;
/// Largest frame this implementation will accept from the overlay. The real ceiling comes from
/// the configured `overlay_mtu`; this is the absolute IEEE 802.3 maximum.
pub const max_frame_len: usize = 1522;

/// Upper bound on the number of stacked VLAN tags walked. 802.1Q-ad capable switches commonly
/// use 1-3; 4 is already pathological. Bounded so hostile input cannot spin the parser.
pub const max_vlan_depth: usize = 4;

pub const Error = error{
    /// Fewer than 14 octets: not a possible Ethernet II frame.
    TruncatedHeader,
    /// A VLAN tag was announced but the frame ended before its 4 octets were present.
    TruncatedVlanTag,
    /// More stacked tags than `max_vlan_depth`.
    VlanStackTooDeep,
};

/// A parsed Ethernet II frame. `payload` and `raw` are zero-copy sub-slices of the input.
pub const Frame = struct {
    destination: [mac_len]u8,
    source: [mac_len]u8,
    /// First EtherType after the MAC addresses, i.e. the inner type when VLAN tags are present.
    ether_type: EtherType,
    /// Stacked VLAN tags in wire order, outermost first. Empty for an untagged frame.
    tags: Tags,
    /// Everything after the innermost EtherType.
    payload: []const u8,
    /// The complete frame exactly as supplied, minus any FCS (see the module docs).
    raw: []const u8,

    pub fn totalLen(self: Frame) usize {
        return self.raw.len;
    }

    /// True when the destination is the IEEE 802 group/bit address (least significant bit of the
    /// first octet set): broadcast, multicast, or any locally administered group address.
    pub fn isGroupDestination(self: Frame) bool {
        return (self.destination[0] & 0x01) != 0;
    }

    /// True for the all-ones broadcast destination address.
    pub fn isBroadcastDestination(self: Frame) bool {
        return std.mem.eql(u8, &self.destination, &[_]u8{0xff} ** mac_len);
    }
};

/// One IEEE 802.1Q / 802.1ad tag: a 16-bit TPID already consumed plus the 16-bit TCI that
/// contains the 3-bit Priority, the Drop Eligible Indicator, and the 12-bit VLAN ID.
pub const Tag = struct {
    /// PCP (Priority Code Point) — RFC 3378 Section 3 notes "Stations processing VLAN datagrams
    /// MAY need to examine the VLAN header", so the PCP is surfaced for tunnel selection rules.
    priority: u3,
    /// Drop Eligible Indicator.
    drop_eligible: bool,
    /// 12-bit VLAN identifier.
    vlan_id: u12,
};

/// Fixed-capacity tag stack; avoids a heap allocation on the frame fast path.
pub const Tags = struct {
    items: [max_vlan_depth]Tag = undefined,
    len: usize = 0,

    pub fn first(self: *const Tags) ?Tag {
        return if (self.len == 0) null else self.items[0];
    }

    pub fn innermostVlanId(self: *const Tags) ?u12 {
        return if (self.len == 0) null else self.items[self.len - 1].vlan_id;
    }

    fn push(self: *Tags, tag: Tag) error{VlanStackTooDeep}!void {
        if (self.len == max_vlan_depth) return error.VlanStackTooDeep;
        self.items[self.len] = tag;
        self.len += 1;
    }
};

/// Parse an Ethernet II frame, transparently walking any stack of 802.1Q / 802.1ad tags.
///
/// Zero copy: `payload` and `raw` alias the input buffer.
///
/// RFC 3378 Section 2 requires that the frame carried by EtherIP be complete, so this parser
/// rejects anything shorter than an Ethernet II header and anything whose declared VLAN tags do
/// not fit. It does **not** require a minimum payload length, because a run of frames short enough
/// to need padding is legitimate on the wire and the padding belongs to the frame.
pub fn parse(frame: []const u8) Error!Frame {
    if (frame.len < header_len) return error.TruncatedHeader;

    var out: Frame = .{
        .destination = frame[0..mac_len].*,
        .source = frame[mac_len..][0..mac_len].*,
        .ether_type = 0,
        .tags = .{},
        .payload = undefined,
        .raw = frame,
    };

    var offset: usize = header_len;
    var eth: EtherType = std.mem.readInt(EtherType, frame[header_len - 2 .. header_len], .big);

    // IEEE 802.1Q / 802.1ad tag stacking. On the wire a tag is a TPID (which occupies the
    // preceding "EtherType" position) followed by a 2-octet TCI, so a tagged frame reads:
    //
    //     MACs(12) | TPID(2) TCI(2) | TPID(2) TCI(2) | ... | EtherType(2) | payload
    //
    while (eth == ether_type_vlan or eth == ether_type_qinq) {
        if (frame.len < offset + 2) return error.TruncatedVlanTag;
        const tci = std.mem.readInt(u16, frame[offset..][0..2], .big);
        try out.tags.push(.{
            .priority = @truncate(tci >> 13),
            .drop_eligible = ((tci >> 12) & 0x1) != 0,
            .vlan_id = @truncate(tci & 0x0fff),
        });
        offset += 2;
        // The next TPID, or the final EtherType.
        if (frame.len < offset + 2) return error.TruncatedVlanTag;
        eth = std.mem.readInt(EtherType, frame[offset..][0..2], .big);
        offset += 2;
    }

    out.ether_type = eth;
    out.payload = frame[offset..];
    return out;
}

/// Build a minimal Ethernet II frame for tests and for the sample-packet generator.
///
/// `payload` is copied verbatim after the 14-octet header. VLAN tags may be prepended to `frame`
/// by the caller; this helper only writes the untagged form.
pub fn writeHeader(
    out: []u8,
    destination: [mac_len]u8,
    source: [mac_len]u8,
    ether_type: EtherType,
) Error!void {
    if (out.len < header_len) return error.TruncatedHeader;
    @memcpy(out[0..mac_len], &destination);
    @memcpy(out[mac_len..][0..mac_len], &source);
    std.mem.writeInt(EtherType, out[header_len - 2 .. header_len], ether_type, .big);
}

/// Write a 2-octet 802.1Q / 802.1ad Tag Control Information field.
///
/// The accompanying TPID is *not* written here: on the wire the TPID occupies the preceding
/// EtherType position, which `writeHeader` (or the previous tag's EtherType slot) already filled.
pub fn writeVlanTci(out: *[2]u8, tag: Tag) void {
    const tci: u16 = (@as(u16, tag.priority) << 13) |
        (@as(u16, @intFromBool(tag.drop_eligible)) << 12) |
        @as(u16, tag.vlan_id);
    std.mem.writeInt(u16, out[0..2], tci, .big);
}

/// Write a bare EtherType field (used for the inner type of a tagged frame).
pub fn writeEtherType(out: *[2]u8, ether_type: EtherType) void {
    std.mem.writeInt(EtherType, out[0..2], ether_type, .big);
}

const t = std.testing;

const mac_a = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
const mac_b = [6]u8{ 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };

fn expectTag(tag: Tag, priority: u3, drop_eligible: bool, vlan_id: u12) !void {
    try t.expectEqual(priority, tag.priority);
    try t.expectEqual(drop_eligible, tag.drop_eligible);
    try t.expectEqual(vlan_id, tag.vlan_id);
}

test "parse: minimum Ethernet frame" {
    // 14-octet header + 46 payload octets == the 802.3 minimum frame length excluding FCS.
    var frame: [min_frame_len]u8 = @splat(0x00);
    try writeHeader(&frame, mac_a, mac_b, ether_type_ipv4);
    const f = try parse(&frame);
    try t.expectEqualSlices(u8, &mac_a, &f.destination);
    try t.expectEqualSlices(u8, &mac_b, &f.source);
    try t.expectEqual(ether_type_ipv4, f.ether_type);
    try t.expectEqual(@as(usize, 0), f.tags.len);
    try t.expectEqual(@as(usize, 46), f.payload.len);
    try t.expectEqual(@as(usize, min_frame_len), f.totalLen());
}

test "parse: normal Ethernet II frame" {
    var frame: [header_len + 28]u8 = undefined;
    try writeHeader(&frame, mac_a, mac_b, ether_type_ipv4);
    @memset(frame[header_len..], 0xCC);

    const f = try parse(&frame);
    try t.expectEqual(ether_type_ipv4, f.ether_type);
    try t.expectEqual(@as(usize, 28), f.payload.len);
    try t.expectEqual(@as(usize, frame.len), f.totalLen());
    try t.expect(!f.isGroupDestination());
    try t.expect(!f.isBroadcastDestination());
}

test "parse: smallest possible frame (header + 1 payload octet)" {
    var frame: [header_len + 1]u8 = undefined;
    try writeHeader(&frame, mac_a, mac_b, ether_type_ipv4);
    const f = try parse(&frame);
    try t.expectEqual(@as(usize, 1), f.payload.len);
}

test "parse: broadcast and multicast destinations" {
    var frame: [header_len]u8 = undefined;
    const bcast: [6]u8 = .{0xff} ** 6;
    try writeHeader(&frame, bcast, mac_b, ether_type_arp);
    const b = try parse(&frame);
    try t.expect(b.isGroupDestination());
    try t.expect(b.isBroadcastDestination());

    try writeHeader(&frame, .{ 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 }, mac_b, ether_type_ipv4);
    const m = try parse(&frame);
    try t.expect(m.isGroupDestination());
    try t.expect(!m.isBroadcastDestination());
}

test "parse: 802.1Q VLAN tagged frame" {
    var frame: [header_len + vlan_tag_len + 40]u8 = undefined;
    try writeHeader(&frame, mac_a, mac_b, ether_type_vlan);
    writeVlanTci(frame[header_len..][0..2], .{ .priority = 5, .drop_eligible = false, .vlan_id = 100 });
    writeEtherType(frame[header_len + 2 ..][0..2], ether_type_ipv4);

    const f = try parse(&frame);
    try t.expectEqual(ether_type_ipv4, f.ether_type);
    try t.expectEqual(@as(usize, 1), f.tags.len);
    try expectTag(f.tags.items[0], 5, false, 100);
    try t.expectEqual(@as(u12, 100), f.tags.innermostVlanId().?);
    try t.expectEqual(@as(usize, 40), f.payload.len);
    try t.expectEqual(@as(usize, frame.len), f.totalLen());
}

test "parse: QinQ double-tagged frame (802.1ad outer + 802.1Q inner)" {
    var frame: [header_len + 2 * vlan_tag_len + 60]u8 = undefined;
    try writeHeader(&frame, mac_a, mac_b, ether_type_qinq);
    writeVlanTci(frame[header_len..][0..2], .{ .priority = 1, .drop_eligible = true, .vlan_id = 4094 });
    writeEtherType(frame[header_len + 2 ..][0..2], ether_type_vlan);
    writeVlanTci(frame[header_len + 4 ..][0..2], .{ .priority = 7, .drop_eligible = false, .vlan_id = 200 });
    writeEtherType(frame[header_len + 6 ..][0..2], ether_type_ipv4);

    const f = try parse(&frame);
    try t.expectEqual(ether_type_ipv4, f.ether_type);
    try t.expectEqual(@as(usize, 2), f.tags.len);
    try expectTag(f.tags.items[0], 1, true, 4094);
    try expectTag(f.tags.items[1], 7, false, 200);
    try t.expectEqual(@as(u12, 200), f.tags.innermostVlanId().?);
    try t.expectEqual(@as(usize, 60), f.payload.len);
    try t.expectEqual(@as(usize, frame.len), f.totalLen());
}

test "parse: DEI bit and priority are extracted from the TCI" {
    var frame: [header_len + vlan_tag_len + 2]u8 = undefined;
    try writeHeader(&frame, mac_a, mac_b, ether_type_vlan);
    writeVlanTci(frame[header_len..][0..2], .{ .priority = 6, .drop_eligible = true, .vlan_id = 0xabc });
    writeEtherType(frame[header_len + 2 ..][0..2], ether_type_ipv6);

    const f = try parse(&frame);
    try expectTag(f.tags.items[0], 6, true, 0xabc);
    try t.expectEqual(ether_type_ipv6, f.ether_type);
}

test "parse: rejects tag stacks deeper than max_vlan_depth" {
    // A stack of `count` tags occupies 14 + count * 4 octets up to the final EtherType.
    const Chain = struct {
        fn build(buf: []u8, count: usize) ![]const u8 {
            var n: usize = 0;
            try writeHeader(buf[n..], mac_a, mac_b, ether_type_vlan);
            n += header_len;
            var i: usize = 0;
            while (i < count) : (i += 1) {
                writeVlanTci(buf[n..][0..2], .{ .priority = 0, .drop_eligible = false, .vlan_id = 1 });
                n += 2;
                // The next slot is the following TPID, or the inner EtherType for the last tag.
                writeEtherType(buf[n..][0..2], if (i + 1 < count) ether_type_vlan else ether_type_ipv4);
                n += 2;
            }
            return buf[0..n];
        }
    };

    var buf: [header_len + (max_vlan_depth + 2) * vlan_tag_len]u8 = undefined;

    // Exactly max_vlan_depth tags is accepted.
    const ok = try Chain.build(&buf, max_vlan_depth);
    const f = try parse(ok);
    try t.expectEqual(@as(usize, max_vlan_depth), f.tags.len);
    try t.expectEqual(ether_type_ipv4, f.ether_type);

    // One more tag is rejected rather than silently ignored.
    const too_deep = try Chain.build(&buf, max_vlan_depth + 1);
    try t.expectError(error.VlanStackTooDeep, parse(too_deep));
}

test "parse: truncated headers and tags never panic" {
    const too_short = [_]u8{0} ** (header_len - 1);
    try t.expectError(error.TruncatedHeader, parse(&too_short));
    try t.expectError(error.TruncatedHeader, parse(&[_]u8{}));

    // VLAN TPID announced but the frame ends before the TCI.
    var no_tci: [header_len]u8 = undefined;
    try writeHeader(&no_tci, mac_a, mac_b, ether_type_vlan);
    try t.expectError(error.TruncatedVlanTag, parse(&no_tci));

    // TCI present but the inner EtherType is missing.
    var no_type: [header_len + 2]u8 = undefined;
    try writeHeader(&no_type, mac_a, mac_b, ether_type_vlan);
    writeVlanTci(no_type[header_len..][0..2], .{ .priority = 0, .drop_eligible = false, .vlan_id = 2 });
    try t.expectError(error.TruncatedVlanTag, parse(&no_type));

    // TCI and inner EtherType present with no payload at all.
    var empty_payload: [header_len + vlan_tag_len]u8 = undefined;
    try writeHeader(&empty_payload, mac_a, mac_b, ether_type_vlan);
    writeVlanTci(empty_payload[header_len..][0..2], .{ .priority = 0, .drop_eligible = false, .vlan_id = 2 });
    writeEtherType(empty_payload[header_len + 2 ..][0..2], ether_type_ipv4);
    const f = try parse(&empty_payload);
    try t.expectEqual(@as(usize, 0), f.payload.len);
    try t.expectEqual(ether_type_ipv4, f.ether_type);
}

test "parse: frame without FCS is passed through unchanged" {
    var frame: [header_len + 4]u8 = undefined;
    try writeHeader(&frame, mac_a, mac_b, ether_type_eapol);
    @memcpy(frame[header_len..], &[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    const f = try parse(&frame);
    // `raw` must alias the input exactly: nothing stripped, nothing appended.
    try t.expectEqualSlices(u8, &frame, f.raw);
    try t.expectEqualSlices(u8, frame[header_len..], f.payload);
    try t.expectEqual(@as(usize, 18), f.totalLen());
}

test "writeHeader / writeVlanTci round trip through parse" {
    var frame: [max_frame_len]u8 = undefined;
    var n: usize = 0;
    try writeHeader(frame[n..], mac_a, mac_b, ether_type_qinq);
    n += header_len;
    writeVlanTci(frame[n..][0..2], .{ .priority = 3, .drop_eligible = false, .vlan_id = 1000 });
    writeEtherType(frame[n..][2..4], ether_type_vlan);
    n += vlan_tag_len;
    writeVlanTci(frame[n..][0..2], .{ .priority = 0, .drop_eligible = true, .vlan_id = 20 });
    writeEtherType(frame[n..][2..4], ether_type_ipv6);
    n += vlan_tag_len;
    @memset(frame[n..], 0xEE);
    n += 64;

    const f = try parse(frame[0..n]);
    try t.expectEqual(ether_type_ipv6, f.ether_type);
    try t.expectEqual(@as(usize, 2), f.tags.len);
    try expectTag(f.tags.items[0], 3, false, 1000);
    try expectTag(f.tags.items[1], 0, true, 20);
    try t.expectEqual(@as(usize, 64), f.payload.len);
    try t.expectEqual(@as(usize, n), f.totalLen());
}

test "fuzz: parse never panics on arbitrary input" {
    const Fuzz = struct {
        fn fuzzer(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [128]u8 = undefined;
            const n: usize = smith.slice(&buf);
            _ = parse(buf[0..n]) catch {};
        }
    };
    try t.fuzz({}, Fuzz.fuzzer, .{});
}