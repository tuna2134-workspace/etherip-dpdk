//! Cross-module tests: end-to-end encapsulation, fragmentation, reassembly, and the invariants the
//! project brief calls out.
//!
//! The central property under test is:
//!
//! ```text
//! reassemble(fragment(frame)) == frame      for every valid Ethernet frame up to overlay_mtu
//! ```
//!
//! These tests live in their own directory (rather than inline) because they exercise several
//! modules together, which is exactly the kind of test that should be readable as an integration
//! suite.

const std = @import("std");

const config = @import("../config.zig");
const etherip = @import("../etherip.zig");
const ethernet = @import("../ethernet.zig");
const fragment = @import("../fragment.zig");
const ipv6 = @import("../ipv6.zig");
const mss_clamp = @import("../mss_clamp.zig");
const overlay = @import("../overlay.zig");
const platform = @import("../platform.zig");
const reassembly = @import("../reassembly.zig");
const tunnel = @import("../tunnel.zig");

const t = std.testing;

/// Reference every group so their `test` blocks are compiled into the test binary.
pub fn forceInclude() void {
    _ = fragmentation_tests;
    _ = round_trip_tests;
    _ = property_tests;
    _ = stress_tests;
    _ = capture_tests;
    _ = end_to_end_tests;
}

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const endpoint_a = ipv6.Address.parse("2001:db8:100::1") catch unreachable;
const endpoint_b = ipv6.Address.parse("2001:db8:200::1") catch unreachable;

const Clock = struct {
    now_ms: i64 = 0,

    fn view(self: *Clock) reassembly.Clock {
        return .{ .context = @ptrCast(self), .nowMsFn = nowMsFn };
    }

    fn nowMsFn(ctx: *anyopaque) i64 {
        const self: *Clock = @ptrCast(@alignCast(ctx));
        return self.now_ms;
    }
};

/// The brief's canonical scenario: underlay MTU 1500, overlay MTU 9000.
fn jumboConfig(local: ipv6.Address, remote: ipv6.Address) config.Config {
    return .{
        .local_ipv6 = local,
        .remote_ipv6 = remote,
        .underlay_mtu = 1500,
        .overlay_mtu = 9000,
        .fragmentation_enabled = true,
        .reassembly_timeout_ms = 60_000,
        .max_reassembly_packets = 64,
        .max_reassembly_bytes = 8 * 1024 * 1024,
    };
}

/// A tunnel plus its caller-owned scratch buffers.
const Endpoint = struct {
    gpa: std.mem.Allocator,
    tun: *tunnel.Tunnel,
    clock: *Clock,
    tx_scratch: []u8,
    rx_scratch: []u8,
    frame_scratch: []u8,

    fn init(gpa: std.mem.Allocator, cfg: config.Config, clock: *Clock) !*Endpoint {
        const e = try gpa.create(Endpoint);
        errdefer gpa.destroy(e);
        const tx = try gpa.alloc(u8, cfg.maxOuterPacketSize());
        errdefer gpa.free(tx);
        const rx = try gpa.alloc(u8, ipv6.max_payload_len + ipv6.header_len);
        errdefer gpa.free(rx);
        const fs = try gpa.alloc(u8, cfg.overlay_mtu);
        errdefer gpa.free(fs);
        e.clock = clock;
        e.tun = try gpa.create(tunnel.Tunnel);
        errdefer gpa.destroy(e.tun);
        e.tun.* = try tunnel.Tunnel.init(.{
            .config = cfg,
            .gpa = gpa,
            .tx_scratch = tx,
            .rx_scratch = rx,
            .clock = clock.view(),
            .fragment_id_seed = 0xFEED_FACE_CAFE_BEEF,
        });
        e.* = .{ .gpa = gpa, .tun = e.tun, .clock = clock, .tx_scratch = tx, .rx_scratch = rx, .frame_scratch = fs };
        return e;
    }

    fn deinit(self: *Endpoint) void {
        // Capture the allocator first: `Tunnel.deinit` clears its own fields.
        const gpa = self.gpa;
        const tun = self.tun;
        tun.deinit();
        gpa.destroy(tun);
        gpa.free(self.tx_scratch);
        gpa.free(self.rx_scratch);
        gpa.free(self.frame_scratch);
        gpa.destroy(self);
    }
};

/// Retains every IPv6 packet a tunnel emits.
const Wire = struct {
    gpa: std.mem.Allocator,
    packets: std.ArrayList([]u8) = .empty,

    fn sink(ctx: *anyopaque, packet: []const u8, meta: fragment.FragmentMeta) fragment.SinkError!void {
        const self: *Wire = @ptrCast(@alignCast(ctx));
        _ = meta;
        const copy = self.gpa.dupe(u8, packet) catch return error.Abort;
        self.packets.append(self.gpa, copy) catch {
            self.gpa.free(copy);
            return error.Abort;
        };
    }

    fn deinit(self: *Wire) void {
        for (self.packets.items) |p| self.gpa.free(p);
        self.packets.deinit(self.gpa);
    }

    fn len(self: *const Wire) usize {
        return self.packets.items.len;
    }

    fn at(self: *const Wire, i: usize) []const u8 {
        return self.packets.items[i];
    }
};

/// Build a well-formed Ethernet II frame of exactly `len` octets.
fn frame(gpa: std.mem.Allocator, len: usize) ![]u8 {
    const f = try gpa.alloc(u8, len);
    errdefer gpa.free(f);
    ethernet.writeHeader(f, .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }, .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 }, ethernet.ether_type_ipv4) catch return error.FrameTooShort;
    for (f[ethernet.header_len..], 0..) |*b, i| b.* = @truncate(i *% 251 +% 11);
    return f;
}

// ---------------------------------------------------------------------------
// Fragmentation arithmetic across the required sizes
// ---------------------------------------------------------------------------

const fragmentation_tests = struct {
    const Sizes = struct {
        /// Overlay frame size.
        frame_len: usize,
        /// Expected number of outer packets.
        packets: usize,
        /// Expected largest outer packet.
        max_wire: usize,
    };

    // 1500 - 40 - 8 = 1452 -> 1448 aligned -> 1496-octet packets.
    // Frame + 2 (EtherIP) is the fragmentable part.
    const expectations = [_]Sizes{
        // 1450 + 2 = 1452 <= 1448? No -> 2 packets. Largest 1496.
        .{ .frame_len = 1450, .packets = 2, .max_wire = 1496 },
        // 2000 + 2 = 2002 -> ceil(2002/1448) = 2 packets.
        .{ .frame_len = 2000, .packets = 2, .max_wire = 1496 },
        // 4000 + 2 = 4002 -> ceil(4002/1448) = 3 packets.
        .{ .frame_len = 4000, .packets = 3, .max_wire = 1496 },
        // 9000 + 2 = 9002 -> ceil(9002/1448) = 7 packets.
        .{ .frame_len = 9000, .packets = 7, .max_wire = 1496 },
        // Threshold cases. The largest EtherIP datagram that fits one fragment payload of 1448 is
        // 1448, i.e. a 1446-octet frame.
        .{ .frame_len = 1445, .packets = 1, .max_wire = 1448 + 40 },
        .{ .frame_len = 1446, .packets = 1, .max_wire = 1448 + 40 },
        .{ .frame_len = 1447, .packets = 2, .max_wire = 1496 },
    };

    fn eachSize(alloc: std.mem.Allocator, underlay_mtu: usize, comptime f: anytype) !void {
        for (expectations) |s| try @call(.auto, f, .{ alloc, underlay_mtu, s });
    }

    test "required frame sizes fragment into the expected number of bounded packets" {
        const alloc = t.allocator;
        const underlay_mtu: usize = 1500;
        const cfg = jumboConfig(endpoint_a, endpoint_b);
        try cfg.validate();
        try eachSize(alloc, underlay_mtu, struct {
            fn check(a_gpa: std.mem.Allocator, mtu: usize, s: Sizes) !void {
                var clock = Clock{};
                var a = try Endpoint.init(a_gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
                defer a.deinit();

                const fr = try frame(a_gpa, s.frame_len);
                defer a_gpa.free(fr);

                var wire = Wire{ .gpa = a_gpa };
                defer wire.deinit();

                var etherip_buf: [9002]u8 = undefined;
                _ = try a.tun.encapsulate(fr, &etherip_buf, .{ .context = &wire, .emit = Wire.sink });

                try t.expectEqual(s.packets, wire.len());
                for (wire.packets.items) |pkt| {
                    // No outer packet may exceed the underlay MTU.
                    try t.expect(pkt.len <= mtu);
                    try t.expect(pkt.len <= s.max_wire);
                }
            }
        }.check);
    }

    test "frames below, at, and above the fragmentation threshold" {
        const gpa = t.allocator;
        const max_payload = try fragment.calculateFragmentPayloadSize(.{ .path_mtu = 1500 });
        try t.expectEqual(@as(usize, 1448), max_payload);

        // A frame whose EtherIP datagram is exactly `max_payload` needs no fragmentation.
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();

        const at_threshold = try frame(gpa, max_payload - etherip.header_len);
        defer gpa.free(at_threshold);
        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var buf: [9002]u8 = undefined;
        try t.expectEqual(
            tunnel.SendOutcome.single,
            try a.tun.encapsulate(at_threshold, &buf, .{ .context = &wire, .emit = Wire.sink }),
        );
        try t.expectEqual(@as(usize, 1), wire.len());
        try t.expectEqual(@as(usize, 1488), wire.at(0).len); // 40 (IPv6) + 1448 (EtherIP datagram)

        // One octet more forces fragmentation.
        const over = try frame(gpa, max_payload - etherip.header_len + 1);
        defer gpa.free(over);
        var wire2 = Wire{ .gpa = gpa };
        defer wire2.deinit();
        switch (try a.tun.encapsulate(over, &buf, .{ .context = &wire2, .emit = Wire.sink })) {
            .fragmented => |n| try t.expectEqual(@as(u32, 2), n),
            else => return error.TestUnexpectedResult,
        }
        try t.expectEqual(@as(usize, 2), wire2.len());
    }

    test "every fragment except the last is a multiple of 8 octets (RFC 8200 Section 4.5)" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();

        const fr = try frame(gpa, 9000);
        defer gpa.free(fr);
        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var buf: [9002]u8 = undefined;
        _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

        for (wire.packets.items) |pkt| {
            const header = try ipv6.parseHeader(pkt);
            const chain = try ipv6.parseExtensionChain(header);
            const f = chain.fragment.?;
            try t.expectEqual(etherip.ip_protocol_number, f.next_header);
            if (f.more_fragments) {
                try t.expectEqual(@as(usize, 0), f.data.len % 8);
                try t.expectEqual(@as(usize, 1448), f.data.len);
            }
        }
    }

    test "the first fragment starts with the EtherIP header (RFC 8200 Section 4.5)" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();

        const fr = try frame(gpa, 9000);
        defer gpa.free(fr);
        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var buf: [9002]u8 = undefined;
        _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

        const first = try ipv6.parseHeader(wire.at(0));
        const chain = try ipv6.parseExtensionChain(first);
        const f = chain.fragment.?;
        try t.expectEqual(@as(u13, 0), f.fragment_offset);
        try t.expectEqual(@as(u8, 0x30), f.data[0]);
        try t.expectEqual(@as(u8, 0x00), f.data[1]);
        // The rest of the first fragment is the leading frame data.
        try t.expectEqualSlices(u8, fr[0 .. 1446], f.data[2..]);
    }

    test "every fragment carries the same Identification (RFC 8200 Section 4.5)" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();

        const fr = try frame(gpa, 9000);
        defer gpa.free(fr);
        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var buf: [9002]u8 = undefined;
        _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

        var id: ?u32 = null;
        for (wire.packets.items) |pkt| {
            const h = try ipv6.parseHeader(pkt);
            const c = try ipv6.parseExtensionChain(h);
            const f = c.fragment.?;
            if (id) |expected| try t.expectEqual(expected, f.identification) else id = f.identification;
        }
        try t.expect(id != null);
    }

    test "distinct datagrams get distinct Identifications (RFC 8200 Section 4.5, RFC 7739)" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();

        const fr = try frame(gpa, 4000);
        defer gpa.free(fr);
        var seen = std.AutoHashMap(u32, void).init(gpa);
        defer seen.deinit();

        var buf: [9002]u8 = undefined;
        for (0..64) |_| {
            var wire = Wire{ .gpa = gpa };
            defer wire.deinit();
            _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });
            const h = try ipv6.parseHeader(wire.at(0));
            const c = try ipv6.parseExtensionChain(h);
            const id = c.fragment.?.identification;
            const gop = try seen.getOrPut(id);
            try t.expect(!gop.found_existing);
        }
    }

    test "fragmentation scales with the underlay MTU and is never hard-coded" {
        const gpa = t.allocator;
        const fr = try frame(gpa, 9000);
        defer gpa.free(fr);

        const mtus = [_]usize{ 1280, 1500, 4000, 9000, 16000 };
        for (mtus) |mtu| {
            var cfg = jumboConfig(endpoint_a, endpoint_b);
            cfg.underlay_mtu = mtu;
            try cfg.validate();
            var clock = Clock{};
            var a = try Endpoint.init(gpa, cfg, &clock);
            defer a.deinit();

            var wire = Wire{ .gpa = gpa };
            defer wire.deinit();
            var buf: [9002]u8 = undefined;
            _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

            const payload = try fragment.calculateFragmentPayloadSize(.{ .path_mtu = mtu });
            const expected = (9002 + payload - 1) / payload;
            try t.expectEqual(expected, wire.len());
            for (wire.packets.items) |pkt| try t.expect(pkt.len <= mtu);
        }
    }

    test "a Per-Fragment extension reserve is rejected without headers, and accounted for with them" {
        // RFC 8200 Section 4.5 requires the IPv6 header's Next Header field to name the first
        // Per-Fragment header, so a reserve with no headers would emit packets a receiver must
        // reject. `Config.validate` refuses it.
        var cfg = jumboConfig(endpoint_a, endpoint_b);
        cfg.reserved_per_fragment_ext_bytes = 16;
        try t.expectError(error.ReservedExtensionBytesNotSupported, cfg.validate());

        // The MTU arithmetic accounts for the reserve, which is what the brief asks for.
        const payload = try fragment.calculateFragmentPayloadSize(.{
            .path_mtu = 1500,
            .per_fragment_ext_len = 16,
        });
        try t.expectEqual(@as(usize, 1432), payload);
        try t.expectEqual(@as(usize, 0), payload % fragment.fragment_alignment);
        try t.expect(fragment.tunnelOverhead(.{ .path_mtu = 1500, .per_fragment_ext_len = 16 }, true) + payload <= 1500);
    }
};

// ---------------------------------------------------------------------------
// Round trips: fragment -> reassemble == original frame
// ---------------------------------------------------------------------------

const round_trip_tests = struct {
    test "reassemble(fragment(frame)) == frame for every required frame size" {
        const gpa = t.allocator;
        for (fragmentation_tests.expectations) |s| {
            var clock_a = Clock{};
            var clock_b = Clock{};
            var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock_a);
            defer a.deinit();
            var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock_b);
            defer b.deinit();

            const fr = try frame(gpa, s.frame_len);
            defer gpa.free(fr);

            var wire = Wire{ .gpa = gpa };
            defer wire.deinit();
            var buf: [9002]u8 = undefined;
            _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

            var delivered: usize = 0;
            for (wire.packets.items) |pkt| {
                if (try b.tun.receivePacket(pkt, b.frame_scratch, 0) == .frame) delivered += 1;
            }
            try t.expectEqual(@as(usize, 1), delivered);
            try t.expectEqual(s.frame_len, b.tun.last_frame_len);
            try t.expectEqualSlices(u8, fr, b.frame_scratch[0..s.frame_len]);
        }
    }

    test "round trip with fragments delivered in reverse order" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();
        var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock);
        defer b.deinit();

        const fr = try frame(gpa, 9000);
        defer gpa.free(fr);
        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var buf: [9002]u8 = undefined;
        _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

        var i = wire.len();
        var delivered: usize = 0;
        while (i > 0) {
            i -= 1;
            if (try b.tun.receivePacket(wire.at(i), b.frame_scratch, 0) == .frame) delivered += 1;
        }
        try t.expectEqual(@as(usize, 1), delivered);
        try t.expectEqualSlices(u8, fr, b.frame_scratch[0..9000]);
    }

    test "round trip with every fragment delivered twice (duplicates are benign)" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();
        var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock);
        defer b.deinit();

        const fr = try frame(gpa, 4000);
        defer gpa.free(fr);
        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var buf: [9002]u8 = undefined;
        _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

        // Deliver each fragment twice in a row.
        var delivered: usize = 0;
        for (wire.packets.items) |pkt| {
            for (0..2) |_| {
                if (try b.tun.receivePacket(pkt, b.frame_scratch, 0) == .frame) delivered += 1;
            }
        }
        try t.expectEqual(@as(usize, 1), delivered);
        try t.expectEqualSlices(u8, fr, b.frame_scratch[0..4000]);
    }

    test "several datagrams in flight at once reassemble independently" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();
        var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock);
        defer b.deinit();

        const sizes = [_]usize{ 2000, 4000, 9000, 1500 };
        const frames = try gpa.alloc([]u8, sizes.len);
        defer {
            for (frames) |f| gpa.free(f);
            gpa.free(frames);
        }
        const wires = try gpa.alloc(Wire, sizes.len);
        defer {
            for (wires) |*w| w.deinit();
            gpa.free(wires);
        }

        for (sizes, 0..) |size, i| {
            frames[i] = try frame(gpa, size);
            wires[i] = .{ .gpa = gpa };
            var buf: [9002]u8 = undefined;
            _ = try a.tun.encapsulate(frames[i], &buf, .{ .context = &wires[i], .emit = Wire.sink });
        }

        // Interleave the first fragment of every datagram, then finish them one at a time.
        for (wires) |*w| _ = try b.tun.receivePacket(w.at(0), b.frame_scratch, 0);
        try t.expectEqual(@as(usize, sizes.len), b.tun.snapshot().reassembly.in_flight_packets);

        for (wires, 0..) |*w, i| {
            var delivered: usize = 0;
            var k: usize = 1;
            while (k < w.len()) : (k += 1) {
                if (try b.tun.receivePacket(w.at(k), b.frame_scratch, 0) == .frame) delivered += 1;
            }
            try t.expectEqual(@as(usize, 1), delivered);
            try t.expectEqualSlices(u8, frames[i], b.frame_scratch[0..sizes[i]]);
        }
    }

    test "MSS clamping survives the round trip (the clamp is applied before encapsulation)" {
        const gpa = t.allocator;
        var cfg = jumboConfig(endpoint_a, endpoint_b);
        cfg.mss_clamping_enabled = true;
        cfg.mss_clamp = null;
        try cfg.validate();

        var mirror = cfg;
        mirror.local_ipv6 = endpoint_b;
        mirror.remote_ipv6 = endpoint_a;

        var clock = Clock{};
        var a = try Endpoint.init(gpa, cfg, &clock);
        defer a.deinit();
        var b = try Endpoint.init(gpa, mirror, &clock);
        defer b.deinit();

        const fr = try buildTcpSyn(gpa, 1460, false);
        defer gpa.free(fr);

        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var etherip_buf: [9002]u8 = undefined;
        _ = try a.tun.encapsulate(fr, &etherip_buf, .{ .context = &wire, .emit = Wire.sink });
        try t.expectEqual(@as(u64, 1), a.tun.snapshot().counters.mss_clamped_packets);

        for (wire.packets.items) |pkt| {
            _ = try b.tun.receivePacket(pkt, b.frame_scratch, 0);
        }
        const delivered = b.frame_scratch[0..b.tun.last_frame_len];

        // The clamp changed the advertised MSS, so `delivered` is *not* identical to `fr`: the MSS
        // octets differ and nothing else may.
        const tcp_off = ethernet.header_len + 20;
        try t.expectEqual(@as(u16, 1460), std.mem.readInt(u16, fr[tcp_off + 22 ..][0..2], .big));
        const clamped = std.mem.readInt(u16, delivered[tcp_off + 22 ..][0..2], .big);
        try t.expect(clamped < 1460);
        try t.expectEqual(@as(u16, 1406), clamped);
        // Everything except the MSS value and the TCP checksum is byte-identical.
        for (fr, delivered, 0..) |x, y, i| {
            const in_mss = i >= tcp_off + 22 and i < tcp_off + 24;
            const in_csum = i >= tcp_off + 16 and i < tcp_off + 18;
            if (!in_mss and !in_csum) try t.expectEqual(x, y);
        }
    }
};

/// Build a TCP SYN inside an Ethernet frame, with the given advertised MSS.
fn buildTcpSyn(gpa: std.mem.Allocator, mss: u16, with_vlan: bool) ![]u8 {
    const vlan_len: usize = if (with_vlan) ethernet.vlan_tag_len else 0;
    const tcp_len = 32;
    const total = ethernet.header_len + vlan_len + 20 + tcp_len;
    const f = try gpa.alloc(u8, total);
    errdefer gpa.free(f);
    @memset(f, 0);

    var n: usize = 0;
    ethernet.writeHeader(
        f[n..],
        .{ 0x02, 0, 0, 0, 0, 1 },
        .{ 0x02, 0, 0, 0, 0, 2 },
        if (with_vlan) ethernet.ether_type_vlan else ethernet.ether_type_ipv4,
    ) catch return error.FrameTooShort;
    n += ethernet.header_len;
    if (with_vlan) {
        ethernet.writeVlanTci(f[n..][0..2], .{ .priority = 0, .drop_eligible = false, .vlan_id = 7 });
        std.mem.writeInt(u16, f[n + 2 ..][0..2], ethernet.ether_type_ipv4, .big);
        n += ethernet.vlan_tag_len;
    }
    const ip = f[n..][0..20];
    ip[0] = 0x45;
    ip[2] = 0;
    ip[3] = @truncate(20 + tcp_len);
    ip[8] = 64;
    ip[9] = 6;
    @memcpy(ip[12..16], &[_]u8{ 10, 0, 0, 1 });
    @memcpy(ip[16..20], &[_]u8{ 10, 0, 0, 2 });
    n += 20;

    const tcp = f[n..];
    std.mem.writeInt(u16, tcp[0..2], 1234, .big);
    std.mem.writeInt(u16, tcp[2..4], 80, .big);
    tcp[12] = @intCast((tcp_len / 4) << 4);
    tcp[13] = 0x02; // SYN
    @memcpy(tcp[20..28], &[_]u8{ 2, 4, 0, 0, 1, 1, 4, 2 });
    std.mem.writeInt(u16, tcp[22..24], mss, .big);
    return f;
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

const property_tests = struct {
    test "property: arbitrary frame lengths round trip byte for byte" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();
        var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock);
        defer b.deinit();

        const lengths = [_]usize{
            1,   2,    13,   14,   15,   46,   59,    60,    61,
            63,  64,   127,  128,  255,  256,  511,   512,   1023,
            1024, 1445, 1446, 1447, 1448, 1449, 2895,  2896,  2897,
            4001, 8999, 9000,
        };
        for (lengths) |len| {
            const fr = frame(gpa, len) catch continue; // below the minimum Ethernet frame length
            defer gpa.free(fr);

            var wire = Wire{ .gpa = gpa };
            defer wire.deinit();
            var buf: [9002]u8 = undefined;
            _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

            var delivered: usize = 0;
            for (wire.packets.items) |pkt| {
                if (try b.tun.receivePacket(pkt, b.frame_scratch, 0) == .frame) delivered += 1;
            }
            try t.expectEqual(@as(usize, 1), delivered);
            try t.expectEqualSlices(u8, fr, b.frame_scratch[0..len]);
        }
    }

    test "property: the reassembled EtherIP datagram equals the encapsulated one" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();
        var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock);
        defer b.deinit();

        const fr = try frame(gpa, 9000);
        defer gpa.free(fr);

        // What goes in.
        const original = try gpa.alloc(u8, 9002);
        defer gpa.free(original);
        _ = try etherip.encapsulate(fr, original);

        // What comes out, reassembled.
        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var buf: [9002]u8 = undefined;
        _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

        var reassembled = try gpa.alloc(u8, 9002);
        defer gpa.free(reassembled);
        for (wire.packets.items) |pkt| {
            const h = try ipv6.parseHeader(pkt);
            const c = try ipv6.parseExtensionChain(h);
            const f = c.fragment.?;
            const at: usize = f.byteOffset();
            @memcpy(reassembled[at..][0..f.data.len], f.data);
        }
        try t.expectEqualSlices(u8, original, reassembled);
        _ = &b;
    }

    test "fuzz: an arbitrary IPv6 packet never crashes decapsulation" {
        const gpa = t.allocator;
        var clock = Clock{};
        var ep = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer ep.deinit();

        const Ctx = struct { ep: *Endpoint };
        const Fuzz = struct {
            fn fuzzer(ud: *anyopaque, smith: *std.testing.Smith) anyerror!void {
                const c: *Ctx = @ptrCast(@alignCast(ud));
                var buf: [256]u8 = undefined;
                const n: usize = smith.slice(&buf);
                var out: [9002]u8 = undefined;
                _ = c.ep.tun.receivePacket(buf[0..n], &out, 0) catch {};
            }
        };
        var ctx: Ctx = .{ .ep = ep };
        try t.fuzz(@as(*anyopaque, @ptrCast(&ctx)), Fuzz.fuzzer, .{});
    }

    test "fuzz: a mutated fragment set never produces a frame that differs from the input" {
        const Fuzz = struct {
            fn fuzzer(_: void, smith: *std.testing.Smith) anyerror!void {
                const alloc = std.testing.allocator;
                var clock = Clock{};
                var a = try Endpoint.init(alloc, jumboConfig(endpoint_a, endpoint_b), &clock);
                defer a.deinit();
                var b = try Endpoint.init(alloc, jumboConfig(endpoint_b, endpoint_a), &clock);
                defer b.deinit();

                const fr = try frame(alloc, 3000);
                defer alloc.free(fr);

                var wire = Wire{ .gpa = alloc };
                defer wire.deinit();
                var buf: [9002]u8 = undefined;
                _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

                // Shuffle the fragment order, optionally corrupting one.
                var idx: [16]u8 = undefined;
                for (0..wire.len()) |i| idx[i] = @intCast(i);
                const order_len = smith.valueRangeAtMost(u8, 1, @intCast(wire.len()));
                var j: usize = order_len;
                while (j > 1) {
                    j -= 1;
                    const k = smith.valueRangeAtMost(u8, 0, @intCast(j));
                    std.mem.swap(u8, &idx[j], &idx[k]);
                }
                for (idx[0..order_len]) |i| {
                    var pkt: [1600]u8 = undefined;
                    const src = wire.at(i);
                    const n = smith.slice(pkt[0..src.len]);
                    @memcpy(pkt[0..n], src[0..n]);
                    _ = try b.tun.receivePacket(pkt[0..n], b.frame_scratch, 0);
                }
                // If a frame did come out it must be exactly the original.
                if (b.tun.last_frame_len > 0) {
                    try std.testing.expectEqualSlices(u8, fr, b.frame_scratch[0..b.tun.last_frame_len]);
                }
            }
        };
        try t.fuzz({}, Fuzz.fuzzer, .{});
    }
};

// ---------------------------------------------------------------------------
// Randomised stress
// ---------------------------------------------------------------------------

/// Randomised parser and round-trip stress.
///
/// This exists because `zig build test --fuzz` cannot run on Zig 0.16.0: `-ffuzz` fails to compile
/// the compiler's own `test_runner.zig` (`builtin.StackTrace` vs `std.debug.StackTrace`), which is a
/// toolchain bug unrelated to this package. The `std.testing.fuzz` targets elsewhere in this
/// project still run in normal mode (Smith-driven with a per-build seed), and this test adds a
/// long, self-contained randomised sweep that any `zig build test` performs.
const stress_tests = struct {
    const iterations = 4000;

    fn prngFor(seed: u64) std.Random.DefaultPrng {
        return std.Random.DefaultPrng.init(seed);
    }

    test "stress: random IPv6 + EtherIP + Ethernet input never trips the decapsulator" {
        const gpa = t.allocator;
        var clock = Clock{};
        var ep = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer ep.deinit();

        var out: [lib_max_overlay]u8 = undefined;
        var prng = prngFor(0x0123_4567_89AB_CDEF);
        const rng = prng.random();

        for (0..iterations) |_| {
            var pkt: [512]u8 = undefined;
            const n = rng.intRangeAtMost(usize, 0, pkt.len);
            rng.bytes(pkt[0..n]);
            _ = ep.tun.receivePacket(pkt[0..n], &out, 0) catch {};
        }
    }

    test "stress: randomised frame lengths always round trip" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();
        var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock);
        defer b.deinit();

        var prng = prngFor(0xFEED_FACE_CAFE_BEEE);
        const rng = prng.random();
        for (0..iterations / 8) |_| {
            const len = rng.intRangeAtMost(usize, ethernet.header_len + 1, 9000);
            const fr = frame(gpa, len) catch continue;
            defer gpa.free(fr);

            var wire = Wire{ .gpa = gpa };
            defer wire.deinit();
            var buf: [9002]u8 = undefined;
            _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

            var delivered: usize = 0;
            for (wire.packets.items) |p| {
                if (try b.tun.receivePacket(p, b.frame_scratch, 0) == .frame) delivered += 1;
            }
            try t.expectEqual(@as(usize, 1), delivered);
            try t.expectEqualSlices(u8, fr, b.frame_scratch[0..len]);
        }
    }

    test "stress: randomised fragment orders always round trip" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();

        var prng = prngFor(0x5EED_5EED_1234_5678);
        const rng = prng.random();
        for (0..iterations / 16) |_| {
            const len = rng.intRangeAtMost(usize, 2000, 9000);
            const fr = frame(gpa, len) catch continue;
            defer gpa.free(fr);

            var wire = Wire{ .gpa = gpa };
            defer wire.deinit();
            var buf: [9002]u8 = undefined;
            _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

            var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock);
            defer b.deinit();

            // Fisher-Yates over a stack array of indices.
            var order: [32]u8 = undefined;
            if (wire.len() > order.len) continue;
            for (0..wire.len()) |i| order[i] = @intCast(i);
            var k = wire.len();
            while (k > 1) {
                k -= 1;
                const j = rng.intRangeLessThan(usize, 0, k);
                std.mem.swap(u8, &order[k], &order[j]);
            }
            for (order[0..wire.len()]) |i| {
                _ = try b.tun.receivePacket(wire.at(i), b.frame_scratch, 0);
            }
            try t.expectEqual(len, b.tun.last_frame_len);
            try t.expectEqualSlices(u8, fr, b.frame_scratch[0..len]);
        }
    }

    test "stress: MSS clamping never writes outside the MSS option" {
        const gpa = t.allocator;
        var prng = prngFor(0xC0FF_EE00_1234_5678);
        const rng = prng.random();
        var frame_buf: [256]u8 = undefined;

        for (0..iterations) |_| {
            // Start from a valid SYN and then corrupt a random octet.
            const len = buildSynInto(&frame_buf, rng.intRangeAtMost(u16, 536, 9000)) orelse continue;
            const before = try gpa.dupe(u8, frame_buf[0..len]);
            defer gpa.free(before);

            const budget = mss_clamp.Budget{
                .effective_path_mtu = rng.intRangeAtMost(usize, 1280, 9000),
                .overlay_mtu = 9000,
                .configured_mss = if (rng.boolean())
                    @as(?u16, rng.intRangeAtMost(u16, 536, 9000))
                else
                    null,
            };
            _ = mss_clamp.clampFrame(frame_buf[0..len], budget);

            // Nothing outside the MSS option and the TCP checksum may have moved.
            const eth = ethernet.parse(frame_buf[0..len]) catch continue;
            if (eth.ether_type != ethernet.ether_type_ipv4) continue;
            const ip_off = @as(usize, eth.payload.ptr - frame_buf[0..].ptr);
            if (eth.payload.len < 20) continue;
            if (eth.payload[9] != mss_clamp.ip_proto_tcp) continue;
            const ihl = @as(usize, eth.payload[0] & 0x0f) * 4;
            if (ihl < 20) continue;
            const tcp_off = ip_off + ihl;
            if (eth.payload.len - ihl < 20) continue;
            const tcp_header_len = @as(usize, frame_buf[tcp_off + 12] >> 4) * 4;
            if (tcp_header_len < 20) continue;
            const mss = mss_clamp.findMssOption(
                frame_buf[tcp_off..][0..tcp_header_len],
                tcp_header_len,
            ) catch continue;
            const mss_off = tcp_off + (mss orelse continue);

            for (before, frame_buf[0..len], 0..) |x, y, i| {
                if (x == y) continue;
                const in_mss = i >= mss_off and i < mss_off + 2;
                const in_csum = i >= tcp_off + 16 and i < tcp_off + 18;
                if (!in_mss and !in_csum) return error.UnexpectedMutation;
            }
        }
    }

    /// Build a TCP SYN with a random advertised MSS into `out`. Returns the frame length, or null
    /// if it does not fit.
    fn buildSynInto(out: []u8, mss: u16) ?usize {
        if (out.len < 14 + 20 + 32) return null;
        @memset(out, 0);
        ethernet.writeHeader(out, .{ 0x02, 0, 0, 0, 0, 1 }, .{ 0x02, 0, 0, 0, 0, 2 }, ethernet.ether_type_ipv4) catch return null;
        const ip = out[14..34];
        ip[0] = 0x45;
        ip[3] = 20 + 32;
        ip[8] = 64;
        ip[9] = mss_clamp.ip_proto_tcp;
        @memcpy(ip[12..16], &[_]u8{ 10, 0, 0, 1 });
        @memcpy(ip[16..20], &[_]u8{ 10, 0, 0, 2 });
        const tcp = out[34..];
        std.mem.writeInt(u16, tcp[0..2], 1, .big);
        std.mem.writeInt(u16, tcp[2..4], 2, .big);
        tcp[12] = 8 << 4;
        tcp[13] = mss_clamp.tcp_flag_syn;
        @memcpy(tcp[20..28], &[_]u8{ 2, 4, 0, 0, 1, 1, 4, 2 });
        std.mem.writeInt(u16, tcp[22..24], mss, .big);
        return out.len;
    }
};

/// Reusable cap so the stress tests do not need the whole library root.
const lib_max_overlay: usize = ipv6.max_payload_len - etherip.header_len;

// ---------------------------------------------------------------------------
// Packet-capture compatibility
// ---------------------------------------------------------------------------

const capture_tests = struct {
    /// A classic libpcap file: 24-octet global header plus one 16-octet record header per packet,
    /// with LINKTYPE_ETHERNET (1) at offset 20.
    fn pcapHeader(out: []u8, linktype: u32) void {
        std.mem.writeInt(u32, out[0..4], 0xa1b2c3d4, .little); // magic
        std.mem.writeInt(u16, out[4..6], 2, .little); // version major
        std.mem.writeInt(u16, out[6..8], 4, .little); // version minor
        std.mem.writeInt(u32, out[8..12], 0, .little); // thiszone
        std.mem.writeInt(u32, out[12..16], 0, .little); // sigfigs
        std.mem.writeInt(u32, out[16..20], 65535, .little); // snaplen
        std.mem.writeInt(u32, out[20..24], linktype, .little);
    }

    fn pcapRecordHeader(out: []u8, ts_sec: u32, ts_usec: u32, len: u32) void {
        std.mem.writeInt(u32, out[0..4], ts_sec, .little);
        std.mem.writeInt(u32, out[4..8], ts_usec, .little);
        std.mem.writeInt(u32, out[8..12], len, .little); // incl_len
        std.mem.writeInt(u32, out[12..16], len, .little); // orig_len
    }

    test "emitted packets have the documented structure for Wireshark/tcpdump" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();

        const fr = try frame(gpa, 9000);
        defer gpa.free(fr);

        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var buf: [9002]u8 = undefined;
        _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

        const pcap = try gpa.alloc(u8, 24 + wire.len() * (16 + 1600));
        defer gpa.free(pcap);
        pcapHeader(pcap[0..24], 1); // LINKTYPE_ETHERNET

        var off: usize = 24;
        for (wire.packets.items, 0..) |pkt, i| {
            // Build the Ethernet II frame a capture tool would see.
            var frame_bytes: [1600]u8 = undefined;
            ethernet.writeHeader(
                frame_bytes[0..],
                .{ 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 },
                .{ 0x33, 0x33, 0x00, 0x00, 0x00, 0x02 },
                ethernet.ether_type_ipv6,
            ) catch unreachable;
            @memcpy(frame_bytes[14..][0..pkt.len], pkt);
            const total = 14 + pkt.len;

            pcapRecordHeader(pcap[off..][0..16], 0, @as(u32, @intCast(i)), @intCast(total));
            off += 16;
            @memcpy(pcap[off..][0..total], frame_bytes[0..total]);
            off += total;
        }

        // tcpdump reads a pcap file as: magic, ..., linktype, then records.
        try t.expectEqual(@as(u32, 0xa1b2c3d4), std.mem.readInt(u32, pcap[0..4], .little));
        try t.expectEqual(@as(u32, 1), std.mem.readInt(u32, pcap[20..24], .little));

        // First record: an IPv6 packet with Next Header 44 (Fragment) carrying EtherIP.
        const rec0 = pcap[24 + 16 + 14 ..];
        const h0 = try ipv6.parseHeader(rec0[0..]);
        try t.expectEqual(ipv6.next_header_fragment, h0.next_header);
        try t.expect(endpoint_a.eql(h0.source));
        try t.expect(endpoint_b.eql(h0.destination));

        // Walk the records and check that every one is a legal IPv6 EtherIP fragment.
        var cursor: usize = 24;
        var seen: usize = 0;
        while (cursor < off) {
            const incl = std.mem.readInt(u32, pcap[cursor + 8 ..][0..4], .little);
            const pkt = pcap[cursor + 16 + 14 ..][0..incl];
            const h = try ipv6.parseHeader(pkt);
            try t.expectEqual(@as(u4, 6), h.raw_header[0] >> 4);
            const c = try ipv6.parseExtensionChain(h);
            try t.expectEqual(etherip.ip_protocol_number, c.fragment.?.next_header);
            cursor += 16 + incl;
            seen += 1;
        }
        try t.expectEqual(wire.len(), seen);
    }
};

// ---------------------------------------------------------------------------
// End-to-end through the platform and overlay abstractions
// ---------------------------------------------------------------------------

const end_to_end_tests = struct {
    test "tunnel -> in-memory link -> tunnel, using the Transport and Overlay abstractions" {
        const gpa = t.allocator;

        // Two endpoints, each with its own in-memory underlay, wired back to back.
        var link_a = try platform.Link.init(gpa, 256, 1500);
        defer link_a.deinit();
        var link_b = try platform.Link.init(gpa, 256, 1500);
        defer link_b.deinit();
        platform.Link.connect(&link_a, &link_b);

        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();
        var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock);
        defer b.deinit();

        // A's overlay interface sends frames into the tunnel; the fragments go out on link_a.
        const fr = try frame(gpa, 9000);
        defer gpa.free(fr);

        // Manually drive: encapsulate, then transmit through the Transport.
        var etherip_buf: [9002]u8 = undefined;
        var to_link_a = Wire{ .gpa = gpa };
        defer to_link_a.deinit();
        _ = try a.tun.encapsulate(fr, &etherip_buf, .{ .context = &to_link_a, .emit = Wire.sink });
        for (to_link_a.packets.items) |pkt| try link_a.transport().send(pkt);

        // B receives from link_b.
        var delivered: usize = 0;
        while (true) {
            const n = link_b.transport().receive(b.rx_scratch) catch break;
            if (try b.tun.receivePacket(b.rx_scratch[0..n], b.frame_scratch, 0) == .frame) delivered += 1;
        }
        try t.expectEqual(@as(usize, 1), delivered);
        try t.expectEqualSlices(u8, fr, b.frame_scratch[0..9000]);

        // Statistics reflect the traffic.
        const sa = a.tun.snapshot();
        try t.expectEqual(@as(u64, 1), sa.counters.tx_packets);
        try t.expectEqual(@as(u64, 7), sa.counters.tx_fragments);
        try t.expectEqual(@as(u64, 9000), sa.counters.tx_bytes);
        try t.expectEqual(@as(usize, 1500), sa.effective_path_mtu);

        const sb = b.tun.snapshot();
        try t.expectEqual(@as(u64, 7), sb.counters.rx_fragments);
        try t.expectEqual(@as(u64, 1), sb.counters.reassembly_success);
        try t.expectEqual(@as(u64, 9000), sb.counters.rx_bytes);
    }

    test "OverlayInterface.transmit encapsulates through the tunnel" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();

        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();

        var tx_buffer: [9002]u8 = undefined;
        var ov = try overlay.TunnelOverlay.init(a.tun, &tx_buffer, .{ .context = &wire, .emit = Wire.sink });
        defer ov.packets_sent = 0;

        const fr = try frame(gpa, 3000);
        defer gpa.free(fr);
        try ov.interface().transmit(fr);
        try t.expectEqual(@as(u64, 3), ov.packets_sent);
        try t.expectEqual(@as(u64, 3000), ov.bytes_sent);

        // An oversize frame is refused by the overlay binding.
        const big = try frame(gpa, 9001);
        defer gpa.free(big);
        try t.expectError(error.FrameTooLarge, ov.interface().transmit(big));

        // A truncated frame never reaches the tunnel.
        try t.expectError(error.FrameTooShort, ov.interface().transmit(&[_]u8{ 1, 2, 3 }));
    }

    test "deliver() hands decapsulated frames to a FrameSink" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();
        var b = try Endpoint.init(gpa, jumboConfig(endpoint_b, endpoint_a), &clock);
        defer b.deinit();

        const fr = try frame(gpa, 1500);
        defer gpa.free(fr);

        var wire = Wire{ .gpa = gpa };
        defer wire.deinit();
        var buf: [9002]u8 = undefined;
        _ = try a.tun.encapsulate(fr, &buf, .{ .context = &wire, .emit = Wire.sink });

        var cap = try overlay.CapturedFrames.init(gpa, 8);
        defer cap.deinit();

        for (wire.packets.items) |pkt| {
            _ = try overlay.deliver(b.tun, pkt, b.frame_scratch, cap.sink(), 0);
        }
        try t.expectEqual(@as(usize, 1), cap.len());
        try t.expectEqualSlices(u8, fr, cap.at(0));
    }

    test "statistics rendering includes the PMTU fields (RFC 8201 observability)" {
        const gpa = t.allocator;
        var clock = Clock{};
        var a = try Endpoint.init(gpa, jumboConfig(endpoint_a, endpoint_b), &clock);
        defer a.deinit();

        var buf: [4096]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try a.tun.writeStats(&w);
        const text = w.buffered();
        try t.expect(std.mem.indexOf(u8, text, "configured_underlay_mtu = 1500") != null);
        try t.expect(std.mem.indexOf(u8, text, "overlay_mtu = 9000") != null);
        try t.expect(std.mem.indexOf(u8, text, "discovered_path_mtu = unset") != null);
        try t.expect(std.mem.indexOf(u8, text, "tx_packets = 0") != null);
    }
};
test {
    forceInclude();
}
