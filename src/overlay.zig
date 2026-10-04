//! The L2 side of the tunnel: an overlay interface abstraction and its EtherIP binding.
//!
//! The project brief requires that protocol logic, packet parsing, fragmentation, reassembly, and
//! platform-specific I/O be separated. This file is the seam between the overlay L2 interface and
//! the EtherIP protocol core, and nothing else:
//!
//! ```text
//! OverlayInterface
//!     |  Ethernet frame (no FCS, RFC 3378 Section 3 step 1)
//!     v
//! TunnelOverlay.transmit()  ->  EtherIP encoder  ->  IPv6 (Next Header 97)
//!     |                                                      |
//!     v                                                      v
//! EtherIP decoder  ->  OverlayInterface           IPv6 network
//! ```
//!
//! ## FCS
//!
//! RFC 3378 Section 4 step 3 makes FCS generation the receiving LAN's responsibility during "data
//! link layer transmission processing". So the contract here is precise and narrow: **`transmit`
//! receives a frame with no FCS, and `onReceive` delivers a frame with no FCS.** Nothing in this
//! module adds, removes, or inspects an FCS. A real deployment binds this to a NIC or a TAP/TUN
//! descriptor, either of which appends the FCS in hardware or in the driver.
//!
//! No TAP/TUN dependency is introduced: the core tunnel is fully exercisable in-process.

const std = @import("std");
const ethernet = @import("ethernet.zig");
const fragment = @import("fragment.zig");
const tunnel = @import("tunnel.zig");

const log = std.log.scoped(.etherip_overlay);

pub const Error = error{
    /// The frame is shorter than an Ethernet header (RFC 3378 Section 2).
    FrameTooShort,
    /// The frame is larger than the configured overlay MTU.
    FrameTooLarge,
    /// The underlying transmit sink failed.
    TransmitFailed,
};

/// A layer-2 interface carrying Ethernet frames.
///
/// Frames crossing this boundary **never contain an FCS**, in either direction.
pub const OverlayInterface = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Hand one complete Ethernet frame (no FCS) to the interface.
        transmit: *const fn (context: *anyopaque, frame: []const u8) Error!void,
        /// Human-readable name for logs.
        name: *const fn (context: *anyopaque) []const u8,
    };

    pub fn transmit(self: OverlayInterface, frame: []const u8) Error!void {
        return self.vtable.transmit(self.context, frame);
    }

    pub fn name(self: OverlayInterface) []const u8 {
        return self.vtable.name(self.context);
    }
};

/// Binds an `OverlayInterface` to an EtherIP tunnel endpoint.
///
/// `tx_buffer` is caller-owned so `transmit` performs no allocation: it holds the largest EtherIP
/// datagram, i.e. `overlay_mtu + 2` octets.
pub const TunnelOverlay = struct {
    tun: *tunnel.Tunnel,
    tx_buffer: []u8,
    /// Where encapsulated IPv6 packets go. A `platform.Transport`-shaped sink, so the same binding
    /// works for the in-memory link, AF_PACKET, or DPDK.
    ip_sink: fragment.FragmentSink,
    /// Sent IPv6 packets, counted here so the binding can be used without a transport.
    packets_sent: u64 = 0,
    bytes_sent: u64 = 0,

    pub fn init(
        tun: *tunnel.Tunnel,
        tx_buffer: []u8,
        ip_sink: fragment.FragmentSink,
    ) Error!TunnelOverlay {
        const needed = tun.cfg.overlay_mtu + 2;
        if (tx_buffer.len < needed) return error.FrameTooLarge;
        return .{ .tun = tun, .tx_buffer = tx_buffer[0..needed], .ip_sink = ip_sink };
    }

    pub fn transmit(self: *TunnelOverlay, frame: []const u8) Error!void {
        // RFC 3378 Section 2: the encapsulated frame must be a complete Ethernet frame.
        _ = ethernet.parse(frame) catch return error.FrameTooShort;

        const outcome = self.tun.encapsulate(frame, self.tx_buffer, self.ip_sink) catch
            return error.TransmitFailed;
        switch (outcome) {
            .single => self.packets_sent += 1,
            .fragmented => |n| self.packets_sent += n,
            .frameTooLarge => {
                log.debug("overlay frame of {d} octets exceeds overlay_mtu {d}", .{
                    frame.len, self.tun.cfg.overlay_mtu,
                });
                return error.FrameTooLarge;
            },
            .fragmentationDisabled => return error.FrameTooLarge,
            .pathMtuTooSmall => return error.TransmitFailed,
        }
        self.bytes_sent += frame.len;
    }

    fn transmitFn(context: *anyopaque, frame: []const u8) Error!void {
        const self: *TunnelOverlay = @ptrCast(@alignCast(context));
        return self.transmit(frame);
    }

    fn nameFn(context: *anyopaque) []const u8 {
        _ = context;
        return "etherip-tunnel-overlay";
    }

    pub fn interface(self: *TunnelOverlay) OverlayInterface {
        return .{ .context = @ptrCast(self), .vtable = &.{
            .transmit = transmitFn,
            .name = nameFn,
        } };
    }
};

/// Records frames delivered from the far end of the tunnel. Used by tests and by the CLI's
/// end-to-end self test; a production deployment would forward to a NIC or TAP/TUN descriptor.
pub const FrameSink = struct {
    context: *anyopaque,
    push: *const fn (context: *anyopaque, frame: []const u8) Error!void,

    pub fn call(self: FrameSink, frame: []const u8) Error!void {
        return self.push(self.context, frame);
    }

};

/// A bounded, in-memory frame sink for tests and the CLI self test.
pub const CapturedFrames = struct {
    gpa: std.mem.Allocator,
    items: std.ArrayList([]u8) = .empty,
    limit: usize = 64,

    pub fn init(gpa: std.mem.Allocator, limit: usize) !CapturedFrames {
        var c: CapturedFrames = .{ .gpa = gpa, .limit = limit };
        errdefer c.deinit();
        try c.items.ensureTotalCapacity(gpa, limit);
        return c;
    }

    pub fn deinit(self: *CapturedFrames) void {
        for (self.items.items) |f| self.gpa.free(f);
        self.items.deinit(self.gpa);
    }

    pub fn len(self: *const CapturedFrames) usize {
        return self.items.items.len;
    }

    pub fn at(self: *const CapturedFrames, i: usize) []const u8 {
        return self.items.items[i];
    }

    fn pushFn(context: *anyopaque, frame: []const u8) Error!void {
        const self: *CapturedFrames = @ptrCast(@alignCast(context));
        if (self.items.items.len >= self.limit) {
            const victim = self.items.orderedRemove(0);
            self.gpa.free(victim);
        }
        const copy = self.gpa.dupe(u8, frame) catch return error.TransmitFailed;
        self.items.append(self.gpa, copy) catch {
            self.gpa.free(copy);
            return error.TransmitFailed;
        };
    }

    pub fn sink(self: *CapturedFrames) FrameSink {
        return .{ .context = @ptrCast(self), .push = pushFn };
    }
};

/// Deliver one already-received IPv6 packet through the tunnel and, if a frame came out, hand it to
/// `frame_sink`. Returns true when a frame was delivered.
pub fn deliver(
    tun: *tunnel.Tunnel,
    packet: []const u8,
    frame_out: []u8,
    frame_sink: FrameSink,
    now_ms: i64,
) Error!bool {
    const outcome = tun.receivePacket(packet, frame_out, now_ms) catch |e| switch (e) {
        error.Abort => return error.TransmitFailed,
    };
    switch (outcome) {
        .frame => {
            try frame_sink.call(frame_out[0..tun.last_frame_len]);
            return true;
        },
        else => return false,
    }
}

const t = std.testing;

/// An `OverlayInterface` that pushes every frame into a `CapturedFrames`, for tests.
pub fn capturedInterface(cap: *CapturedFrames) OverlayInterface {
    return .{
        .context = @ptrCast(cap),
        .vtable = &.{
            .transmit = struct {
                fn f(ctx: *anyopaque, frame: []const u8) Error!void {
                    const self: *CapturedFrames = @ptrCast(@alignCast(ctx));
                    return self.sink().call(frame);
                }
            }.f,
            .name = struct {
                fn f(ctx: *anyopaque) []const u8 {
                    _ = ctx;
                    return "captured";
                }
            }.f,
        },
    };
}

test "OverlayInterface is a two-method vtable" {
    const gpa = t.allocator;
    var cap = try CapturedFrames.init(gpa, 4);
    defer cap.deinit();

    const o = capturedInterface(&cap);
    var frame = [_]u8{0} ** 60;
    try o.transmit(&frame);
    try t.expectEqualStrings("captured", o.name());
    try t.expectEqual(@as(usize, 1), cap.len());
    try t.expectEqualSlices(u8, &frame, cap.at(0));
}

test "CapturedFrames is bounded and evicts the oldest" {
    const gpa = t.allocator;
    var cap = try CapturedFrames.init(gpa, 2);
    defer cap.deinit();

    const sink = cap.sink();
    var a = [_]u8{1} ** 4;
    var b = [_]u8{2} ** 4;
    var c = [_]u8{3} ** 4;
    try sink.call(&a);
    try sink.call(&b);
    try sink.call(&c);

    try t.expectEqual(@as(usize, 2), cap.len());
    try t.expectEqual(@as(u8, 2), cap.at(0)[0]);
    try t.expectEqual(@as(u8, 3), cap.at(1)[0]);
}

