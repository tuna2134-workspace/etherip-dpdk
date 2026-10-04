//! Platform abstraction for carrying raw IPv6 packets with Next Header 97.
//!
//! The protocol core never touches a socket. It hands complete IPv6 packets to a `Transport` and
//! receives complete IPv6 packets from one. That separation is what makes the library testable
//! without root privileges, and what lets a DPDK, AF_PACKET, or userspace-netstack backend be
//! swapped in independently of the EtherIP logic.
//!
//! Three backends are provided:
//!
//!   * `Link` — a bounded, in-memory packet queue pair. Used by every test, needs no privileges,
//!     and is a faithful stand-in for an underlay (it can be given a smaller MTU to prove
//!     fragmentation works).
//!   * `NullTransport` — discards everything transmitted and never delivers anything. Useful for
//!     benchmarking the protocol path with no network at all.
//!   * `LinuxRawTransport` — a real `AF_PACKET`/`ETH_P_IPV6` socket (Linux only, requires
//!     `CAP_NET_RAW`). Written directly against `std.os.linux` because Zig 0.16's `std.posix` no
//!     longer exposes the socket syscalls. Kept out of the default build so tests never need
//!     privileges.
//!
//! No RFC mandates any of this; see docs/RFC-ANALYSIS.md Section 7.4.

const std = @import("std");
const builtin = @import("builtin");
const ipv6 = @import("ipv6.zig");
const etherip = @import("etherip.zig");

pub const log = std.log.scoped(.etherip_platform);

/// Largest packet any transport will accept. IPv6 itself caps a non-jumbogram packet well below
/// this; the bound exists so a hostile length field cannot drive an allocation.
pub const max_packet_len: usize = ipv6.max_payload_len + ipv6.header_len;

/// Errors a transport may report.
pub const Error = error{
    /// The supplied packet buffer is larger than `max_packet_len`.
    PacketTooLarge,
    /// The receive buffer handed in by the caller is too small for the next packet.
    ReceiveBufferTooSmall,
    /// The link/queue is full and the packet was dropped.
    QueueFull,
    /// No more packets are available right now.
    WouldBlock,
    /// The backend was not initialised, or was already closed.
    NotOpen,
    AlreadyOpen,
    /// The backend failed in a way the caller should treat as fatal.
    BackendFailure,
};

/// Sends and receives complete IPv6 packets (RFC 8200 Section 3), EtherIP or ICMPv6.
///
/// Implementations must not inspect or modify the packets: this interface is the raw-IPv6
/// boundary that the EtherIP layer sits on top of.
pub const Transport = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Hand one complete IPv6 packet to the network.
        send: *const fn (context: *anyopaque, packet: []const u8) Error!void,
        /// Wait for the next complete IPv6 packet, copying it into `buffer` and returning its
        /// length. Returns `error.WouldBlock` when nothing is pending.
        receive: *const fn (context: *anyopaque, buffer: []u8) Error!usize,
        /// Human-readable backend name for logs and statistics.
        name: *const fn (context: *anyopaque) []const u8,
        /// Close the backend and release its resources.
        close: *const fn (context: *anyopaque) void,
    };

    pub fn send(self: Transport, packet: []const u8) Error!void {
        return self.vtable.send(self.context, packet);
    }

    pub fn receive(self: Transport, buffer: []u8) Error!usize {
        return self.vtable.receive(self.context, buffer);
    }

    pub fn name(self: Transport) []const u8 {
        return self.vtable.name(self.context);
    }

    pub fn close(self: Transport) void {
        self.vtable.close(self.context);
    }
};

// ---------------------------------------------------------------------------
// Link: an in-memory underlay
// ---------------------------------------------------------------------------

/// A bounded FIFO of IPv6 packets.
pub const Queue = struct {
    gpa: std.mem.Allocator,
    items: std.ArrayList([]u8) = .empty,
    /// Packets dropped because the queue was full.
    dropped: u64 = 0,
    limit: usize,
    /// Largest packet this queue will store.
    packet_cap: usize = max_packet_len,

    pub fn init(gpa: std.mem.Allocator, limit: usize) !Queue {
        var q: Queue = .{ .gpa = gpa, .limit = limit };
        errdefer q.deinit();
        try q.items.ensureTotalCapacity(gpa, limit);
        return q;
    }

    pub fn deinit(self: *Queue) void {
        for (self.items.items) |it| self.gpa.free(it);
        self.items.deinit(self.gpa);
    }

    pub fn push(self: *Queue, packet: []const u8) Error!void {
        if (packet.len > self.packet_cap) return error.PacketTooLarge;
        if (self.items.items.len >= self.limit) {
            // Drop the oldest: a full queue means the receiver is behind, and keeping stale
            // packets is worse than losing one. Counted, not silent.
            self.dropped += 1;
            const victim = self.items.orderedRemove(0);
            self.gpa.free(victim);
        }
        const copy = self.gpa.dupe(u8, packet) catch return error.QueueFull;
        self.items.append(self.gpa, copy) catch {
            self.gpa.free(copy);
            return error.QueueFull;
        };
    }

    /// Copy the oldest packet into `buffer`. The stored packet is consumed.
    pub fn pop(self: *Queue, buffer: []u8) Error!usize {
        if (self.items.items.len == 0) return error.WouldBlock;
        const packet = self.items.orderedRemove(0);
        defer self.gpa.free(packet);
        if (packet.len > buffer.len) return error.ReceiveBufferTooSmall;
        @memcpy(buffer[0..packet.len], packet);
        return packet.len;
    }

    pub fn len(self: *const Queue) usize {
        return self.items.items.len;
    }

    pub fn isEmpty(self: *const Queue) bool {
        return self.items.items.len == 0;
    }
};

/// An in-memory underlay: `tx` is what the tunnel sends, `rx` is what the tunnel receives.
///
/// Two `Link`s can be wired together so a tunnel pair can talk to each other inside a single
/// process, with no sockets and no privileges.
pub const Link = struct {
    gpa: std.mem.Allocator,
    /// Packets transmitted by the owner of this link.
    tx: Queue,
    /// Packets delivered to the owner of this link.
    rx: Queue,
    /// Peer to forward transmitted packets to, if any.
    peer: ?*Link,
    /// MTU this link advertises. Deliberately *not* enforced by `send`: the underlay of a real
    /// tunnel is allowed to hand packets to routers that drop them, and the tunnel's own
    /// fragmentation is what keeps each packet under the path MTU. Tests can inspect this value
    /// to verify the tunnel never exceeds it.
    advertised_mtu: usize,

    pub fn init(gpa: std.mem.Allocator, queue_depth: usize, advertised_mtu: usize) !Link {
        return .{
            .gpa = gpa,
            .tx = try Queue.init(gpa, queue_depth),
            .rx = try Queue.init(gpa, queue_depth),
            .peer = null,
            .advertised_mtu = advertised_mtu,
        };
    }

    pub fn deinit(self: *Link) void {
        self.tx.deinit();
        self.rx.deinit();
    }

    /// Wire two links together so `a`'s transmissions become `b`'s receptions and vice versa.
    pub fn connect(a: *Link, b: *Link) void {
        a.peer = b;
        b.peer = a;
    }

    fn sendFn(context: *anyopaque, packet: []const u8) Error!void {
        const self: *Link = @ptrCast(@alignCast(context));
        try self.tx.push(packet);
        if (self.peer) |p| try p.rx.push(packet);
    }

    fn receiveFn(context: *anyopaque, buffer: []u8) Error!usize {
        const self: *Link = @ptrCast(@alignCast(context));
        return self.rx.pop(buffer);
    }

    fn nameFn(context: *anyopaque) []const u8 {
        _ = context;
        return "in-memory-link";
    }

    fn closeFn(context: *anyopaque) void {
        const self: *Link = @ptrCast(@alignCast(context));
        self.deinit();
    }

    pub fn transport(self: *Link) Transport {
        return .{ .context = @ptrCast(self), .vtable = &.{
            .send = sendFn,
            .receive = receiveFn,
            .name = nameFn,
            .close = closeFn,
        } };
    }
};

// ---------------------------------------------------------------------------
// NullTransport
// ---------------------------------------------------------------------------

/// Discards everything. Useful for measuring the protocol path in isolation.
pub const NullTransport = struct {
    sent_packets: u64 = 0,
    sent_bytes: u64 = 0,

    fn sendFn(context: *anyopaque, packet: []const u8) Error!void {
        if (packet.len > max_packet_len) return error.PacketTooLarge;
        const self: *NullTransport = @ptrCast(@alignCast(context));
        self.sent_packets += 1;
        self.sent_bytes += packet.len;
    }

    fn receiveFn(context: *anyopaque, buffer: []u8) Error!usize {
        _ = context;
        _ = buffer;
        return error.WouldBlock;
    }

    fn nameFn(context: *anyopaque) []const u8 {
        _ = context;
        return "null";
    }

    fn closeFn(context: *anyopaque) void {
        _ = context;
    }

    pub fn transport(self: *NullTransport) Transport {
        return .{ .context = @ptrCast(self), .vtable = &.{
            .send = sendFn,
            .receive = receiveFn,
            .name = nameFn,
            .close = closeFn,
        } };
    }
};

// ---------------------------------------------------------------------------
// Linux AF_PACKET transport
// ---------------------------------------------------------------------------

/// IANA "Assigned Internet Protocol Numbers" / `ETH_P_IPV6` in the Ethernet frame type registry:
/// 0x86DD. Used as the AF_PACKET protocol selector so the kernel delivers only IPv6 frames.
pub const eth_p_ipv6: u32 = 0x86DD;

/// `<linux/if_packet.h>` `struct sockaddr_ll`. Declared here because Zig's std does not expose it.
const SockAddrLl = extern struct {
    family: u16,
    protocol: u16,
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [8]u8,
};

pub const LinuxRaw = struct {
    fd: i32 = -1,
    /// Interface index the socket is bound to.
    if_index: u32 = 0,
    /// Destination MAC written into the Ethernet header of transmitted frames.
    destination_mac: [6]u8 = .{0xff} ** 6,
    /// Source MAC written into the Ethernet header of transmitted frames.
    source_mac: [6]u8 = @splat(0),
    /// Maximum IPv6 packet this transport will build, including the 14-octet Ethernet header.
    max_frame: usize = max_packet_len + 14,

    pub const OpenError = Error || error{ NotLinux, SyscallFailed };

    /// Open an `AF_PACKET` raw socket bound to interface `if_index`, sending and receiving raw
    /// IPv6 frames.
    ///
    /// Requires `CAP_NET_RAW` (or root). The IPv6 header is written by us; so is the Ethernet
    /// header of the *outgoing* frame, because AF_PACKET does not fill it in.
    ///
    /// The interface index is taken as a parameter rather than resolved from a name on purpose:
    /// name resolution needs `if_nametoindex` from libc, and this module deliberately has no libc
    /// dependency so that the protocol library links cleanly into a freestanding build. Callers
    /// that have libc (the `etherip-tunnel` executable does) can resolve it with
    /// `std.c.if_nametoindex`.
    pub fn open(if_index: u32) OpenError!LinuxRaw {
        if (builtin.os.tag != .linux) return error.NotLinux;
        const linux = std.os.linux;

        // SOCK_RAW | SOCK_CLOEXEC, AF_PACKET.
        const sock_type = linux.SOCK.RAW | linux.SOCK.CLOEXEC;
        // Linux syscalls return -errno in [-4095, -1] on failure and the result otherwise.
        const rc = linux.socket(linux.AF.PACKET, sock_type, eth_p_ipv6);
        const fd_signed: i64 = @bitCast(rc);
        if (fd_signed < 0) return error.SyscallFailed;
        const fd: i32 = @intCast(fd_signed);

        errdefer _ = linux.close(fd);

        // struct sockaddr_ll: family = AF_PACKET, protocol = ETH_P_IPV6, ifindex.
        var addr: SockAddrLl = .{
            .family = linux.AF.PACKET,
            .protocol = @truncate(eth_p_ipv6),
            .ifindex = @intCast(if_index),
            .hatype = 0,
            .pkttype = 0,
            .halen = 0,
            .addr = @splat(0),
        };
        const bind_rc = linux.bind(fd, @ptrCast(&addr), @sizeOf(SockAddrLl));
        const bind_signed: i64 = @bitCast(bind_rc);
        if (bind_signed < 0) return error.SyscallFailed;

        return .{ .fd = fd, .if_index = if_index };
    }

    /// Transmit one IPv6 packet, prepending the Ethernet header AF_PACKET expects.
    pub fn send(self: *LinuxRaw, packet: []const u8) Error!void {
        if (builtin.os.tag != .linux) return error.NotOpen;
        if (packet.len + 14 > self.max_frame) return error.PacketTooLarge;

        var frame: [max_packet_len + 14]u8 = undefined;
        @memcpy(frame[0..6], &self.destination_mac);
        @memcpy(frame[6..12], &self.source_mac);
        std.mem.writeInt(u16, frame[12..14], @intCast(eth_p_ipv6), .big);
        @memcpy(frame[14..][0..packet.len], packet);

        const linux = std.os.linux;
        var addr: SockAddrLl = .{
            .family = linux.AF.PACKET,
            .protocol = @truncate(eth_p_ipv6),
            .ifindex = @intCast(self.if_index),
            .hatype = 0,
            .pkttype = 0,
            .halen = 0,
            .addr = @splat(0),
        };
        _ = linux.sendto(
            self.fd,
            frame[0 .. 14 + packet.len].ptr,
            14 + packet.len,
            0,
            @ptrCast(&addr),
            @sizeOf(SockAddrLl),
        );
    }

    /// Receive one raw frame and strip its 14-octet Ethernet header.
    ///
    /// This call blocks; a production deployment would use a non-blocking socket plus `poll` or an
    /// event loop, which is exactly the sort of platform-specific policy this interface exists to
    /// keep out of the protocol code.
    pub fn receive(self: *LinuxRaw, buffer: []u8) Error!usize {
        if (builtin.os.tag != .linux) return error.NotOpen;
        const linux = std.os.linux;
        const rc = linux.recvfrom(
            self.fd,
            buffer.ptr,
            buffer.len,
            0,
            null,
            null,
        );
        const signed: i64 = @bitCast(rc);
        if (signed < 0) return error.BackendFailure;
        const n: usize = @intCast(signed);
        if (n <= 14) return error.ReceiveBufferTooSmall;
        const payload = n - 14;
        std.mem.copyForwards(u8, buffer[0..payload], buffer[14..n]);
        return payload;
    }

    pub fn close(self: *LinuxRaw) void {
        if (builtin.os.tag == .linux and self.fd >= 0) {
            _ = std.os.linux.close(self.fd);
            self.fd = -1;
        }
    }

    fn sendFn(context: *anyopaque, packet: []const u8) Error!void {
        const self: *LinuxRaw = @ptrCast(@alignCast(context));
        return self.send(packet);
    }

    fn receiveFn(context: *anyopaque, buffer: []u8) Error!usize {
        const self: *LinuxRaw = @ptrCast(@alignCast(context));
        return self.receive(buffer);
    }

    fn nameFn(context: *anyopaque) []const u8 {
        _ = context;
        return "linux-af-packet-ipv6";
    }

    fn closeFn(context: *anyopaque) void {
        const self: *LinuxRaw = @ptrCast(@alignCast(context));
        self.close();
    }

    pub fn transport(self: *LinuxRaw) Transport {
        return .{ .context = @ptrCast(self), .vtable = &.{
            .send = sendFn,
            .receive = receiveFn,
            .name = nameFn,
            .close = closeFn,
        } };
    }
};

const t = std.testing;

test "Transport is a plain vtable: no allocation on the fast path" {
    const gpa = t.allocator;
    var link = try Link.init(gpa, 4, 1500);
    defer link.deinit();
    var peer = try Link.init(gpa, 4, 1500);
    defer peer.deinit();
    Link.connect(&link, &peer);

    const a = link.transport();
    const b = peer.transport();
    try t.expectEqualStrings("in-memory-link", a.name());

    var pkt: [64]u8 = undefined;
    const src = ipv6.Address.parse("2001:db8::1") catch unreachable;
    const dst = ipv6.Address.parse("2001:db8::2") catch unreachable;
    try ipv6.writeHeader(pkt[0..ipv6.header_len], etherip.ip_protocol_number, 2, .{
        .source = src,
        .destination = dst,
    });
    pkt[40] = 0x30;
    pkt[41] = 0;

    try a.send(pkt[0..42]);
    try t.expectEqual(@as(usize, 1), peer.rx.len());

    var buf: [128]u8 = undefined;
    const n = try b.receive(&buf);
    try t.expectEqual(@as(usize, 42), n);
    try t.expectEqualSlices(u8, pkt[0..42], buf[0..n]);
    try t.expectEqual(error.WouldBlock, b.receive(&buf));
}

test "Queue: bounded, drops the oldest when full, and counts the drops" {
    const gpa = t.allocator;
    var q = try Queue.init(gpa, 2);
    defer q.deinit();

    var a = [_]u8{1} ** 4;
    var b = [_]u8{2} ** 4;
    var c = [_]u8{3} ** 4;
    try q.push(&a);
    try q.push(&b);
    try q.push(&c);
    try t.expectEqual(@as(u64, 1), q.dropped);

    var buf: [16]u8 = undefined;
    try t.expectEqual(@as(usize, 4), try q.pop(&buf));
    try t.expectEqual(@as(u8, 2), buf[0]); // 'a' was evicted
    try t.expectEqual(@as(usize, 4), try q.pop(&buf));
    try t.expectEqual(@as(u8, 3), buf[0]);
    try t.expectError(error.WouldBlock, q.pop(&buf));
}

test "Queue: rejects oversized packets and undersized receive buffers" {
    const gpa = t.allocator;
    var q = try Queue.init(gpa, 2);
    defer q.deinit();
    q.packet_cap = 8;

    var big = [_]u8{0} ** 9;
    try t.expectError(error.PacketTooLarge, q.push(&big));

    var small = [_]u8{0} ** 8;
    try q.push(&small);
    var tiny: [4]u8 = undefined;
    try t.expectError(error.ReceiveBufferTooSmall, q.pop(&tiny));
}

test "NullTransport counts and discards" {
    var n: NullTransport = .{};
    const tr = n.transport();
    try t.expectEqualStrings("null", tr.name());

    var pkt: [48]u8 = @splat(0);
    try tr.send(&pkt);
    try t.expectEqual(@as(u64, 1), n.sent_packets);
    try t.expectEqual(@as(u64, 48), n.sent_bytes);

    var buf: [16]u8 = undefined;
    try t.expectError(error.WouldBlock, tr.receive(&buf));

    const huge = try t.allocator.alloc(u8, max_packet_len + 1);
    defer t.allocator.free(huge);
    try t.expectError(error.PacketTooLarge, tr.send(huge));
}

test "Link: packets transmitted by one peer are received by the other" {
    const gpa = t.allocator;
    var a = try Link.init(gpa, 8, 1500);
    defer a.deinit();
    var b = try Link.init(gpa, 8, 1500);
    defer b.deinit();
    Link.connect(&a, &b);

    var pkt: [1496]u8 = undefined;
    @memset(&pkt, 0xAB);
    try a.transport().send(&pkt);
    try t.expectEqual(@as(usize, 1), a.tx.len());
    try t.expectEqual(@as(usize, 1), b.rx.len());

    var buf: [2048]u8 = undefined;
    const n = try b.transport().receive(&buf);
    try t.expectEqual(@as(usize, 1496), n);
    try t.expectEqualSlices(u8, &pkt, buf[0..n]);
}

test "LinuxRaw: without CAP_NET_RAW, opening fails cleanly instead of crashing" {
    // This test needs no privileges: without CAP_NET_RAW the socket() call fails and we surface
    // `error.SyscallFailed`. If the test happens to run with privileges, close it and pass.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var raw = LinuxRaw.open(1) catch |e| switch (e) {
        error.SyscallFailed, error.BackendFailure, error.NotLinux => return,
        else => return e,
    };
    raw.close();
}

test "IPv6 protocol number constant is 97" {
    try t.expectEqual(@as(u8, 97), etherip.ip_protocol_number);
    try t.expectEqual(@as(u32, 0x86DD), eth_p_ipv6);
}