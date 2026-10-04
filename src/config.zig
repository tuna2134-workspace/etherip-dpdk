//! Tunnel configuration and its startup validation.
//!
//! No RFC specifies a configuration format. The structure below is an implementation choice, but
//! every validation rule traces to a real constraint:
//!
//!   * `overlay_mtu` must fit a 16-bit IPv6 Payload Length after the EtherIP header
//!     (RFC 8200 Section 3, and RFC 8200 Section 4.5 error condition 3).
//!   * `underlay_mtu` must be at least the IPv6 minimum link MTU (RFC 8200 Section 5).
//!   * `underlay_mtu` must leave room for the IPv6 header, any reserved extension headers, the
//!     Fragment header, and one 8-octet aligned unit (RFC 8200 Sections 4.5 and 5).
//!   * `overlay_mtu` must be at least the largest possible EtherIP header plus a legal Ethernet
//!     frame (RFC 3378 Section 2 requires "a complete Ethernet or IEEE 802.3 frame").
//!   * `reassembly_timeout_ms` must not exceed 60 000 (RFC 8200 Section 4.5 requires abandonment
//!     "within 60 seconds of the reception of the first-arriving fragment").
//!   * `local_ipv6` must be a real unicast address: RFC 4291 Section 2.2 forbids the unspecified
//!     address `::` as a source, and RFC 4291 Section 2.5.2 documents `::ffff:0:0/96` as the
//!     IPv4-mapped range, which is not a valid EtherIP tunnel endpoint.

const std = @import("std");
const Io = std.Io;
const ipv6 = @import("ipv6.zig");
const etherip = @import("etherip.zig");
const ethernet = @import("ethernet.zig");
const fragment = @import("fragment.zig");
const reassembly = @import("reassembly.zig");

pub const Config = struct {
    /// Local (tunnel) IPv6 address: the source address of every outer IPv6 packet.
    local_ipv6: ipv6.Address,
    /// Remote (tunnel) IPv6 address: the destination address of every outer IPv6 packet.
    remote_ipv6: ipv6.Address,
    /// MTU of the IPv6 interface carrying the tunnel. Distinct from `overlay_mtu`.
    underlay_mtu: usize,
    /// Largest Ethernet frame accepted from the overlay interface. May exceed `underlay_mtu`;
    /// that is exactly the case IPv6 source fragmentation exists to handle.
    overlay_mtu: usize,
    /// When false, an EtherIP datagram that does not fit `underlay_mtu` is dropped instead of
    /// fragmented.
    fragmentation_enabled: bool = true,
    /// Milliseconds before an incomplete reassembly is abandoned (RFC 8200 Section 4.5).
    reassembly_timeout_ms: u64 = reassembly.default_timeout_ms,
    /// Maximum datagrams being reassembled at once.
    max_reassembly_packets: usize = 256,
    /// Maximum octets of fragment payload buffered across all reassemblies.
    max_reassembly_bytes: usize = 16 * 1024 * 1024,
    /// Maximum fragments tracked per reassembled datagram.
    max_fragments_per_datagram: usize = reassembly.default_max_chunks,
    /// TCP MSS clamping is strictly optional; EtherIP works identically without it.
    mss_clamping_enabled: bool = false,
    /// Target MSS. `null` means derive it from `effective_path_mtu` at run time.
    mss_clamp: ?u16 = null,
    /// Hop Limit for the outer IPv6 header (RFC 8200 Section 3). Implementation-specific.
    hop_limit: u8 = 64,
    /// Traffic Class for the outer IPv6 header. Implementation-specific.
    traffic_class: u8 = 0,
    /// Flow Label for the outer IPv6 header. Implementation-specific.
    flow_label: u32 = 0,
    /// Octets reserved in the Per-Fragment Headers region for en-route-processed IPv6 extension
    /// headers (RFC 8200 Section 4.5). No RFC mandates a value; this implementation inserts none,
    /// so the default is 0.
    ///
    /// A non-zero value is **rejected by `validate`**. RFC 8200 Section 4.5 requires the IPv6
    /// header's Next Header field to name the *first* Per-Fragment header, so reserving octets
    /// without supplying actual headers would emit packets that a conformant receiver must reject
    /// (it would parse the reserved region as a second Fragment header). The MTU arithmetic still
    /// accounts for a reserve, via `fragment.calculateFragmentPayloadSize`, for callers that do
    /// their own encapsulation.
    reserved_per_fragment_ext_bytes: usize = 0,

    pub const defaults: Config = .{
        .local_ipv6 = ipv6.Address.any,
        .remote_ipv6 = ipv6.Address.any,
        .underlay_mtu = 1500,
        .overlay_mtu = 1500,
    };

    pub const Error = error{
        LocalAddressIsUnspecified,
        LocalAddressIsLoopback,
        LocalAddressIsMulticast,
        LocalAddressIsIpv4Mapped,
        RemoteAddressIsUnspecified,
        RemoteAddressIsLoopback,
        RemoteAddressIsMulticast,
        RemoteAddressIsIpv4Mapped,
        AddressesAreEqual,
        /// RFC 8200 Section 5: "IPv6 requires that every link in the Internet have an MTU of
        /// 1280 octets or greater."
        UnderlayMtuBelowIpv6Minimum,
        /// The underlay MTU cannot hold the IPv6 header, the reserved extension octets, the
        /// Fragment header, and one 8-octet unit (RFC 8200 Sections 4.5 and 5).
        UnderlayMtuTooSmallForFragmentation,
        /// RFC 8200 Section 3: Payload Length is 16 bits.
        OverlayMtuExceedsPayloadLength,
        /// RFC 3378 Section 2 requires "a complete Ethernet or IEEE 802.3 frame".
        OverlayMtuTooSmallForEthernetFrame,
        ZeroReassemblyPackets,
        ZeroReassemblyBytes,
        ZeroMaxFragmentsPerDatagram,
        /// RFC 8200 Section 4.5.
        ReassemblyTimeoutTooLong,
        /// An MSS larger than 65 535 cannot be advertised (RFC 9293 Section 3.1 option length).
        MssOutOfRange,
        /// An MSS smaller than the IPv6 minimum link MTU is meaningless and usually a typo.
        MssBelowIpv6Minimum,
        MssExceedsOverlayMtu,
        ReservedExtensionBytesTooLarge,
        /// A non-zero `reserved_per_fragment_ext_bytes` without actual headers to emit. RFC 8200
        /// Section 4.5 requires the IPv6 header's Next Header to name the first Per-Fragment header.
        ReservedExtensionBytesNotSupported,
        HopLimitZero,
        FragmentationDisabledWithJumboOverlay,
    };

    /// Validate every field, returning the first problem found.
    pub fn validate(self: Config) Error!void {
        try validateLocalAddress(self.local_ipv6);
        try validateRemoteAddress(self.remote_ipv6);
        if (self.local_ipv6.eql(self.remote_ipv6)) return error.AddressesAreEqual;

        // RFC 8200 Section 5.
        if (self.underlay_mtu < ipv6.min_link_mtu) return error.UnderlayMtuBelowIpv6Minimum;

        // 2048 keeps the field from being mistaken for a real header block; the binding
        // constraint is the fragment-budget check below.
        if (self.reserved_per_fragment_ext_bytes > 2048) return error.ReservedExtensionBytesTooLarge;
        // See the field docs: this endpoint emits no en-route extension headers, so a reserve
        // without headers would produce invalid packets.
        if (self.reserved_per_fragment_ext_bytes != 0) return error.ReservedExtensionBytesNotSupported;

        // RFC 8200 Sections 4.5 and 5: the underlay must still fit one aligned fragment unit.
        _ = fragment.calculateFragmentPayloadSize(.{
            .path_mtu = self.underlay_mtu,
            .per_fragment_ext_len = self.reserved_per_fragment_ext_bytes,
        }) catch return error.UnderlayMtuTooSmallForFragmentation;

        // RFC 3378 Section 2: the frame must be a complete Ethernet frame.
        if (self.overlay_mtu < ethernet.header_len + 1) return error.OverlayMtuTooSmallForEthernetFrame;
        // RFC 8200 Section 3: the reassembled Payload Length is 16 bits and includes the EtherIP
        // header, so the frame cannot exceed 65 535 - 2.
        // RFC 8200 Section 3: the reassembled Payload Length is 16 bits and comprises the
        // reserved Per-Fragment octets plus the EtherIP header plus the frame.
        const max_frame = ipv6.max_payload_len - etherip.header_len - self.reserved_per_fragment_ext_bytes;
        if (self.overlay_mtu > max_frame) return error.OverlayMtuExceedsPayloadLength;

        if (self.max_reassembly_packets == 0) return error.ZeroReassemblyPackets;
        if (self.max_reassembly_bytes == 0) return error.ZeroReassemblyBytes;
        if (self.max_fragments_per_datagram == 0) return error.ZeroMaxFragmentsPerDatagram;
        if (self.reassembly_timeout_ms == 0 or
            self.reassembly_timeout_ms > reassembly.max_timeout_ms)
        {
            return error.ReassemblyTimeoutTooLong;
        }

        if (self.mss_clamp) |mss| {
            if (mss == 0) return error.MssOutOfRange;
            if (mss > max_advertised_mss) return error.MssOutOfRange;
            if (mss < ipv6.min_link_mtu) return error.MssBelowIpv6Minimum;
            if (mss > self.overlay_mtu) return error.MssExceedsOverlayMtu;
        }
        // RFC 8200 Section 3: a Hop Limit of 0 means the packet must not be forwarded, which makes
        // it useless for a tunnel.
        if (self.hop_limit == 0) return error.HopLimitZero;

        // An overlay larger than the underlay only works with fragmentation; without it the
        // mandatory 9000-over-1500 scenario would silently drop traffic.
        if (!self.fragmentation_enabled and self.overlay_mtu > self.underlay_mtu) {
            return error.FragmentationDisabledWithJumboOverlay;
        }

        // The reassembly limits must be internally consistent with `max_reassembly_bytes`.
        const limits: reassembly.Limits = self.reassemblyLimits();
        limits.validate() catch return error.ZeroReassemblyBytes;
    }

    /// Largest Fragmentable Part this endpoint will reassemble: the 2-octet EtherIP header plus
    /// the configured overlay MTU.
    pub fn maxReassemblyDatagram(self: Config) usize {
        return self.overlay_mtu + etherip.header_len;
    }

    /// MTU parameters for fragmentation, derived from this configuration.
    pub fn mtuParams(self: Config) fragment.MtuParams {
        return .{
            .path_mtu = self.underlay_mtu,
            .per_fragment_ext_len = self.reserved_per_fragment_ext_bytes,
        };
    }

    /// Largest outer IPv6 packet this tunnel will emit (fragmented case).
    pub fn maxOuterPacketSize(self: Config) usize {
        const payload = fragment.calculateFragmentPayloadSize(self.mtuParams()) catch return 0;
        return fragment.tunnelOverhead(self.mtuParams(), true) + payload;
    }

    /// Largest EtherIP datagram that can be sent **without** fragmentation: the IPv6 header plus
    /// the whole EtherIP datagram.
    pub fn maxUnfragmentedDatagram(self: Config) usize {
        const overhead = fragment.tunnelOverhead(self.mtuParams(), false);
        return if (self.underlay_mtu > overhead) self.underlay_mtu - overhead else 0;
    }

    /// Reassembly limits implied by this configuration.
    pub fn reassemblyLimits(self: Config) reassembly.Limits {
        return .{
            .max_packets = self.max_reassembly_packets,
            .max_bytes = self.max_reassembly_bytes,
            .max_datagram = self.maxReassemblyDatagram(),
            .timeout_ms = self.reassembly_timeout_ms,
            .max_chunks = self.max_fragments_per_datagram,
            // The reassembled packet is Per-Fragment Headers + Fragmentable Part (RFC 8200
            // Section 4.5), and the reserved octets count towards its 16-bit Payload Length.
            .per_fragment_header_len = self.reserved_per_fragment_ext_bytes,
        };
    }
};

/// RFC 9293 Section 3.1: the TCP MSS option is 2 octets, so an advertised MSS cannot exceed
/// 65 535. In practice the largest usable value is bounded by the overlay MTU.
pub const max_advertised_mss: u16 = std.math.maxInt(u16);

/// RFC 4291 Section 2.7: IPv6 multicast addresses are `FF00::/8`, i.e. the first octet is 0xff.
fn isMulticast(a: ipv6.Address) bool {
    return @as(u8, @truncate(a.groups[0] >> 8)) == 0xff;
}

fn validateLocalAddress(a: ipv6.Address) Config.Error!void {
    if (a.isUnspecified()) return error.LocalAddressIsUnspecified;
    if (a.eql(ipv6.Address.loopback)) return error.LocalAddressIsLoopback;
    if (a.isIpv4Mapped()) return error.LocalAddressIsIpv4Mapped;
    if (isMulticast(a)) return error.LocalAddressIsMulticast;
    return;
}

fn validateRemoteAddress(a: ipv6.Address) Config.Error!void {
    if (a.isUnspecified()) return error.RemoteAddressIsUnspecified;
    if (a.eql(ipv6.Address.loopback)) return error.RemoteAddressIsLoopback;
    if (a.isIpv4Mapped()) return error.RemoteAddressIsIpv4Mapped;
    if (isMulticast(a)) return error.RemoteAddressIsMulticast;
    return;
}

/// Optional explicit clamp value, validated against `Config.overlay_mtu`.
pub const MssClampMode = union(enum) {
    disabled,
    auto,
    fixed: u16,
};

const t = std.testing;

fn baseConfig() Config {
    const local = ipv6.Address.parse("2001:db8:100::1") catch unreachable;
    const remote = ipv6.Address.parse("2001:db8:200::1") catch unreachable;
    return .{ .local_ipv6 = local, .remote_ipv6 = remote, .underlay_mtu = 1500, .overlay_mtu = 1500 };
}

test "Config.validate accepts the brief's canonical example" {
    var c = baseConfig();
    c.underlay_mtu = 1500;
    c.overlay_mtu = 9000;
    try c.validate();

    // The mandatory scenario's arithmetic comes straight out of the configuration.
    const p = c.mtuParams();
    try t.expectEqual(@as(usize, 1448), try fragment.calculateFragmentPayloadSize(p));
    try t.expectEqual(@as(usize, 1496), fragment.tunnelOverhead(p, true) + 1448);
    try t.expect(c.maxOuterPacketSize() <= c.underlay_mtu);
    try t.expectEqual(@as(usize, 9002), c.maxReassemblyDatagram());
}

test "Config.validate rejects invalid tunnel addresses" {
    const remote = ipv6.Address.parse("2001:db8:200::1") catch unreachable;
    const good = ipv6.Address.parse("2001:db8:100::1") catch unreachable;

    try t.expectError(error.LocalAddressIsUnspecified, (Config{
        .local_ipv6 = ipv6.Address.any,
        .remote_ipv6 = remote,
        .underlay_mtu = 1500,
        .overlay_mtu = 1500,
    }).validate());

    try t.expectError(error.LocalAddressIsLoopback, (Config{
        .local_ipv6 = ipv6.Address.loopback,
        .remote_ipv6 = remote,
        .underlay_mtu = 1500,
        .overlay_mtu = 1500,
    }).validate());

    try t.expectError(error.LocalAddressIsMulticast, (Config{
        .local_ipv6 = ipv6.Address.parse("ff02::1") catch unreachable,
        .remote_ipv6 = remote,
        .underlay_mtu = 1500,
        .overlay_mtu = 1500,
    }).validate());

    try t.expectError(error.LocalAddressIsIpv4Mapped, (Config{
        .local_ipv6 = ipv6.Address.parse("::ffff:192.0.2.1") catch unreachable,
        .remote_ipv6 = remote,
        .underlay_mtu = 1500,
        .overlay_mtu = 1500,
    }).validate());

    try t.expectError(error.RemoteAddressIsUnspecified, (Config{
        .local_ipv6 = good,
        .remote_ipv6 = ipv6.Address.any,
        .underlay_mtu = 1500,
        .overlay_mtu = 1500,
    }).validate());

    try t.expectError(error.RemoteAddressIsLoopback, (Config{
        .local_ipv6 = good,
        .remote_ipv6 = ipv6.Address.loopback,
        .underlay_mtu = 1500,
        .overlay_mtu = 1500,
    }).validate());

    try t.expectError(error.AddressesAreEqual, (Config{
        .local_ipv6 = good,
        .remote_ipv6 = good,
        .underlay_mtu = 1500,
        .overlay_mtu = 1500,
    }).validate());
}

test "Config.validate rejects MTUs the standards forbid" {
    // RFC 8200 Section 5: the IPv6 minimum link MTU is 1280.
    var c = baseConfig();
    c.underlay_mtu = 1279;
    try t.expectError(error.UnderlayMtuBelowIpv6Minimum, c.validate());

    // 1280 is legal but leaves 1232 octets of aligned fragment payload.
    c.underlay_mtu = 1280;
    try c.validate();

    // RFC 8200 Section 3: Payload Length is 16 bits, and the EtherIP header occupies 2 of them.
    c.underlay_mtu = 1500;
    c.overlay_mtu = ipv6.max_payload_len - etherip.header_len;
    try c.validate();
    c.overlay_mtu = ipv6.max_payload_len - etherip.header_len + 1;
    try t.expectError(error.OverlayMtuExceedsPayloadLength, c.validate());

    // RFC 3378 Section 2 needs a complete Ethernet frame.
    c.overlay_mtu = ethernet.header_len;
    try t.expectError(error.OverlayMtuTooSmallForEthernetFrame, c.validate());
    c.overlay_mtu = ethernet.header_len + 1;
    try c.validate();
}

test "Config.validate rejects an underlay too small to fragment, and a header reserve without headers" {
    var c = baseConfig();
    try c.validate();

    // This endpoint emits no en-route extension headers, so a reserve without headers is rejected
    // rather than silently producing packets a receiver must discard (RFC 8200 Section 4.5 requires
    // the IPv6 header's Next Header to name the first Per-Fragment header).
    c.reserved_per_fragment_ext_bytes = 16;
    try t.expectError(error.ReservedExtensionBytesNotSupported, c.validate());
    c.reserved_per_fragment_ext_bytes = 4_096;
    try t.expectError(error.ReservedExtensionBytesTooLarge, c.validate());
    c.reserved_per_fragment_ext_bytes = 0;
    try c.validate();

    // The MTU arithmetic itself does account for a reserve, for callers that encapsulate themselves.
    const reserved = try fragment.calculateFragmentPayloadSize(.{
        .path_mtu = 1500,
        .per_fragment_ext_len = 16,
    });
    try t.expectEqual(@as(usize, 1432), reserved);
    try t.expectEqual(@as(usize, 0), reserved % fragment.fragment_alignment);
    // 40 (IPv6) + 16 (reserved) + 8 (Fragment) + 1432 = 1496 <= 1500.
    try t.expectEqual(@as(usize, 1496), fragment.tunnelOverhead(.{
        .path_mtu = 1500,
        .per_fragment_ext_len = 16,
    }, true) + reserved);

    // At the IPv6 minimum link MTU the budget with a reserve is much tighter.
    try t.expectError(
        error.PathMtuTooSmall,
        fragment.calculateFragmentPayloadSize(.{ .path_mtu = 1280, .per_fragment_ext_len = 1_225 }),
    );
}

test "Config.validate rejects zero or out-of-range reassembly limits" {
    var c = baseConfig();
    c.max_reassembly_packets = 0;
    try t.expectError(error.ZeroReassemblyPackets, c.validate());

    c = baseConfig();
    c.max_reassembly_bytes = 0;
    try t.expectError(error.ZeroReassemblyBytes, c.validate());

    c = baseConfig();
    c.max_fragments_per_datagram = 0;
    try t.expectError(error.ZeroMaxFragmentsPerDatagram, c.validate());

    c = baseConfig();
    c.reassembly_timeout_ms = 0;
    try t.expectError(error.ReassemblyTimeoutTooLong, c.validate());

    // RFC 8200 Section 4.5 mandates abandonment within 60 seconds.
    c.reassembly_timeout_ms = 60_001;
    try t.expectError(error.ReassemblyTimeoutTooLong, c.validate());
    c.reassembly_timeout_ms = 60_000;
    try c.validate();
}

test "Config.validate rejects impossible MSS values" {
    var c = baseConfig();
    c.mss_clamping_enabled = true;
    c.mss_clamp = 0;
    try t.expectError(error.MssOutOfRange, c.validate());

    c.mss_clamp = 100; // below the IPv6 minimum link MTU
    try t.expectError(error.MssBelowIpv6Minimum, c.validate());

    c.overlay_mtu = 1400;
    c.mss_clamp = 1401; // larger than the frame the tunnel will carry
    try t.expectError(error.MssExceedsOverlayMtu, c.validate());

    c.mss_clamp = 1392;
    try c.validate();

    // "auto" (null) is always acceptable.
    c.mss_clamp = null;
    try c.validate();
}

test "Config.validate: fragmentation disabled with a jumbo overlay is rejected" {
    var c = baseConfig();
    c.underlay_mtu = 1500;
    c.overlay_mtu = 9000;
    c.fragmentation_enabled = false;
    try t.expectError(error.FragmentationDisabledWithJumboOverlay, c.validate());

    c.fragmentation_enabled = true;
    try c.validate();

    // With overlay <= underlay, disabling fragmentation is fine.
    c.overlay_mtu = 1500;
    c.fragmentation_enabled = false;
    try c.validate();
}

test "Config.validate rejects Hop Limit 0" {
    var c = baseConfig();
    c.hop_limit = 0;
    try t.expectError(error.HopLimitZero, c.validate());
    c.hop_limit = 1;
    try c.validate();
}

test "Config derived quantities" {
    var c = baseConfig();
    c.underlay_mtu = 1500;
    c.overlay_mtu = 9000;
    try c.validate();

    try t.expectEqual(@as(usize, 40 + 8), fragment.tunnelOverhead(c.mtuParams(), true));
    try t.expectEqual(@as(usize, 40), fragment.tunnelOverhead(c.mtuParams(), false));
    try t.expectEqual(@as(usize, 1496), c.maxOuterPacketSize());
    // Without a Fragment header, one unfragmented packet can carry 1500 - 40 = 1460 octets.
    try t.expectEqual(@as(usize, 1460), c.maxUnfragmentedDatagram());

    const limits = c.reassemblyLimits();
    try t.expectEqual(@as(usize, 9002), limits.max_datagram);
    try t.expectEqual(reassembly.default_timeout_ms, limits.timeout_ms);
    try t.expectEqual(@as(usize, 0), limits.per_fragment_header_len);

    // `reassemblyLimits` forwards the reserve so the 65 535 check stays honest (RFC 8200 Section 3).
    try t.expectEqual(@as(usize, 0), c.reassemblyLimits().per_fragment_header_len);
}

test "Config: the brief's example addresses validate" {
    var c = baseConfig();
    c.local_ipv6 = ipv6.Address.parse("2001:db8:100::1") catch unreachable;
    c.remote_ipv6 = ipv6.Address.parse("2001:db8:200::1") catch unreachable;
    c.underlay_mtu = 1500;
    c.overlay_mtu = 9000;
    c.fragmentation_enabled = true;
    c.reassembly_timeout_ms = 60_000;
    c.max_reassembly_packets = 512;
    c.max_reassembly_bytes = 8 * 1024 * 1024;
    c.mss_clamping_enabled = true;
    c.mss_clamp = null;
    try c.validate();
}