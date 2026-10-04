//! EtherIP tunnel endpoint: encapsulation, decapsulation, PMTUD, and observability.
//!
//! RFCs: RFC 3378 (EtherIP wire format), RFC 8200 (IPv6 and fragment reassembly),
//! RFC 8201 (PMTUD), RFC 4443 (ICMPv6).
//!
//! ## Packet layouts produced
//!
//! Unfragmented (the datagram fits the path MTU):
//!
//! ```text
//! +--------------------+-------------------------------+
//! | IPv6 header,       | EtherIP header | Ethernet frame|
//! | Next Header = 97   | Version 3      | (no FCS)      |
//! +--------------------+-------------------------------+
//! ```
//!
//! Fragmented (the datagram exceeds the path MTU) — RFC 8200 Section 4.5:
//!
//! ```text
//! +----------+---------------+-------------------------------+
//! | IPv6     | IPv6 Fragment | EtherIP header | Ethernet     |
//! | header   | header        | (first frag)  | frame part   |
//! | NH = 44  | offset, M, id |               |              |
//! +----------+---------------+-------------------------------+
//! | IPv6     | IPv6 Fragment |          Ethernet frame part       |
//! | header   | header        |                                   |
//! | NH = 44  | offset, M, id |                                   |
//! +----------+---------------+-------------------------------------+
//! ```
//!
//! ## No allocation on the fast path
//!
//! The caller supplies two scratch buffers (`tx_scratch`, `rx_scratch`) at construction. Sending
//! an unfragmented frame, sending a fragmented datagram, and receiving every packet kind are all
//! allocation-free. The only allocations happen in `init` (the reassembly pools) and in the
//! statistics snapshot.

const std = @import("std");
const Io = std.Io;

const config = @import("config.zig");
const etherip = @import("etherip.zig");
const ethernet = @import("ethernet.zig");
const fragment = @import("fragment.zig");
const checksum = @import("checksum.zig");
const icmpv6 = @import("icmpv6.zig");
const ipv6 = @import("ipv6.zig");
const mss_clamp = @import("mss_clamp.zig");
const reassembly = @import("reassembly.zig");
const stats = @import("stats.zig");

const log = std.log.scoped(.etherip);

/// Monotonic clock in milliseconds, supplied by the caller so tests are deterministic.
pub const Clock = reassembly.Clock;

/// Outcome of encapsulating one Ethernet frame.
pub const SendOutcome = union(enum) {
    /// One unfragmented IPv6 packet was produced.
    single,
    /// `count` fragment packets were produced, in order.
    fragmented: u32,
    /// The frame exceeded `overlay_mtu`.
    frameTooLarge,
    /// The frame needed fragmentation but fragmentation is disabled.
    fragmentationDisabled,
    /// The path MTU is currently too small to emit even one aligned fragment.
    pathMtuTooSmall,
};

/// Outcome of processing one received IPv6 packet.
pub const ReceiveOutcome = union(enum) {
    /// A complete Ethernet frame is ready in the caller's buffer.
    frame,
    /// An IPv6 packet was consumed but belongs to another flow or protocol.
    ignored,
    /// A fragment was buffered; more are needed.
    fragmentBuffered,
    /// A fragment duplicated one already held.
    duplicateFragment,
    /// An ICMPv6 Packet Too Big was consumed and the path MTU updated.
    pathMtuUpdated: u32,
    /// The packet was rejected.
    rejected: union(enum) {
        simple: RejectReason,
        fragment: reassembly.RejectReason,
    },
};

pub const RejectReason = enum {
    /// The outer IPv6 header did not satisfy RFC 8200 Section 3 or Section 4.
    MalformedOuterIpv6,
    /// RFC 3378 Section 4 step 1 rejected the EtherIP header.
    MalformedEtherIp,
    /// RFC 3378 Section 2 requires a complete Ethernet frame; this was not one.
    MalformedEthernet,
    /// An ICMPv6 message failed checksum validation (RFC 4443 Section 2.1).
    IcmpMalformed,
};

/// Everything the tunnel needs at construction time. Buffers are caller-owned so the fast path
/// stays allocation-free.
pub const Options = struct {
    config: config.Config,
    gpa: std.mem.Allocator,
    /// Scratch buffer for outbound IPv6 packets. Must be at least
    /// `config.maxOuterPacketSize()` bytes.
    tx_scratch: []u8,
    /// Scratch buffer for inbound IPv6 packets. Must be at least `max_packet_len` bytes.
    rx_scratch: []u8,
    clock: Clock,
    /// Seed for the Fragment Identification generator (RFC 8200 Section 4.5; algorithms per
    /// RFC 7739 Section 5.2). Pass OS entropy for the strongest guarantee that an off-path attacker
    /// cannot predict the value and spoof fragments with it (RFC 7739 Section 3). When null the
    /// tunnel falls back to mixing the monotonic clock with an address, which is enough for
    /// correctness and interoperability but is *not* unpredictable.
    fragment_id_seed: ?u64 = null,
};

pub const InitError = config.Config.Error || fragment.Fragmenter.InitError ||
    reassembly.Limits.Error || error{ScratchBufferTooSmall};

pub const Tunnel = struct {
    gpa: std.mem.Allocator,
    cfg: config.Config,
    clock: Clock,

    fragmenter: fragment.Fragmenter,
    reassembler: reassembly.Reassembler,
    counters: stats.Counters = .{},
    pmtu: Pmtu,

    /// Fragment Identification generator state (RFC 8200 Section 4.5, algorithms per RFC 7739).
    frag_id_rng: std.Random.DefaultPrng,
    /// ICMPv6 messages the platform should transmit, each in its own fixed-size buffer so nothing
    /// borrows a stack frame. Bounded, so a peer that provokes many errors cannot grow memory.
    icmp_queue: [icmp_queue_capacity]QueuedIcmp = undefined,
    icmp_queue_len: usize = 0,
    icmp_queue_dropped: u64 = 0,

    /// Complete frame delivered by the most recent successful `receive`.
    last_frame_len: usize = 0,

    /// Scratch for `expireReassemblies`, so that call is allocation-free after `init`.
    expire_scratch: [expire_capacity]reassembly.Expired = undefined,

    /// Ring of recently transmitted packet descriptors, used to validate an inbound ICMPv6 Packet
    /// Too Big against traffic we actually sent (RFC 8201 Section 4). See `SentRecord`.
    sent: [sent_history_capacity]SentRecord = undefined,
    sent_len: usize = 0,
    sent_next: usize = 0,

    const icmp_queue_capacity: usize = 32;
    const sent_history_capacity: usize = 64;
    const expire_capacity: usize = 256;
    /// Largest ICMPv6 error message this endpoint originates: 8 octets of ICMPv6 header plus as
    /// much of the invoking packet as fits under the IPv6 minimum link MTU (RFC 4443 Section 2.4
    /// (c), RFC 8200 Section 5).
    const icmp_queue_message_len: usize = ipv6.min_link_mtu - ipv6.header_len;

    /// An owned ICMPv6 error message waiting to be transmitted.
    pub const QueuedIcmp = struct {
        destination: ipv6.Address,
        len: u16,
        bytes: [icmp_queue_message_len]u8 = undefined,
    };

    pub fn init(opts: Options) InitError!Tunnel {
        try opts.config.validate();

        if (opts.tx_scratch.len < opts.config.maxOuterPacketSize()) return error.ScratchBufferTooSmall;
        const min_rx = ipv6.max_payload_len + ipv6.header_len;
        if (opts.rx_scratch.len < min_rx) return error.ScratchBufferTooSmall;

        const self = Tunnel{
            .gpa = opts.gpa,
            .cfg = opts.config,
            .clock = opts.clock,
            .fragmenter = try fragment.Fragmenter.init(opts.tx_scratch, opts.config.mtuParams()),
            .reassembler = try reassembly.Reassembler.init(opts.gpa, .{
                .limits = opts.config.reassemblyLimits(),
                .clock = opts.clock,
            }),
            .pmtu = .{},
            .frag_id_rng = std.Random.DefaultPrng.init(
                opts.fragment_id_seed orelse weakEntropy(opts.clock),
            ),
        };
        log.info(
            "tunnel configured local={any} remote={any} underlay_mtu={d} overlay_mtu={d} max_outer={d}",
            .{
                opts.config.local_ipv6,
                opts.config.remote_ipv6,
                opts.config.underlay_mtu,
                opts.config.overlay_mtu,
                opts.config.maxOuterPacketSize(),
            },
        );
        return self;
    }

    pub fn deinit(self: *Tunnel) void {
        self.fragmenter.deinit();
        self.reassembler.deinit();
        self.* = undefined;
    }

    /// Fallback seed when the caller supplied none. Documented as predictable: RFC 7739 Section 3
    /// notes that predictable Fragment Identifications are a security weakness for off-path
    /// spoofing, so a production deployment should pass `Options.fragment_id_seed`.
    fn weakEntropy(clock: Clock) u64 {
        var marker: usize = 0;
        const addr = @intFromPtr(&marker);
        const now = clock.nowMs();
        const stamp: u64 = @bitCast(now);
        return stamp *% 0x9E37_79B9_7F4A_7C15 ^
            @as(u64, @truncate(addr)) *% 0xBF58_476D_1CE4_E5B9;
    }

    // -----------------------------------------------------------------------
    // PMTU
    // -----------------------------------------------------------------------

    /// Path-MTU state.
    ///
    /// Three values, never conflated (docs/RFC-ANALYSIS.md Section 5.10):
    ///   * `configured_underlay_mtu` — from configuration, the local link MTU.
    ///   * `discovered_path_mtu` — learned from ICMPv6 Packet Too Big, null until one arrives.
    ///   * `effective_path_mtu` — `min(configured, discovered)`, never below the IPv6 minimum
    ///     link MTU of 1280 (RFC 8200 Section 5, RFC 8201 Section 4).
    pub const Pmtu = struct {
        discovered: ?u32 = null,
        /// RFC 8201 Section 4: "An attempt to detect an increase … must not be done less than 5
        /// minutes after a Packet Too Big message has been received for the given path." Probing is
        /// not implemented by default; this records the earliest legal time if it is enabled.
        last_packet_too_big_ms: ?i64 = null,
        pmtu_probe_interval_ms: u64 = 10 * 60 * 1000,

        pub fn effective(self: Pmtu, configured: usize) usize {
            const discovered = self.discovered orelse return configured;
            const clamped = @max(discovered, @as(u32, ipv6.min_link_mtu));
            return @min(configured, @as(usize, clamped));
        }
    };

    /// `min(configured_underlay_mtu, discovered_path_mtu)`.
    pub fn effectivePathMtu(self: *const Tunnel) usize {
        return self.pmtu.effective(self.cfg.underlay_mtu);
    }

    /// MTU parameters for the *currently known* path MTU, not the configured one.
    fn effectiveMtuParams(self: *const Tunnel) fragment.MtuParams {
        var p = self.cfg.mtuParams();
        p.path_mtu = self.effectivePathMtu();
        return p;
    }

    /// Apply an ICMPv6 Packet Too Big message (RFC 8201 Section 4 and Section 5.2).
    /// Returns the new effective path MTU if it changed.
    pub fn onPacketTooBig(self: *Tunnel, ptb: icmpv6.PacketTooBig, now_ms: i64) ?u32 {
        self.counters.icmp_packet_too_big += 1;
        self.pmtu.last_packet_too_big_ms = now_ms;

        const before = self.pmtu.effective(self.cfg.underlay_mtu);
        // RFC 8201 Section 4: never raise the estimate in response to a PTB.
        self.pmtu.discovered = icmpv6.applyPacketTooBig(self.pmtu.discovered, ptb.mtu, false);
        const after = self.pmtu.effective(self.cfg.underlay_mtu);

        if (after == before) return null;
        self.counters.pmtu_updates += 1;
        log.info(
            "pmtu update: effective_path_mtu {d} -> {d} (reported {d}, configured {d})",
            .{ before, after, ptb.mtu, self.cfg.underlay_mtu },
        );
        return @intCast(after);
    }

    // -----------------------------------------------------------------------
    // Encapsulation
    // -----------------------------------------------------------------------

    /// Everything an outbound packet needs, derived once per frame.
    fn writeOptions(self: *const Tunnel) ipv6.WriteOptions {
        return .{
            .traffic_class = self.cfg.traffic_class,
            .flow_label = self.cfg.flow_label,
            .hop_limit = self.cfg.hop_limit,
            .source = self.cfg.local_ipv6,
            .destination = self.cfg.remote_ipv6,
        };
    }

    /// Encapsulate one Ethernet frame and write the resulting IPv6 packet(s) through `sink`.
    ///
    /// `frame` must not contain an FCS (RFC 3378 Section 3 step 1) and is copied verbatim.
    /// `scratch` is a caller-owned buffer used only when `sink` needs the packet to persist; it
    /// must be at least `config.overlay_mtu + etherip.header_len` bytes.
    ///
    /// Optional TCP MSS clamping runs on a *copy* of the frame in `scratch` before encapsulation,
    /// so a clamped frame is what gets tunnelled and the overlay's own buffer is left alone.
    pub fn encapsulate(
        self: *Tunnel,
        frame: []const u8,
        scratch: []u8,
        sink: fragment.FragmentSink,
    ) !SendOutcome {
        if (frame.len > self.cfg.overlay_mtu) {
            self.counters.tx_dropped += 1;
            log.debug("dropping {d}-octet frame: over overlay_mtu {d}", .{ frame.len, self.cfg.overlay_mtu });
            return .frameTooLarge;
        }

        // Build the EtherIP datagram in `scratch`.
        const datagram_len = etherip.header_len + frame.len;
        if (scratch.len < datagram_len) {
            self.counters.tx_dropped += 1;
            return .frameTooLarge;
        }
        const datagram = scratch[0..datagram_len];
        _ = etherip.encapsulate(frame, datagram) catch {
            self.counters.tx_dropped += 1;
            return .frameTooLarge;
        };

        // Optional MSS clamping operates on the Ethernet frame inside the EtherIP datagram.
        if (self.cfg.mss_clamping_enabled) {
            const eth_frame = datagram[etherip.header_len..];
            switch (mss_clamp.clampFrame(eth_frame, .{
                .effective_path_mtu = self.effectivePathMtu(),
                .overlay_mtu = self.cfg.overlay_mtu,
                .configured_mss = self.cfg.mss_clamp,
            })) {
                .clamped => |c| {
                    self.counters.mss_clamped_packets += 1;
                    log.debug(
                        "mss clamped {d} -> {d} (effective_path_mtu {d})",
                        .{ c.from, c.to, self.effectivePathMtu() },
                    );
                },
                .skipped => self.counters.mss_clamp_noop += 1,
                .unparseable => self.counters.mss_clamp_unparseable += 1,
            }
        }

        const params = self.effectiveMtuParams();
        const max_frag = fragment.calculateFragmentPayloadSize(params) catch |e| switch (e) {
            error.PathMtuTooSmall, error.PayloadLengthOverflow => {
                self.counters.tx_dropped += 1;
                return .pathMtuTooSmall;
            },
        };

        if (datagram_len <= max_frag) {
            // Fits: one packet, no Fragment header.
            const packet_len = ipv6.header_len + datagram_len;
            ipv6.writeHeader(
                self.fragmenter.scratch[0..ipv6.header_len],
                etherip.ip_protocol_number,
                datagram_len,
                self.writeOptions(),
            ) catch {
                self.counters.tx_dropped += 1;
                return .pathMtuTooSmall;
            };
            @memcpy(self.fragmenter.scratch[ipv6.header_len..][0..datagram_len], datagram);
            sink.call(self.fragmenter.scratch[0..packet_len], .{
                .index = 0,
                .count = 1,
                .fragment_offset = 0,
                .more_fragments = false,
                .identification = 0,
                .wire_len = packet_len,
            }) catch return error.Abort;
            recordSent_(self, etherip.ip_protocol_number, packet_len - ipv6.header_len);
            self.counters.tx_packets += 1;
            self.counters.tx_bytes += frame.len;
            self.counters.tx_ipv6_packets += 1;
            log.debug("encapsulated {d}-octet frame into one {d}-octet packet", .{ frame.len, packet_len });
            return .single;
        }

        if (!self.cfg.fragmentation_enabled) {
            self.counters.tx_dropped += 1;
            log.debug("frame needs fragmentation but it is disabled", .{});
            return .fragmentationDisabled;
        }

        // Fragment. RFC 8200 Section 4.5 requires a fresh Identification per fragmented datagram;
        // RFC 7739 Section 5.2 recommends a PRNG, which also stops an off-path attacker predicting
        // the value to spoof fragments.
        const identification: u32 = self.frag_id_rng.random().int(u32);
        const count = self.fragmenter.emitFragments(.{
            .mtu = params,
            .source = self.cfg.local_ipv6,
            .destination = self.cfg.remote_ipv6,
            .write_options = self.writeOptions(),
            .identification = identification,
        }, datagram, sink) catch |e| switch (e) {
            // The datagram already fit, or the MTU / Per-Fragment header configuration is
            // inconsistent with the Fragmenter. All are configuration faults.
            error.NotFragmentable,
            error.PathMtuTooSmall,
            error.ScratchTooSmall,
            error.PerFragmentExtLengthMismatch,
            error.PerFragmentExtNextHeaderMismatch,
            error.Ipv6HeaderLenMismatch,
            => {
                self.counters.tx_dropped += 1;
                return .pathMtuTooSmall;
            },
            // The datagram cannot be carried in a 16-bit Payload Length (RFC 8200 Section 4.5 error 3).
            error.DatagramTooLarge,
            error.PayloadLengthOverflow,
            => {
                self.counters.tx_dropped += 1;
                return .frameTooLarge;
            },
            error.Abort => return error.Abort,
        };

        recordSent_(self, ipv6.next_header_fragment, fragment.fragment_header_len + (datagram.len / count));
        self.counters.tx_packets += 1;
        self.counters.tx_bytes += frame.len;
        self.counters.tx_fragments += count;
        self.counters.tx_ipv6_packets += count;
        log.debug("fragmented {d}-octet EtherIP datagram into {d} fragments", .{ datagram_len, count });
        return .{ .fragmented = count };
    }

    // -----------------------------------------------------------------------
    // Decapsulation
    // -----------------------------------------------------------------------

    /// Process one received IPv6 packet.
    ///
    /// On success the decapsulated Ethernet frame is written to `frame_out` (the reassembly buffer,
    /// or `rx_scratch` for an unfragmented packet) and `last_frame_len` holds its length. The
    /// returned slice borrows the tunnel's internal buffer and is valid until the next
    /// `receivePacket` call.
    pub fn receivePacket(self: *Tunnel, packet: []const u8, frame_out: []u8, now_ms: i64) !ReceiveOutcome {
        // RFC 8200 Section 4.5 error condition 1 is enforced here, before anything else, so the
        // ICMPv6 Time Exceeded it requires is queued rather than lost. The reassembler deliberately
        // does not sweep on its own: it would discard the records without reporting them.
        _ = self.expireReassemblies(now_ms);

        const header = ipv6.parseHeader(packet) catch {
            self.counters.malformed_packets += 1;
            log.debug("malformed outer IPv6 header ({d} octets)", .{packet.len});
            return .{ .rejected = .{ .simple = .MalformedOuterIpv6 } };
        };

        // RFC 4443 Section 2.4 (d): the upper-layer protocol type comes from the ICMPv6 message's
        // quoted packet, so ICMPv6 must be accepted alongside EtherIP.
        // ICMPv6 must be accepted directly in the IPv6 header: an ICMPv6 error is addressed to the
        // tunnel endpoint, never encapsulated in EtherIP (RFC 4443 Section 2.4 (d)).
        if (header.next_header == ipv6.next_header_icmpv6) {
            return self.handleIcmpv6(&header, now_ms);
        }

        if (!header.destination.eql(self.cfg.local_ipv6)) {
            self.counters.not_for_us += 1;
            return .ignored;
        }

        var chain_error_offset: u32 = 0;
        const chain = ipv6.parseExtensionChainReporting(header, &chain_error_offset) catch {
            self.counters.malformed_packets += 1;
            self.queueExtensionChainError(header, packet, chain_error_offset);
            return .{ .rejected = .{ .simple = .MalformedOuterIpv6 } };
        };

        // An AH- or ESP-protected payload cannot be validated as a plain EtherIP datagram. This
        // tunnel never inserts AH or ESP itself (RFC 3378 provides no cryptographic protection;
        // see docs/RFC-ANALYSIS.md Section 8), so such packets are simply not ours.
        if (chain.saw_ah or chain.saw_esp) {
            self.counters.not_for_us += 1;
            return .ignored;
        }
        if (chain.upper_layer_next_header != etherip.ip_protocol_number) {
            self.counters.not_for_us += 1;
            return .ignored;
        }

        self.counters.rx_packets += 1;

        if (chain.fragment) |f| {
            return self.handleFragment(&header, f, packet, frame_out, now_ms);
        }

        // Unfragmented EtherIP datagram.
        return self.finishDatagram(chain.upper_layer, frame_out);
    }

    fn handleFragment(
        self: *Tunnel,
        header: *const ipv6.Packet,
        f: ipv6.FragmentHeaderView,
        packet: []const u8,
        frame_out: []u8,
        now_ms: i64,
    ) !ReceiveOutcome {
        self.counters.rx_fragments += 1;

        // RFC 8200 Section 4.5 notes that the Fragment header's Next Header value may differ across
        // fragments and that only the offset-zero fragment's value is used. So the "is this ours?"
        // question is asked only about that fragment, and a later fragment with a different value is
        // still accepted rather than reported on another protocol's behalf.
        if (f.fragment_offset == 0 and f.next_header != etherip.ip_protocol_number) {
            self.counters.not_for_us += 1;
            return .ignored;
        }

        // RFC 8200 Section 4.5 error condition 2, checked before anything is queued.
        if (f.more_fragments and f.data.len % fragment.fragment_alignment != 0) {
            self.counters.malformed_packets += 1;
            self.queueIcmp(header.*, .{ .fragment_length_not_aligned = .{
                .invoking_packet = packet,
            } });
            return .{ .rejected = .{ .fragment = .FragmentLengthNotAligned } };
        }
        // RFC 8200 Section 4.5: the Fragment header's Next Header identifies the Fragmentable
        // Part's first header. Only the offset-zero fragment's value is used, so accept anything
        // here and validate on the reassembled datagram.
        if (f.next_header != etherip.ip_protocol_number and f.fragment_offset == 0) {
            self.counters.not_for_us += 1;
            return .ignored;
        }

        // RFC 8200 Section 4.5 error condition 4: "If the first fragment does not include all
        // headers through an Upper-Layer header, then that fragment should be discarded and an
        // ICMP Parameter Problem, Code 3, message should be sent to the source of the fragment,
        // with the Pointer field set to zero." The Upper-Layer header here is the 2-octet EtherIP
        // header, so an offset-zero fragment shorter than that cannot be valid.
        if (f.fragment_offset == 0 and f.data.len < etherip.header_len) {
            self.counters.malformed_packets += 1;
            self.queueIcmp(header.*, .{ .first_fragment_incomplete = .{ .invoking_packet = packet } });
            return .{ .rejected = .{ .simple = .MalformedEtherIp } };
        }

        // RFC 8200 Section 4.5: an atomic datagram (offset 0 and M 0) needs no reassembly at all.
        if (f.fragment_offset == 0 and !f.more_fragments) {
            return self.finishDatagram(f.data, frame_out);
        }

        switch (self.reassembler.addFragment(header.source, header.destination, f, now_ms)) {
            .buffered => {
                self.counters.rx_fragment_accepted += 1;
                log.debug("buffered fragment id=0x{X} offset={d} len={d}", .{
                    f.identification, f.byteOffset(), f.data.len,
                });
                return .fragmentBuffered;
            },
            .duplicate => {
                self.counters.rx_fragment_duplicate += 1;
                return .duplicateFragment;
            },
            .complete => |datagram| {
                self.counters.rx_fragment_accepted += 1;
                // `reassembly_success` is taken from the reassembler's own `datagrams_completed`
                // in `snapshot()`, so it is not incremented here too.
                log.debug("reassembled {d} octets from fragments", .{datagram.len});
                return self.finishDatagram(datagram, frame_out);
            },
            .rejected => |reason| {
                self.counters.malformed_packets += 1;
                switch (reason) {
                    .Overlapping => self.counters.reassembly_overlap_drop += 1,
                    .QueueFull => self.counters.reassembly_evicted += 1,
                    else => {},
                }
                // RFC 8200 Section 4.5 error condition 5: send no ICMP for an overlap.
                switch (reason) {
                    .FragmentLengthNotAligned => self.queueIcmp(header.*, .{
                        .fragment_length_not_aligned = .{ .invoking_packet = packet },
                    }),
                    .ExceedsDatagramLimit => self.queueIcmp(header.*, .{
                        .fragment_exceeds_payload_length = .{ .invoking_packet = packet },
                    }),
                    else => {},
                }
                return .{ .rejected = .{ .fragment = reason } };
            },
        }
    }

    /// Validate the EtherIP header, extract the Ethernet frame, and validate the frame structure.
    fn finishDatagram(
        self: *Tunnel,
        datagram: []const u8,
        frame_out: []u8,
    ) ReceiveOutcome {
        const ether = etherip.parse(datagram) catch |e| switch (e) {
            error.TruncatedHeader,
            error.BufferTooSmall,
            error.MissingEthernetFrame,
            => {
                self.counters.malformed_packets += 1;
                log.debug("malformed EtherIP datagram: {t}", .{e});
                return .{ .rejected = .{ .simple = .MalformedEtherIp } };
            },
            // RFC 3378 Section 4 step 1: "Confirm that the value of the version field is 3 (three),
            // and that the value of the Reserved field is 0 (zero). Frames with other values MUST
            // be discarded."
            error.UnsupportedVersion => {
                self.counters.malformed_packets += 1;
                log.debug("discarding EtherIP datagram: unsupported Version (RFC 3378 Section 4)", .{});
                return .{ .rejected = .{ .simple = .MalformedEtherIp } };
            },
            error.ReservedNotZero => {
                self.counters.malformed_packets += 1;
                // Never reinterpreted as another protocol: no XET fallback exists.
                log.debug("discarding EtherIP datagram: non-zero Reserved (RFC 3378 Section 4)", .{});
                return .{ .rejected = .{ .simple = .MalformedEtherIp } };
            },
        };

        if (ether.frame.len > frame_out.len) {
            self.counters.malformed_packets += 1;
            return .{ .rejected = .{ .simple = .MalformedEthernet } };
        }
        // RFC 3378 Section 2: the frame must be a complete Ethernet or IEEE 802.3 frame.
        _ = ethernet.parse(ether.frame) catch {
            self.counters.malformed_packets += 1;
            return .{ .rejected = .{ .simple = .MalformedEthernet } };
        };

        @memcpy(frame_out[0..ether.frame.len], ether.frame);
        self.last_frame_len = ether.frame.len;
        self.counters.rx_bytes += ether.frame.len;
        return .frame;
    }

    /// Offset of the first extension header, i.e. 40 octets past the start of the IPv6 header.
    /// RFC 4443 Section 3.4 gives exactly this as the Pointer for "the IPv6 extension header
    /// following the IPv6 header ... holds an unrecognized Next Header field value".
    const first_ext_header_pointer: u32 = ipv6.header_len;

    /// Build the ICMPv6 error for a rejected extension-header chain.
    ///
    /// RFC 4443 Section 3.4 distinguishes two situations and they need different codes:
    ///   * an unrecognised Next Header **type** -> Code 1, Pointer at the offending value. RFC 4443
    ///     Section 3.4's own example uses Pointer 40 for a bad value inside the first extension
    ///     header, and 6 for one in the IPv6 header itself.
    ///   * a header that is malformed, truncated or out of place -> Code 0 ("Erroneous header field
    ///     encountered"), Pointer at the header that could not be processed.
    fn queueExtensionChainError(
        self: *Tunnel,
        header: ipv6.Packet,
        packet: []const u8,
        error_offset: u32,
    ) void {
        // RFC 4443 Section 3.4 needs the Pointer to name the offending header, so use the offset the
        // parser reported rather than guessing. Every failure inside the walk happens on an extension
        // header (the walk only runs while `isExtensionHeader(nh)` holds), so the Pointer is never
        // the IPv6 header's own Next Header field at offset 6.
        const pointer = if (error_offset >= ipv6.header_len) error_offset else first_ext_header_pointer;
        self.queueIcmp(header, .{ .malformed_extension_header = .{
            .invoking_packet = packet,
            .pointer = pointer,
        } });
    }

    /// RFC 4443 Section 2.4 (e.6): true only for an address that identifies a single node, i.e.
    /// neither the unspecified address nor a multicast address.
    fn isUniqueNode(a: ipv6.Address) bool {
        if (a.isUnspecified()) return false;
        if (@as(u8, @truncate(a.groups[0] >> 8)) == 0xff) return false; // RFC 4291 Section 2.7
        return true;
    }

    fn handleIcmpv6(self: *Tunnel, header: *const ipv6.Packet, now_ms: i64) ReceiveOutcome {
        if (!header.destination.eql(self.cfg.local_ipv6)) {
            self.counters.not_for_us += 1;
            return .ignored;
        }
        const ptb = icmpv6.parsePacketTooBig(header.payload, header.source, header.destination) catch |e| {
            switch (e) {
                // An ICMPv6 message for another protocol, or informational: RFC 4443 Section 2.4 (b)
                // requires informational messages to be silently discarded.
                error.NotAnErrorMessage, error.Truncated => return .ignored,
                error.BadChecksum => {
                    self.counters.malformed_packets += 1;
                    log.debug("ICMPv6 Packet Too Big failed checksum validation", .{});
                    return .{ .rejected = .{ .simple = .IcmpMalformed } };
                },
            }
        };

        // RFC 8201 Section 4: validate that the PTB corresponds to traffic we actually sent.
        if (!correlatesWithSentTraffic_(self, ptb)) {
            log.debug("ignoring an ICMPv6 Packet Too Big that matches no transmitted packet", .{});
            self.counters.unmatched_packet_too_big += 1;
            return .ignored;
        }

        if (self.onPacketTooBig(ptb, now_ms)) |new_mtu| return .{ .pathMtuUpdated = new_mtu };
        return .ignored;
    }

    fn queueIcmp(self: *Tunnel, header: ipv6.Packet, request: icmpv6.ErrorRequest) void {
        if (self.icmp_queue_len == icmp_queue_capacity) {
            self.icmp_queue_dropped += 1;
            log.debug("ICMPv6 error queue full; dropping error message", .{});
            return;
        }
        // RFC 4443 Sections 3.1, 3.3 and 3.4: the destination is "Copied from the Source Address
        // field of the invoking packet".
        const destination = header.source;
        // RFC 4443 Section 2.4 (e.6): an ICMPv6 error message "MUST NOT be originated as a result
        // of receiving ... A packet whose source address does not uniquely identify a single node
        // - e.g., the IPv6 Unspecified Address, an IPv6 multicast address, or an address known to be
        // anycast." The unspecified address and multicast are detectable here; anycast is not, and
        // RFC 4443 accepts that: the quoted packet and the checksum still let the far end decide.
        if (!isUniqueNode(destination)) {
            log.debug(
                "not originating ICMPv6 for a non-unicast source (RFC 4443 Section 2.4 (e.6))",
                .{},
            );
            return;
        }
        var slot: QueuedIcmp = undefined;
        slot.destination = destination;
        const n = icmpv6.writeError(&slot.bytes, self.cfg.local_ipv6, destination, request) catch
            return;
        slot.len = @intCast(n);
        self.icmp_queue[self.icmp_queue_len] = slot;
        self.icmp_queue_len += 1;
        self.counters.icmp_errors_sent += 1;
    }

    /// Take one queued ICMPv6 error message, if any.
    ///
    /// The returned message is written into `out`, whose buffer the caller owns, because the
    /// queue's own storage is compacted on the next `queueIcmp` call. Returns false when the queue
    /// is empty.
    pub fn takeIcmp(self: *Tunnel, out: *icmpv6.Outgoing) bool {
        if (self.icmp_queue_len == 0) return false;
        const front = &self.icmp_queue[0];
        if (front.len > out.buffer.len) return false;
        @memcpy(out.buffer[0..front.len], front.bytes[0..front.len]);
        out.destination = front.destination;
        out.len = front.len;
        if (self.icmp_queue_len > 1) {
            std.mem.copyForwards(
                QueuedIcmp,
                self.icmp_queue[0 .. self.icmp_queue_len - 1],
                self.icmp_queue[1..self.icmp_queue_len],
            );
        }
        self.icmp_queue_len -= 1;
        return true;
    }

    /// Number of ICMPv6 error messages waiting to be transmitted.
    pub fn queuedIcmpCount(self: *const Tunnel) usize {
        return self.icmp_queue_len;
    }

    /// Expire incomplete reassemblies (RFC 8200 Section 4.5 error condition 1).
    ///
    /// RFC 8200 Section 4.5 error condition 1 requires, in addition to abandoning the reassembly:
    /// "If the first fragment (i.e., the one with a Fragment Offset of zero) has been received, an
    /// ICMP Time Exceeded -- Fragment Reassembly Time Exceeded message should be sent to the source
    /// of that fragment." That message is queued here.
    pub fn expireReassemblies(self: *Tunnel, now_ms: i64) usize {
        const n = self.reassembler.expireInto(&self.expire_scratch, now_ms);
        var reported: usize = 0;
        for (self.expire_scratch[0..@min(self.expire_scratch.len, n)]) |e| {
            if (!e.have_first) continue;
            // Quote the IPv6 and Fragment headers so the peer can identify the abandoned datagram by
            // its (Source, Destination, Identification) triple (RFC 8200 Section 4.5, RFC 4443 2.4(c)).
            var quoted: [ipv6.header_len + fragment.fragment_header_len]u8 = undefined;
            const header = ipv6PacketStub(e.key, &quoted);
            self.queueIcmp(header, .{ .reassembly_time_exceeded = .{ .invoking_packet = &quoted } });
            reported += 1;
        }
        self.counters.reassembly_timeout += n;
        if (n > 0) log.info("abandoned {d} incomplete reassembly context(s), {d} ICMPv6 Time Exceeded queued", .{ n, reported });
        return n;
    }

    /// Rebuild the headers of an abandoned fragment packet, for ICMPv6 quoting.
    ///
    /// RFC 4443 Section 2.4 (c) requires "as much of the invoking packet as possible". The fragment
    /// payload is gone by this point, but the headers that identify the datagram are not: the IPv6
    /// header and the Fragment header carrying the Identification. Both are reproduced here so the
    /// peer can correlate the message (RFC 8200 Section 4.5).
    fn ipv6PacketStub(key: reassembly.Key, out: *[ipv6.header_len + fragment.fragment_header_len]u8) ipv6.Packet {
        // The reassembled Payload Length is unknown (no fragment carried the end), so the quoted
        // Payload Length covers just the Fragment header.
        ipv6.writeHeader(out[0..], ipv6.next_header_fragment, fragment.fragment_header_len, .{
            .source = key.source,
            .destination = key.destination,
        }) catch unreachable;
        const fh = out[ipv6.header_len..][0..fragment.fragment_header_len];
        fh[0] = etherip.ip_protocol_number; // the Fragmentable Part starts with the EtherIP header
        fh[1] = 0; // Reserved
        std.mem.writeInt(u16, fh[2..4], 0, .big); // Fragment Offset 0, Res 0, M = 0
        std.mem.writeInt(u32, fh[4..8], key.identification, .big);

        return .{
            .raw_header = out[0..ipv6.header_len].*,
            .traffic_class = 0,
            .flow_label = 0,
            .payload_length = fragment.fragment_header_len,
            .next_header = ipv6.next_header_fragment,
            .hop_limit = 0,
            .source = key.source,
            .destination = key.destination,
            .payload = out[ipv6.header_len..],
            .header_bytes = ipv6.header_len + fragment.fragment_header_len,
        };
    }

    /// Point-in-time statistics snapshot.
    pub fn snapshot(self: *const Tunnel) stats.Snapshot {
        const rs = self.reassembler.statistics();
        // The tunnel owns the counters it increments itself; the reassembler's are folded in without
        // overwriting. In particular `reassembly_timeout` counts *every* abandoned context, while the
        // reassembler's `datagrams_timed_out` only counts those that had an offset-zero fragment
        // (RFC 8200 Section 4.5 error condition 1 only reports those).
        var c = self.counters;
        c.rx_fragment_duplicate += rs.counters.fragments_duplicate;
        c.rx_fragment_accepted += rs.counters.fragments_accepted;
        c.reassembly_overlap_drop += rs.counters.datagrams_overlapped;
        c.reassembly_evicted += rs.counters.datagrams_evicted;
        c.reassembly_success += rs.counters.datagrams_completed;
        return .{
            .counters = c,
            .reassembly = .{
                .in_flight_packets = rs.in_flight_packets,
                .in_flight_bytes = rs.in_flight_bytes,
                .buffered_bytes = rs.buffered_bytes,
                .max_packets = self.cfg.max_reassembly_packets,
                .max_bytes = self.cfg.max_reassembly_bytes,
            },
            .effective_path_mtu = self.effectivePathMtu(),
            .discovered_path_mtu = self.pmtu.discovered,
            .configured_underlay_mtu = self.cfg.underlay_mtu,
            .overlay_mtu = self.cfg.overlay_mtu,
        };
    }

    pub fn writeStats(self: *const Tunnel, w: *Io.Writer) Io.Writer.Error!void {
        return stats.formatSnapshot(self.snapshot(), w);
    }
};

/// Descriptor of a packet this endpoint transmitted, used to validate an inbound ICMPv6 Packet
/// Too Big before trusting it.
///
/// RFC 8201 Section 4: "Nodes should appropriately validate the payload of ICMPv6 PTB messages to
/// ensure these are received in response to transmitted traffic (i.e., a reported error condition
/// that corresponds to an IPv6 packet actually sent by the application)." Without this, a single
/// forged PTB permanently degrades the tunnel to the 1280-octet minimum.
pub const SentRecord = struct {
    /// Next Header the outer IPv6 header carried: 44 for a fragmented datagram, 97 otherwise.
    next_header: u8,
    /// Payload Length of the packet we sent, recorded for diagnostics and future correlation.
    payload_length: u16,
};

/// Remember a transmitted packet so a later Packet Too Big referring to it can be recognised.
fn recordSent_(self: *Tunnel, next_header: u8, payload_length: usize) void {
    self.sent[self.sent_next] = .{
        .next_header = next_header,
        .payload_length = @intCast(@min(payload_length, 0xffff)),
    };
    self.sent_next = (self.sent_next + 1) % self.sent.len;
    if (self.sent_len < self.sent.len) self.sent_len += 1;
}

/// True when a Packet Too Big plausibly refers to something we actually sent (RFC 8201 Section 4).
///
/// The correlation is deliberately on the **quoted packet**, not on the PTB's source address.
/// RFC 4443 Section 3.2 makes the Source Address of a PTB the node that could not forward the
/// packet — an on-path router, which is never the EtherIP peer (the peer never emits PTBs). So
/// requiring the source to match would discard every genuine PTB while accepting only spoofed ones.
///
/// What is checked:
///   * the quoted packet's Source Address must be this endpoint's tunnel address, i.e. the quote must
///     be of a packet *we* sent;
///   * if the quote is long enough to read a Next Header, that value must match the Next Header of
///     some recently transmitted packet. RFC 4443 Section 2.4 (c) lets a router truncate the quote,
///     so an unreadable Next Header falls back to the address check alone.
fn correlatesWithSentTraffic_(self: *const Tunnel, ptb: icmpv6.PacketTooBig) bool {
    if (self.sent_len == 0) return false;

    const quoted = ptb.invoking_packet;
    if (quoted.len < ipv6.header_len) return false;
    if ((quoted[0] >> 4) != ipv6.version) return false;
    if (!ipv6.Address.fromBytes(quoted[8..24]).eql(self.cfg.local_ipv6)) return false;

    const quoted_nh = quoted[6];
    for (self.sent[0..self.sent_len]) |r| {
        if (r.next_header == quoted_nh) return true;
        // A datagram we fragmented is announced with Next Header 44; one we sent whole is announced
        // with 97. Accept either association so a PTB is not lost purely because the send history
        // has since rolled over to the other shape.
        if (quoted_nh == ipv6.next_header_fragment and r.next_header == etherip.ip_protocol_number) {
            return true;
        }
    }
    return false;
}

/// Convenience: a `fragment.FragmentSink` that just hands packets to a callback.
pub fn sinkFromFunction(
    context: *anyopaque,
    comptime f: *const fn (*anyopaque, []const u8) anyerror!void,
) fragment.FragmentSink {
    return .{
        .context = context,
        .emit = struct {
            fn wrapper(ctx: *anyopaque, packet: []const u8, meta: fragment.FragmentMeta) fragment.SinkError!void {
                _ = meta;
                f(ctx, packet) catch return error.Abort;
            }
        }.wrapper,
    };
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;

/// A deterministic clock so timeout behaviour is testable.
const TestClock = struct {
    now: i64 = 0,

    fn clock(self: *TestClock) Clock {
        return .{ .context = @ptrCast(self), .nowMsFn = nowMsFn };
    }

    fn nowMsFn(ctx: *anyopaque) i64 {
        const self: *TestClock = @ptrCast(@alignCast(ctx));
        return self.now;
    }
};

const local_addr = ipv6.Address.parse("2001:db8:100::1") catch unreachable;
const remote_addr = ipv6.Address.parse("2001:db8:200::1") catch unreachable;

/// Collects the IPv6 packets a tunnel emits, keeping each one alive.
const Pcap = struct {
    gpa: std.mem.Allocator,
    packets: std.ArrayList([]u8) = .empty,

    fn sink(ctx: *anyopaque, packet: []const u8, meta: fragment.FragmentMeta) fragment.SinkError!void {
        const self: *Pcap = @ptrCast(@alignCast(ctx));
        _ = meta;
        const copy = self.gpa.dupe(u8, packet) catch return error.Abort;
        self.packets.append(self.gpa, copy) catch {
            self.gpa.free(copy);
            return error.Abort;
        };
    }

    fn deinit(self: *Pcap) void {
        for (self.packets.items) |p| self.gpa.free(p);
        self.packets.deinit(self.gpa);
    }

    fn len(self: *const Pcap) usize {
        return self.packets.items.len;
    }

    fn at(self: *const Pcap, i: usize) []const u8 {
        return self.packets.items[i];
    }
};

/// Build a deterministic Ethernet frame of `len` octets.
fn makeFrame(gpa: std.mem.Allocator, len: usize) ![]u8 {
    const frame = try gpa.alloc(u8, len);
    errdefer gpa.free(frame);
    ethernet.writeHeader(frame, .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, .{ 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb }, ethernet.ether_type_ipv4) catch unreachable;
    for (frame[ethernet.header_len..], 0..) |*b, i| b.* = @truncate(i *% 251 +% 17);
    return frame;
}

const Harness = struct {
    gpa: std.mem.Allocator,
    clock: TestClock = .{},
    tun: *Tunnel,
    tx_scratch: []u8,
    rx_scratch: []u8,
    frame_scratch: []u8,

    fn init(gpa: std.mem.Allocator, cfg: config.Config) !*Harness {
        const h = try gpa.create(Harness);
        errdefer gpa.destroy(h);
        const tx = try gpa.alloc(u8, cfg.maxOuterPacketSize());
        errdefer gpa.free(tx);
        const rx = try gpa.alloc(u8, ipv6.max_payload_len + ipv6.header_len);
        errdefer gpa.free(rx);
        const fs = try gpa.alloc(u8, cfg.overlay_mtu);
        errdefer gpa.free(fs);
        h.clock = .{};
        h.tun = try gpa.create(Tunnel);
        errdefer gpa.destroy(h.tun);
        h.tun.* = try Tunnel.init(.{
            .config = cfg,
            .gpa = gpa,
            .tx_scratch = tx,
            .rx_scratch = rx,
            .clock = h.clock.clock(),
            // A fixed seed keeps fragment Identifications reproducible inside a test binary.
            .fragment_id_seed = 0x0123_4567_89AB_CDEF,
        });
        h.* = .{
            .gpa = gpa,
            .tun = h.tun,
            .tx_scratch = tx,
            .rx_scratch = rx,
            .frame_scratch = fs,
        };
        return h;
    }

    fn deinit(self: *Harness) void {
        self.tun.deinit();
        const gpa = self.gpa;
        gpa.destroy(self.tun);
        gpa.free(self.tx_scratch);
        gpa.free(self.rx_scratch);
        gpa.free(self.frame_scratch);
        gpa.destroy(self);
    }
};

/// Configuration for one end of the tunnel.
fn stdConfig() config.Config {
    return .{
        .local_ipv6 = local_addr,
        .remote_ipv6 = remote_addr,
        .underlay_mtu = 1500,
        .overlay_mtu = 9000,
        .max_reassembly_packets = 64,
        .max_reassembly_bytes = 4 * 1024 * 1024,
    };
}

/// The far end of the tunnel: same MTUs, addresses swapped. Two endpoints of one tunnel always see
/// each other's addresses as (remote, local).
fn mirrorConfig() config.Config {
    var c = stdConfig();
    c.local_ipv6 = remote_addr;
    c.remote_ipv6 = local_addr;
    return c;
}

test "tunnel: 9000-octet overlay frame over a 1500-octet underlay round trips byte for byte" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    const frame = try makeFrame(gpa, 9000);
    defer gpa.free(frame);

    var pcap = Pcap{ .gpa = gpa };
    defer pcap.deinit();

    var etherip_buf: [9002]u8 = undefined;
    const outcome = try h.tun.encapsulate(frame, &etherip_buf, .{ .context = &pcap, .emit = Pcap.sink });
    try t.expect(outcome == .fragmented);

    // Every emitted packet fits the path MTU and the total is the whole datagram.
    var total: usize = 0;
    for (pcap.packets.items, 0..) |pkt, i| {
        try t.expect(pkt.len <= cfg.underlay_mtu);
        total += pkt.len;
        _ = i;
    }
    // 7 fragments of a 9002-octet EtherIP datagram.
    try t.expectEqual(@as(usize, 7), pcap.len());
    try t.expect(total > 9000);

    // Feed every fragment to the far-end tunnel and reassemble.
    var h2 = try Harness.init(gpa, mirrorConfig());
    defer h2.deinit();
    var delivered: usize = 0;
    for (pcap.packets.items) |pkt| {
        const out = try h2.tun.receivePacket(pkt, h2.frame_scratch, 0);
        if (out == .frame) delivered += 1;
    }
    try t.expectEqual(@as(usize, 1), delivered);
    try t.expectEqual(@as(usize, 9000), h2.tun.last_frame_len);
    try t.expectEqualSlices(u8, frame, h2.frame_scratch[0..9000]);

    const snap = h2.tun.snapshot();
    try t.expectEqual(@as(u64, 7), snap.counters.rx_fragments);
    try t.expectEqual(@as(u64, 1), snap.counters.reassembly_success);
    try t.expectEqual(@as(u64, 0), snap.counters.malformed_packets);
}

test "tunnel: an unfragmented EtherIP packet has Next Header 97 and no Fragment header" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    const frame = try makeFrame(gpa, 60);
    defer gpa.free(frame);

    var pcap = Pcap{ .gpa = gpa };
    defer pcap.deinit();
    var etherip_buf: [9002]u8 = undefined;
    try t.expectEqual(SendOutcome.single, try h.tun.encapsulate(frame, &etherip_buf, .{ .context = &pcap, .emit = Pcap.sink }));
    try t.expectEqual(@as(usize, 1), pcap.len());

    const pkt = pcap.at(0);
    try t.expectEqual(@as(usize, 60 + 2 + 40), pkt.len);
    const header = try ipv6.parseHeader(pkt);
    try t.expectEqual(etherip.ip_protocol_number, header.next_header);
    try t.expectEqual(@as(u16, 62), header.payload_length);
    // Version 3, Reserved 0 (RFC 3378 Section 3 step 1).
    try t.expectEqual(@as(u8, 0x30), pkt[40]);
    try t.expectEqual(@as(u8, 0x00), pkt[41]);
    // The frame is preserved verbatim.
    try t.expectEqualSlices(u8, frame, pkt[42..]);
}

test "tunnel: a frame larger than overlay_mtu is refused" {
    const gpa = t.allocator;
    var cfg = stdConfig();
    cfg.overlay_mtu = 1500;
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    const frame = try makeFrame(gpa, 1501);
    defer gpa.free(frame);

    var pcap = Pcap{ .gpa = gpa };
    defer pcap.deinit();
    var buf: [4096]u8 = undefined;
    try t.expectEqual(
        SendOutcome.frameTooLarge,
        try h.tun.encapsulate(frame, &buf, .{ .context = &pcap, .emit = Pcap.sink }),
    );
    try t.expectEqual(@as(usize, 0), pcap.len());
}

test "tunnel: ICMPv6 Packet Too Big lowers the effective path MTU (RFC 8201)" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();
    try t.expectEqual(@as(usize, 1500), h.tun.effectivePathMtu());

    // RFC 8201 Section 4: a PTB is only believed when it corresponds to traffic we actually sent.
    // Send something first so the PTB below has something to refer to.
    {
        const fr = try makeFrame(gpa, 9000);
        defer gpa.free(fr);
        var pcap = Pcap{ .gpa = gpa };
        defer pcap.deinit();
        var buf: [9002]u8 = undefined;
        _ = try h.tun.encapsulate(fr, &buf, .{ .context = &pcap, .emit = Pcap.sink });
    }

    // RFC 4443 Section 3.2: the PTB comes from the router that could not forward, not from the
    // EtherIP peer, and quotes a packet sourced from this endpoint.
    const router = ipv6.Address.parse("2001:db8:ffff::1") catch unreachable;
    var body: [256]u8 = undefined;
    const n = buildPacketTooBig(&body, router, local_addr, 1400, local_addr);

    try t.expect(n > ipv6.header_len);
    @memcpy(h.rx_scratch[0..n], body[0..n]);
    const out = try h.tun.receivePacket(h.rx_scratch[0..n], h.frame_scratch, 0);
    try t.expectEqual(@as(usize, 1400), out.pathMtuUpdated);
    try t.expectEqual(@as(usize, 1400), h.tun.effectivePathMtu());
    try t.expectEqual(@as(u64, 1), h.tun.snapshot().counters.pmtu_updates);
}

test "tunnel: a Packet Too Big with no matching transmitted packet is ignored (RFC 8201 Section 4)" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();
    try t.expectEqual(@as(usize, 1500), h.tun.effectivePathMtu());

    // Nothing has been sent, so any PTB is unsolicited even though its quote is well-formed.
    const router = ipv6.Address.parse("2001:db8:ffff::1") catch unreachable;
    var body: [256]u8 = undefined;
    const n = buildPacketTooBig(&body, router, local_addr, 1280, local_addr);
    @memcpy(h.rx_scratch[0..n], body[0..n]);

    try t.expectEqual(ReceiveOutcome.ignored, try h.tun.receivePacket(h.rx_scratch[0..n], h.frame_scratch, 0));
    // RFC 8201 Section 4: only reduce in response to a PTB for traffic we sent.
    try t.expectEqual(@as(usize, 1500), h.tun.effectivePathMtu());
    try t.expectEqual(@as(u64, 0), h.tun.snapshot().counters.pmtu_updates);
    try t.expectEqual(@as(u64, 1), h.tun.snapshot().counters.unmatched_packet_too_big);
}

test "tunnel: an ICMPv6 error is never originated for a non-unicast source (RFC 4443 2.4 (e.6))" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    // Use RFC 8200 Section 4.5 error condition 2, which does require an ICMPv6 Parameter Problem
    // Code 0: an M = 1 fragment whose length is not a multiple of 8 octets.
    var pkt: [64]u8 = undefined;
    const writeBadFragment = struct {
        fn f(out: []u8, source: ipv6.Address, dst: ipv6.Address) !void {
            try ipv6.writeHeader(out[0..40], ipv6.next_header_fragment, 8 + 15, .{
                .source = source,
                .destination = dst,
            });
            const fh = out[40..48];
            fh[0] = etherip.ip_protocol_number;
            fh[1] = 0;
            std.mem.writeInt(u16, fh[2..4], 0x0001, .big); // M = 1, 15 octets
            std.mem.writeInt(u32, fh[4..8], 7, .big);
            @memset(out[48..63], 0xEE);
        }
    }.f;

    // The unspecified address (RFC 4291 Section 2.2) does not identify a node.
    try writeBadFragment(&pkt, ipv6.Address.any, local_addr);
    _ = try h.tun.receivePacket(&pkt, h.frame_scratch, 0);
    try t.expectEqual(@as(usize, 0), h.tun.queuedIcmpCount());

    // A multicast source (RFC 4291 Section 2.7) does not either.
    try writeBadFragment(&pkt, ipv6.Address.parse("ff02::1") catch unreachable, local_addr);
    _ = try h.tun.receivePacket(&pkt, h.frame_scratch, 0);
    try t.expectEqual(@as(usize, 0), h.tun.queuedIcmpCount());

    // A unicast source does, proving the guard is the only thing that suppressed the replies.
    try writeBadFragment(&pkt, ipv6.Address.parse("2001:db8:200::9") catch unreachable, local_addr);
    _ = try h.tun.receivePacket(&pkt, h.frame_scratch, 0);
    try t.expectEqual(@as(usize, 1), h.tun.queuedIcmpCount());
}

test "takeIcmp copies into the caller's buffer, never a stack frame" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    // Force an ICMPv6 Parameter Problem Code 0 with a unicast source.
    var pkt: [128]u8 = undefined;
    const src = try ipv6.Address.parse("2001:db8:200::9");
    try ipv6.writeHeader(pkt[0..40], ipv6.next_header_fragment, 8 + 15, .{
        .source = src,
        .destination = local_addr,
    });
    const fh = pkt[40..48];
    fh[0] = etherip.ip_protocol_number;
    fh[1] = 0;
    std.mem.writeInt(u16, fh[2..4], 0x0001, .big); // M = 1, 15 octets -> not a multiple of 8
    std.mem.writeInt(u32, fh[4..8], 7, .big);

    const out = try h.tun.receivePacket(&pkt, h.frame_scratch, 0);
    try t.expect(out == .rejected);
    try t.expectEqual(@as(usize, 1), h.tun.queuedIcmpCount());

    var outgoing: icmpv6.Outgoing = .{};
    try t.expect(h.tun.takeIcmp(&outgoing));
    try t.expect(src.eql(outgoing.destination));
    // The message is a Parameter Problem Code 0 pointing at the Payload Length field, with a
    // correct checksum over the full quoted packet.
    try t.expectEqual(icmpv6.type_parameter_problem, outgoing.message()[0]);
    try t.expectEqual(icmpv6.code_erroneous_header_field, outgoing.message()[1]);
    try t.expectEqual(
        icmpv6.pointer_payload_length,
        std.mem.readInt(u32, outgoing.message()[4..8], .big),
    );
    try t.expect(icmpv6.checksumValid(outgoing.message(), local_addr, src));
    // RFC 4443 Section 2.4 (c): quote as much as fits, i.e. far more than the 40-octet header.
    try t.expect(outgoing.message().len > ipv6.header_len + 8);
    try t.expect(!h.tun.takeIcmp(&outgoing));
}

/// Build an ICMPv6 Packet Too Big (RFC 4443 Section 3.2) around a quoted IPv6 packet.
///
/// `router` is the source address of the ICMPv6 message: RFC 4443 Section 3.2 makes that the node
/// that could not forward the packet, i.e. an on-path **router**, never the EtherIP peer. `quoted`
/// is the source address of the offending packet, which for us is our own tunnel address.
///
/// Both halves carry correct checksums: the ICMPv6 one over the pseudo-header of the outer packet
/// (RFC 4443 Section 2.1, RFC 8200 Section 8.1), and a syntactically valid quoted IPv6 header.
fn buildPacketTooBig(
    out: []u8,
    router: ipv6.Address,
    dst: ipv6.Address,
    mtu: u32,
    quoted: ipv6.Address,
) usize {
    // The offending packet: a bare IPv6 header with a Fragment header, so the quote shows the shape
    // this tunnel actually emits (RFC 8200 Section 4.5).
    var quote: [64]u8 = undefined;
    ipv6.writeHeader(quote[0..40], ipv6.next_header_fragment, 8, .{
        .source = quoted,
        .destination = dst,
    }) catch unreachable;
    const fh = quote[40..48];
    fh[0] = etherip.ip_protocol_number;
    fh[1] = 0;
    std.mem.writeInt(u16, fh[2..4], 0x0000, .big); // offset 0, M = 0
    std.mem.writeInt(u32, fh[4..8], 0, .big);

    const body_len = icmpv6.error_header_len + quote.len;
    const total = ipv6.header_len + body_len;
    out[ipv6.header_len] = icmpv6.type_packet_too_big;
    out[ipv6.header_len + 1] = 0; // Code: set to 0 by the originator, ignored by the receiver.
    std.mem.writeInt(u16, out[ipv6.header_len + 2 ..][0..2], 0, .big); // Checksum, filled in below.
    std.mem.writeInt(u32, out[ipv6.header_len + 4 ..][0..4], mtu, .big);
    @memcpy(out[ipv6.header_len + icmpv6.error_header_len ..][0..quote.len], &quote);

    ipv6.writeHeader(out[0..ipv6.header_len], ipv6.next_header_icmpv6, body_len, .{
        .source = router,
        .destination = dst,
    }) catch unreachable;

    // RFC 8200 Section 8.1: the pseudo-header's Upper-Layer Packet Length is the length of the
    // ICMPv6 message, i.e. everything after the IPv6 header.
    const sum = checksum.accumulatePseudoHeader(
        0,
        .ipv6,
        &router.bytes(),
        &dst.bytes(),
        ipv6.next_header_icmpv6,
        body_len,
    ) catch unreachable;
    // The ICMPv6 checksum covers the pseudo-header plus the ICMPv6 message only, i.e. everything
    // after the IPv6 header (RFC 4443 Section 2.1).
    const c: u16 = @truncate(~checksum.fold(checksum.accumulate(sum, out[ipv6.header_len..total])));
    std.mem.writeInt(u16, out[ipv6.header_len + 2 ..][0..2], if (c == 0) 0xffff else c, .big);
    return total;
}


test "tunnel: unknown EtherIP Version is discarded, never reinterpreted (RFC 3378 Section 4)" {
    const gpa = t.allocator;
    var cfg = stdConfig();
    cfg.overlay_mtu = 1500;
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    var pkt: [64]u8 = undefined;
    const frame = try makeFrame(gpa, 22);
    defer gpa.free(frame);

    for (0..16) |v| {
        try ipv6.writeHeader(pkt[0..40], etherip.ip_protocol_number, 24, .{
            .source = remote_addr,
            .destination = local_addr,
        });
        @memcpy(pkt[40 + 2 ..][0..22], frame);
        pkt[40] = @as(u8, @intCast(v)) << 4;
        pkt[41] = 0;
        const out = try h.tun.receivePacket(&pkt, h.frame_scratch, 0);
        if (v == 3) {
            try t.expect(out == .frame);
        } else {
            try t.expect(out == .rejected);
        }
    }
    try t.expectEqual(@as(u64, 15), h.tun.snapshot().counters.malformed_packets);
}

test "tunnel: non-zero Reserved is discarded (RFC 3378 Section 4)" {
    const gpa = t.allocator;
    var cfg = stdConfig();
    cfg.overlay_mtu = 1500;
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    var pkt: [64]u8 = undefined;
    const frame = try makeFrame(gpa, 22);
    defer gpa.free(frame);
    try ipv6.writeHeader(pkt[0..40], etherip.ip_protocol_number, 24, .{
        .source = remote_addr,
        .destination = local_addr,
    });
    @memcpy(pkt[40 + 2 ..][0..22], frame);
    pkt[40] = 0x30;
    pkt[41] = 0x01;
    const out = try h.tun.receivePacket(&pkt, h.frame_scratch, 0);
    try t.expect(out == .rejected);
}

test "tunnel: packets for another destination are ignored" {
    const gpa = t.allocator;
    var cfg = stdConfig();
    cfg.overlay_mtu = 1500;
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    var pkt: [64]u8 = undefined;
    try ipv6.writeHeader(pkt[0..40], etherip.ip_protocol_number, 2, .{
        .source = remote_addr,
        .destination = ipv6.Address.parse("2001:db8:dead::1") catch unreachable,
    });
    pkt[40] = 0x30;
    pkt[41] = 0;
    try t.expectEqual(ReceiveOutcome.ignored, try h.tun.receivePacket(&pkt, h.frame_scratch, 0));
}

test "tunnel: fragmented reassembly with out-of-order and duplicate fragments" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    const frame = try makeFrame(gpa, 4000);
    defer gpa.free(frame);

    var pcap = Pcap{ .gpa = gpa };
    defer pcap.deinit();
    var etherip_buf: [9002]u8 = undefined;
    _ = try h.tun.encapsulate(frame, &etherip_buf, .{ .context = &pcap, .emit = Pcap.sink });
    try t.expect(pcap.len() > 2);

    var h2 = try Harness.init(gpa, mirrorConfig());
    defer h2.deinit();

    // Reverse order: the last fragment arrives first.
    var i = pcap.len();
    var delivered: usize = 0;
    while (i > 0) {
        i -= 1;
        const out = try h2.tun.receivePacket(pcap.at(i), h2.frame_scratch, 0);
        if (out == .frame) delivered += 1;
    }
    try t.expectEqual(@as(usize, 1), delivered);
    try t.expectEqualSlices(u8, frame, h2.frame_scratch[0..frame.len]);
}

test "tunnel: reassembly timeout is enforced" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    const frame = try makeFrame(gpa, 4000);
    defer gpa.free(frame);
    var pcap = Pcap{ .gpa = gpa };
    defer pcap.deinit();
    var etherip_buf: [9002]u8 = undefined;
    _ = try h.tun.encapsulate(frame, &etherip_buf, .{ .context = &pcap, .emit = Pcap.sink });

    var h2 = try Harness.init(gpa, mirrorConfig());
    defer h2.deinit();

    // Deliver everything except the last fragment.
    const n = pcap.len();
    for (pcap.packets.items[0 .. n - 1]) |pkt| {
        _ = try h2.tun.receivePacket(pkt, h2.frame_scratch, 0);
    }
    try t.expectEqual(@as(usize, 1), h2.tun.snapshot().reassembly.in_flight_packets);
    // RFC 8200 Section 4.5: abandonment within 60 seconds of the first-arriving fragment.
    try t.expectEqual(@as(usize, 0), h2.tun.expireReassemblies(59_999));
    try t.expectEqual(@as(usize, 1), h2.tun.expireReassemblies(60_000));
    try t.expectEqual(@as(u64, 1), h2.tun.snapshot().counters.reassembly_timeout);

    // The abandoned datagram never completes: the stray last fragment opens a fresh, incomplete
    // context that can never be finished (its siblings were discarded) and is itself reclaimed by
    // the timeout. This is the bounded, self-healing behaviour the design intends.
    const out = try h2.tun.receivePacket(pcap.at(n - 1), h2.frame_scratch, 60_001);
    try t.expect(out != .frame);
    try t.expectEqual(@as(usize, 1), h2.tun.snapshot().reassembly.in_flight_packets);
    try t.expectEqual(@as(usize, 1), h2.tun.expireReassemblies(120_001));
    try t.expectEqual(@as(usize, 0), h2.tun.snapshot().reassembly.in_flight_packets);
}


test "tunnel: RFC 8200 Section 4.5 error condition 4 -- an offset-zero fragment too short for the upper-layer header" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    // One octet of fragment data cannot hold the 2-octet EtherIP header, which is the
    // upper-layer header, so RFC 8200 Section 4.5 error condition 4 applies.
    var pkt: [64]u8 = undefined;
    try ipv6.writeHeader(pkt[0..40], ipv6.next_header_fragment, 8 + 1, .{
        .source = remote_addr,
        .destination = local_addr,
    });
    const fh = pkt[40..48];
    fh[0] = etherip.ip_protocol_number;
    fh[1] = 0;
    std.mem.writeInt(u16, fh[2..4], 0x0000, .big); // offset 0, M = 0: atomic
    std.mem.writeInt(u32, fh[4..8], 3, .big);
    pkt[48] = 0x30;

    const out = try h.tun.receivePacket(&pkt, h.frame_scratch, 0);
    try t.expect(out == .rejected);
    try t.expectEqual(@as(usize, 1), h.tun.queuedIcmpCount());

    // RFC 8200 Section 4.5 error condition 4: Parameter Problem Code 3 with Pointer 0.
    var outgoing: icmpv6.Outgoing = .{};
    try t.expect(h.tun.takeIcmp(&outgoing));
    try t.expectEqual(icmpv6.type_parameter_problem, outgoing.message()[0]);
    try t.expectEqual(icmpv6.code_ipv6_header_error, outgoing.message()[1]);
    try t.expectEqual(@as(u32, 0), std.mem.readInt(u32, outgoing.message()[4..8], .big));
    try t.expect(icmpv6.checksumValid(outgoing.message(), local_addr, remote_addr));
}

test "tunnel: RFC 8200 Section 4.5 error condition 1 -- an ICMPv6 Time Exceeded on reassembly timeout" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();
    var b = try Harness.init(gpa, mirrorConfig());
    defer b.deinit();

    const fr = try makeFrame(gpa, 4000);
    defer gpa.free(fr);
    var pcap = Pcap{ .gpa = gpa };
    defer pcap.deinit();
    var buf: [9002]u8 = undefined;
    _ = try h.tun.encapsulate(fr, &buf, .{ .context = &pcap, .emit = Pcap.sink });

    // Deliver only the first fragment, so the context has the offset-zero fragment.
    _ = try b.tun.receivePacket(pcap.at(0), b.frame_scratch, 0);
    try t.expectEqual(@as(usize, 1), b.tun.snapshot().reassembly.in_flight_packets);
    try t.expectEqual(@as(usize, 0), b.tun.queuedIcmpCount());

    try t.expectEqual(@as(usize, 1), b.tun.expireReassemblies(60_000));

    // RFC 8200 Section 4.5 error condition 1: "If the first fragment ... has been received, an ICMP
    // Time Exceeded -- Fragment Reassembly Time Exceeded message should be sent to the source of
    // that fragment."
    try t.expectEqual(@as(usize, 1), b.tun.queuedIcmpCount());
    var outgoing: icmpv6.Outgoing = .{};
    try t.expect(b.tun.takeIcmp(&outgoing));
    // RFC 4443 Section 3.3: the destination is the Source Address field of the invoking packet,
    // which is endpoint A's tunnel address.
    try t.expect(local_addr.eql(outgoing.destination));
    try t.expectEqual(icmpv6.type_time_exceeded, outgoing.message()[0]);
    try t.expectEqual(icmpv6.code_fragment_reassembly_time_exceeded, outgoing.message()[1]);
    try t.expect(icmpv6.checksumValid(outgoing.message(), remote_addr, local_addr));
    try t.expectEqual(@as(u64, 1), b.tun.snapshot().counters.icmp_errors_sent);
}

test "tunnel: a timeout with no offset-zero fragment originates no ICMPv6" {
    const gpa = t.allocator;
    var b = try Harness.init(gpa, mirrorConfig());
    defer b.deinit();

    // A fragment with a non-zero offset and M = 1: no offset-zero fragment, so RFC 8200 Section 4.5
    // error condition 1's ICMPv6 has nothing meaningful to refer to.
    var pkt: [64]u8 = undefined;
    try ipv6.writeHeader(pkt[0..40], ipv6.next_header_fragment, 8 + 8, .{
        .source = local_addr,
        .destination = remote_addr,
    });
    const fh = pkt[40..48];
    fh[0] = etherip.ip_protocol_number;
    fh[1] = 0;
    std.mem.writeInt(u16, fh[2..4], (1 << 3) | 1, .big); // offset 1 (8 octets in), M = 1
    std.mem.writeInt(u32, fh[4..8], 3, .big);

    const out = try b.tun.receivePacket(&pkt, b.frame_scratch, 0);
    try t.expectEqual(ReceiveOutcome.fragmentBuffered, out);
    try t.expectEqual(@as(usize, 1), b.tun.snapshot().reassembly.in_flight_packets);
    try t.expectEqual(@as(usize, 1), b.tun.expireReassemblies(60_000));
    try t.expectEqual(@as(usize, 0), b.tun.queuedIcmpCount());
}

test "tunnel: a malformed extension-header chain produces the right ICMPv6 code and Pointer" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    // A Destination Options header that overruns the payload: an erroneous header field, not an
    // unrecognised Next Header, so RFC 4443 Section 3.4 Code 0 with Pointer 40.
    var pkt: [128]u8 = undefined;
    try ipv6.writeHeader(pkt[0..40], ipv6.next_header_destination_options, 8, .{
        .source = remote_addr,
        .destination = local_addr,
    });
    pkt[40] = etherip.ip_protocol_number;
    pkt[41] = 255; // Hdr Ext Len 255 => 2048 octets, far more than the 8 available

    const out = try h.tun.receivePacket(&pkt, h.frame_scratch, 0);
    try t.expect(out == .rejected);
    var outgoing: icmpv6.Outgoing = .{};
    try t.expect(h.tun.takeIcmp(&outgoing));
    try t.expectEqual(icmpv6.type_parameter_problem, outgoing.message()[0]);
    try t.expectEqual(icmpv6.code_erroneous_header_field, outgoing.message()[1]);
    try t.expectEqual(@as(u32, 40), std.mem.readInt(u32, outgoing.message()[4..8], .big));
}

test "tunnel: an upper-layer protocol that is not EtherIP is ignored without ICMPv6" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var h = try Harness.init(gpa, cfg);
    defer h.deinit();

    // Next Header 253 is unassigned, is not an extension header, so the chain walk stops cleanly with
    // 253 as the upper-layer protocol.
    var pkt: [64]u8 = undefined;
    try ipv6.writeHeader(pkt[0..40], 253, 2, .{
        .source = remote_addr,
        .destination = local_addr,
    });
    _ = try h.tun.receivePacket(&pkt, h.frame_scratch, 0);

    // 253 is not EtherIP, so the packet is simply not ours and no error is generated. This is the
    // RFC 4443 Section 2.4 (d) path: the upper-layer protocol is recognised as "not mine".
    try t.expectEqual(@as(usize, 0), h.tun.queuedIcmpCount());
}


test "tunnel: the reassembly-timeout ICMPv6 quotes a correlatable Fragment header" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var b = try Harness.init(gpa, mirrorConfig());
    defer b.deinit();

    // Deliver the offset-zero fragment of a 3-fragment datagram, then let it time out.
    const fr = try makeFrame(gpa, 4000);
    defer gpa.free(fr);
    var a = try Harness.init(gpa, cfg);
    defer a.deinit();
    var pcap = Pcap{ .gpa = gpa };
    defer pcap.deinit();
    var buf: [9002]u8 = undefined;
    _ = try a.tun.encapsulate(fr, &buf, .{ .context = &pcap, .emit = Pcap.sink });

    _ = try b.tun.receivePacket(pcap.at(0), b.frame_scratch, 0);
    try t.expectEqual(@as(usize, 1), b.tun.expireReassemblies(60_000));

    var outgoing: icmpv6.Outgoing = .{};
    try t.expect(b.tun.takeIcmp(&outgoing));
    try t.expectEqual(icmpv6.type_time_exceeded, outgoing.message()[0]);
    try t.expect(icmpv6.checksumValid(outgoing.message(), b.tun.cfg.local_ipv6, b.tun.cfg.remote_ipv6));

    // The quote must contain an IPv6 header plus a Fragment header naming the datagram's
    // Identification, so the peer can correlate it (RFC 8200 Section 4.5, RFC 4443 Section 2.4 (c)).
    const quote = outgoing.message()[icmpv6.error_header_len..];
    // 40 octets of IPv6 header + 8 octets of Fragment header.
    try t.expectEqual(@as(usize, ipv6.header_len + fragment.fragment_header_len), quote.len);
    try t.expectEqual(@as(u4, 6), quote[0] >> 4);
    try t.expectEqual(ipv6.next_header_fragment, quote[6]);
    // The quoted Payload Length covers the Fragment header: the reassembled length is unknown.
    try t.expectEqual(@as(u16, fragment.fragment_header_len), std.mem.readInt(u16, quote[4..6], .big));
    // The Fragment header's Next Header names the EtherIP header, and Res is zero.
    try t.expectEqual(etherip.ip_protocol_number, quote[ipv6.header_len]);
    try t.expectEqual(@as(u8, 0), quote[ipv6.header_len + 1]);
    try t.expectEqual(@as(u16, 0), std.mem.readInt(u16, quote[ipv6.header_len + 2 ..][0..2], .big));

    const id: u32 = std.mem.readInt(u32, quote[ipv6.header_len + 4 ..][0..4], .big);
    // It must be the Identification of the datagram that was abandoned.
    const h = try ipv6.parseHeader(pcap.at(0));
    const c = try ipv6.parseExtensionChain(h);
    try t.expectEqual(c.fragment.?.identification, id);
}

test "tunnel: receivePacket itself enforces the reassembly timeout, so no message is lost" {
    const gpa = t.allocator;
    const cfg = stdConfig();
    var a = try Harness.init(gpa, cfg);
    defer a.deinit();
    var b = try Harness.init(gpa, mirrorConfig());
    defer b.deinit();

    const fr = try makeFrame(gpa, 4000);
    defer gpa.free(fr);
    var pcap = Pcap{ .gpa = gpa };
    defer pcap.deinit();
    var buf: [9002]u8 = undefined;
    _ = try a.tun.encapsulate(fr, &buf, .{ .context = &pcap, .emit = Pcap.sink });

    _ = try b.tun.receivePacket(pcap.at(0), b.frame_scratch, 0);
    try t.expectEqual(@as(usize, 1), b.tun.snapshot().reassembly.in_flight_packets);
    try t.expectEqual(@as(usize, 0), b.tun.queuedIcmpCount());

    // The sweep happens inside receivePacket, so delivering *anything* later is enough to reap the
    // stale context and queue the Time Exceeded -- no separate expireReassemblies call needed. The
    // context created by fragment 2 is a fresh one (its siblings were discarded), which is exactly
    // the bounded, self-healing behaviour the design intends.
    _ = try b.tun.receivePacket(pcap.at(1), b.frame_scratch, 60_000);
    try t.expectEqual(@as(usize, 1), b.tun.queuedIcmpCount());
    try t.expectEqual(@as(u64, 1), b.tun.snapshot().counters.reassembly_timeout);
}
