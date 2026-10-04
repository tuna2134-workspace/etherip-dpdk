//! `etherip-dpdk` — command-line front end for the EtherIP-over-IPv6 library.
//!
//! Subcommands:
//!
//!   * `selftest`      — run an end-to-end check entirely in memory: a 9000-octet Ethernet frame
//!                        encapsulated, fragmented to a 1500-octet underlay, transmitted, and
//!                        reassembled, then compared byte for byte. Needs no privileges.
//!   * `config-check`  — validate a configuration file (or the built-in example) and print the
//!                        derived MTU arithmetic.
//!   * `inspect`       — decode an IPv6/EtherIP packet from a hex dump on stdin and print its
//!                        structure, so a capture can be diagnosed without Wireshark.
//!   * `emit-sample`   — write a `pcap` file containing a full EtherIP conversation for a
//!                        9000-octet overlay frame over a 1500-octet underlay, ready to open in
//!                        Wireshark or tcpdump.
//!   * `stats`         — print the statistics schema and an example rendering.
//!
//! Nothing here requires `CAP_NET_RAW`; a deployment daemon that binds a raw socket is out of
//! scope and deliberately separated in `platform.zig`.

const std = @import("std");
const Io = std.Io;

const lib = @import("etherip_dpdk");

const config = lib.config;
const etherip = lib.etherip;
const ethernet = lib.ethernet;
const fragment = lib.fragment;
const ipv6 = lib.ipv6;
const icmpv6 = lib.icmpv6;
const overlay = lib.overlay;
const stats = lib.stats;
const tunnel = lib.tunnel;

const log = std.log.scoped(.etherip_cli);

/// Runtime log level, set from `--log-level`. `std.options` is a compile-time constant, so
/// controlling the level at run time requires supplying our own `logFn`.
var runtime_log_level: std.log.Level = .warn;

/// Format one log line to stderr. Deliberately simple: the packet path logs at `debug` and only,
/// so per-packet logging is off by default.
fn logFn(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    // `std_options.log_level` is `.debug` so that nothing is lost before this gate; the effective
    // level is chosen at run time from `--log-level`.
    if (@intFromEnum(message_level) > @intFromEnum(runtime_log_level)) return;
    std.log.defaultLog(message_level, scope, format, args);
}

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = logFn,
};

const usage =
    \\etherip-dpdk — RFC 3378 EtherIP tunnel over IPv6 (library CLI)
    \\
    \\USAGE
    \\  etherip-dpdk <command> [options]
    \\
    \\COMMANDS
    \\  selftest       Fragment and reassemble a 9000-octet frame in memory; needs no privileges.
    \\  config-check   Validate a configuration and print the derived MTU arithmetic.
    \\  inspect        Decode an IPv6/EtherIP packet from a hex dump read on stdin.
    \\  emit-sample    Write a pcap file of a full 9000-over-1500 conversation.
    \\  stats          Print the statistics schema.
    \\
    \\OPTIONS
    \\  --local <IPv6>       Tunnel source address.        Default 2001:db8:100::1
    \\  --remote <IPv6>      Tunnel destination address.   Default 2001:db8:200::1
    \\  --underlay-mtu <n>   IPv6 underlay MTU.            Default 1500
    \\  --overlay-mtu <n>    Overlay Ethernet MTU.         Default 9000
    \\  --out <path>         Output file for emit-sample.  Default etherip-sample.pcap
    \\  --log-level <level>  err | warn | info | debug.    Default warn
    \\
    \\NOTES
    \\  RFC 3378 is Informational, not Standards Track, and provides no cryptographic protection.
    \\  See README.md and docs/COMPLIANCE.md.
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    var out_buffer: [16 * 1024]u8 = undefined;
    var out = Io.File.Writer.init(.stdout(), io, &out_buffer);
    const w = &out.interface;
    defer w.flush() catch {};

    var err_buffer: [1024]u8 = undefined;
    var err = Io.File.Writer.init(.stderr(), io, &err_buffer);
    const ew = &err.interface;

    const opts = try Options.parse(arena, args);
    setLogLevel(opts.log_level);

    if (opts.command) |cmd| {
        if (std.mem.eql(u8, cmd, "selftest")) {
            try runSelftest(w, opts);
        } else if (std.mem.eql(u8, cmd, "config-check")) {
            try runConfigCheck(w, opts);
        } else if (std.mem.eql(u8, cmd, "inspect")) {
            try runInspect(w, io);
        } else if (std.mem.eql(u8, cmd, "emit-sample")) {
            try runEmitSample(w, io, opts);
        } else if (std.mem.eql(u8, cmd, "stats")) {
            try runStats(w);
        } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
            try w.writeAll(usage);
        } else {
            try ew.print("unknown command: {s}\n\n", .{cmd});
            try w.writeAll(usage);
            return error.UnknownCommand;
        }
    } else {
        try w.writeAll(usage);
        return error.MissingCommand;
    }
    ew.flush() catch {};
}

fn setLogLevel(name: []const u8) void {
    const lvl: std.log.Level = if (std.mem.eql(u8, name, "debug"))
        .debug
    else if (std.mem.eql(u8, name, "info"))
        .info
    else if (std.mem.eql(u8, name, "err"))
        .err
    else
        .warn;
    runtime_log_level = lvl;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

const Options = struct {
    command: ?[]const u8 = null,
    local: []const u8 = "2001:db8:100::1",
    remote: []const u8 = "2001:db8:200::1",
    underlay_mtu: usize = 1500,
    overlay_mtu: usize = 9000,
    out_path: []const u8 = "etherip-sample.pcap",
    log_level: []const u8 = "warn",

    fn parse(arena: std.mem.Allocator, args: []const []const u8) !Options {
        var opts: Options = .{};
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (std.mem.eql(u8, a, "--local")) {
                i += 1;
                if (i >= args.len) return error.MissingValue;
                opts.local = args[i];
            } else if (std.mem.eql(u8, a, "--remote")) {
                i += 1;
                if (i >= args.len) return error.MissingValue;
                opts.remote = args[i];
            } else if (std.mem.eql(u8, a, "--underlay-mtu")) {
                i += 1;
                if (i >= args.len) return error.MissingValue;
                opts.underlay_mtu = try parseMtu(args[i]);
            } else if (std.mem.eql(u8, a, "--overlay-mtu")) {
                i += 1;
                if (i >= args.len) return error.MissingValue;
                opts.overlay_mtu = try parseMtu(args[i]);
            } else if (std.mem.eql(u8, a, "--out")) {
                i += 1;
                if (i >= args.len) return error.MissingValue;
                opts.out_path = args[i];
            } else if (std.mem.eql(u8, a, "--log-level")) {
                i += 1;
                if (i >= args.len) return error.MissingValue;
                opts.log_level = args[i];
            } else if (std.mem.startsWith(u8, a, "-")) {
                // Unknown flags are ignored so the library CLI stays forgiving; a daemon would
                // reject them.
                continue;
            } else if (opts.command == null) {
                opts.command = a;
            }
        }
        _ = arena;
        return opts;
    }

    fn parseMtu(text: []const u8) !usize {
        return std.fmt.parseInt(usize, text, 10) catch error.InvalidMtu;
    }

    fn buildConfig(self: Options) !config.Config {
        return .{
            .local_ipv6 = try ipv6.Address.parse(self.local),
            .remote_ipv6 = try ipv6.Address.parse(self.remote),
            .underlay_mtu = self.underlay_mtu,
            .overlay_mtu = self.overlay_mtu,
        };
    }
};

// ---------------------------------------------------------------------------
// selftest
// ---------------------------------------------------------------------------

/// Retains every IPv6 packet an endpoint emits, so the self test can replay them.
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
};

const FakeClock = struct {
    now_ms: i64 = 0,

    fn view(self: *FakeClock) tunnel.Clock {
        return .{ .context = @ptrCast(self), .nowMsFn = nowMsFn };
    }

    fn nowMsFn(ctx: *anyopaque) i64 {
        const self: *FakeClock = @ptrCast(@alignCast(ctx));
        return self.now_ms;
    }
};

fn runSelftest(w: *Io.Writer, opts: Options) !void {
    const gpa = std.heap.page_allocator;
    const cfg = try opts.buildConfig();
    try cfg.validate();

    var clock = FakeClock{};
    var wire = Wire{ .gpa = gpa };
    defer wire.deinit();

    var captured = try overlay.CapturedFrames.init(gpa, 16);
    defer captured.deinit();

    try w.print("EtherIP over IPv6 self test\n", .{});
    try w.print("  local           {f}\n", .{fmtAddr(cfg.local_ipv6)});
    try w.print("  remote          {f}\n", .{fmtAddr(cfg.remote_ipv6)});
    try w.print("  underlay MTU    {d}\n", .{cfg.underlay_mtu});
    try w.print("  overlay MTU     {d}\n", .{cfg.overlay_mtu});
    const max_frag = try fragment.calculateFragmentPayloadSize(cfg.mtuParams());
    try w.print("  tunnel overhead {d} (IPv6 {d} + Fragment {d})\n", .{
        fragment.tunnelOverhead(cfg.mtuParams(), true), ipv6.header_len, fragment.fragment_header_len,
    });
    try w.print("  max frag data   {d}\n", .{max_frag});
    try w.print("  max wire size   {d}\n", .{fragment.tunnelOverhead(cfg.mtuParams(), true) + max_frag});
    try w.print("\n", .{});

    // Endpoint A.
    const tx_a = try gpa.alloc(u8, cfg.maxOuterPacketSize());
    defer gpa.free(tx_a);
    const rx_a = try gpa.alloc(u8, ipv6.max_payload_len + ipv6.header_len);
    defer gpa.free(rx_a);
    var a = try tunnel.Tunnel.init(.{
        .config = cfg,
        .gpa = gpa,
        .tx_scratch = tx_a,
        .rx_scratch = rx_a,
        .clock = clock.view(),
        .fragment_id_seed = 0x5EED_1234_ABCD_0001,
    });
    defer a.deinit();

    // Endpoint B sees the mirrored addresses.
    var mirror = cfg;
    mirror.local_ipv6 = cfg.remote_ipv6;
    mirror.remote_ipv6 = cfg.local_ipv6;
    const tx_b = try gpa.alloc(u8, mirror.maxOuterPacketSize());
    defer gpa.free(tx_b);
    const rx_b = try gpa.alloc(u8, ipv6.max_payload_len + ipv6.header_len);
    defer gpa.free(rx_b);
    var b = try tunnel.Tunnel.init(.{
        .config = mirror,
        .gpa = gpa,
        .tx_scratch = tx_b,
        .rx_scratch = rx_b,
        .clock = clock.view(),
        .fragment_id_seed = 0x5EED_1234_ABCD_0002,
    });
    defer b.deinit();

    // A frame of exactly overlay_mtu octets.
    const frame_len = cfg.overlay_mtu;
    const frame = try gpa.alloc(u8, frame_len);
    defer gpa.free(frame);
    try ethernet.writeHeader(
        frame,
        .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 },
        ethernet.ether_type_ipv6,
    );
    for (frame[ethernet.header_len..], 0..) |*b_byte, i| b_byte.* = @truncate(i *% 251 +% 13);

    // A's overlay interface encapsulates it.
    var etherip_buf: [lib.max_overlay_mtu + etherip.header_len]u8 = undefined;
    const outcome = try a.encapsulate(frame, &etherip_buf, .{ .context = &wire, .emit = Wire.sink });
    try w.print("encapsulated {d}-octet frame -> {s}\n", .{ frame_len, @tagName(outcome) });
    try w.print("  outer packets  {d}\n", .{wire.packets.items.len});

    var largest: usize = 0;
    for (wire.packets.items) |p| largest = @max(largest, p.len);
    try w.print("  largest packet {d} octets (must be <= {d})\n", .{ largest, cfg.underlay_mtu });
    if (largest > cfg.underlay_mtu) return error.UnderlayMtuViolated;

    // B receives every packet exactly once, through the overlay frame sink.
    var frame_out: [lib.max_overlay_mtu]u8 = undefined;
    var delivered: usize = 0;
    for (wire.packets.items) |p| {
        if (overlay.deliver(&b, p, &frame_out, captured.sink(), 0) catch false) delivered += 1;
    }
    try w.print("\nreceived {d} outer packets, decapsulated {d} frame(s)\n", .{ wire.packets.items.len, delivered });
    try w.print("  frame length   {d}\n", .{b.last_frame_len});

    if (delivered != 1 or b.last_frame_len != frame_len) return error.RoundTripFailed;
    if (!std.mem.eql(u8, frame, frame_out[0..frame_len])) return error.RoundTripMismatch;

    try w.print("\nRESULT: reassemble(fragment(frame)) == frame  ({d} octets, byte identical)\n", .{frame_len});

    var buf: [4096]u8 = undefined;
    var sw = Io.Writer.fixed(&buf);
    try a.writeStats(&sw);
    try w.print("\ntransmit-side statistics\n{s}", .{sw.buffered()});
    var buf2: [4096]u8 = undefined;
    var sw2 = Io.Writer.fixed(&buf2);
    try b.writeStats(&sw2);
    try w.print("\nreceive-side statistics\n{s}", .{sw2.buffered()});
}

fn fmtAddr(a: ipv6.Address) AddressFmt {
    return .{ .a = a };
}

const AddressFmt = struct {
    a: ipv6.Address,

    pub fn format(self: AddressFmt, w: *Io.Writer) Io.Writer.Error!void {
        var buf: [48]u8 = undefined;
        const text = self.a.format(&buf) catch return error.WriteFailed;
        try w.writeAll(text);
    }
};

// ---------------------------------------------------------------------------
// config-check
// ---------------------------------------------------------------------------

fn runConfigCheck(w: *Io.Writer, opts: Options) !void {
    const cfg = try opts.buildConfig();
    cfg.validate() catch |e| {
        try w.print("INVALID: {t}\n", .{e});
        return e;
    };

    var local_buf: [48]u8 = undefined;
    var remote_buf: [48]u8 = undefined;
    try w.print("configuration is valid\n", .{});
    try w.print("  local_ipv6                 {s}\n", .{try cfg.local_ipv6.format(&local_buf)});
    try w.print("  remote_ipv6                {s}\n", .{try cfg.remote_ipv6.format(&remote_buf)});
    try w.print("  underlay_mtu               {d}\n", .{cfg.underlay_mtu});
    try w.print("  overlay_mtu                {d}\n", .{cfg.overlay_mtu});
    try w.print("  fragmentation_enabled      {}\n", .{cfg.fragmentation_enabled});
    try w.print("  reassembly_timeout_ms      {d}\n", .{cfg.reassembly_timeout_ms});
    try w.print("  max_reassembly_packets     {d}\n", .{cfg.max_reassembly_packets});
    try w.print("  max_reassembly_bytes       {d}\n", .{cfg.max_reassembly_bytes});
    try w.print("  mss_clamping_enabled       {}\n", .{cfg.mss_clamping_enabled});
    try w.print("  mss_clamp                  ", .{});
    if (cfg.mss_clamp) |m| {
        try w.print("{d}\n", .{m});
    } else {
        try w.print("auto\n", .{});
    }

    const params = cfg.mtuParams();
    const max_frag = try fragment.calculateFragmentPayloadSize(params);
    try w.print("\nderived MTU arithmetic\n", .{});
    try w.print("  IPv6 header                {d}\n", .{params.ipv6_header_len});
    try w.print("  reserved ext header bytes  {d}\n", .{params.per_fragment_ext_len});
    try w.print("  IPv6 Fragment header       {d}\n", .{fragment.fragment_header_len});
    try w.print("  EtherIP header             {d}   (inside the fragmentable part)\n", .{etherip.header_len});
    try w.print("  tunnel overhead            {d}\n", .{fragment.tunnelOverhead(params, true)});
    try w.print("  available                  {d}\n", .{cfg.underlay_mtu - fragment.tunnelOverhead(params, true)});
    try w.print("  max fragment payload       {d}  (floor to 8-octet units)\n", .{max_frag});
    try w.print("  max outer packet           {d}\n", .{cfg.maxOuterPacketSize()});
    try w.print("  max unfragmented datagram  {d}\n", .{cfg.maxUnfragmentedDatagram()});
    try w.print("  max reassembly datagram    {d}\n", .{cfg.maxReassemblyDatagram()});

    const datagram = cfg.overlay_mtu + etherip.header_len;
    const count = (datagram + max_frag - 1) / max_frag;
    try w.print("\n  a {d}-octet frame becomes a {d}-octet EtherIP datagram, i.e. {d} fragment(s)\n", .{
        cfg.overlay_mtu, datagram, count,
    });
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

/// Read all of stdin into a heap buffer. Used only by `inspect`, which is a debugging aid and not
/// on any packet path.
fn readStdin(gpa: std.mem.Allocator, io: Io) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    var scratch: [4096]u8 = undefined;
    var chunk: [4096]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &scratch);
    while (true) {
        const n = try reader.interface.readSliceShort(&chunk);
        if (n == 0) break;
        try buf.appendSlice(gpa, chunk[0..n]);
    }
    return buf.toOwnedSlice(gpa);
}

fn runInspect(w: *Io.Writer, io: Io) !void {
    const gpa = std.heap.page_allocator;
    const text = readStdin(gpa, io) catch |e| {
        try w.print("cannot read stdin: {t}\n", .{e});
        return;
    };
    defer gpa.free(text);

    var packet = try gpa.alloc(u8, lib.max_overlay_mtu + ipv6.header_len);
    defer gpa.free(packet);
    const n = parseHex(text, packet) catch |e| {
        try w.print("cannot parse hex input: {t}\n", .{e});
        try w.writeAll("\nexpected whitespace- or colon-separated hex octets, for example:\n");
        try w.writeAll("  60000000 003c 2c40 40000440 <40 octets of addresses> ...\n");
        try w.writeAll("  (separators are ignored: spaces, colons and newlines all work)\n");
        return;
    };
    try w.print("decoded {d} octet(s)\n\n", .{n});
    if (n == 0) return;

    const cfg = config.Config{
        .local_ipv6 = ipv6.Address.any,
        .remote_ipv6 = ipv6.Address.any,
        .underlay_mtu = 1500,
        .overlay_mtu = 9000,
    };
    inspectPacket(w, cfg, packet[0..n]) catch |e| {
        try w.print("\n(packet rejected: {t})\n", .{e});
    };
}

fn inspectPacket(w: *Io.Writer, cfg: config.Config, bytes: []const u8) !void {
    const header = ipv6.parseHeader(bytes) catch |e| {
        try w.print("malformed IPv6 header: {t}\n", .{e});
        return e;
    };
    var buf: [48]u8 = undefined;
    try w.print("IPv6 header (RFC 8200 Section 3)\n", .{});
    try w.print("  Version          {d}\n", .{header.raw_header[0] >> 4});
    try w.print("  Traffic Class    0x{X:0>2}\n", .{header.traffic_class});
    try w.print("  Flow Label       0x{X}\n", .{header.flow_label});
    try w.print("  Payload Length   {d}\n", .{header.payload_length});
    try w.print("  Next Header      {d}\n", .{header.next_header});
    try w.print("  Hop Limit        {d}\n", .{header.hop_limit});
    try w.print("  Source           {s}\n", .{try header.source.format(&buf)});
    try w.print("  Destination      {s}\n", .{try header.destination.format(&buf)});
    try w.print("  addressed to us  {}\n", .{header.destination.eql(cfg.local_ipv6)});

    const chain = ipv6.parseExtensionChain(header) catch |e| {
        try w.print("extension header chain rejected: {t}\n", .{e});
        return e;
    };
    try w.print("\nextension headers (RFC 8200 Section 4)\n", .{});
    try w.print("  bytes consumed   {d}\n", .{chain.ext_header_bytes});
    try w.print("  upper-layer NH   {d}\n", .{chain.upper_layer_next_header});
    try w.print("  Hop-by-Hop       {}\n", .{chain.saw_hop_by_hop});
    try w.print("  Dest Options     {}\n", .{chain.saw_destination_options});
    try w.print("  AH               {}\n", .{chain.saw_ah});
    try w.print("  ESP              {}\n", .{chain.saw_esp});

    if (chain.fragment) |f| {
        try w.print("\nIPv6 Fragment header (RFC 8200 Section 4.5)\n", .{});
        try w.print("  Next Header      {d}\n", .{f.next_header});
        try w.print("  Reserved         0x{X:0>2}\n", .{f.reserved});
        try w.print("  Fragment Offset  {d}  ({d} octets from the Fragmentable Part)\n", .{
            f.fragment_offset, f.byteOffset(),
        });
        try w.print("  Res              {d}\n", .{f.res});
        try w.print("  M flag           {d}  ({s} fragments follow)\n", .{
            @intFromBool(f.more_fragments),
            if (f.more_fragments) "more" else "no",
        });
        try w.print("  Identification   0x{X}\n", .{f.identification});
        try w.print("  fragment data    {d} octets\n", .{f.data.len});
        if (f.more_fragments and f.data.len % 8 != 0) {
            try w.print("  WARNING: an M=1 fragment whose length is not a multiple of 8 must be\n", .{});
            try w.print("           discarded with ICMPv6 Parameter Problem Code 0 (RFC 8200 4.5).\n", .{});
        }
    }

    try w.print("\nEtherIP header (RFC 3378)\n", .{});
    if (chain.upper_layer_next_header != etherip.ip_protocol_number) {
        try w.print("  Next Header is {d}, not 97: this packet is not EtherIP.\n", .{chain.upper_layer_next_header});
        return;
    }
    if (chain.fragment != null and chain.fragment.?.fragment_offset != 0) {
        try w.print("  offset != 0: the EtherIP header is in an earlier fragment.\n", .{});
    }
    const ether = etherip.parse(chain.upper_layer) catch |e| {
        try w.print("  REJECTED: {t}\n", .{e});
        return;
    };
    try w.print("  Version          {d}\n", .{ether.version});
    try w.print("  Reserved         {d}\n", .{ether.reserved});

    // The EtherIP header lives in the Fragmentable Part, so it is only present in the offset-zero
    // fragment (RFC 8200 Section 4.5).
    if (chain.fragment != null and chain.fragment.?.fragment_offset != 0) return;
    try w.print("\nEthernet frame (RFC 3378 Section 2, no FCS)\n", .{});
    try w.print("  length           {d} octets\n", .{ether.frame.len});
    const f = ethernet.parse(ether.frame) catch |e| {
        try w.print("  rejected: {t}\n", .{e});
        return;
    };
    try w.print("  destination MAC  {f}\n", .{macFmt(f.destination)});
    try w.print("  source MAC       {f}\n", .{macFmt(f.source)});
    try w.print("  EtherType        0x{X:0>4}\n", .{f.ether_type});
    if (f.tags.len > 0) {
        try w.print("  VLAN tags        {d}\n", .{f.tags.len});
        for (f.tags.items[0..f.tags.len]) |tag| {
            try w.print("    PCP {d} DEI {d} VLAN {d}\n", .{ tag.priority, @intFromBool(tag.drop_eligible), tag.vlan_id });
        }
    }
    try w.print("  payload          {d} octets\n", .{f.payload.len});
}

const MacFmt = struct {
    m: [6]u8,

    pub fn format(self: MacFmt, w: *Io.Writer) Io.Writer.Error!void {
        var buf: [18]u8 = undefined;
        const n = std.fmt.bufPrint(&buf, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
            self.m[0], self.m[1], self.m[2], self.m[3], self.m[4], self.m[5],
        }) catch return error.WriteFailed;
        try w.writeAll(n);
    }
};

fn macFmt(m: [6]u8) MacFmt {
    return .{ .m = m };
}

/// Decode a hex dump into octets.
///
/// Every hex digit in the input is significant, and all non-hex characters (spaces, tabs, newlines,
/// commas, colons, semicolons, and a leading `0x`) are ignored. That makes every common dump
/// spelling work without special cases: `60 00 00 00`, `6000:0000:0000:0000:...`, and a single
/// unbroken `60000000...` string.
fn parseHex(text: []const u8, out: []u8) !usize {
    var n: usize = 0;
    var hi: ?u8 = null;
    for (text) |c| {
        const nibble: u8 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            // Separators and an optional "0x" prefix carry no data.
            'x', 'X' => continue,
            ' ', '\t', '\r', '\n', ',', ':', ';', '-' => continue,
            else => return error.NotHex,
        };
        if (hi) |h| {
            if (n >= out.len) return error.TooLong;
            out[n] = (h << 4) | nibble;
            n += 1;
            hi = null;
        } else {
            hi = nibble;
        }
    }
    if (hi != null) return error.OddHexDigits;
    return n;
}

// ---------------------------------------------------------------------------
// emit-sample
// ---------------------------------------------------------------------------

fn runEmitSample(w: *Io.Writer, io: Io, opts: Options) !void {
    const gpa = std.heap.page_allocator;
    const cfg = try opts.buildConfig();
    try cfg.validate();

    var clock = FakeClock{};
    var wire = Wire{ .gpa = gpa };
    defer wire.deinit();

    const tx = try gpa.alloc(u8, cfg.maxOuterPacketSize());
    defer gpa.free(tx);
    const rx = try gpa.alloc(u8, ipv6.max_payload_len + ipv6.header_len);
    defer gpa.free(rx);
    var a = try tunnel.Tunnel.init(.{
        .config = cfg,
        .gpa = gpa,
        .tx_scratch = tx,
        .rx_scratch = rx,
        .clock = clock.view(),
        .fragment_id_seed = 0x0DDBA11_0000_0001,
    });
    defer a.deinit();

    const frame = try gpa.alloc(u8, cfg.overlay_mtu);
    defer gpa.free(frame);
    try ethernet.writeHeader(
        frame,
        .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 },
        ethernet.ether_type_ipv6,
    );
    for (frame[ethernet.header_len..], 0..) |*b, i| b.* = @truncate(i *% 251 +% 13);

    var etherip_buf: [lib.max_overlay_mtu + etherip.header_len]u8 = undefined;
    _ = try a.encapsulate(frame, &etherip_buf, .{ .context = &wire, .emit = Wire.sink });
    if (wire.packets.items.len == 0) return error.NothingToWrite;

    // Classic libpcap, LINKTYPE_ETHERNET (1).
    var file = try std.Io.Dir.cwd().createFile(io, opts.out_path, .{});
    defer file.close(io);
    var file_buf: [4096]u8 = undefined;
    var fw = file.writer(io, &file_buf);
    const pw = &fw.interface;

    var hdr: [24]u8 = undefined;
    writePcapGlobalHeader(&hdr);
    try pw.writeAll(&hdr);

    const eth_hdr = [14]u8{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x86, 0xdd,
    };
    var scratch: [1600 + 16]u8 = undefined;
    for (wire.packets.items, 0..) |pkt, i| {
        @memcpy(scratch[16..16 + 14], &eth_hdr);
        @memcpy(scratch[16 + 14 ..][0..pkt.len], pkt);
        const total = 14 + pkt.len;
        writePcapRecordHeader(scratch[0..16], @intCast(i), total);
        try pw.writeAll(scratch[0 .. 16 + total]);
    }
    try pw.flush();

    try w.print("wrote {d} Ethernet-framed IPv6 packet(s) to {s}\n", .{ wire.packets.items.len, opts.out_path });
    try w.print("\nopen it with:  tcpdump -r {s} -nn -vv\n", .{opts.out_path});
    try w.print("               wireshark {s}\n", .{opts.out_path});
    try w.print("\nexpected decode:\n", .{});
    try w.print("  Ethernet II  type 0x86dd (IPv6)\n", .{});
    try w.print("  IPv6         Next Header {d}\n", .{ipv6.next_header_fragment});
    try w.print("  IPv6 Fragment  offset/M/Res/Identification, payload {d} octets\n", .{wire.packets.items[0].len - 48});
    try w.print("  EtherIP      Next Header {d} (EtherIP), Version 3, Reserved 0\n", .{etherip.ip_protocol_number});
    try w.print("  Ethernet     the overlay frame, no FCS\n", .{});
}

/// `struct pcap_file_header`, 24 octets, host byte order little-endian.
fn writePcapGlobalHeader(out: *[24]u8) void {
    std.mem.writeInt(u32, out[0..4], 0xa1b2c3d4, .little);
    std.mem.writeInt(u16, out[4..6], 2, .little);
    std.mem.writeInt(u16, out[6..8], 4, .little);
    std.mem.writeInt(u32, out[8..12], 0, .little);
    std.mem.writeInt(u32, out[12..16], 0, .little);
    std.mem.writeInt(u32, out[16..20], 65535, .little);
    std.mem.writeInt(u32, out[20..24], 1, .little); // LINKTYPE_ETHERNET
}

/// `struct pcap_pkthdr`, 16 octets.
fn writePcapRecordHeader(out: *[16]u8, index: u32, len: usize) void {
    std.mem.writeInt(u32, out[0..4], 0, .little);
    std.mem.writeInt(u32, out[4..8], index, .little);
    std.mem.writeInt(u32, out[8..12], @intCast(len), .little);
    std.mem.writeInt(u32, out[12..16], @intCast(len), .little);
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

fn runStats(w: *Io.Writer) !void {
    try w.print("statistics counters\n", .{});
    inline for (std.meta.fields(stats.Counters)) |f| {
        try w.print("  {s}\n", .{f.name});
    }
    try w.print("\nreassembly occupancy and path MTU fields\n", .{});
    try w.print("  reassembly_in_flight_packets\n  reassembly_in_flight_bytes\n", .{});
    try w.print("  reassembly_buffered_bytes\n  reassembly_max_packets\n", .{});
    try w.print("  reassembly_max_bytes\n  effective_path_mtu\n", .{});
    try w.print("  discovered_path_mtu\n  configured_underlay_mtu\n  overlay_mtu\n", .{});
    try w.print("\nICMPv6 types this endpoint originates (RFC 8200 Section 4.5)\n", .{});
    try w.print("  {d} Destination Unreachable\n", .{icmpv6.type_destination_unreachable});
    try w.print("  {d} Packet Too Big\n", .{icmpv6.type_packet_too_big});
    try w.print("  {d} Time Exceeded (code {d} = Fragment Reassembly Time Exceeded)\n", .{
        icmpv6.type_time_exceeded, icmpv6.code_fragment_reassembly_time_exceeded,
    });
    try w.print("  {d} Parameter Problem (codes {d}, {d}, {d})\n", .{
        icmpv6.type_parameter_problem,
        icmpv6.code_erroneous_header_field,
        icmpv6.code_unrecognized_next_header,
        icmpv6.code_ipv6_header_error,
    });
}

test {
    _ = lib;
}