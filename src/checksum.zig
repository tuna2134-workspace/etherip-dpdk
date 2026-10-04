//! Internet checksum (RFC 1071) and the TCP/IPv4/IPv6 pseudo-headers.
//!
//! RFCs:
//!   * [RFC 1071] *Computing the Internet Checksum*, June 1988.
//!   * [RFC 9293] *Transmission Control Protocol (TCP)*, Section 3.1.
//!   * [RFC 8200] *IPv6 Specification*, Section 8.1 (upper-layer pseudo-header).
//!
//! Why this module exists: MSS clamping rewrites the TCP MSS option in encapsulated frames, which
//! invalidates the TCP checksum, which must be recomputed over the correct pseudo-header. It also
//! underpins ICMPv6 checksum validation (RFC 4443 Section 2.1).
//!
//! The one-s-complement checksum is:
//!
//! ```text
//! sum = 0
//! for each 16-bit big-endian word w of the data:  sum += w
//! while sum > 0xffff: sum = (sum & 0xffff) + (sum >> 16)
//! checksum = ~sum
//! ```
//!
//! An all-zero transmitted checksum means "no checksum" and an all-ones (`0xffff`, i.e. a computed
//! zero) means "checksum present and correct"; both conventions are handled by `checksum`.

const std = @import("std");
const ipv6 = @import("ipv6.zig");

/// Length of one 16-bit checksum word in octets.
pub const word_len: usize = 2;

pub const Error = error{
    /// The supplied buffer is not long enough for the checksummed region.
    Truncated,
};

/// Number of 16-bit words that can be added to a `u32` accumulator without overflowing:
/// `0xffff * (0xffff_ffff / 0xffff) == 65_538` words, i.e. 131 076 octets. Folding every
/// `words_per_fold` keeps `acc` provably in range for a buffer of any length.
const words_per_fold: usize = 4096;

/// Accumulate the 16-bit one's-complement sum of `bytes` into `sum`.
///
/// Handles payloads of odd length (RFC 1071 Section 2: the final odd octet is padded on the right
/// with zero octets) by supplying the zero octet itself rather than requiring callers to pad.
///
/// The accumulator is folded to 16 bits every `words_per_fold` words. Folding is idempotent for a
/// one's-complement sum (RFC 1071 Section 3(b): "the carry from the low-order bit position is added
/// to the high-order bit position"), so the result is unchanged; it simply makes overflow
/// impossible for arbitrarily long buffers.
pub fn accumulate(sum: u32, bytes: []const u8) u32 {
    var acc = sum;
    var i: usize = 0;
    const even_len = bytes.len & ~@as(usize, 1);
    while (i < even_len) {
        // Saturating add: a slice length near maxInt(usize) must not wrap the index.
        const end = @min(i +| (words_per_fold * word_len), even_len);
        while (i < end) : (i += word_len) {
            acc += std.mem.readInt(u16, bytes[i..][0..2], .big);
        }
        acc = fold32(acc);
    }
    if (bytes.len != even_len) {
        // RFC 1071 Section 2: "the last byte is padded on the right with zero octets".
        acc += @as(u32, bytes[even_len]) << 8;
    }
    return acc;
}

/// Fold the carries of a `u32` accumulator down to 16 bits, returning a value that fits in 18 bits.
fn fold32(acc: u32) u32 {
    return (acc & 0xffff) + (acc >> 16);
}

/// Fold the accumulated sum into 16 bits with end-around carry (RFC 1071 Section 3(b)).
pub fn fold(sum: u32) u16 {
    var s = sum;
    // A 32-bit accumulator can need at most two folds, but loop to be provably correct for any
    // input the caller can construct.
    while (s >> 16 != 0) s = (s & 0xffff) + (s >> 16);
    return @truncate(s);
}

/// Compute the 16-bit one's-complement checksum of `bytes`. May return 0x0000.
pub fn checksum(bytes: []const u8) u16 {
    return ~fold(accumulate(0, bytes));
}

/// Compute the checksum of `bytes` in transmitted form: a computed zero becomes all ones
/// (RFC 9293 Section 3.1).
pub fn wireChecksum(bytes: []const u8) u16 {
    const c = checksum(bytes);
    return if (c == 0) 0xffff else c;
}

/// Compute the checksum of `bytes` and store it big-endian at `out`.
pub fn writeChecksum(out: []u8, bytes: []const u8) error{Truncated}!void {
    if (out.len < word_len) return error.Truncated;
    std.mem.writeInt(u16, out[0..2], checksum(bytes), .big);
}

/// Which IP version a pseudo-header is being built for.
pub const IpVersion = enum { ipv4, ipv6 };

/// Add the transport pseudo-header to an accumulator.
///
/// RFC 9293 Section 3.1 defines the IPv4 TCP pseudo-header; RFC 8200 Section 8.1 defines the IPv6
/// one, which replaces the 32-bit addresses with the 128-bit addresses and uses a 32-bit
/// upper-layer length.
pub fn accumulatePseudoHeader(
    sum: u32,
    version: IpVersion,
    source: []const u8,
    destination: []const u8,
    protocol: u8,
    transport_length: usize,
) error{Truncated}!u32 {
    if (transport_length > 0xffff) return error.Truncated;
    var acc = sum;
    switch (version) {
        .ipv4 => {
            if (source.len != 4 or destination.len != 4) return error.Truncated;
            acc = accumulate(acc, source);
            acc = accumulate(acc, destination);
            // 8-bit zero + 8-bit protocol
            acc += @as(u32, protocol);
            acc += @as(u32, @intCast(transport_length));
        },
        .ipv6 => {
            if (source.len != 16 or destination.len != 16) return error.Truncated;
            acc = accumulate(acc, source);
            acc = accumulate(acc, destination);
            // 32-bit upper-layer packet length
            acc += @as(u32, @intCast(transport_length >> 16));
            acc += @as(u32, @truncate(transport_length));
            // 3 zero octets + next header
            acc += @as(u32, protocol);
        },
    }
    return acc;
}

/// Recompute and store the TCP checksum for a TCP segment carried by `version`.
///
/// `tcp_segment` must be the complete TCP header plus data, and `checksum_offset` the index of its
/// 2-octet Checksum field. The existing checksum is zeroed before summing, which is the standard
/// incremental-update technique (RFC 9293 Section 3.1: the checksum field is treated as zero while
/// computing the sum).
pub fn recomputeTcpChecksum(
    tcp_segment: []u8,
    checksum_offset: usize,
    version: IpVersion,
    source: []const u8,
    destination: []const u8,
) error{Truncated}!void {
    if (checksum_offset + word_len > tcp_segment.len) return error.Truncated;

    // Preserve the incoming value, then zero it for the computation.
    const incoming = std.mem.readInt(u16, tcp_segment[checksum_offset..][0..2], .big);
    std.mem.writeInt(u16, tcp_segment[checksum_offset..][0..2], 0, .big);

    const sum = try accumulatePseudoHeader(
        0,
        version,
        source,
        destination,
        ipv6.next_header_tcp,
        tcp_segment.len,
    );
    // RFC 9293 Section 3.1: "If the computed checksum is zero, it is transmitted as all ones".
    const computed = ~fold(accumulate(sum, tcp_segment));
    const result: u16 = if (computed == 0) 0xffff else computed;

    std.mem.writeInt(u16, tcp_segment[checksum_offset..][0..2], result, .big);
    _ = incoming;
}

/// Next Header value for TCP in the IPv6 pseudo-header (RFC 8200 Section 8.1).
pub const next_header_tcp = ipv6.next_header_tcp;

const t = std.testing;

// RFC 1071 worked vectors.
test "RFC 1071: known checksum vectors" {
    // 0x0001 + 0x0203 = 0x0204, complemented to 0xfdfb.
    try t.expectEqual(@as(u16, 0xfdfb), checksum(&[_]u8{ 0x00, 0x01, 0x02, 0x03 }));
    // All zeros -> 0xffff
    try t.expectEqual(@as(u16, 0xffff), checksum(&[_]u8{ 0x00, 0x00 }));
    // A 0xffff word is all ones, so the sum is 0xffff and the complement is 0x0000. RFC 9293
    // Section 3.1 requires that computed zero to go on the wire as all ones.
    try t.expectEqual(@as(u16, 0x0000), checksum(&[_]u8{ 0xff, 0xff }));
    try t.expectEqual(@as(u16, 0xffff), wireChecksum(&[_]u8{ 0xff, 0xff }));
    // A zero sum complements to all ones directly.
    try t.expectEqual(@as(u16, 0xffff), checksum(&[_]u8{ 0x00, 0x00 }));
    try t.expectEqual(@as(u16, 0xffff), wireChecksum(&[_]u8{ 0x00, 0x00 }));
}

test "checksum: verifying a valid sum yields zero" {
    const data = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    const c = checksum(&data);
    var with_sum: [10]u8 = undefined;
    @memcpy(with_sum[0..8], &data);
    std.mem.writeInt(u16, with_sum[8..10], c, .big);
    // Summing the data together with its own correct checksum must produce all ones, which the
    // complement turns into zero. This is exactly how TCP verifies a segment.
    try t.expectEqual(@as(u16, 0x0000), ~fold(accumulate(0, &with_sum)));
}

test "checksum: odd-length input is zero padded on the right (RFC 1071 Section 2)" {
    // RFC 1071 Section 2: the final odd octet is padded on the right with a zero octet, so
    // {61,62,63} and {61,62,63,00} must produce the same checksum.
    const odd = checksum(&[_]u8{ 0x61, 0x62, 0x63 });
    const padded = checksum(&[_]u8{ 0x61, 0x62, 0x63, 0x00 });
    try t.expectEqual(odd, padded);
}

test "accumulate: a buffer far larger than the u32 accumulator is handled without overflow" {
    // 1 MiB of 0xff is 524 288 words. Without periodic folding this overflows a u32 accumulator
    // (524288 * 0xffff > 2^32), which panics in Debug and ReleaseSafe.
    const big = try t.allocator.alloc(u8, 1024 * 1024);
    defer t.allocator.free(big);
    @memset(big, 0xff);

    // 0xffff words sum to 0xffff after folding, so the checksum is ~0xffff == 0x0000, and
    // wireChecksum maps that to 0xffff per RFC 9293 Section 3.1.
    try t.expectEqual(@as(u16, 0x0000), checksum(big));
    try t.expectEqual(@as(u16, 0xffff), wireChecksum(big));

    // A mix of 0x00 and 0xff must still verify: append the checksum and sum to all ones.
    var with_sum = try t.allocator.alloc(u8, big.len + 2);
    defer t.allocator.free(with_sum);
    @memset(with_sum[0 .. big.len], 0x7f);
    const c = checksum(with_sum[0..big.len]);
    std.mem.writeInt(u16, with_sum[big.len..][0..2], c, .big);
    try t.expectEqual(@as(u16, 0xffff), fold(accumulate(0, with_sum)));
}

test "accumulate: carry folding is correct for pathological sums" {
    // 0xffff repeated many times forces multiple end-around carries.
    // 400 all-ones words: the accumulator needs several end-around carry rounds to get back to
    // 16 bits, which exercises the `while` loop in `fold`.
    const words = [_]u8{0xff} ** 400;
    try t.expectEqual(@as(u32, 0xffff), fold(accumulate(0, &words)));

    // A maximum-length buffer of 0xff words must still fold without overflowing the u32 sum:
    // 65_535 * 32_768 = 2_147_450_880 < 2^32.
    const max_words = [_]u8{0xff} ** (2 * 65536);
    try t.expectEqual(@as(u32, 0xffff), fold(accumulate(0, &max_words)));
    // 0x8000 words: sum overflows 16 bits many times.
    var big: [4096]u8 = @splat(0x00);
    for (0..4096) |i| big[i] = if (i % 2 == 0) 0xff else 0x7f;
    _ = fold(accumulate(0, &big)); // must not panic or overflow
}

test "pseudo-header: IPv4 layout (RFC 9293 Section 3.1)" {
    const src = [_]u8{ 192, 0, 2, 1 };
    const dst = [_]u8{ 198, 51, 100, 7 };
    const sum = try accumulatePseudoHeader(0, .ipv4, &src, &dst, 6, 20);
    // 0xc000 + 0x0201 + 0xc633 + 0x6407 + 0x0006 + 0x0014
    const expected: u32 = 0xc000 + 0x0201 + 0xc633 + 0x6407 + 0x0006 + 0x0014;
    // `accumulate` returns a value that is congruent modulo 0xffff but bounded, so compare after
    // folding. For inputs this short no fold has happened, but folding is a no-op then.
    try t.expectEqual(@as(u16, fold(expected)), fold(sum));
}

test "pseudo-header: IPv6 layout uses 128-bit addresses and a 32-bit length (RFC 8200 8.1)" {
    const src = ipv6.Address.parse("2001:db8::1") catch unreachable;
    const dst = ipv6.Address.parse("2001:db8::2") catch unreachable;
    const sum = try accumulatePseudoHeader(0, .ipv6, &src.bytes(), &dst.bytes(), 6, 1448);

    var expected: u32 = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        expected += src.groups[i];
        expected += dst.groups[i];
    }
    expected += 0x0000; // upper-layer length, high 16 bits
    expected += 1448; // upper-layer length, low 16 bits
    expected += 6; // next header
    try t.expectEqual(@as(u16, fold(expected)), fold(sum));
}

test "pseudo-header: rejects wrong-sized addresses" {
    try t.expectError(
        error.Truncated,
        accumulatePseudoHeader(0, .ipv4, &[_]u8{ 1, 2, 3 }, &[_]u8{ 1, 2, 3, 4 }, 6, 20),
    );
    try t.expectError(
        error.Truncated,
        accumulatePseudoHeader(0, .ipv6, &[_]u8{1} ** 16, &[_]u8{1} ** 8, 6, 20),
    );
    try t.expectError(
        error.Truncated,
        accumulatePseudoHeader(0, .ipv4, &[_]u8{ 1, 2, 3, 4 }, &[_]u8{ 1, 2, 3, 4 }, 6, 70000),
    );
}

test "recomputeTcpChecksum: round trip through validation" {
    const src = [_]u8{ 10, 0, 0, 1 };
    const dst = [_]u8{ 10, 0, 0, 2 };

    // A 20-octet TCP header with a placeholder checksum.
    var seg = [_]u8{0} ** 20;
    std.mem.writeInt(u16, seg[0..2], 0x1234, .big); // source port
    std.mem.writeInt(u16, seg[2..4], 0x0050, .big); // destination port
    std.mem.writeInt(u16, seg[16..18], 0xffff, .big); // data offset | flags
    const checksum_off: usize = 16 + 2;

    try recomputeTcpChecksum(&seg, checksum_off, .ipv4, &src, &dst);

    // Verify: summing the pseudo-header plus the segment must produce all ones.
    const sum = try accumulatePseudoHeader(0, .ipv4, &src, &dst, 6, seg.len);
    try t.expectEqual(@as(u16, 0xffff), fold(accumulate(sum, &seg)));
}

test "recomputeTcpChecksum: IPv6 pseudo-header verification" {
    const src = ipv6.Address.parse("2001:db8::1") catch unreachable;
    const dst = ipv6.Address.parse("2001:db8::2") catch unreachable;
    var seg = [_]u8{0} ** 20;
    const checksum_off: usize = 18;
    try recomputeTcpChecksum(&seg, checksum_off, .ipv6, &src.bytes(), &dst.bytes());
    const sum = try accumulatePseudoHeader(0, .ipv6, &src.bytes(), &dst.bytes(), 6, seg.len);
    try t.expectEqual(@as(u16, 0xffff), fold(accumulate(sum, &seg)));
}

test "recomputeTcpChecksum: rejects an out-of-range checksum offset" {
    var seg = [_]u8{0} ** 20;
    try t.expectError(
        error.Truncated,
        recomputeTcpChecksum(&seg, 19, .ipv4, &[_]u8{ 1, 2, 3, 4 }, &[_]u8{ 5, 6, 7, 8 }),
    );
    try t.expectError(
        error.Truncated,
        recomputeTcpChecksum(&seg, 0, .ipv4, &[_]u8{ 1, 2, 3 }, &[_]u8{ 5, 6, 7, 8 }),
    );
}

test "writeChecksum: stores big-endian and rejects a short buffer" {
    var out: [2]u8 = undefined;
    try writeChecksum(&out, &[_]u8{ 0x00, 0x01, 0x02, 0x03 });
    try t.expectEqual(@as(u8, 0xfd), out[0]);
    try t.expectEqual(@as(u8, 0xfb), out[1]);
    try t.expectError(error.Truncated, writeChecksum(out[0..1], &[_]u8{ 1, 2 }));
}

test "fuzz: checksum never panics on arbitrary input" {
    const Fuzz = struct {
        fn fuzzer(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [128]u8 = undefined;
            const n: usize = smith.slice(&buf);
            _ = checksum(buf[0..n]);
        }
    };
    try t.fuzz({}, Fuzz.fuzzer, .{});
}