//! Bounded IPv6 fragment reassembly for EtherIP datagrams.
//!
//! RFC: RFC 8200 Section 4.5 ("Fragment Header"), reassembly rules.
//!
//! ## Design constraints
//!
//! RFC 8200 Section 4.5 dictates the *protocol* behaviour; it says nothing about how many
//! concurrent reassemblies a host must support. That is an implementation resource decision, so
//! this module makes the bounds explicit and configurable (`max_reassembly_packets`,
//! `max_reassembly_bytes`, `reassembly_timeout_ms`) and enforces them without a `HashMap` that
//! could grow without limit:
//!
//!   * Every reassembly context owns a fixed-size buffer carved out of one byte pool allocated once
//!     at `init`. Fragment data is copied into it; there is no per-fragment heap allocation.
//!   * The key index is a `HashMapUnmanaged` with capacity fixed at `max_reassembly_packets`, so it
//!     cannot outgrow its reservation.
//!   * Expired contexts are swept on every insert, and if the table is still full the **oldest**
//!     context is evicted (docs/RFC-ANALYSIS.md Section 5.8 explains why eviction beats drop-new).
//!
//! ## Normative rules implemented
//!
//! RFC 8200 Section 4.5:
//!   * Key on (Source Address, Destination Address, Fragment Identification).
//!   * A fragment with Fragment Offset 0 **and** M 0 is a whole datagram: process it immediately
//!     with no queue state.
//!   * "Each complete fragment, except possibly the last ... is an integer multiple of 8 octets":
//!     an M=1 fragment whose length is not a multiple of 8 is discarded (error condition 2).
//!   * "If any of the fragments being reassembled overlap ... reassembly of that packet must be
//!     abandoned and all the fragments ... must be discarded, and no ICMP error messages should be
//!     sent" (error condition 5).
//!   * "an implementation may choose to detect this case and drop exact duplicate fragments while
//!     keeping the other fragments belonging to the same packet" — duplicates are dropped, not
//!     treated as overlaps.
//!   * "If insufficient fragments are received ... within 60 seconds of the reception of the
//!     first-arriving fragment ... reassembly of that packet must be abandoned and all the
//!     fragments ... must be discarded."

const std = @import("std");
const ipv6 = @import("ipv6.zig");
const etherip = @import("etherip.zig");

/// RFC 8200 Section 4.5: Fragment Offset units, and therefore the alignment of every non-final
/// fragment.
pub const fragment_alignment: usize = 8;

/// Default reassembly timeout, from RFC 8200 Section 4.5: reassembly "must be abandoned ... within
/// 60 seconds of the reception of the first-arriving fragment".
pub const default_timeout_ms: u64 = 60_000;

/// Upper bound on the timeout. RFC 8200 mandates abandonment *within* 60 seconds, so a longer
/// configured value would be non-conformant and is rejected by `Limits.init`.
pub const max_timeout_ms: u64 = 60_000;

/// Hard ceiling on the number of fragments tracked per datagram. A datagram needs at most
/// `65535 / 8 = 8192` fragments in the pathological case, but real tunnels produce a handful; the
/// default of 64 bounds memory without affecting legitimate traffic.
pub const default_max_chunks: usize = 64;

/// Monotonic millisecond clock, abstracted so tests can drive time deterministically.
pub const Clock = struct {
    context: *anyopaque,
    nowMsFn: *const fn (context: *anyopaque) i64,

    pub fn nowMs(self: Clock) i64 {
        return self.nowMsFn(self.context);
    }
};

/// A clock driven by the caller. Used by every test that exercises the timeout.
pub const ManualClock = struct {
    now: i64 = 0,

    pub fn clock(self: *ManualClock) Clock {
        return .{ .context = @ptrCast(self), .nowMsFn = nowMs };
    }

    pub fn advance(self: *ManualClock, delta_ms: i64) void {
        self.now += delta_ms;
    }

    fn nowMs(ctx: *anyopaque) i64 {
        const self: *ManualClock = @ptrCast(@alignCast(ctx));
        return self.now;
    }
};

/// The RFC 8200 Section 4.5 reassembly key: Source Address, Destination Address, and Fragment
/// Identification.
pub const Key = struct {
    source: ipv6.Address,
    destination: ipv6.Address,
    identification: u32,

    pub fn eql(a: Key, b: Key) bool {
        return a.identification == b.identification and
            a.source.eql(b.source) and
            a.destination.eql(b.destination);
    }
};

/// Bounds on reassembly resources.
pub const Limits = struct {
    /// Maximum number of datagrams being reassembled concurrently.
    max_packets: usize = 256,
    /// Maximum total octets of fragment payload buffered across all contexts.
    max_bytes: usize = 16 * 1024 * 1024,
    /// Largest reassembled Fragmentable Part this endpoint will accept. Must be at least the
    /// configured overlay MTU plus the EtherIP header.
    max_datagram: usize = 9002,
    /// Milliseconds before an incomplete reassembly is abandoned (1..60000, RFC 8200 Section 4.5).
    timeout_ms: u64 = default_timeout_ms,
    /// Maximum number of disjoint fragments tracked per datagram.
    max_chunks: usize = default_max_chunks,
    /// Octets of Per-Fragment Headers that precede the Fragmentable Part (RFC 8200 Section 4.5).
    /// These count towards the reassembled packet's 16-bit Payload Length, so the 65 535 check
    /// must include them. Zero unless the sender reserves extension-header octets.
    per_fragment_header_len: usize = 0,
    /// Entries in the recently-completed duplicate filter.
    max_recent_completions: usize = 64,
    /// Milliseconds a completed datagram's key is remembered so replays are cheap to drop.
    duplicate_window_ms: i64 = 1000,

    /// The slot index is stored as `u16`, so the slot count is bounded accordingly. Without this,
    /// a large `max_packets` reaches an `@intCast` that panics.
    pub const max_packets_limit: usize = std.math.maxInt(u16);

    pub const Error = error{
        TooManyPacketsLimit,
        ZeroPacketsLimit,
        ZeroByteLimit,
        ZeroDatagramLimit,
        ZeroChunkLimit,
        NegativeDuplicateWindow,
        /// RFC 8200 Section 4.5 caps reassembly at 60 seconds.
        TimeoutTooLong,
        /// The Fragmentable Part must be able to hold at least one EtherIP header.
        DatagramLimitTooSmall,
        /// Not enough memory to satisfy `max_bytes`.
        OutOfMemory,
    };

    pub fn validate(self: Limits) Error!void {
        if (self.max_packets == 0) return error.ZeroPacketsLimit;
        if (self.max_packets > max_packets_limit) return error.TooManyPacketsLimit;
        if (self.max_bytes == 0) return error.ZeroByteLimit;
        if (self.max_datagram == 0) return error.ZeroDatagramLimit;
        if (self.max_chunks == 0) return error.ZeroChunkLimit;
        if (self.max_recent_completions == 0) return error.ZeroChunkLimit;
        if (self.duplicate_window_ms < 0) return error.NegativeDuplicateWindow;
        if (self.timeout_ms == 0) return error.TimeoutTooLong;
        if (self.timeout_ms > max_timeout_ms) return error.TimeoutTooLong;
        if (self.max_datagram < etherip.header_len) return error.DatagramLimitTooSmall;
        // Every context needs room for its own chunk table.
        const chunk_table_bytes = std.math.mul(usize, @sizeOf(Chunk) * self.max_chunks, self.max_packets) catch return error.OutOfMemory;
        if (self.max_bytes < chunk_table_bytes) return error.OutOfMemory;
        return;
    }
};

/// One received, disjoint byte range of the datagram being reassembled.
const Chunk = struct {
    start: u32,
    end: u32,

    fn len(self: Chunk) u32 {
        return self.end - self.start;
    }
};

/// A datagram key remembered for `duplicate_window_ms` after reassembly completed.
const RecentCompletion = struct {
    key: Key,
    at_ms: i64,
};

    /// A datagram abandoned by `expire`, reported so the caller can originate the ICMPv6 that
/// RFC 8200 Section 4.5 error condition 1 requires.
pub const Expired = struct {
    key: Key,
    /// True when the Fragment Offset 0 fragment was received. RFC 8200 Section 4.5 error
    /// condition 1: "If the first fragment ... has been received, an ICMP Time Exceeded --
    /// Fragment Reassembly Time Exceeded message should be sent to the source of that
    /// fragment." Without it there is nothing meaningful to quote, so no message is sent.
    have_first: bool,
};

const Context = struct {
    key: Key,
    /// Reassembly payload buffer.
    data: []u8,
    /// Fixed-capacity backing store for `chunk_count` sorted, disjoint, non-adjacent chunks of
    /// `data`. Always `limits.max_chunks` long; use `chunk_count`, not `chunks.len`.
    chunks: []Chunk,
    /// Number of valid entries in `chunks`.
    chunk_count: usize,
    /// Timestamp of the first fragment received for this datagram (RFC 8200 Section 4.5's
    /// "60 seconds of the reception of the first-arriving fragment").
    first_seen_ms: i64,
    /// Timestamp of the most recent fragment, used for LRU-style eviction.
    last_seen_ms: i64,
    /// Total octets received.
    received: u32,
    /// Known datagram length, established by the fragment with M = 0.
    total_len: ?u32,
    /// Whether the Fragment Offset 0 fragment arrived, which decides whether a timeout can be
    /// reported (RFC 8200 Section 4.5 error condition 1: the ICMP error is sent "If the first
    /// fragment ... has been received").
    have_first: bool,

    fn isEmpty(self: *const Context) bool {
        return self.chunk_count == 0;
    }

    fn isComplete(self: *const Context) bool {
        const total = self.total_len orelse return false;
        if (!self.have_first) return false;
        return self.chunk_count == 1 and self.chunks[0].start == 0 and self.chunks[0].end == total;
    }

    /// Append a chunk. `max_chunks` is threaded in so the fixed-capacity slice can be bounded
    /// without relying on `capacity` bookkeeping.
    fn insertChunk(self: *Context, start: u32, end: u32, max_chunks: usize) error{ChunkTableFull}!void {
        if (self.chunk_count == max_chunks) return error.ChunkTableFull;
        self.chunks[self.chunk_count] = .{ .start = start, .end = end };
        self.chunk_count += 1;
    }

    /// Find the index of the first chunk whose end is strictly greater than `start`.
    fn lowerBound(self: *const Context, start: u32) usize {
        var lo: usize = 0;
        var hi: usize = self.chunk_count;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.chunks[mid].end > start) hi = mid else lo = mid + 1;
        }
        return lo;
    }
};

pub const ReassemblyCounters = struct {
    fragments_accepted: u64 = 0,
    fragments_duplicate: u64 = 0,
    datagrams_completed: u64 = 0,
    datagrams_overlapped: u64 = 0,
    datagrams_timed_out: u64 = 0,
    datagrams_evicted: u64 = 0,
    fragments_rejected: u64 = 0,
};

pub const Statistics = struct {
    in_flight_packets: usize,
    in_flight_bytes: usize,
    buffered_bytes: usize,
    counters: ReassemblyCounters,
};

/// What `addFragment` did with a fragment.
pub const Outcome = union(enum) {
    /// More fragments are needed.
    buffered,
    /// The fragment was an exact duplicate of data already held; the context is untouched.
    duplicate,
    /// The datagram is complete. The slice borrows the reassembler's internal buffer and is valid
    /// only until the next `addFragment` call, at which point the slot may be reused. Copy it
    /// (or transmit it) before returning to the packet loop.
    complete: []const u8,
    /// A context for this key did not exist and the queue was full after sweeping expired entries,
    /// or this fragment was malformed. `complete` is false.
    rejected: RejectReason,
};

pub const RejectReason = enum {
    /// RFC 8200 Section 4.5 error condition 2: an M=1 fragment whose length is not a multiple of
    /// 8 octets.
    FragmentLengthNotAligned,
    /// RFC 8200 Section 4.5 error condition 3: length + offset would push the reassembled Payload
    /// Length past 65 535 octets.
    ExceedsDatagramLimit,
    /// The fragment's Next Header is not EtherIP, so this datagram is not ours.
    NotEtherIp,
    /// The fragment's bytes conflict with bytes already buffered (RFC 8200 Section 4.5 error
    /// condition 5).
    Overlapping,
    /// The fragment offset/length pair is internally inconsistent (for example, a non-final
    /// fragment that would extend past the known datagram length).
    InconsistentLength,
    /// `max_reassembly_packets` contexts are already live and the oldest could not be evicted
    /// because it is the only one.
    QueueFull,
    /// `max_chunks` fragments were already tracked for this datagram.
    TooManyFragments,
};

pub const Options = struct {
    limits: Limits = .{},
    clock: Clock,
};

pub const Reassembler = struct {
    gpa: std.mem.Allocator,
    limits: Limits,
    clock: Clock,

    /// One flat byte pool shared by all contexts, so total buffered bytes are bounded by
    /// construction.
    pool: []u8,
    /// One flat `Chunk` table pool, parallel to `pool`.
    chunk_pool: []Chunk,
    /// Slot index -> live context, or null when the slot is free.
    slots: []Context,
    /// Which slot a key lives in. Capacity is reserved once at `init` and never grown, so the
    /// index cannot become an unbounded structure (the project explicitly forbids an unbounded
    /// HashMap here).
    index: Index,
    used_slots: std.ArrayList(u16) = .empty,

    buffered_bytes: usize = 0,
    counters: ReassemblyCounters = .{},

    /// Fixed-capacity ring of recently completed datagram keys.
    ///
    /// RFC 8200 Section 4.5 warns that "fragments may be duplicated in the network" but does not
    /// say what to do with a duplicate of a datagram that has *already* been reassembled and
    /// delivered. Without a record of completions, a replayed final fragment would allocate a
    /// fresh, permanently-incomplete context on every replay: a cheap memory-exhaustion vector
    /// (RFC 8200 Section 4.5 error condition 1 territory). This ring turns such replays into a
    /// counter increment. Bounded and fixed-size; documented in docs/RFC-ANALYSIS.md Section 5.7.
    recent: []RecentCompletion,
    recent_len: usize = 0,
    recent_next: usize = 0,
    /// How long a completed key is remembered.
    duplicate_window_ms: i64 = 1000,

    const KeyContext = struct {
        pub fn hash(_: KeyContext, key: Key) u64 {
            var h = std.hash.Wyhash.hash(0, std.mem.asBytes(&key.identification));
            h = std.hash.Wyhash.hash(h, std.mem.asBytes(&key.source.groups));
            h = std.hash.Wyhash.hash(h, std.mem.asBytes(&key.destination.groups));
            return h;
        }
        pub fn eql(_: KeyContext, a: Key, b: Key) bool {
            return a.eql(b);
        }
    };

    const Index = std.HashMapUnmanaged(
        Key,
        u16,
        KeyContext,
        std.hash_map.default_max_load_percentage,
    );

    pub const InitError = Limits.Error;

    pub fn init(gpa: std.mem.Allocator, options: Options) InitError!Reassembler {
        try options.limits.validate();

        const per_context = options.limits.max_datagram;
        const pool_len = std.math.mul(usize, options.limits.max_packets, per_context) catch
            return error.OutOfMemory;
        if (pool_len > options.limits.max_bytes) return error.OutOfMemory;

        const pool = try gpa.alloc(u8, pool_len);
        errdefer gpa.free(pool);

        const slots = try gpa.alloc(Context, options.limits.max_packets);
        errdefer gpa.free(slots);
        for (slots) |*s| s.* = .{ .key = undefined, .data = undefined, .chunks = undefined, .chunk_count = 0, .first_seen_ms = 0, .last_seen_ms = 0, .received = 0, .total_len = null, .have_first = false };

        const chunk_pool: []Chunk = try gpa.alloc(
            Chunk,
            std.math.mul(usize, options.limits.max_chunks, options.limits.max_packets) catch return error.OutOfMemory,
        );
        errdefer gpa.free(chunk_pool);

        var index: Index = .empty;
        errdefer index.deinit(gpa);
        try index.ensureTotalCapacityContext(gpa, @intCast(options.limits.max_packets), .{});

        const recent = try gpa.alloc(RecentCompletion, options.limits.max_recent_completions);
        errdefer gpa.free(recent);

        var used = std.ArrayList(u16).empty;
        errdefer used.deinit(gpa);
        try used.ensureTotalCapacity(gpa, options.limits.max_packets);

        var self = Reassembler{
            .gpa = gpa,
            .limits = options.limits,
            .clock = options.clock,
            .pool = pool,
            .chunk_pool = chunk_pool,
            .slots = slots,
            .index = index,
            .used_slots = used,
            .recent = recent,
            .duplicate_window_ms = options.limits.duplicate_window_ms,
        };
        for (self.slots, 0..) |*s, i| {
            s.data = self.pool[i * per_context ..][0..per_context];
            s.chunks = self.chunkStorageFor(@intCast(i));
        }
        return self;
    }

    pub fn deinit(self: *Reassembler) void {
        self.index.deinit(self.gpa);
        self.used_slots.deinit(self.gpa);
        self.gpa.free(self.slots);
        self.gpa.free(self.recent);
        self.gpa.free(self.chunk_pool);
        self.gpa.free(self.pool);
        self.* = undefined;
    }

    /// The `max_chunks` per-context chunk tables are carved out of one flat `Chunk` array so that
    /// the whole reassembly table costs exactly one allocation and cannot grow.
    fn chunkStorageFor(self: *const Reassembler, slot: u16) []Chunk {
        const base = @as(usize, slot) * self.limits.max_chunks;
        return self.chunk_pool[base..][0..self.limits.max_chunks];
    }

    /// Offer one received fragment to the reassembler.
    ///
    /// `view` is the zero-copy view of the received packet's Fragment header and following data
    /// (`ipv6.Chain.fragment`). `source` / `destination` are the outer IPv6 header's addresses.
    ///
    /// `view.data` is copied into the context's own buffer, so the caller may reuse its receive
    /// buffer immediately.
    pub fn addFragment(
        self: *Reassembler,
        source: ipv6.Address,
        destination: ipv6.Address,
        frag: ipv6.FragmentHeaderView,
        now_ms: i64,
    ) Outcome {
        // Expired contexts are swept by the caller (the Tunnel does it, so that it can originate the
        // ICMPv6 Time Exceeded RFC 8200 Section 4.5 error condition 1 requires). Sweeping here would
        // discard the `Expired` records and lose those messages.
        const key: Key = .{
            .source = source,
            .destination = destination,
            .identification = frag.identification,
        };

        // A replay of any fragment of a datagram we just completed is dropped without allocating.
        if (self.wasRecentlyCompleted(key, now_ms)) {
            self.counters.fragments_duplicate += 1;
            return .duplicate;
        }

        // RFC 8200 Section 4.5 error condition 2: "If the length of a fragment ... is not a
        // multiple of 8 octets and the M flag of that fragment is 1, then that fragment must be
        // discarded".
        if (frag.next_header != etherip.ip_protocol_number) {
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .NotEtherIp };
        }
        if (frag.more_fragments and frag.data.len % fragment_alignment != 0) {
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .FragmentLengthNotAligned };
        }
        if (frag.data.len == 0 and !frag.more_fragments and frag.fragment_offset == 0) {
            // A zero-length whole datagram cannot contain an EtherIP header.
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .InconsistentLength };
        }

        const start = frag.byteOffset();
        // RFC 8200 Section 4.5 error condition 3: length + offset must not push the reassembled
        // Payload Length past 65 535 octets. The reassembled packet is Per-Fragment Headers plus the
        // Fragmentable Part, so the reserved Per-Fragment octets count towards that total.
        const end = std.math.add(u32, start, @intCast(frag.data.len)) catch {
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .ExceedsDatagramLimit };
        };
        const payload_length = std.math.add(u32, end, @intCast(self.limits.per_fragment_header_len)) catch {
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .ExceedsDatagramLimit };
        };
        if (payload_length > ipv6.max_payload_len or end > self.limits.max_datagram) {
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .ExceedsDatagramLimit };
        }

        const gop = self.index.getOrPutContext(self.gpa, key, .{}) catch {
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .QueueFull };
        };

        if (gop.found_existing) {
            return self.addToContext(gop.value_ptr.*, frag, start, end, now_ms);
        }

        // A new datagram needs a slot.
        const slot = self.acquireSlot() orelse {
            _ = self.index.remove(key);
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .QueueFull };
        };
        const ctx = &self.slots[slot];
        ctx.* = .{
            .key = key,
            .data = self.pool[@as(usize, slot) * self.limits.max_datagram ..][0..self.limits.max_datagram],
            .chunks = self.chunkStorageFor(slot),
            .chunk_count = 0,
            .first_seen_ms = now_ms,
            .last_seen_ms = now_ms,
            .received = 0,
            .total_len = if (frag.more_fragments) null else end,
            .have_first = frag.fragment_offset == 0,
        };
        gop.value_ptr.* = @intCast(slot);
        self.used_slots.append(self.gpa, @intCast(slot)) catch {
            _ = self.index.remove(key);
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .QueueFull };
        };
        return self.addToContext(@intCast(slot), frag, start, end, now_ms);
    }

    fn addToContext(
        self: *Reassembler,
        slot: u16,
        frag: ipv6.FragmentHeaderView,
        start: u32,
        end: u32,
        now_ms: i64,
    ) Outcome {
        const ctx = &self.slots[slot];
        const key = ctx.key;
        ctx.last_seen_ms = now_ms;

        // Merge metadata before anything else. Coverage duplicates are idempotent, but the M flag
        // and Fragment Offset carry information that is *not* implied by coverage: a byte range
        // may first arrive with M = 1 and later (as a duplicate) with M = 0. Dropping that update
        // would leave the datagram with no known total length and it would never complete.
        if (frag.fragment_offset == 0) ctx.have_first = true;
        if (!frag.more_fragments) ctx.total_len = end;
        // A fragment that reaches past the known total length is internally inconsistent: no
        // reordering of a valid fragment set can produce that.
        if (ctx.total_len) |total| {
            if (end > total) {
                self.counters.fragments_rejected += 1;
                return .{ .rejected = .InconsistentLength };
            }
        }

        // Classify the incoming range against the chunks already held.
        var overlapping_chunks: usize = 0;
        var identical = true;
        var fully_covered = false;
        {
            const first = ctx.lowerBound(start);
            var i = first;
            while (i < ctx.chunk_count and ctx.chunks[i].start < end) : (i += 1) {
                overlapping_chunks += 1;
                const ov_start = @max(start, ctx.chunks[i].start);
                const ov_end = @min(end, ctx.chunks[i].end);
                const a = ctx.data[ov_start..ov_end];
                const b = frag.data[ov_start - start .. ov_end - start];
                if (!std.mem.eql(u8, a, b)) identical = false;
            }
            if (overlapping_chunks == 1 and
                ctx.chunks[first].start <= start and
                ctx.chunks[first].end >= end)
            {
                fully_covered = true;
            }
        }

        if (overlapping_chunks > 0) {
            if (fully_covered and identical) {
                // RFC 8200 Section 4.5: "an implementation may choose to detect this case and drop
                // exact duplicate fragments while keeping the other fragments belonging to the
                // same packet."
                self.counters.fragments_duplicate += 1;
                if (ctx.isComplete()) {
                    self.counters.datagrams_completed += 1;
                    const total = ctx.total_len.?;
                    self.rememberCompleted(key, now_ms);
                    self.release(slot);
                    return .{ .complete = ctx.data[0..total] };
                }
                return .duplicate;
            }
            // RFC 8200 Section 4.5 error condition 5: abandon the whole reassembly, discard every
            // fragment, and send no ICMP error.
            self.counters.datagrams_overlapped += 1;
            self.release(slot);
            return .{ .rejected = .Overlapping };
        }

        // Copy the payload into the context's own buffer so the caller may reuse its receive
        // buffer immediately.
        @memcpy(ctx.data[start..end], frag.data);
        self.buffered_bytes += frag.data.len;
        ctx.received += @intCast(frag.data.len);

        ctx.insertChunk(start, end, self.limits.max_chunks) catch {
            self.counters.fragments_rejected += 1;
            return .{ .rejected = .TooManyFragments };
        };
        // Keep the chunk list sorted and coalesced so `isComplete` is a single comparison.
        normalise(ctx);

        self.counters.fragments_accepted += 1;

        if (ctx.isComplete()) {
            self.counters.datagrams_completed += 1;
            const total = ctx.total_len.?;
            self.rememberCompleted(key, now_ms);
            // The pool is handed to the caller; release the slot so a new datagram can use it
            // immediately. The returned slice stays valid only until the next `addFragment`
            // call, which is exactly when the slot could be reused.
            self.release(slot);
            return .{ .complete = ctx.data[0..total] };
        }
        return .buffered;
    }

    fn wasRecentlyCompleted(self: *const Reassembler, key: Key, now_ms: i64) bool {
        for (self.recent[0..self.recent_len]) |r| {
            if (r.key.eql(key) and now_ms - r.at_ms < self.duplicate_window_ms) return true;
        }
        return false;
    }

    fn rememberCompleted(self: *Reassembler, key: Key, now_ms: i64) void {
        const slot = if (self.recent_len < self.recent.len) self.recent_len else self.recent_next;
        self.recent[slot] = .{ .key = key, .at_ms = now_ms };
        if (self.recent_len < self.recent.len) self.recent_len += 1;
        self.recent_next = (self.recent_next + 1) % self.recent.len;
    }

    /// Sort and coalesce the chunk list so `isComplete` is a single comparison.
    fn normalise(ctx: *Context) void {
        std.sort.block(Chunk, ctx.chunks[0..ctx.chunk_count], {}, chunkLessThan);
        var w: usize = 0;
        for (ctx.chunks[0..ctx.chunk_count]) |c| {
            if (w > 0 and ctx.chunks[w - 1].end == c.start) {
                ctx.chunks[w - 1].end = c.end;
            } else {
                ctx.chunks[w] = c;
                w += 1;
            }
        }
        ctx.chunk_count = w;
    }

    fn chunkLessThan(_: void, a: Chunk, b: Chunk) bool {
        return a.start < b.start;
    }

    /// Abandon datagrams that have been incomplete for longer than the configured timeout
    /// (RFC 8200 Section 4.5 error condition 1: "If insufficient fragments are received ... within
    /// 60 seconds of the reception of the first-arriving fragment ... reassembly of that packet
    /// must be abandoned and all the fragments that have been received for that packet must be
    /// discarded"). Returns the number abandoned by this call.
    pub fn expire(self: *Reassembler, now_ms: i64) usize {
        return self.expireInto(&.{}, now_ms);
    }

    /// As `expire`, but records each abandoned datagram in `out` so the caller can act on it.
    /// Returns the total number abandoned, which may exceed `out.len` if `out` is too small.
    pub fn expireInto(self: *Reassembler, out: []Expired, now_ms: i64) usize {
        var abandoned: usize = 0;
        var slot_out = out;
        var i: usize = 0;
        while (i < self.used_slots.items.len) {
            const slot = self.used_slots.items[i];
            const ctx = &self.slots[slot];
            const age = now_ms - ctx.first_seen_ms;
            if (age >= @as(i64, @intCast(self.limits.timeout_ms))) {
                if (ctx.have_first) self.counters.datagrams_timed_out += 1;
                if (slot_out.len > 0) {
                    slot_out[0] = .{ .key = ctx.key, .have_first = ctx.have_first };
                    slot_out = slot_out[1..];
                }
                abandoned += 1;
                self.release(slot);
                // `release` removes the slot from `used_slots`, so do not advance `i`.
                continue;
            }
            i += 1;
        }
        return abandoned;
    }

    /// Free a context's resources and remove it from the index.
    fn release(self: *Reassembler, slot: u16) void {
        const ctx = &self.slots[slot];
        self.buffered_bytes -= @min(self.buffered_bytes, ctx.received);
        _ = self.index.remove(ctx.key);
        ctx.chunk_count = 0;
        ctx.received = 0;
        ctx.total_len = null;
        ctx.have_first = false;
        // Compact the used-slot list.
        for (self.used_slots.items, 0..) |u, i| {
            if (u == slot) {
                _ = self.used_slots.swapRemove(i);
                break;
            }
        }
    }

    /// Find a free slot, evicting the oldest live context if necessary.
    fn acquireSlot(self: *Reassembler) ?u16 {
        // Prefer a slot that already owns its buffer and chunk table, i.e. any slot not currently
        // listed in `used_slots`.
        for (self.slots, 0..) |_, i| {
            var tracked = false;
            for (self.used_slots.items) |u| {
                if (@as(usize, u) == i) tracked = true;
            }
            if (!tracked) return @intCast(i);
        }
        // Evict the context with the oldest first-arrival timestamp (docs/RFC-ANALYSIS.md 5.8).
        var oldest: ?u16 = null;
        for (self.used_slots.items) |u| {
            if (oldest == null or self.slots[u].first_seen_ms < self.slots[oldest.?].first_seen_ms) {
                oldest = u;
            }
        }
        if (oldest) |o| {
            self.counters.datagrams_evicted += 1;
            self.release(o);
            return o;
        }
        return null;
    }

    /// Drop every in-flight context without touching the counters for completed work.
    pub fn reset(self: *Reassembler) void {
        while (self.used_slots.items.len > 0) {
            self.release(self.used_slots.items[0]);
        }
        self.buffered_bytes = 0;
    }

    pub fn statistics(self: *const Reassembler) Statistics {
        return .{
            .in_flight_packets = self.used_slots.items.len,
            .in_flight_bytes = self.used_slots.items.len * self.limits.max_datagram,
            .buffered_bytes = self.buffered_bytes,
            .counters = self.counters,
        };
    }

    /// True when a reassembly context exists for `key`.
    pub fn hasContext(self: *Reassembler, key: Key) bool {
        return self.index.containsContext(key, .{});
    }

    pub fn activeKeys(self: *Reassembler, out: []Key) usize {
        var n: usize = 0;
        var it = self.index.keyIterator();
        while (it.next()) |k| {
            if (n < out.len) {
                out[n] = k.*;
                n += 1;
            }
        }
        return n;
    }
};
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t = std.testing;
const reassembly_max_packets_limit = Limits.max_packets_limit;

const local_src = ipv6.Address.loopback;
const local_dst = ipv6.Address.any;

/// Build a `FragmentHeaderView` for tests. `data` is not copied.
fn fragView(fragment_offset: u13, more: bool, id: u32, data: []const u8) ipv6.FragmentHeaderView {
    return .{
        .next_header = etherip.ip_protocol_number,
        .reserved = 0,
        .fragment_offset = fragment_offset,
        .res = 0,
        .more_fragments = more,
        .identification = id,
        .data = data,
    };
}

const TestRig = struct {
    gpa: std.mem.Allocator,
    clock: ManualClock = .{},
    limits: Limits,
    re: Reassembler,

    fn init(gpa: std.mem.Allocator, limits: Limits) !TestRig {
        return .{
            .gpa = gpa,
            .limits = limits,
            .re = try Reassembler.init(gpa, .{ .limits = limits, .clock = undefined }),
        };
    }

    fn deinit(self: *TestRig) void {
        self.re.deinit();
    }

    fn feed(self: *TestRig, src: ipv6.Address, dst: ipv6.Address, v: ipv6.FragmentHeaderView) Outcome {
        return self.re.addFragment(src, dst, v, self.clock.now);
    }
};

test "Limits.validate rejects nonsense configuration" {
    const base: Limits = .{};
    try base.validate();

    try t.expectError(error.ZeroPacketsLimit, (Limits{ .max_packets = 0 }).validate());
    try t.expectError(error.ZeroByteLimit, (Limits{ .max_bytes = 0 }).validate());
    try t.expectError(error.OutOfMemory, (Limits{ .max_bytes = 16 }).validate());
    try t.expectError(error.ZeroDatagramLimit, (Limits{ .max_datagram = 0 }).validate());
    try t.expectError(error.ZeroChunkLimit, (Limits{ .max_chunks = 0 }).validate());
    try t.expectError(error.TimeoutTooLong, (Limits{ .timeout_ms = 0 }).validate());
    // RFC 8200 Section 4.5 mandates abandonment within 60 seconds.
    try t.expectError(error.TimeoutTooLong, (Limits{ .timeout_ms = 60_001 }).validate());
    try t.expectError(error.DatagramLimitTooSmall, (Limits{ .max_datagram = 1 }).validate());
    try (Limits{ .timeout_ms = 1 }).validate();
}

test "reassembly: fragments in order" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 4, .max_datagram = 100, .max_bytes = 4096 });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xA0);
    var b: [8]u8 = @splat(0xB0);
    var c: [4]u8 = @splat(0xC0);

    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(0, true, 7, &a)));
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(1, true, 7, &b)));
    const out = rig.feed(local_src, local_dst, fragView(2, false, 7, &c));
    try t.expect(out == .complete);
    try t.expectEqualSlices(u8, &[_]u8{0xA0} ** 8 ++ &[_]u8{0xB0} ** 8 ++ &[_]u8{0xC0} ** 4, out.complete);
    try t.expectEqual(@as(usize, 0), rig.re.statistics().in_flight_packets);
}

test "reassembly: fragments out of order" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 4, .max_datagram = 100, .max_bytes = 4096 });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xA0);
    var b: [8]u8 = @splat(0xB0);
    var c: [4]u8 = @splat(0xC0);

    // Last first, then middle, then first.
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(2, false, 7, &c)));
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(1, true, 7, &b)));
    const out = rig.feed(local_src, local_dst, fragView(0, true, 7, &a));
    try t.expect(out == .complete);
    try t.expectEqualSlices(u8, &[_]u8{0xA0} ** 8 ++ &[_]u8{0xB0} ** 8 ++ &[_]u8{0xC0} ** 4, out.complete);
}

test "reassembly: duplicate fragments are dropped without destroying the context" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 4, .max_datagram = 100, .max_bytes = 4096 });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xA0);
    var b: [8]u8 = @splat(0xB0);

    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(0, true, 7, &a)));
    // RFC 8200 Section 4.5: "an implementation may choose to detect this case and drop exact
    // duplicate fragments while keeping the other fragments belonging to the same packet."
    try t.expectEqual(Outcome{ .duplicate = {} }, rig.feed(local_src, local_dst, fragView(0, true, 7, &a)));
    // The context survived the duplicate and still completes.
    const out = rig.feed(local_src, local_dst, fragView(1, false, 7, &b));
    try t.expectEqualSlices(u8, &[_]u8{0xA0} ** 8 ++ &[_]u8{0xB0} ** 8, out.complete);
    try t.expectEqual(@as(u64, 1), rig.re.statistics().counters.fragments_duplicate);
}

test "reassembly: replay of a completed datagram is dropped, not re-queued" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{
        .max_packets = 4,
        .max_datagram = 100,
        .max_bytes = 4096,
        .duplicate_window_ms = 1000,
    });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xA0);
    var b: [8]u8 = @splat(0xB0);

    _ = rig.feed(local_src, local_dst, fragView(0, true, 7, &a));
    _ = rig.feed(local_src, local_dst, fragView(1, false, 7, &b));
    try t.expectEqual(@as(usize, 0), rig.re.statistics().in_flight_packets);

    // A full replay inside the window costs nothing but a counter increment.
    try t.expectEqual(Outcome{ .duplicate = {} }, rig.feed(local_src, local_dst, fragView(0, true, 7, &a)));
    try t.expectEqual(Outcome{ .duplicate = {} }, rig.feed(local_src, local_dst, fragView(1, false, 7, &b)));
    try t.expectEqual(@as(usize, 0), rig.re.statistics().in_flight_packets);
    try t.expectEqual(@as(u64, 2), rig.re.statistics().counters.fragments_duplicate);
    try t.expectEqual(@as(u64, 1), rig.re.statistics().counters.datagrams_completed);

    // Once the window expires, a stray fragment starts a fresh (bounded) context.
    rig.clock.advance(1001);
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(1, false, 7, &b)));
    try t.expectEqual(@as(usize, 1), rig.re.statistics().in_flight_packets);
}

test "reassembly: overlapping fragments abandon the whole datagram (RFC 8200 4.5 error 5)" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 4, .max_datagram = 100, .max_bytes = 4096 });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xA0);
    var b: [8]u8 = @splat(0xB0);
    // Overlaps bytes 4..12, conflicting content.
    var overlap: [8]u8 = @splat(0xFF);

    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(0, true, 7, &a)));
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(1, true, 7, &b)));
    const out = rig.feed(local_src, local_dst, fragView(0, false, 7, &overlap));
    try t.expectEqual(Outcome{ .rejected = .Overlapping }, out);
    try t.expectEqual(@as(usize, 0), rig.re.statistics().in_flight_packets);
    try t.expectEqual(@as(u64, 1), rig.re.statistics().counters.datagrams_overlapped);
}

test "reassembly: M=1 fragment whose length is not a multiple of 8 is rejected (error 2)" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 4, .max_datagram = 100, .max_bytes = 4096 });
    defer rig.deinit();

    var odd: [7]u8 = @splat(0x11);
    const out = rig.feed(local_src, local_dst, fragView(0, true, 7, &odd));
    try t.expectEqual(Outcome{ .rejected = .FragmentLengthNotAligned }, out);
    try t.expectEqual(@as(usize, 0), rig.re.statistics().in_flight_packets);

    // The same length is fine when M = 0, because RFC 8200 Section 4.5 exempts the last fragment.
    var odd_last: [7]u8 = @splat(0x11);
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(1, false, 7, &odd_last)));
}

test "reassembly: fragments beyond the datagram limit are rejected (error 3)" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 4, .max_datagram = 32, .max_bytes = 4096 });
    defer rig.deinit();

    var chunk: [16]u8 = @splat(0x22);
    // offset 8 * 8 = 64, length 16 => end 80 > max_datagram 32.
    const out = rig.feed(local_src, local_dst, fragView(8, false, 7, &chunk));
    try t.expectEqual(Outcome{ .rejected = .ExceedsDatagramLimit }, out);
    try t.expectEqual(@as(usize, 0), rig.re.statistics().in_flight_packets);
}

test "reassembly: a non-final fragment past the known total length is inconsistent" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 4, .max_datagram = 100, .max_bytes = 4096 });
    defer rig.deinit();

    var last: [8]u8 = @splat(0x33);
    var beyond: [8]u8 = @splat(0x44);

    // Total length is established at 16 octets.
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(1, false, 7, &last)));
    // offset 3 => 24..32, past 16.
    const out = rig.feed(local_src, local_dst, fragView(3, true, 7, &beyond));
    try t.expectEqual(Outcome{ .rejected = .InconsistentLength }, out);
}

test "reassembly: incomplete datagrams time out (RFC 8200 Section 4.5 error 1)" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{
        .max_packets = 4,
        .max_datagram = 100,
        .max_bytes = 4096,
        .timeout_ms = 60_000,
    });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xA0);
    var b: [8]u8 = @splat(0xB0);
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(0, true, 7, &a)));
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(1, true, 7, &b)));
    try t.expectEqual(@as(usize, 1), rig.re.statistics().in_flight_packets);

    rig.clock.advance(59_999);
    try t.expectEqual(@as(usize, 0), rig.re.expire(rig.clock.now));
    try t.expectEqual(@as(usize, 1), rig.re.statistics().in_flight_packets);

    rig.clock.advance(1);
    try t.expectEqual(@as(usize, 1), rig.re.expire(rig.clock.now));
    try t.expectEqual(@as(usize, 0), rig.re.statistics().in_flight_packets);
    try t.expectEqual(@as(u64, 1), rig.re.statistics().counters.datagrams_timed_out);
    try t.expectEqual(@as(usize, 0), rig.re.statistics().buffered_bytes);
}

test "reassembly: timeout measured from the FIRST arriving fragment, not the last" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{
        .max_packets = 4,
        .max_datagram = 100,
        .max_bytes = 4096,
        .timeout_ms = 10_000,
    });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xA0);
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(0, true, 7, &a)));
    // Trickle a late fragment in, then let the first-fragment deadline pass.
    rig.clock.advance(9_000);
    var b: [8]u8 = @splat(0xB0);
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(1, true, 7, &b)));
    rig.clock.advance(1_000);
    try t.expectEqual(@as(usize, 1), rig.re.expire(rig.clock.now));
}

test "reassembly: the key includes source, destination and identification (RFC 8200 4.5)" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 8, .max_datagram = 100, .max_bytes = 8192 });
    defer rig.deinit();

    const src2 = try ipv6.Address.parse("2001:db8::2");
    const dst2 = try ipv6.Address.parse("2001:db8::3");
    var a: [8]u8 = @splat(0xA0);

    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(0, true, 1, &a)));
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(0, true, 2, &a)));
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(src2, local_dst, fragView(0, true, 1, &a)));
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, dst2, fragView(0, true, 1, &a)));
    try t.expectEqual(@as(usize, 4), rig.re.statistics().in_flight_packets);

    var keys: [8]Key = undefined;
    try t.expectEqual(@as(usize, 4), rig.re.activeKeys(&keys));
}

test "reassembly: multiple simultaneous reassemblies complete independently" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 8, .max_datagram = 100, .max_bytes = 8192 });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xAA);
    var b: [8]u8 = @splat(0xBB);
    var x: [8]u8 = @splat(0x11);
    var y: [8]u8 = @splat(0x22);

    _ = rig.feed(local_src, local_dst, fragView(0, true, 1, &a));
    _ = rig.feed(local_src, local_dst, fragView(1, true, 1, &b));
    _ = rig.feed(local_src, local_dst, fragView(0, true, 2, &x));
    _ = rig.feed(local_src, local_dst, fragView(1, true, 2, &y));

    // Each `complete` result borrows the reassembly buffer only until the next call, so consume
    // each one before offering the next fragment.
    {
        const o1 = rig.feed(local_src, local_dst, fragView(1, false, 2, &y));
        try t.expectEqualSlices(u8, &[_]u8{0x11} ** 8 ++ &[_]u8{0x22} ** 8, o1.complete);
    }
    {
        const o2 = rig.feed(local_src, local_dst, fragView(1, false, 1, &b));
        try t.expectEqualSlices(u8, &[_]u8{0xAA} ** 8 ++ &[_]u8{0xBB} ** 8, o2.complete);
    }
    try t.expectEqual(@as(usize, 0), rig.re.statistics().in_flight_packets);
    try t.expectEqual(@as(u64, 2), rig.re.statistics().counters.datagrams_completed);
}

test "reassembly: memory limit exhaustion evicts the oldest context" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 2, .max_datagram = 64, .max_bytes = 4096 });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xAA);
    _ = rig.feed(local_src, local_dst, fragView(0, true, 1, &a));
    rig.clock.advance(10);
    _ = rig.feed(local_src, local_dst, fragView(0, true, 2, &a));
    try t.expectEqual(@as(usize, 2), rig.re.statistics().in_flight_packets);

    // A third datagram evicts identification 1, the oldest.
    rig.clock.advance(10);
    _ = rig.feed(local_src, local_dst, fragView(0, true, 3, &a));
    try t.expectEqual(@as(usize, 2), rig.re.statistics().in_flight_packets);
    try t.expectEqual(@as(u64, 1), rig.re.statistics().counters.datagrams_evicted);

    var keys: [8]Key = undefined;
    const n = rig.re.activeKeys(&keys);
    try t.expectEqual(@as(usize, 2), n);
    for (keys[0..n]) |k| try t.expect(k.identification != 1);
}

test "reassembly: expired entries are reclaimed before eviction" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{
        .max_packets = 2,
        .max_datagram = 64,
        .max_bytes = 4096,
        .timeout_ms = 5_000,
    });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xAA);
    _ = rig.feed(local_src, local_dst, fragView(0, true, 1, &a));
    rig.clock.advance(6_000);
    // The sweep is the caller's responsibility (see `addFragment`), so a caller that never sweeps
    // sees the stale context. Sweep, then offer a second datagram.
    try t.expectEqual(@as(usize, 1), rig.re.expire(rig.clock.now));
    _ = rig.feed(local_src, local_dst, fragView(0, true, 2, &a));
    try t.expectEqual(@as(usize, 1), rig.re.statistics().in_flight_packets);
    // Expired, so a new datagram takes the free slot instead of evicting.
    rig.clock.advance(6_000);
    try t.expectEqual(@as(usize, 1), rig.re.expire(rig.clock.now));
    _ = rig.feed(local_src, local_dst, fragView(0, true, 3, &a));
    try t.expectEqual(@as(u64, 0), rig.re.statistics().counters.datagrams_evicted);
    try t.expectEqual(@as(u64, 2), rig.re.statistics().counters.datagrams_timed_out);
}

test "Limits.validate bounds max_packets to the slot index width" {
    // The slot index is a u16; a larger limit would reach an @intCast that panics.
    try t.expectError(
        error.TooManyPacketsLimit,
        (Limits{ .max_packets = reassembly_max_packets_limit + 1 }).validate(),
    );
    // At the limit the numbers must merely be internally consistent; `validate` does no allocation.
    try (Limits{
        .max_packets = reassembly_max_packets_limit,
        .max_bytes = reassembly_max_packets_limit * 9002 + (1 << 20),
    }).validate();
}

test "reassembly: too many chunks for one datagram is bounded" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{
        .max_packets = 2,
        .max_datagram = 512,
        .max_bytes = 4096,
        .max_chunks = 4,
    });
    defer rig.deinit();

    // Five disjoint 8-octet fragments starting at byte offsets 0, 16, 32, 48 and 64 cannot all be
    // tracked by a 4-entry chunk table. Gaps are left between the fragments so the table cannot
    // coalesce them away.
    var chunks: [5][8]u8 = undefined;
    for (&chunks, 0..) |*c, i| @memset(c, @truncate(0x30 + i));

    var i: u13 = 0;
    while (i < 4) : (i += 1) {
        const out = rig.feed(local_src, local_dst, fragView(@intCast(i * 2), true, 9, &chunks[i]));
        try t.expectEqual(Outcome{ .buffered = {} }, out);
    }
    // offset 8 * 8 = 64: disjoint from 0..8, 16..24, 32..40 and 48..56, but the table is full.
    const out = rig.feed(local_src, local_dst, fragView(8, true, 9, &chunks[4]));
    try t.expectEqual(Outcome{ .rejected = .TooManyFragments }, out);
}

test "reassembly: fragment payload is copied, not aliased (RFC 8200 buffers its own copy)" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 2, .max_datagram = 64, .max_bytes = 4096 });
    defer rig.deinit();

    var scratch: [8]u8 = @splat(0xAA);
    try t.expectEqual(Outcome{ .buffered = {} }, rig.feed(local_src, local_dst, fragView(0, true, 5, &scratch)));
    // Overwrite the caller's buffer: the reassembly must be unaffected.
    @memset(&scratch, 0xEE);
    var last: [8]u8 = @splat(0xBB);
    const out = rig.feed(local_src, local_dst, fragView(1, false, 5, &last));
    try t.expectEqualSlices(u8, &[_]u8{0xAA} ** 8 ++ &[_]u8{0xBB} ** 8, out.complete);
}

test "reassembly: adjacent fragments coalesce" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 2, .max_datagram = 256, .max_bytes = 4096 });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xAA);
    var b: [8]u8 = @splat(0xBB);
    var c: [8]u8 = @splat(0xCC);
    var d: [8]u8 = @splat(0xDD);

    // A 32-octet datagram: fragments at octet offsets 0, 8, 16 and 24, with only the last
    // carrying M = 0. Delivered as 16, 8, 24, 0 the chunk table must coalesce into a single
    // 0..32 entry and the final arrival completes it.
    _ = rig.feed(local_src, local_dst, fragView(2, true, 3, &c));
    _ = rig.feed(local_src, local_dst, fragView(1, true, 3, &b));
    _ = rig.feed(local_src, local_dst, fragView(3, false, 3, &d));
    switch (rig.feed(local_src, local_dst, fragView(0, true, 3, &a))) {
        .complete => |datagram| try t.expectEqualSlices(
            u8,
            &[_]u8{0xAA} ** 8 ++ &[_]u8{0xBB} ** 8 ++ &[_]u8{0xCC} ** 8 ++ &[_]u8{0xDD} ** 8,
            datagram,
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "reassembly: statistics counters" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 2, .max_datagram = 64, .max_bytes = 4096 });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xAA);
    var b: [8]u8 = @splat(0xBB);
    _ = rig.feed(local_src, local_dst, fragView(0, true, 1, &a));
    _ = rig.feed(local_src, local_dst, fragView(0, true, 1, &a)); // duplicate
    _ = rig.feed(local_src, local_dst, fragView(1, false, 1, &b));

    const s = rig.re.statistics();
    try t.expectEqual(@as(u64, 2), s.counters.fragments_accepted);
    try t.expectEqual(@as(u64, 1), s.counters.fragments_duplicate);
    try t.expectEqual(@as(u64, 1), s.counters.datagrams_completed);
    try t.expectEqual(@as(usize, 0), s.buffered_bytes);
    try t.expectEqual(@as(usize, 0), s.in_flight_packets);
}

test "reassembly: reset clears in-flight state" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 4, .max_datagram = 64, .max_bytes = 4096 });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xAA);
    _ = rig.feed(local_src, local_dst, fragView(0, true, 1, &a));
    _ = rig.feed(local_src, local_dst, fragView(0, true, 2, &a));
    try t.expectEqual(@as(usize, 2), rig.re.statistics().in_flight_packets);
    rig.re.reset();
    try t.expectEqual(@as(usize, 0), rig.re.statistics().in_flight_packets);
    try t.expectEqual(@as(usize, 0), rig.re.statistics().buffered_bytes);
}

test "reassembly: hasContext" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 2, .max_datagram = 64, .max_bytes = 4096 });
    defer rig.deinit();

    const key: Key = .{ .source = local_src, .destination = local_dst, .identification = 42 };
    try t.expect(!rig.re.hasContext(key));
    var a: [8]u8 = @splat(0xAA);
    _ = rig.feed(local_src, local_dst, fragView(0, true, 42, &a));
    try t.expect(rig.re.hasContext(key));
}

test "reassembly: an empty atomic datagram is rejected" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{ .max_packets = 2, .max_datagram = 64, .max_bytes = 4096 });
    defer rig.deinit();
    const empty: [0]u8 = .{};
    const out = rig.feed(local_src, local_dst, fragView(0, false, 1, &empty));
    try t.expectEqual(Outcome{ .rejected = .InconsistentLength }, out);
}

test "fuzz: addFragment never panics on arbitrary fragment data" {
    const Fuzz = struct {
        fn fuzzer(_: void, smith: *std.testing.Smith) anyerror!void {
            const gpa = std.testing.allocator;
            var re = Reassembler.init(gpa, .{
                .limits = .{ .max_packets = 2, .max_datagram = 128, .max_bytes = 1024 },
                .clock = undefined,
            }) catch return;
            defer re.deinit();

            var buf: [256]u8 = undefined;
            const n: usize = smith.slice(&buf);
            // Random-ish offset and M flag.
            const off: u13 = @truncate(smith.value(u16));
            const more = smith.value(bool);
            const id = smith.value(u32);
            _ = re.addFragment(ipv6.Address.loopback, ipv6.Address.any, .{
                .next_header = etherip.ip_protocol_number,
                .reserved = 0,
                .fragment_offset = off,
                .res = 0,
                .more_fragments = more,
                .identification = id,
                .data = buf[0..n],
            }, 0);
        }
    };
    try t.fuzz({}, Fuzz.fuzzer, .{});
}


test "reassembly: the 65 535 cap includes the Per-Fragment header octets" {
    const gpa = t.allocator;
    // 8 reserved Per-Fragment octets: the Fragmentable Part may be at most 65527 octets.
    var rig = try TestRig.init(gpa, .{
        .max_packets = 2,
        .max_datagram = 1 << 20,
        .max_bytes = 1 << 21,
        .per_fragment_header_len = 8,
    });
    defer rig.deinit();

    // Offset 65520 with 8 octets lands exactly on 65528; adding the 8 reserved octets gives
    // 65536, one over the limit.
    var chunk: [8]u8 = @splat(0x77);
    const over = rig.feed(local_src, local_dst, fragView(8190, false, 1, &chunk));
    try t.expectEqual(Outcome{ .rejected = .ExceedsDatagramLimit }, over);

    // One octet lower fits.
    var ok_chunk: [8]u8 = @splat(0x77);
    const under = rig.feed(local_src, local_dst, fragView(8189, false, 1, &ok_chunk));
    try t.expectEqual(Outcome{ .buffered = {} }, under);
}

test "reassembly: expireInto reports abandoned datagrams so the caller can originate ICMPv6" {
    const gpa = t.allocator;
    var rig = try TestRig.init(gpa, .{
        .max_packets = 4,
        .max_datagram = 100,
        .max_bytes = 4096,
        .timeout_ms = 1000,
    });
    defer rig.deinit();

    var a: [8]u8 = @splat(0xA0);
    _ = rig.feed(local_src, local_dst, fragView(0, true, 1, &a)); // has the first fragment
    _ = rig.feed(local_src, local_dst, fragView(1, true, 2, &a)); // does not

    var out: [4]Expired = undefined;
    rig.clock.advance(1001);
    try t.expectEqual(@as(usize, 2), rig.re.expireInto(&out, rig.clock.now));
    try t.expect(out[0].have_first);
    try t.expect(!out[1].have_first);
    try t.expectEqual(@as(u32, 1), out[0].key.identification);
    try t.expectEqual(@as(u32, 2), out[1].key.identification);
    try t.expect(local_src.eql(out[0].key.source));
}
