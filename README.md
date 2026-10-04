# EtherIP over IPv6 — a production-quality Zig implementation

A tunnel that carries **IEEE 802.3 / Ethernet II frames inside IPv6 datagrams** using the EtherIP
wire format from **RFC 3378**, and performs **IPv6 source fragmentation** so that a jumbo overlay
frame can cross an underlay whose MTU is far smaller.

The headline scenario works and is proven by tests:

```
overlay MTU 9000  ->  7 outer IPv6 packets  ->  underlay MTU 1500
                    reassemble(fragment(frame)) == frame, byte for byte
```

```
$ zig build run -- selftest
EtherIP over IPv6 self test
  local           2001:db8:100::1
  remote          2001:db8:200::1
  underlay MTU    1500
  overlay MTU     9000
  tunnel overhead 48 (IPv6 40 + Fragment 8)
  max frag data   1448
  max wire size   1496

encapsulated 9000-octet frame -> fragmented
  outer packets  7
  largest packet 1496 octets (must be <= 1500)

received 7 outer packets, decapsulated 1 frame(s)
  frame length   9000

RESULT: reassemble(fragment(frame)) == frame  (9000 octets, byte identical)
```

---

## Table of contents

1. [What EtherIP is](#1-what-etherip-is)
2. [RFC 3378 wire format](#2-rfc-3378-wire-format)
3. [Why protocol number 97](#3-why-protocol-number-97)
4. [How IPv6 transport is implemented](#4-how-ipv6-transport-is-implemented)
5. [RFC 3378 vs the IPv6 adaptation — the distinction that matters](#5-rfc-3378-vs-the-ipv6-adaptation--the-distinction-that-matters)
6. [How IPv6 fragmentation works](#6-how-ipv6-fragmentation-works)
7. [How a 9000-byte overlay frame traverses a 1500-byte underlay](#7-how-a-9000-byte-overlay-frame-traverses-a-1500-byte-underlay)
8. [Reassembly behaviour](#8-reassembly-behaviour)
9. [PMTUD](#9-pmtud)
10. [TCP MSS clamping](#10-tcp-mss-clamping)
11. [Security considerations](#11-security-considerations)
12. [Why not just use EtherIP?](#12-why-not-just-use-etherip)
13. [Known limitations](#13-known-limitations)
14. [Building, testing, and using the CLI](#14-building-testing-and-using-the-cli)
15. [Project layout](#15-project-layout)
16. [Documentation index](#16-documentation-index)

---

## 1. What EtherIP is

EtherIP is a **very lightweight encapsulation format**. It prepends a 16-bit header to a complete
Ethernet frame and puts the result in an IP datagram. That is the entire protocol.

RFC 3378 §1 explains its origin: *"EtherIP was first designed and developed in 1991. This document
was written to document the protocol for informational purposes and to provide historical context
for the assignment of IP protocol 97 by IANA."*

Three consequences follow, and this implementation honours all three:

- **EtherIP is Informational, not Standards Track.** RFC 3378's own status section: *"This memo
  provides information for the Internet community. It does not specify an Internet standard of any
  kind."* RFC 3378 §1 adds: *"the standards track protocols produced by these IETF working groups
  should be used instead of EtherIP."* This project makes no claim that EtherIP is a standard.
- **EtherIP carries non-IP traffic.** Its purpose is to bridge Ethernet segments across an IP
  network, including traffic whose layer 3 is not IP or is encrypted and therefore unroutable.
  That is exactly why the tunnelled payload is an *Ethernet frame*, not an IP packet.
- **EtherIP has no security and no loop protection.** See [§11](#11-security-considerations).

## 2. RFC 3378 wire format

RFC 3378 §2 defines the entire EtherIP header as 16 bits:

```
 0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|               |                                               |
|    VERSION    |                   RESERVED                    |
|               |                                               |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

| Field | Bits | Requirement | RFC 3378 |
|---|---|---|---|
| Version | 0–3 | MUST be 3 (`0b0011`) | §2, §3 step 1, §4 step 1 |
| Reserved | 4–15 | MUST be 0 when transmitting | §2, §3 step 1 |
| Reserved (receive) | 4–15 | *"Frames with other values MUST be discarded."* | §4 step 1 |

The encapsulated payload is *"a complete Ethernet or IEEE 802.3 frame of any type less the frame
check sequence (FCS) value"* (§2). IEEE 802.1Q VLAN frames are explicitly in scope (§1, §2), so
VLAN and QinQ tags are carried **inside** the EtherIP payload, verbatim.

On transmission: *"The MAC frame MUST NOT include the FCS"* (§3 step 1); the FCS is the receiving
LAN's job on egress (§4 step 3). **This implementation never adds, strips, or inspects an FCS.**

### Strict validation, and why there is no lenient mode

RFC 3378 §4 step 1 is unambiguous: a Version other than 3, or a non-zero Reserved field, means
**discard**. RFC 3378 §2 also records that *"Earlier versions of this protocol used an 8-bit header
field. The Xerox Ethernet Tunnel (XET) employed the 8-bit header."*

So `src/etherip.zig` rejects:

- every Version value other than 3, including the legacy XET encoding — with **no** fallback
  interpretation;
- every non-zero Reserved value.

There is deliberately **no configuration knob** for leniency, because a second, non-conformant mode
would have no RFC basis. Some stacks warn-and-continue to interoperate with buggy senders; this one
does not, and says so. See `docs/RFC-ANALYSIS.md` §5.1.

## 3. Why protocol number 97

RFC 3378 §5: *"IANA has assigned IP protocol value 97 (decimal) for EtherIP."*

The IANA *Assigned Internet Protocol Numbers* registry lists:

| Decimal | Keyword | Name | IPv6 Extension Header | Reference |
|---|---|---|---|---|
| 97 | `ETHERIP` | Ethernet-within-IP Encapsulation | *(empty)* | RFC 3378 |

The registry's Note is the key to IPv6 use: *"In Internet Protocol version 4 (IPv4) [RFC 791] there
is a field called 'Protocol' to identify the next level protocol. In Internet Protocol version 6
(IPv6) [RFC 8200], this field is called the 'Next Header' field."*

And the **"IPv6 Extension Header" column is empty for 97**, meaning EtherIP is registered as an
*upper-layer* protocol, not an extension header. RFC 8200 §4 confirms this reading: *"Extension
headers are numbered from IANA IP Protocol Numbers … When processing a sequence of Next Header
values in a packet, the first one that is not an extension header indicates that the next item in
the packet is the corresponding upper-layer header."*

## 4. How IPv6 transport is implemented

There is **no UDP and no TCP**. The EtherIP datagram is the IPv6 payload:

```
+---------------------------+
| Outer IPv6 Header         |  Next Header = 97 (EtherIP)
+---------------------------+
| EtherIP Header            |  Version = 3, Reserved = 0
+---------------------------+
| Ethernet Frame            |  destination MAC, source MAC,
|                           |  [VLAN/QinQ tags], EtherType,
|                           |  payload — no FCS
+---------------------------+
```

When the datagram does not fit the path MTU, a Fragment header is inserted *between* the IPv6
header and the EtherIP header:

```
+----------+---------------+-------------------------------+
| IPv6     | IPv6 Fragment | EtherIP header | Ethernet     |
| header   | header        | (in fragment 1)| frame part   |
| Next     | offset, M,    |               |              |
| Header=44| Res, ID       |               |              |
+----------+---------------+-------------------------------+
```

No other encapsulation is used or supported.

## 5. RFC 3378 vs the IPv6 adaptation — the distinction that matters

**RFC 3378 does not describe IPv6 EtherIP.** Concretely:

- §1 and §2 speak of *"internet datagrams"* generically; §2, §3 step 3 and §4 step 5 each name only
  the **IPv4** Protocol field.
- The words "IPv6", "Next Header" and "IPv6-Frag" do not appear in RFC 3378 at all.

So this project makes the following explicit claim:

> Carrying the EtherIP datagram in IPv6 with `Next Header = 97` is a **transport adaptation** of
> the EtherIP datagram defined by RFC 3378. The 16-bit EtherIP header is byte-for-byte unchanged.
> **No new EtherIP header field is invented.** Every EtherIP-layer statement is traceable to
> RFC 3378; every IPv6-layer statement is traceable to RFC 8200 / 8201 / 4443.

The full derivation, including why the IANA registry and RFC 8200 §4 close the gap without touching
the wire format, is in [`docs/RFC-ANALYSIS.md` §2](docs/RFC-ANALYSIS.md).

## 6. How IPv6 fragmentation works

RFC 8200 §4.5, with its **original-packet model as corrected by Errata ID 5945** (Verified,
Technical, 2020-02-03):

```
original packet:
+------------------+-----------------------------//----------------+
|  Per-Fragment    |               Fragmentable                    |
|    Headers       |                   Part                        |
+------------------+-----------------------------//----------------+
```

Applied here:

| Original-packet component | In this tunnel |
|---|---|
| Per-Fragment Headers | the 40-octet IPv6 header (Next Header = 44, per-fragment Payload Length) |
| Upper-Layer header | the 16-bit **EtherIP** header |
| **Fragmentable Part** | **`EtherIP header || Ethernet frame`** |

Because the EtherIP header *is* the upper-layer header, and the upper-layer header is the first
thing inside the Fragmentable Part, the EtherIP header is fragmented along with the frame. Fragment
Offset 0 addresses the first nibble of the EtherIP Version field.

Rules implemented, all from RFC 8200 §4.5:

- Fragmentation is performed **only by the source**; routers never fragment.
- Fragment Offset is in **8-octet units**; every fragment except the last is a multiple of 8 octets.
- Fragments never overlap.
- All fragments of one datagram share a Fragment **Identification**, unique among recently sent
  fragmented packets with the same (Source, Destination).
- The upper-layer header must be in the **first** fragment (so a receiver can validate the EtherIP
  header from fragment 1 alone).
- Payload Length is recomputed per fragment and must never overflow 16 bits.

Identification generation follows RFC 8200 §4.5's pointer to RFC 7739 §5.2: a PRNG draw per
fragmented datagram. That is also a security control — RFC 7739 §3 notes that predictable Fragment
IDs enable off-path spoofing. Supply real entropy via `Options.fragment_id_seed`; the fallback is
documented as predictable.

## 7. How a 9000-byte overlay frame traverses a 1500-byte underlay

The MTU arithmetic is computed, never hard-coded. `zig build run -- config-check` prints it:

```
derived MTU arithmetic
  IPv6 header                40
  reserved ext header bytes  0
  IPv6 Fragment header       8
  EtherIP header             2   (inside the fragmentable part)
  tunnel overhead            48
  available                  1452
  max fragment payload       1448  (floor to 8-octet units)
  max outer packet           1496
  max unfragmented datagram  1460
  max reassembly datagram    9002

  a 9000-octet frame becomes a 9002-octet EtherIP datagram, i.e. 7 fragment(s)
```

Step by step:

```
Fragmentable Part                 = EtherIP header (2) + Ethernet frame (9000) = 9002 octets
available under the MTU           = 1500 - 40 (IPv6) - 8 (Fragment)            = 1452 octets
largest legal fragment payload    = floor(1452 / 8) * 8                        = 1448 octets
largest outer packet              = 40 + 8 + 1448                               = 1496 octets  <= 1500  OK

fragments                         = ceil(9002 / 1448)                           = 7
  fragment 1  offset    0  1448 octets  EtherIP header + first 1446 frame octets
  fragment 2  offset  181  1448 octets
  fragment 3  offset  362  1448 octets
  fragment 4  offset  543  1448 octets
  fragment 5  offset  724  1448 octets
  fragment 6  offset  905  1448 octets
  fragment 7  offset 1086   314 octets  M = 0
```

Two things are easy to get wrong and are called out here:

1. **The EtherIP header is not "tunnel overhead" for fragmentation purposes.** It is inside the
   fragmentable payload. That is exactly why 9000 bytes of frame still fits 1496-byte packets.
2. **The 4 lost octets** (1452 → 1448) are the cost of RFC 8200's 8-octet alignment. They are
   recovered on the final fragment, which has no alignment requirement.

Try it with any MTU you like:

```
$ zig build run -- config-check --underlay-mtu 1280 --overlay-mtu 9000
$ zig build run -- config-check --underlay-mtu 9000 --overlay-mtu 9000
```

Tests cover 1280, 1500, 4000, 9000 and 16000 underlay MTUs, plus 1450-, 2000-, 4000- and
9000-octet frames, and the just-below / exactly-at / just-above threshold cases (1445, 1446, 1447
octets).

## 8. Reassembly behaviour

The receiver implements RFC 8200 §4.5 in full:

| Situation | Behaviour | RFC 8200 §4.5 |
|---|---|---|
| Fragment Offset 0 **and** M 0 | processed immediately, no queue state created | "does not need any further reassembly" |
| M 1, length not a multiple of 8 | fragment discarded, ICMPv6 Parameter Problem Code 0 (Pointer = Payload Length field) | error condition 2 |
| offset + length beyond 65 535 | fragment discarded, ICMPv6 Parameter Problem Code 0 (Pointer = Fragment Offset field) | error condition 3 |
| first fragment missing headers through the upper layer | discarded, ICMPv6 Parameter Problem Code 3 (Pointer = 0) | error condition 4 |
| incomplete after the timeout | whole reassembly abandoned, all fragments discarded, ICMPv6 Time Exceeded Code 1 if the offset-0 fragment was seen | error condition 1 |
| overlapping fragments | **whole reassembly abandoned, all fragments discarded, no ICMP at all** | error condition 5 |
| exact duplicate fragment | dropped, the other fragments are kept | "an implementation **may** choose to detect this case and drop exact duplicate fragments" |
| replay of an already-completed datagram | dropped by a fixed-capacity recently-completed filter | *no RFC basis — hardening, see below* |

The reassembly key is `(source IPv6 address, destination IPv6 address, fragment identification)`,
exactly as RFC 8200 §4.5 specifies.

### Bounded memory

There is **no unbounded `HashMap`**. At construction:

- one flat byte pool holds every context's payload buffer (`max_reassembly_packets ×
  max_datagram` octets, one allocation);
- one flat `Chunk` array holds every context's fragment table;
- the key index is a `HashMapUnmanaged` whose capacity is reserved once and never grown;
- fragment payload is **copied** into the context's own buffer, so the receive buffer is reusable
  immediately and a fragment cannot be modified after the fact.

Expired contexts are swept on every insert. If the table is still full, the **oldest** context is
evicted to admit the new one and `reassembly_evicted` is incremented. Eviction rather than
drop-new is a deliberate choice: with drop-new, one attacker-started context pins the table
permanently. The reasoning is in `docs/RFC-ANALYSIS.md` §5.8; the choice is documented as
implementation-specific.

### The recently-completed filter

A replayed fragment of a datagram that has already been delivered has, per RFC 8200, no defined
meaning. Without a record of completions, each replay of a final fragment would allocate a fresh,
permanently-incomplete context — a cheap memory-exhaustion vector. A fixed-capacity ring of the last
`max_recent_completions` completed keys (default 64) turns replays into a counter increment. This
has no RFC basis and is documented as hardening in `docs/RFC-ANALYSIS.md` §5.7.

### Timeout

`reassembly_timeout_ms` is configurable but validated to `1…60000`. RFC 8200 §4.5 requires
abandonment *"within 60 seconds of the reception of the first-arriving fragment"*, so a longer value
is non-conformant and rejected at startup. The default is 60 000. Timing is measured from the
**first** fragment received, not the most recent.

## 9. PMTUD

Three values are maintained and never conflated:

| Value | Source | Meaning |
|---|---|---|
| `configured_underlay_mtu` | configuration | the local link MTU |
| `discovered_path_mtu` | ICMPv6 Packet Too Big | unknown until a PTB arrives |
| `effective_path_mtu` | derived | `min(configured, discovered)`, floored at 1280 |

`effective_path_mtu` feeds both the fragment budget and the MSS budget, so **no code path assumes
1500**.

Implemented from RFC 8201 §4 and §5.2:

- a PTB reporting an MTU below the IPv6 minimum link MTU (1280) is **discarded**;
- the estimate is **never** raised in response to a PTB;
- the estimate is **never** reduced below 1280;
- a reduction immediately shrinks the fragments emitted, so the tunnel never keeps producing
  fragments that are themselves too large;
- `pmtu_updates` counts each change and the change is logged.

Packet Too Big parsing is RFC 4443 §3.2: Type 2, Code 0 (**ignored on receipt**), and a 32-bit MTU
field that is the **next-hop link MTU as-is** — no header size is subtracted, unlike IPv4's RFC 1191.
The ICMPv6 checksum is verified over the RFC 8200 §8.1 pseudo-header before any field is trusted.

Probe-for-increase (RFC 8201 §4's "not less than 5 minutes") is recorded in `Pmtu` but not enabled;
tunnels that fragment anyway have no incentive to probe.

## 10. TCP MSS clamping

**Optional, off by default, and never a substitute for fragmentation.**

```toml
mss_clamping_enabled = true
mss_clamp = null      # auto
# or
mss_clamp = 1392      # explicit
```

EtherIP works identically without it. And it cannot help a 9000-octet frame at all — there is no
TCP MSS to shrink — which is why fragmentation is unconditional and independent.

### How the safe MSS is computed

Nothing is hard-coded:

```
effective_path_mtu  = min(configured_underlay_mtu, discovered_path_mtu)     RFC 8201 5.2
effective_inner_mtu = effective_path_mtu - 40 (outer IPv6) - 2 (EtherIP)
clamp               = effective_inner_mtu - inner_ip_header_len - inner_tcp_header_len
further limited by  overlay_mtu and any explicit mss_clamp
```

With `effective_path_mtu = 1500`:

| Inner stack | Arithmetic | Clamp |
|---|---|---|
| Ethernet II + IPv4 + TCP (20 + 20) | `1500 − 40 − 2 − 20 − 20` | **1418** |
| Ethernet II + IPv6 + TCP (40 + 20) | `1500 − 40 − 2 − 40 − 20` | **1398** |

With the IPv6 minimum link MTU (1280) they become 1198 and 1178. VLAN tags are not subtracted
because the MSS is a property of the inner IP/TCP pair and the EtherIP datagram — Ethernet header
included — already fits the tunnel.

### Scope, deliberately narrow

- Ethernet II, with any 802.1Q / 802.1ad tags.
- IPv4 or IPv6 as the inner network layer; IPv6 extension headers are walked **in order**
  (RFC 8200 §4).
- A **fragmented** inner IPv6 SYN is refused, not mis-clamped: a non-zero Fragment Offset means the
  TCP header may be split across fragments.
- **SYN set and ACK clear only.** RFC 9293 §3.1 makes the MSS option meaningful only in a SYN.
  Simultaneous-open SYN-ACKs are left alone.
- Only when an MSS option is **present** and **larger** than the target. A SYN without an MSS
  option is not given an invented one — RFC 9293 makes the option optional.
- Only when every header parses safely. Anything unparseable leaves the frame untouched.

**Every unrelated TCP option is preserved byte for byte.** The tests assert this precisely: after
clamping, no octet outside the 2-octet MSS option and the 2-octet TCP Checksum field may differ. The
TCP checksum is recomputed over the correct pseudo-header (RFC 9293 §3.1 for IPv4, RFC 8200 §8.1 for
IPv6).

## 11. Security considerations

**EtherIP provides no confidentiality, no integrity, and no authentication.** This project adds
none, and does not pretend otherwise.

RFC 3378 §6 notes EtherIP *"can be used to enable the transfer of encrypted Ethernet … frame
payloads"*, but that describes tunnelling already-encrypted traffic — not a property of EtherIP
itself. RFC 3378 §2 is blunt about the integrity story: *"The IP checksum does not provide integrity
protection for the Ethernet/IEEE 802.3 frame, so some higher-layer protocol encapsulated by the
Ethernet/IEEE 802.3 frame is expected to provide the integrity protection."* IPv6 removed the
header checksum entirely, so the outer header is not protected either.

RFC 3378's own recommendation is to wrap it: *"One solution is to protect the IP datagrams that
carry EtherIP with IPsec [RFC2401]."*

### Fragmentation-specific hardening

Source fragmentation is a well-known attack surface, and RFC 8200 §4.5 is written with that in mind.
Implemented defences:

| Threat | Mitigation |
|---|---|
| Overlapping fragments | RFC 8200 error condition 5: abandon the **whole** reassembly, discard every fragment, send **no** ICMP |
| Fragment storms | `max_reassembly_packets` and `max_reassembly_bytes`; expired contexts swept first; oldest evicted |
| Memory exhaustion via incomplete datagrams | fixed pool; `reassembly_timeout_ms` (RFC 8200's 60 s ceiling enforced) |
| Duplicate-fragment floods | duplicate detection, plus the recently-completed filter |
| Over-long / overflowing fragment IDs and sizes | 16-bit Payload Length cap enforced (RFC 8200 error condition 3); `u32` arithmetic with checked addition |
| Malformed IPv6 / EtherIP / Ethernet headers | every parser returns an error; **no parser panics on malformed input**, proven by fuzz targets |
| Truncated packets | bounds are checked before every field access; zero-copy sub-slices, never reads past the input |
| Extension-header chains crafted to loop | bounded walk (`max_extension_headers = 8`) |
| VLAN tag stacks crafted to loop | bounded walk (`max_vlan_depth = 4`) |
| Predictable Fragment IDs (off-path spoofing) | PRNG-seeded Identifications (RFC 7739 §5.2); supply real entropy via `Options.fragment_id_seed` |
| Unbounded ICMPv6 error generation | bounded queue; overflow counted |
| Spoofed ICMPv6 errors (RFC 4443 §2.4 (e.6)) | no error is originated for a packet whose source is the unspecified address or multicast |
| Forged Packet Too Big degrading the path MTU | RFC 8201 §4 validation against a ring of recently transmitted packets |
| Tunnel loops | **not solved** — see below |

**No parser panics on malformed network input.** `src/tests/` contains `std.testing.fuzz` targets
for the IPv6 parser, the EtherIP parser, the Ethernet parser, the MSS clamp, the checksum, and
decapsulation of arbitrary packets, plus 4 000-iteration randomised stress sweeps.

### Tunnel loops are unfixable here

RFC 3378 §1: EtherIP *"does not provide protection against infinite loops"*, and: *"Infinite loops
can result if the topology is not restricted to a tree."* The abstract says the same. The EtherIP
header carries no TTL and no loop token, so nothing in the encapsulation can detect a loop.
Mitigation is topological — RFC 3378 §1's advice: keep the tunnel topology a tree, and choose
tunnelling-selection rules carefully so the same frame is not re-tunnelled between peers, especially
when broadcast or multicast destination MACs are the selection criterion.

### Firewall caveat

RFC 3378 §6: *"if a firewall is configured to permit communication using EtherIP, then additional
checking of each frame is probably necessary to ensure that the security policy that the firewall is
installed to enforce is not violated."*

## 12. Why not just use EtherIP?

RFC 3378 §1: *"In general, the standards track protocols produced by these IETF working groups should
be used instead of EtherIP."* EtherIP is a 1991 design documented in 2002 as historical context.
Plausible modern alternatives:

| Alternative | Why it may be preferable |
|---|---|
| **IPsec (RFC 4303)** | Standard cryptographic protection and replay defence. RFC 3378 §6 suggests it explicitly. ESP adds IPv6 extension headers, so MTU budgeting must account for them — `reserved_per_fragment_ext_bytes` exists for exactly this. |
| **WireGuard** | Modern, minimal, authenticated key exchange; MTU-aware. |
| **GENE / GSO tunnel encapsulation** | Standard (drafted and widely deployed) Ethernet-over-IP with sequence numbers, so loss is detected rather than silent. |
| **VXLAN (RFC 7348)** | Adds an 8-octet control header and, crucially, a **24-bit VXLAN Segment ID** — gives multi-tenant domain separation that EtherIP has no equivalent of. Requires its own fragmentation story. |
| **Ethernet Next Header 143 (RFC 8986 §10.1)** | IANA has assigned value **143 "Ethernet"** for Ethernet carried as an IPv6 upper-layer protocol, used by SRv6 `H.Encaps.L2`. Standards-track, and it composes with segment routing. |

Choose EtherIP when you specifically need maximum interoperability with existing Cisco XTS-style
infrastructure, when you cannot add even an 8-byte header, or when a legacy peer requires it.
Otherwise, prefer a protocol that authenticates its peers.

## 13. Known limitations

- **The IPv6 EtherIP adaptation is ours.** RFC 3378 does not describe it. Everything specific to it
  (source fragmentation of EtherIP, reassembly of EtherIP, the ICMPv6 error generation a destination
  node owes, the reassembly bounds, the eviction policy, the recently-completed filter) is an
  implementation extension, documented as such in `docs/RFC-ANALYSIS.md` §7.3 and §7.4.
- **No Jumbograms.** RFC 2675 support is not implemented; `Payload Length == 0` with trailing octets
  is rejected rather than mis-parsed. This caps `overlay_mtu` at 65 533.
- **No IPv4 tunnel endpoints.** The brief specifies IPv6-only, and the code is IPv6-only.
- **No AH/ESP.** The receive path recognises them and ignores such packets rather than pretending to
  validate them. This tunnel never inserts IPsec.
- **`reserved_per_fragment_ext_bytes` must be 0.** RFC 8200 §4.5 requires the IPv6 header's Next
  Header to name the *first* Per-Fragment header, so reserving octets without supplying real headers
  would emit packets a receiver must reject. `Config.validate` refuses a non-zero value; the MTU
  arithmetic still accounts for a reserve (`fragment.calculateFragmentPayloadSize`) for callers that
  encapsulate themselves, and `Fragmenter.EmitParams` accepts real header octets.
- **Fragment-offset-zero retry of the EtherIP header.** RFC 8200 §4.5 says only the offset-zero
  fragment's Fragment-header Next Header is used; a peer that sets it to something other than 97 in
  later fragments is tolerated.
- **The Linux `AF_PACKET` backend is blocking.** It has no `poll`/event-loop integration, and
  `open()` takes an interface *index* rather than a name (the library has no libc dependency; see
  `src/platform.zig`). A DPDK backend is not implemented.
- **No daemon.** The CLI is a debugging and validation tool. A deployment needs a supervisor,
  a transmit/receive loop, and NIC binding.
- **Single-threaded counters.** `stats.Counters` uses plain `u64`s. Shard `Tunnel` per thread and
  sum snapshots for a multi-threaded deployment.
- **`Fragment` Identification seeding.** Without `Options.fragment_id_seed` the fallback seed is
  documented as predictable. Pass OS entropy in production.
- **`zig build test --fuzz` does not work on Zig 0.16.0.** `-ffuzz` fails to compile the compiler's
  own `test_runner.zig` (`builtin.StackTrace` vs `std.debug.StackTrace` at
  `test_runner.zig:566`) — a toolchain bug unrelated to this package. The `std.testing.fuzz` targets
  here still run in normal mode (Smith-driven, with a fresh seed per build), and
  `src/tests/tests.zig` adds 4 000-iteration randomised stress sweeps that any `zig build test`
  performs.
- **No PMTU probe-for-increase.** Recorded in `Pmtu`, not enabled.

## 14. Building, testing, and using the CLI

Requirements: **Zig 0.16.0**. No libc, no third-party dependencies.

```bash
zig build                 # build zig-out/bin/etherip_dpdk
zig build test            # 197 tests
zig build test -Doptimize=ReleaseSafe
```

### `selftest`

Full end-to-end exercise in memory. No privileges, no sockets.

```bash
zig build run -- selftest
```

### `config-check`

Validate a configuration and print the derived MTU arithmetic.

```bash
zig build run -- config-check
zig build run -- config-check --local 2001:db8:100::1 --remote 2001:db8:200::1 \
                              --underlay-mtu 1280 --overlay-mtu 9000
```

Invalid configurations are rejected with the specific RFC constraint that failed, e.g.
`UnderlayMtuBelowIpv6Minimum`, `OverlayMtuExceedsPayloadLength`,
`ReassemblyTimeoutTooLong`, `FragmentationDisabledWithJumboOverlay`.

### `inspect`

Decode an IPv6/EtherIP packet from a hex dump on stdin. Useful for diagnosing a capture without
Wireshark.

```bash
tcpdump -r sample.pcap -w - | xxd -p -c0 | tr -d '\n' | zig build run -- inspect
```

Output walks RFC 8200 §3 → §4 → §4.5 → RFC 3378 → Ethernet, and flags an M=1 fragment whose length is
not a multiple of 8 (which RFC 8200 requires be discarded).

### `emit-sample`

Write a `pcap` of a full 9000-over-1500 conversation, ready for Wireshark or tcpdump.

```bash
zig build run -- emit-sample --out etherip-sample.pcap
tcpdump -r etherip-sample.pcap -nn -vv
```

```
reading from file etherip-sample.pcap, link-type EN10MB (Ethernet), snapshot length 65535
09:00:00.000000 IP6 2001:db8:100::1 > 2001:db8:200::1: frag (0|1448)  ip-proto-97 1448
09:00:00.000001 IP6 2001:db8:100::1 > 2001:db8:200::1: frag (1448|1448)
...
```

`ip-proto-97` and `frag (0|1448)` are exactly what the RFCs predict: IANA protocol 97 inside an
IPv6 Fragment header, with 8-octet fragment offsets.

### `stats`

Print the statistics schema and the ICMPv6 types this endpoint originates.

### Capture structure

Unfragmented:

```
Ethernet II (link-layer framing added by the NIC or AF_PACKET, not by the tunnel)
  IPv6
    Next Header: 97 (EtherIP)
      EtherIP: Version 3, Reserved 0
        Ethernet frame (no FCS)
```

Fragmented:

```
Ethernet II
  IPv6
    Next Header: 44 (Fragment)
      Fragment Header: Next Header 97, Offset, Res 0, M, Identification
        EtherIP header (fragment 1 only) + Ethernet frame fragment
```

## 15. Project layout

```
src/
  main.zig          CLI: selftest, config-check, inspect, emit-sample, stats
  root.zig          library root; re-exports and documents every module
  etherip.zig       RFC 3378 header: encode, decode, strict validation
  ethernet.zig      Ethernet II / 802.1Q / 802.1ad parsing and validation
  ipv6.zig          RFC 8200 header, extension-header chain, RFC 4291 addresses
  fragment.zig      MTU arithmetic and RFC 8200 source fragmentation
  reassembly.zig    bounded, overlap-aware fragment reassembly
  icmpv6.zig        RFC 4443 Packet Too Big; RFC 8200 error generation
  mss_clamp.zig     optional TCP MSS clamping
  checksum.zig      RFC 1071 checksum and IPv4/IPv6/TCP pseudo-headers
  config.zig        configuration and startup validation
  tunnel.zig        encapsulation, decapsulation, PMTUD, statistics
  overlay.zig       L2 interface abstraction and its EtherIP binding
  platform.zig      raw-IPv6 transport vtable, in-memory link, Linux AF_PACKET
  stats.zig         counters and snapshot rendering
  tests/
    tests.zig       cross-module fragmentation, round-trip, property, stress
                    and packet-capture tests
docs/
  RFC-ANALYSIS.md   pre-implementation RFC analysis, ambiguities, decisions
  COMPLIANCE.md     requirement -> RFC -> implementation -> test matrix
etherip.conf        example configuration
```

### Design notes

- **No allocation on the packet fast path.** `Tunnel` takes `tx_scratch` and `rx_scratch` from the
  caller; `Fragmenter` owns one reusable buffer; the fragment sink is a callback, so the tunnel never
  allocates to send. The only allocations are in `init` (the reassembly pools) and in a statistics
  snapshot.
- **Zero-copy parsing** throughout: `parseHeader`, `parseExtensionChain`, `etherip.parse`, and
  `ethernet.parse` return sub-slices of the input and never copy.
- **Explicit error handling.** Every parser returns a typed error set; no `@panic`, no `unreachable`
  on network input, no `catch unreachable` on untrusted data.
- **Checked arithmetic** for every length, offset and size computation.

## 16. Documentation index

| Document | Contents |
|---|---|
| [`docs/RFC-ANALYSIS.md`](docs/RFC-ANALYSIS.md) | The pre-implementation RFC analysis: documents reviewed, every normative requirement extracted, **15 ambiguities with the chosen resolution and why**, and the four-way requirement provenance split. |
| [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) | Requirement → RFC → implementation → test matrix, plus intentional deviations. |
| [`etherip.conf`](etherip.conf) | Annotated example configuration. |
| Module doc comments | Each module's doc comment cites the specific RFC section it implements. |

## Licence and attribution

This is an independent implementation. RFC 3378 is Informational and, per its own §1, exists to
provide historical context for IANA's assignment of protocol number 97; its authors are R. Housley
and S. Hollenbeck. RFC 8200, RFC 8201 and RFC 4443 are IETF Standards Track documents.