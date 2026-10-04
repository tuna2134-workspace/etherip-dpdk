# RFC Analysis — EtherIP over IPv6 with IPv6 Source Fragmentation

This document is the **pre-implementation** record required by the project brief. It states
what each RFC actually says, where the RFCs are silent or ambiguous, and which decisions the
implementation makes. No code was written before this analysis was completed.

Documents reviewed (fetched from `https://www.rfc-editor.org/rfc/rfcNNNN.txt`, errata from
`https://www.rfc-editor.org/errata_search.php`):

| RFC | Title | Category |
|---|---|---|
| [RFC 3378] | EtherIP: Tunneling Ethernet Frames in IP Datagrams | **Informational** |
| [RFC 8200] | Internet Protocol, Version 6 (IPv6) Specification | Standards Track |
| [RFC 8201] | Path MTU Discovery for IP version 6 | Standards Track |
| [RFC 4443] | ICMPv6 for IPv6 | Standards Track |
| [RFC 7739] | Implications of Predictable Fragment IDs | Informational |
| [RFC 8899] | IP Packetization Layer Path MTU Discovery (IPPMTUD) | Informational |
| [RFC 8986] | SRv6 Network Programming (registers NH 143 "Ethernet") | Standards Track |
| [RFC 9673] | IPv6 Hop-by-Hop Options Processing Procedures (`Updates: 8200`) | Standards Track |
| [RFC 2473] | IP encapsulation over IPv6 | Standards Track |

IANA registry consulted: *Assigned Internet Protocol Numbers*
(<https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>, last updated
2026-03-09).

---

## 1. RFC 3378 — EtherIP

### 1.1 Document status

RFC 3378 is **Informational**. Its own status section reads: *"This memo provides information
for the Internet community. It does not specify an Internet standard of any kind."*
RFC 3378 §1 further states: *"the standards track protocols produced by these IETF working
groups should be used instead of EtherIP."* This implementation therefore makes **no claim
that EtherIP is a standard**, and README section "Why not just use EtherIP?" repeats this.

### 1.2 Wire format (verbatim requirements)

RFC 3378 §2 defines the EtherIP header as 16 bits:

```
 0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|               |                                               |
|    VERSION    |                   RESERVED                    |
|               |                                               |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

| Field | Bits | Requirement | RFC cite |
|---|---|---|---|
| Version | 0–3 | MUST be 3 (`0b0011`) | §2, §3 step 1, §4 step 1 |
| Reserved | 4–15 | MUST be 0 when transmitting | §2, §3 step 1 |
| Reserved (on receive) | 4–15 | *"Frames with other values MUST be discarded."* | §4 step 1 |

RFC 3378 also records that *"Earlier versions of this protocol used an 8-bit header field. The
Xerox Ethernet Tunnel (XET) employed the 8-bit header."* Consequently a Version other than 3 is
**not** to be reinterpreted as XET — see §5.1 below.

Encapsulated frame requirements (RFC 3378 §2):

* *"The encapsulated Ethernet frame field contains a complete Ethernet or IEEE 802.3 frame of
  any type less the frame check sequence (FCS) value."*
* §3 step 1: *"The MAC frame MUST NOT include the FCS."*
* §4 step 2 (receive): *"the extracted frame MUST NOT include a FCS value."*
* §4 step 3: on egress from the LAN, *"The FCS MUST be calculated and appended to the frame as
  part of the data link layer transmission processing."* → **not** the tunnel's job; that is the
  NIC/L2 driver's job (see `docs/README` "FCS handling").
* VLAN: §1/§2 explicitly include IEEE 802.1Q datagrams in the tunnelled frame set, so VLAN and
  QinQ tags are carried **inside** the EtherIP payload and must not be stripped.
* §2: *"The IP checksum does not provide integrity protection for the Ethernet/IEEE 802.3
  frame, so some higher-layer protocol encapsulated by the Ethernet/IEEE 802.3 frame is
  expected to provide the integrity protection."*

Protocol number (RFC 3378 §2/§5, IANA):

* RFC 3378 §5: *"IANA has assigned IP protocol value 97 (decimal) for EtherIP."*
* IANA *Assigned Internet Protocol Numbers*: decimal `97`, keyword `ETHERIP`, name
  *"Ethernet-within-IP Encapsulation"*, reference `[RFC 3378]`. The registry's
  **"IPv6 Extension Header" column is empty for 97**, i.e. EtherIP is registered as an
  upper-layer protocol, **not** as an IPv6 extension header.

Sending procedure (RFC 3378 §3): decide whether the frame needs tunnelling → prepend the 16-bit
EtherIP header (Version 3, Reserved 0, no FCS) → encapsulate in an IP datagram with Protocol 97
→ transmit via the IP router.

Receiving procedure (RFC 3378 §4): demultiplex frames containing an IP datagram → confirm
Protocol == 97 → validate EtherIP Version == 3 and Reserved == 0, otherwise discard → extract
the MAC frame → transmit on the LAN, appending the FCS.

### 1.3 Loop consideration (RFC 3378 §1)

> *"Care in establishing these rules must be exercised to ensure that the same MAC frame does
> not get transmitted endlessly between several bridge-like stations, especially when broadcast
> or multicast destination MAC addresses are used as selection criteria. Infinite loops can
> result if the topology is not restricted to a tree."*

The abstract also states EtherIP *"does not provide protection against infinite loops."*
This is **unfixable at the EtherIP layer** because the EtherIP header carries no TTL and no
loop-prevention token. Documented, and mitigated only by the deployment topology (a tree), per
RFC 3378 §1.

---

## 2. RFC 3378 and IPv6 — the compatibility gap

**RFC 3378 does not describe IPv6 EtherIP.** Concretely:

* §1 and §2 speak only of *"internet datagrams"* generically, then §2, §3 step 3 and §4 step 5
  each name only the **IPv4** Protocol field explicitly.
* There is no occurrence of "IPv6", "Next Header", or "IPv6-Frag" anywhere in RFC 3378.
* RFC 3378 (September 2002) predates RFC 2460 (IPv6 core, December 1998) being widely deployed
  and predates RFC 3513/8200.

However, the gap is closed *without touching the EtherIP wire format*:

1. **IANA** registers 97 for EtherIP in the shared *IP Protocol Numbers* registry, whose Note
   states: *"In Internet Protocol version 4 (IPv4) [RFC 791] there is a field called 'Protocol'
   to identify the next level protocol. In Internet Protocol version 6 (IPv6) [RFC 8200], this
   field is called the 'Next Header' field."*
2. **RFC 8200 §4** states: *"Extension headers are numbered from IANA IP Protocol Numbers, the
   same values used for IPv4 and IPv6. When processing a sequence of Next Header values in a
   packet, the first one that is not an extension header indicates that the next item in the
   packet is the corresponding upper-layer header."* EtherIP (97) is not an extension header, so
   97 is legal directly as an IPv6 Next Header.
3. **RFC 8200 §3** specifies the Next Header field as an *"8-bit selector"* that *"Uses the same
   values as the IPv4 Protocol field [IANA-PN]"*.

**Conclusion / design rule.** Carrying EtherIP in IPv6 with `Next Header = 97` is a *transport
adaptation* of the EtherIP datagram defined by RFC 3378. The 16-bit EtherIP header is
byte-for-byte unchanged. **No new EtherIP header fields are invented.** Every EtherIP-layer
statement in `docs/COMPLIANCE.md` is traceable to RFC 3378; every IPv6 statement is traceable to
RFC 8200/8201/4443.

> The design diagram is therefore:
> ```
> +---------------------------+
> | Outer IPv6 Header         |  Next Header = 97 (or 44 when fragmented)
> +---------------------------+
> | EtherIP Header            |  Version = 3, Reserved = 0   <-- RFC 3378, unchanged
> +---------------------------+
> | Ethernet Frame            |  no FCS                       <-- RFC 3378
> +---------------------------+
> ```

---

## 3. RFC 8200 — IPv6 fragmentation

### 3.1 Fragment Header format (§4.5)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Identification                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Width | Requirement |
|---|---|---|
| Next Header | 8 | Identifies the first header of the Fragmentable Part. For us: **97 (EtherIP)**, identical in *every* fragment. |
| Reserved | 8 | *"Initialized to zero for transmission; ignored on reception."* |
| Fragment Offset | 13 | Offset in **8-octet units** of the data following this header, relative to the start of the Fragmentable Part. Leftmost fragment = 0. |
| Res | 2 | *"Initialized to zero for transmission; ignored on reception."* |
| M | 1 | 1 = more fragments, 0 = last fragment. |
| Identification | 32 | Unique among recently-sent fragmented packets with the same (Source, Destination). |

### 3.2 Original-packet model and the *Fragmentable Part*

RFC 8200 §4.5 (as corrected by **Errata ID 5945**, Verified/Technical, 2020-02-03; RFC 8200 is
also updated by RFC 9673) reduces the original packet to two parts:

```
original packet:
+------------------+-----------------------------//----------------+
|  Per-Fragment    |               Fragmentable                    |
|    Headers       |                   Part                        |
+------------------+-----------------------------//----------------+
```

* **Per-Fragment Headers** = IPv6 header + extension headers processed en route (up to and
  including the Routing header, else the Hop-by-Hop header, else none).
* **Fragmentable Part** = *"any extension headers that need be processed only by the final
  destination node(s), plus the upper-layer header and data."*

**Application to EtherIP.** We emit no Per-Fragment extension headers, so:

* Per-Fragment Headers = the 40-byte IPv6 header, with Next Header = 44 and Payload Length set
  per fragment.
* Upper-Layer header = the 16-bit **EtherIP** header.
* **Fragmentable Part = `EtherIP header (2 bytes) || Ethernet frame`**.

This is the direct justification for the project requirement *"the EtherIP header is part of the
encapsulated datagram and therefore must be included in the fragmentable portion"*: the EtherIP
header **is** the upper-layer header, and the upper-layer header is the first thing inside the
Fragmentable Part. Consequently Fragment Offset 0 addresses the first high nibble of the EtherIP
header, and the first fragment carries the EtherIP header plus the leading bytes of the Ethernet
frame.

### 3.3 Fragment construction rules (§4.5)

* Fragments must fit the path MTU; *"Each complete fragment, except possibly the last
  ('rightmost') one, is an integer multiple of 8 octets long."*
* First fragment: Per-Fragment headers (Payload Length = this fragment's length excluding the
  IPv6 header; last Per-Fragment header's Next Header = 44) + Fragment header + Extension and
  Upper-Layer headers + the first fragment. All non-Per-Fragment extension headers **and the
  upper-layer header must be in the first fragment**.
* Subsequent fragments: Per-Fragment headers (same adjustments) + Fragment header + fragment.
* *"Fragments must not be created that overlap with any other fragments created from the original
  packet."*
* Fragmentation is performed **only by the source**; routers never fragment (§4.5, §5).
* Identification algorithms: RFC 8200 §4.5 points at RFC 7739.

### 3.4 Reassembly rules (§4.5)

* Key = (Source Address, Destination Address, Fragment Identification). Only the **Offset-zero**
  fragment's Per-Fragment headers are retained; the Fragment header is not present in the
  reassembled packet.
* Reassembled Payload Length: `PL.orig = PL.first - FL.first - 8 + (8 * FO.last) + FL.last`.
* **Atomic datagram** (Fragment Offset 0 *and* M 0): *"it does not need any further reassembly and
  should be processed as a fully reassembled packet."* → must **not** create a reassembly queue
  entry.
* Error conditions (all normative):
  1. Incomplete after 60 s → abandon, discard all fragments; if the offset-0 fragment was
     received, send ICMPv6 Time Exceeded / Fragment Reassembly Time Exceeded (Code 1).
  2. Fragment length (from Payload Length) not a multiple of 8 **and** M = 1 → discard fragment,
     ICMPv6 Parameter Problem **Code 0** pointing at the Payload Length field.
  3. Fragment length + offset would make the reassembled Payload Length exceed 65 535 → discard
     fragment, ICMPv6 Parameter Problem Code 0 pointing at the Fragment Offset field.
  4. First fragment does not include all headers through an Upper-Layer header → discard, ICMPv6
     Parameter Problem **Code 3**, Pointer = 0.
  5. Overlapping fragments → abandon the whole reassembly, discard all fragments for that packet,
     and **send no ICMP**.
  6. *"fragments may be duplicated in the network. Instead of treating these exact duplicate
     fragments as overlapping fragments, an implementation **may** choose to detect this case and
     drop exact duplicate fragments while keeping the other fragments belonging to the same
     packet."*
* Tolerated, non-error variations: differing Per-Fragment headers and differing Fragment-header
  Next Header values across fragments of the same datagram. Only the offset-0 fragment's values
  are used.

### 3.5 Packet size (§5)

* *"IPv6 requires that every link in the Internet have an MTU of 1280 octets or greater"* — the
  **IPv6 minimum link MTU is 1280**.
* *"A node must be able to accept a fragmented packet that, after reassembly, is as large as 1500
  octets. A node is permitted to accept fragmented packets that reassemble to more than 1500
  octets. An upper-layer protocol … that depends on IPv6 fragmentation to send packets larger
  than the MTU of a path **should not send packets larger than 1500 octets unless it has
  assurance that the destination is capable of reassembling packets of that larger size**."*

---

## 4. RFC 8201 / RFC 4443 — PMTUD and ICMPv6 Packet Too Big

### 4.1 ICMPv6 Packet Too Big (RFC 4443 §3.2)

```
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             MTU                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    As much of invoking packet                 |
```

* Type = **2**; Code = *"Set to 0 (zero) by the originator and **ignored by the receiver**"*;
  MTU = *"The Maximum Transmission Unit of the next-hop link."*
* Note carefully: unlike IPv4's RFC 1191, the MTU value is the **link MTU as-is**; no header
  size is subtracted from it.
* RFC 4443 §2.4 (c): every ICMPv6 error message must include as much of the invoking packet as
  possible without exceeding the minimum IPv6 MTU. §2.4 (d): the receiver extracts the
  upper-layer protocol type from the quoted packet; if it is not retrievable the message is
  silently dropped.
* RFC 4443 §3.2: PTB is an explicit exception to the "don't generate errors for multicast" rule.

### 4.2 PMTUD protocol requirements (RFC 8201 §4)

* *"If a node receives a Packet Too Big message reporting a next-hop MTU that is less than the
  IPv6 minimum link MTU, it must discard it. A node must not reduce its estimate of the Path MTU
  below the IPv6 minimum link MTU on receipt of a Packet Too Big message."*
* On receipt, the node **must reduce** its PMTU estimate to the MTU field.
* *"A node must not increase its estimate of the Path MTU in response to the contents of a Packet
  Too Big message."*
*"An attempt to detect an increase … must not be done less than 5 minutes after a Packet Too Big
  message has been received for the given path. The recommended setting for this timer is twice
  its minimum value (10 minutes)."*
* RFC 8201 §4: *"Nodes should appropriately validate the payload of ICMPv6 PTB messages to ensure
  these are received in response to transmitted traffic."*

### 4.3 Storing / purging (RFC 8201 §5.2, §5.3)

* Initially the PMTU value for a path is the first-hop link MTU.
* On PTB: tentative PMTU = MTU field, or the 1280 minimum if that is larger; if tentative <
  existing, replace.
* §5.1: when source fragmentation is available, `EMTU_S` may be set to `EMTU_R`; packetization
  layers *"are encouraged to avoid sending messages that will require source fragmentation."*

---

## 5. Ambiguities identified, and the resolution chosen

Each entry states the ambiguity, the candidate readings, and which one the code implements plus
why. Nothing below is silently chosen.

### 5.1 Non-zero EtherIP Reserved / unsupported Version on receive

* **RFC text (§4 step 1):** *"Confirm that the value of the version field is 3 (three), and that
  the value of the Reserved field is 0 (zero). **Frames with other values MUST be discarded.**"*
* **Ambiguity:** none in the RFC — the requirement is unambiguous and normative. The temptation
  is to be lenient (some stacks warn and continue, so they interoperate with buggy Cisco XTS
  senders), and to treat non-3 Versions as legacy 8-bit XET headers.
* **Resolution:** **strict discard** is the default and the only mode offered
  (`EtherIpError.UnsupportedVersion` / `EtherIpError.ReservedNotZero`). No XET fallback exists in
  the code, and no non-EtherIP interpretation of those bits is ever attempted. A config knob is
  deliberately *not* provided: adding a lenient mode would create a second, non-conformant
  behaviour with no RFC basis.

### 5.2 Whether the EtherIP header is inside or outside the Fragmentable Part

* RFC 8200 §4.5 defines the Fragmentable Part as starting *after* the upper-layer header's
  predecessors; the EtherIP header **is** the upper-layer header here.
* **Resolution:** Fragmentable Part = `EtherIP header || Ethernet frame`, i.e. the EtherIP header
  is fragmented along with the frame. This is forced by RFC 8200, not chosen for convenience.
  Consequence: the first fragment always begins at the EtherIP header, so a receiver can parse
  the EtherIP header from the first fragment alone (needed for the "first fragment must contain
  all headers through the Upper-Layer header" check).

### 5.3 IPv6 fragmentation of EtherIP is unspecified by RFC 3378

* No RFC mandates that an EtherIP tunnel be fragmented. RFC 3378 is silent; RFC 8200 §4.5 defines
  how *any* IPv6 packet is fragmented.
* **Resolution:** apply RFC 8200 §4.5 unmodified to the EtherIP datagram. Implemented as a
  *transport-layer* capability, documented as an implementation extension, with the EtherIP
  header itself untouched.

### 5.4 "Tunnel overhead" for MTU purposes

* No RFC defines a "tunnel overhead" number. The value depends on which optional IPv6 extension
  headers a deployment inserts.
* **Resolution:** compute it, never hard-code it.
  `tunnel_overhead(fragmenting) = 40 (IPv6) + per_fragment_ext_bytes + (if fragmenting) 8`.
  `per_fragment_ext_bytes` is a config field (default 0) reserved for en-route-processed
  extension headers. The EtherIP header is *not* part of the outer-header overhead — it is part of
  the fragmentable payload, which is why a 9000-byte Ethernet frame still fits.

### 5.5 `overlay_mtu` vs 65 535

* RFC 8200: Payload Length is 16 bits; a fragment whose offset+length would push the reassembled
  Payload Length past 65 535 must be discarded (ICMPv6 Param Prob Code 0).
* **Resolution:** `overlay_mtu` is validated at startup to `≤ 65535 − 2 = 65533`, so a
  reassembled EtherIP datagram always fits a 16-bit Payload Length. Any *received* fragment that
  would exceed 65 535 is rejected with that same error, per §4.5.

### 5.6 Reassembly-timeout value

* RFC 8200 §4.5 mandates abandoning reassembly *"within 60 seconds of the reception of the
  first-arriving fragment"*.
* **Resolution:** `reassembly_timeout_ms` is configurable but validated to `1…60 000`, default
  `60 000`. RFC 8200 says *"within"* 60 s, so shorter values are conformant; longer ones are not
  and are rejected at startup.

### 5.7 Overlap vs duplicate

* RFC 8200 §4.5 mandates abandoning reassembly on overlap, but explicitly *permits* dropping
  exact duplicates instead.
* **Resolution:** implement the permitted behaviour. An incoming fragment whose byte range is
  **fully covered by already-received bytes and byte-identical** is counted as a duplicate and
  dropped without destroying the reassembly. Any *partial* overlap with different content, or any
  overlap with a partially-covered range, abandons the whole reassembly, discards every fragment,
  and emits **no** ICMPv6 error.

### 5.8 Reassembly queue exhaustion

* No RFC specifies what a host does when it runs out of reassembly slots.
* **Resolution (implementation-specific):** expired entries are swept first; if the table is still
  full, the **oldest** entry (by first-fragment arrival time) is evicted to admit the new one, and
  the eviction is counted (`reassembly_queue_full`). The alternative — dropping the *new* fragment —
  lets an attacker pin the table with one bad entry, so eviction is the safer default. A drop-new
  policy would be equally conformant; this is a documented implementation choice.

### 5.9 Fragment Identification generation

* RFC 8200 §4.5 requires the Identification to differ from any other fragmented packet *"sent
  recently"* with the same (Source, Destination), and suggests RFC 7739.
* RFC 7739 §5.2: `Identification = random()` from a PRNG.
* **Resolution:** a PRNG seeded from OS entropy at construction; one draw per fragmented
  datagram. All fragments of one datagram share the value. Note RFC 7739 §4's warning that under
  IPv6/IPv4 translation only the low 16 bits matter; the PRNG covers the full 32 bits.
* RFC 8200 also references RFC 7739 §3: *predictable* Fragment IDs are a security weakness
  (off-path spoofing). Randomisation is therefore also a security control, not just a
  correctness one.

### 5.10 PMTU interaction with fragmentation

* RFC 8201 §5.1 says that when source fragmentation is available `EMTU_S = EMTU_R`, so a PTB is
  only generated for packets that still exceed the PMTU.
* **Resolution / design:** three separate values, never conflated:
  * `configured_underlay_mtu` — from config, the local link MTU.
  * `discovered_path_mtu` — `?u32`, learned from ICMPv6 PTB, `null` = unknown.
  * `effective_path_mtu = min(configured_underlay_mtu, discovered_path_mtu)`, clamped to ≥ 1280.
  The fragment payload budget is derived from `effective_path_mtu`, so a PTB immediately shrinks
  the fragments we emit and never leaves us emitting fragments that are themselves too large.
  `effective_path_mtu` also feeds the MSS-clamp budget. As required, no code path assumes 1500.

### 5.11 TCP MSS clamping: what exactly is the safe MSS?

* No RFC in this set specifies MSS clamping for EtherIP; it is an implementation feature
  (cf. RFC 6691 *TCP MSS clamping* generally, and RFC 8201 §5.1's encouragement to avoid
  fragmentation).
* The brief's example of `1392` is illustrative only. Because the clamp must account for the
  inner IP version and header lengths, this implementation **computes** it:
  ```
  effective_inner_mtu = effective_path_mtu − 40 (outer IPv6) − 2 (EtherIP)
  clamp              = effective_inner_mtu − inner_ip_header_len − inner_tcp_header_len
  ```
  For `effective_path_mtu = 1500`: IPv4/TCP → `1500 − 40 − 2 − 20 − 20 = 1418`;
  IPv6/TCP → `1500 − 40 − 2 − 40 − 20 = 1398`. With `effective_path_mtu = 1280` these become
  `1198` / `1178`. Both are clamped further by `overlay_mtu` and by any explicit `tcp_mss`.
* VLAN tags are **not** subtracted because the MSS is a property of the inner IP/TCP pair, and
  the EtherIP datagram (Ethernet header included) already fits the tunnel.

### 5.12 MSS clamping must not become a substitute for fragmentation

* The brief requires fragmentation for jumbo frames; clamping cannot help a 9000-byte Ethernet
  frame because there is no TCP MSS to shrink.
* **Resolution:** clamping is strictly optional (`mss_clamping_enabled`, default `false`). The
  fragmentation path is unconditional and is exercised independently in tests, including a
  9000-byte non-TCP frame. Documentation states MSS clamping *reduces* the incidence of
  fragmentation; it never replaces it.

### 5.13 Ethernet FCS

* RFC 3378 §2/§3/§4 require the tunnelled frame to omit the FCS and require the FCS to be
  re-appended when the frame is transmitted on the LAN.
* **Ambiguity:** a receiver cannot reliably detect whether the last 4 octets are an FCS or payload
  (many NICs strip it before delivery; some do not).
* **Resolution:** the EtherIP layer never adds, strips, or inspects an FCS. The parsed
  `EthernetFrame` is delivered byte-for-byte. FCS generation is delegated to the L2 driver via the
  `OverlayInterface` contract (`transmit(frame)` is documented as "frame without FCS"). VLAN and
  QinQ tags are preserved verbatim; no tag is added, removed, or rewritten.

### 5.14 Which extension headers are accepted on receive

* RFC 8200 §4 requires processing extension headers **strictly in order** and requires that an
  unrecognised Next Header cause discard + ICMPv6 Param Prob Code 1.
* **Resolution:** the receive path walks the extension-header chain in order with a bounded loop
  (max 8 headers), and understands: Hop-by-Hop (0), Routing (43), Destination Options (60),
  Fragment (44), AH (51). ESP (50) terminates the walk (its payload is encrypted). Anything else
  is `error.UnsupportedExtensionHeader` → discard, and ICMPv6 Param Prob Code 1 is queued. The
  brief requires "unsupported extension headers" to be testable, hence rejection rather than
  skipping.

### 5.15 Fragment Offset beyond the limit

* 13-bit field, so `offset × 8 ≤ 65528`. RFC 8200's error case 3 caps the *reassembled* length at
  65 535.
* **Resolution:** arithmetic uses `u32`/`usize` with explicit overflow checks
  (`std.math.mul/add` in checked form, or pre-validated `u16` arithmetic). A fragment whose end
  exceeds the configured per-datagram cap, or would exceed 65 535, is rejected with
  `error.FragmentExceedsReassemblyLimit`, incrementing `malformed_packets`.

---

## 6. MTU arithmetic (the mandatory 9000-over-1500 scenario)

Given `underlay_mtu = 1500`, `overlay_mtu = 9000`, no extra extension headers:

```
per-fragment wire bytes available for the Fragmentable Part
  = effective_path_mtu − 40 (IPv6) − 0 (reserved ext) − 8 (Fragment header)
  = 1500 − 40 − 8
  = 1452

largest legal non-final Fragmentable-Part length (multiple of 8)
  = floor(1452 / 8) × 8
  = 181 × 8
  = 1448

resulting fragment wire size
  = 40 + 8 + 1448
  = 1496        ≤ 1500  ✓
```

The Fragmentable Part is `EtherIP header (2) || Ethernet frame (9000)` = 9002 bytes, so it
becomes `ceil(9002 / 1448) = 7` fragments (1448 × 6 + 914). Fragment 1 carries
`EtherIP header + 1446 bytes of frame`; fragments 2…7 carry raw frame bytes at Fragment Offsets
`181, 362, 543, 724, 905, 1086`.

`calculateFragmentPayloadSize()` performs exactly this arithmetic from parameters, so 1280, 1500,
9000, 4000 and any other underlay MTU work without code changes.

---

## 7. Requirement provenance

### 7.1 Directly specified by RFC 3378

* EtherIP header = 16 bits: 4-bit Version + 12-bit Reserved.
* Version MUST be 3; Reserved MUST be 0 on transmit.
* On receive, Version ≠ 3 or Reserved ≠ 0 → **discard**.
* IP protocol number 97.
* Ethernet frame carried complete but **without** the FCS.
* 802.1Q VLAN frames are in scope (hence VLAN/QinQ preserved verbatim).
* IPv6 is *not* mentioned → the IPv6 adaptation is ours.
* No loop protection in the protocol.

### 7.2 Specified by the IPv6 RFCs

* IPv6 header layout, Payload Length, Next Header, Hop Limit, Source/Destination (RFC 8200 §3).
* Extension-header chain processing order; Next Header values (RFC 8200 §4).
* Fragment Header format, 8-octet offsets, M flag, Identification, source-only fragmentation,
  no overlapping fragments, reassembly key and rules, the five error conditions, the 60-second
  reassembly timeout, IPv6 minimum link MTU 1280 (RFC 8200 §4.5, §5).
* ICMPv6 Packet Too Big: Type 2, Code 0 (ignored on receipt), 32-bit MTU = next-hop link MTU,
  quoted packet (RFC 4443 §3.2, §2.4).
* PMTUD: discard PTB < 1280, never go below 1280, only ever reduce, never raise in response to
  PTB, ≥ 5 min before probing for an increase (RFC 8201 §4, §5.2, §5.3).

### 7.3 Necessary implementation extensions for IPv6 EtherIP

* Encoding the EtherIP datagram in IPv6 with Next Header = 97 (closed by IANA + RFC 8200 §4, but
  not written down in RFC 3378).
* Performing IPv6 **source** fragmentation of the EtherIP datagram, and reassembling it at the
  far end (RFC 8200 §4.5 applied to EtherIP).
* Configurable bounded reassembly context (packets / bytes / timeout), chosen because RFC 8200
  leaves host resource policy to the implementation.
* Emitting the ICMPv6 errors RFC 8200 §4.5 requires from a *destination* node performing
  reassembly (Param Prob Code 0/3, Time Exceeded Code 1). Our endpoint is the destination, so
  these are host-side obligations, not router obligations.
* Outer IPv6 header field choices (Traffic Class, Flow Label, Hop Limit) and tunnel endpoint
  address selection — unspecified by any of these RFCs.
* A Fragment-Identification generator (RFC 8200 delegates to RFC 7739).

### 7.4 Implementation-specific (no RFC basis; documented choices)

* `overlay_mtu` / `underlay_mtu` configuration and their defaults.
* TCP MSS clamping algorithm and its defaults.
* Statistics counters and log messages.
* Reassembly eviction policy (oldest-first) — see §5.8.
* Outer Hop Limit default (64), and the `per_fragment_ext_bytes` reserve.
* CLI surface (`selftest`, `inspect`, `emit-sample`, `config-check`).
* Linux `AF_PACKET` `ETH_P_IPV6` backend for the raw-IPv6 transport; the protocol core is
  transport-agnostic and fully testable in-process.

---

## 8. Cryptographic security — explicit non-claim

RFC 3378 §6 states EtherIP *"can be used to enable the transfer of encrypted Ethernet … frame
payloads"*, but that is a statement about tunnelling already-encrypted traffic. **EtherIP itself
provides no confidentiality, no integrity, and no authentication.** The abstract says it is
*"very lightweight"*. Its only integrity story is whatever the tunnelled payload provides, and
RFC 3378 §2 states plainly that *"The IP checksum does not provide integrity protection for the
Ethernet/IEEE 802.3 frame."* IPv6's header checksum was removed in RFC 2460/8200, so the outer
IPv6 header is not even protected.

Anyone deploying this should read RFC 3378 §6's own recommendation: *"One solution is to protect
the IP datagrams that carry EtherIP with IPsec [RFC2401]."* See README for the alternatives
discussion.

---

## References

* [RFC 3378] Housley, R., Hollenbeck, S., *"EtherIP: Tunneling Ethernet Frames in IP Datagrams"*, September 2002. Informational.
* [RFC 8200] Deering, D., Hinden, R., *"Internet Protocol, Version 6 (IPv6) Specification"*, July 2017.
* [RFC 8201] McCann, J., Deering, S., Mogul, J., *"Path MTU Discovery for IP version 6"*, July 2017.
* [RFC 4443] Conta, S., Deering, M., Idris, M., *"ICMPv6 for IPv6"*, March 2006.
* [RFC 7739] Gont, F., *"Implications of Predictable Fragment IDs"*, February 2016.
* [RFC 8899] Gont, F., Ford, B., *"IP Packetization Layer Path MTU Discovery"*, September 2020.
* [RFC 8986] Liu, A., et al., *"SRv6 Network Programming"*, February 2021.
* [RFC 9673] Hinden, R., Fairhurst, G., *"IPv6 Hop-by-Hop Options Processing Procedures"*, October 2024.
* IANA, *Assigned Internet Protocol Numbers*, <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
* RFC 8200 Errata ID **5945** (Verified, Technical) — restructuring of the original-packet model in §4.5 into Per-Fragment Headers + Fragmentable Part.