# RFC Compliance Matrix

Every row maps a normative requirement to the RFC (or RFC section) that states it, the code that
implements it, and the test that proves it. Test names are quoted as they appear in the source; run
`zig build test` to execute all 176 of them.

Requirement sources are abbreviated:

- **[3378]** — RFC 3378, *EtherIP: Tunneling Ethernet Frames in IP Datagrams*, Informational,
  September 2002.
- **[8200]** — RFC 8200, *Internet Protocol, Version 6 (IPv6) Specification*, Standards Track,
  July 2017 (updated by RFC 9673).
- **[8200 §4.5]** — RFC 8200 Section 4.5, *Fragment Header*, **as corrected by Errata ID 5945**
  (Verified, Technical, 2020-02-03).
- **[8201]** — RFC 8201, *Path MTU Discovery for IP version 6*, Standards Track, July 2017.
- **[4443]** — RFC 4443, *ICMPv6 for IPv6*, Standards Track, March 2006.
- **[1071]** — RFC 1071, *Computing the Internet Checksum*.
- **[9293]** — RFC 9293, *Transmission Control Protocol*, Standards Track.
- **[4291]** — RFC 4291, *IP Version 6 Addressing Architecture*.
- **[7739]** — RFC 7739, *Implications of Predictable Fragment IDs*, Informational.
- **[IANA-PN]** — IANA *Assigned Internet Protocol Numbers* registry.
- **[FEAT]** — implementation feature with no RFC basis; documented as such.

---

## 1. EtherIP wire format (RFC 3378)

| Requirement | RFC | Implementation | Test |
|---|---|---|---|
| EtherIP Version = 3 | [3378] §2, §3 step 1, §4 step 1 | `src/etherip.zig` `version = 3`, `encodeHeader` writes `0x30 0x00` | `header_len and protocol number match RFC 3378 / IANA`; `encodeHeader emits Version 3 and Reserved 0` |
| EtherIP Reserved = 0 on transmit | [3378] §2, §3 step 1 | `src/etherip.zig` `Header.encode`, `encodeHeader` | `encodeHeader emits Version 3 and Reserved 0 (RFC 3378 Section 3 step 1)` |
| Header is exactly 16 bits / 2 octets | [3378] §2 | `src/etherip.zig` `header_len = 2` | `header_len and protocol number match RFC 3378 / IANA` asserts `header_len == 2` and `header_len * 8 == 16` |
| Version other than 3 MUST be discarded | [3378] §4 step 1 | `etherip.parse` → `error.UnsupportedVersion` | `parse: every unsupported Version is rejected (RFC 3378 Section 4 step 1)` (loops all 16 values); `tunnel: unknown EtherIP Version is discarded, never reinterpreted (RFC 3378 Section 4)` |
| Non-zero Reserved MUST be discarded | [3378] §4 step 1 | `etherip.parse` → `error.ReservedNotZero` | `parse: every non-zero Reserved value is rejected (RFC 3378 Section 4 step 1)`; `tunnel: non-zero Reserved is discarded (RFC 3378 Section 4)` |
| No reinterpretation as legacy 8-bit XET | [3378] §2, §4 step 1 | No fallback code path exists; documented | `parse: every unsupported Version is rejected` comments XET explicitly; `docs/RFC-ANALYSIS.md` §5.1 |
| Encapsulated frame is a complete Ethernet / IEEE 802.3 frame | [3378] §2 | `src/etherip.zig` `parse` → `error.MissingEthernetFrame`; `src/ethernet.zig` validates structure | `parse: truncated and empty input never panics`; `tunnel: 9000-octet overlay frame over a 1500-octet underlay round trips byte for byte` |
| Frame MUST NOT include the FCS | [3378] §3 step 1, §4 step 2 | No FCS is added anywhere; `ethernet.zig` never touches a trailing 4 octets | `parse: frame without FCS is passed through unchanged`; `tunnel: an unfragmented EtherIP packet has Next Header 97 and no Fragment header` |
| FCS is the egress LAN's job | [3378] §4 step 3 | `src/overlay.zig` module docs and `OverlayInterface` contract | `OverlayInterface.transmit encapsulates through the tunnel`; `docs/RFC-ANALYSIS.md` §5.13 |
| IEEE 802.1Q VLAN frames are in scope | [3378] §1, §2 | `src/ethernet.zig` walks 802.1Q/802.1ad tags, bounded at `max_vlan_depth` | `parse: 802.1Q VLAN tagged frame`; `parse: QinQ double-tagged frame (802.1ad outer + 802.1Q inner)`; `parse: DEI bit and priority are extracted from the TCI` |
| VLAN tags preserved verbatim, never rewritten | [3378] §2 | `ethernet.parse` is read-only; `Frame.raw` aliases the input | `clampFrame: VLAN-tagged IPv4 TCP SYN` re-parses and asserts the VLAN id survives |
| No integrity claim from the IP checksum | [3378] §2 | No integrity verification is claimed or attempted | `docs/RFC-ANALYSIS.md` §8 |
| Protocol number 97 | [3378] §5, [IANA-PN] | `etherip.ip_protocol_number = 97`; `ipv6.next_header_etherip = 97` | `Next Header registry values match IANA`; `IPv6 protocol number constant is 97`; `tunnel: an unfragmented EtherIP packet has Next Header 97 and no Fragment header` |

## 2. IPv6 transport adaptation

| Requirement | RFC | Implementation | Test |
|---|---|---|---|
| EtherIP carried as IPv6 upper-layer protocol (Next Header 97) | [8200] §4, [IANA-PN] | `tunnel.encapsulate` writes `ipv6.writeHeader(..., 97, ...)` | `tunnel: an unfragmented EtherIP packet has Next Header 97 and no Fragment header` |
| EtherIP is **not** an extension header | [IANA-PN] (column empty for 97) | `ipv6.isExtensionHeader(97) == false` | `Next Header registry values match IANA` asserts `!isExtensionHeader(next_header_etherip)` |
| No IPv6 header checksum exists | [8200] §3 | No IPv6 checksum is computed anywhere | `parseExtensionChain: Fragment header (RFC 8200 Section 4.5)` (no checksum field expected) |
| IPv6 header layout: Version 6, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit, 128-bit addresses | [8200] §3 | `src/ipv6.zig` `writeHeader`, `parseHeader` | `parseHeader: RFC 8200 Section 3 field extraction` |
| Payload Length counts extension headers | [8200] §3 | `parseHeader` bounds payload by `payload_length`; `Fragmenter.emitFragments` sets it per fragment | `parseHeader: rejects malformed input` (PayloadLengthExceedsBuffer) |
| IPv6 Version MUST be 6 | [8200] §3 | `ipv6.parseHeader` → `error.UnsupportedVersion` | `parseHeader: rejects malformed input` |
| Extension headers processed strictly in order | [8200] §4 | `ipv6.parseExtensionChain` walks a single forward pass | `parseExtensionChain: Hop-by-Hop + Fragment ordering`; `clampFrame: inner IPv6 extension headers are walked in order (RFC 8200 Section 4)` |
| Hop-by-Hop MUST immediately follow the IPv6 header | [8200] §4.3 | `parseExtensionChain` rejects a later Hop-by-Hop header | `parseExtensionChain: Hop-by-Hop must immediately follow the IPv6 header (RFC 8200 4.3)` |
| Malformed / truncated / misordered extension header → discard (+ ICMPv6 Code 0) | [8200] §4, [4443] §3.4 | `ipv6.parseExtensionChainReporting` returns the offset of the header that failed; `Tunnel.queueExtensionChainError` emits Code 0 with that Pointer | `tunnel: a malformed extension-header chain produces the right ICMPv6 code and Pointer`; `writeError: Parameter Problem Code 0 for a malformed extension header`; `parseExtensionChain: unsupported extension header is rejected, not skipped` |
| An upper-layer protocol that is not EtherIP is simply not ours | [4443] §2.4 (d) | The chain walk stops cleanly and `receivePacket` returns `ReceiveOutcome.ignored`, counting `not_for_us`. No ICMPv6 is generated, because RFC 4443 §2.4 (c) only requires one "if the error can be uniquely attributed". | `tunnel: an upper-layer protocol that is not EtherIP is ignored without ICMPv6` |
| Parameter Problem Code 1 encoder available | [4443] §3.4 | `icmpv6.ErrorRequest.unrecognized_next_header` (Pointer 6) | `writeError: Parameter Problem Code 1 for an unrecognised Next Header (RFC 8200 Section 4)` |
| Hop-by-Hop must immediately follow the IPv6 header | [8200] §4.3 | `error.MisplacedHopByHopHeader` | `parseExtensionChain: Hop-by-Hop must immediately follow the IPv6 header (RFC 8200 4.3)` |
| Only one Fragment header per packet | [8200] §4.5 | `error.DuplicateFragmentHeader` | `a second Fragment header is refused rather than silently consuming 8 octets` |
| "No Next Header" with trailing octets → ignore them | [8200] §4.7 | `parseExtensionChain` reports an empty upper layer | `RFC 8200 Section 4.7: No Next Header with trailing octets is ignored, not an error` |
| Payload Length 0 means "no payload"; trailing octets are padding | [8200] §3 | `parseHeader` treats trailing octets as padding | `parseHeader: rejects malformed input` |
| Extension headers are integer multiples of 8 octets | [8200] §4 | `Hdr Ext Len` arithmetic in `parseExtensionChain` | `parseExtensionChain: truncated and overlong chains` |
| AH length in 4-octet units (len + 2) * 4 | RFC 4302 §2.1 | `parseExtensionChain` AH branch | `parseExtensionChain: Authentication Header length is in 4-octet units (RFC 4302)` |

## 3. IPv6 fragmentation (RFC 8200 §4.5)

| Requirement | RFC | Implementation | Test |
|---|---|---|---|
| IPv6 Fragment Header format: Next Header, Reserved, Fragment Offset (13), Res (2), M (1), Identification (32) | [8200] §4.5 | `ipv6.FragmentHeaderView`; `Fragmenter.emitFragments` writes octets 0–7 | `parseExtensionChain: Fragment header (RFC 8200 Section 4.5)`; `emitFragments: 9000-octet Ethernet frame over a 1500-octet underlay` |
| Fragment Header Next Header = 44 | [8200] §4.5 | `ipv6.next_header_fragment = 44` | `Next Header registry values match IANA` |
| Fragment header Next Header = first header of the Fragmentable Part (97 for us) | [8200] §4.5 | `Fragmenter.emitFragments` writes `etherip.ip_protocol_number` in every fragment | `emitFragments: 9000-octet Ethernet frame over a 1500-octet underlay`; `every fragment carries the same Identification (RFC 8200 Section 4.5)` |
| Fragment header Reserved initialised to 0 | [8200] §4.5 | `fh[1] = 0` | `emitFragments: 9000-octet Ethernet frame over a 1500-octet underlay` |
| Res initialised to 0 | [8200] §4.5 | offset/flags written as `offset << 3 \| M` | `emitFragments: 9000-octet Ethernet frame over a 1500-octet underlay` |
| Fragment Offset in **8-octet units** | [8200] §4.5 | `unit_offset = offset / fragment_alignment` | `emitFragments: exactly two fragments, boundary at the alignment limit` asserts offset 181 for byte 1448 |
| First fragment's Fragment Offset is 0 | [8200] §4.5 | Loop starts at `offset = 0` | `every fragment except the last is a multiple of 8 octets`; `the first fragment starts with the EtherIP header (RFC 8200 Section 4.5)` |
| M = 1 for every fragment but the last | [8200] §4.5 | `is_last` drives the M bit | `emitFragments: exactly two fragments, boundary at the alignment limit` |
| Every fragment except the last is a multiple of 8 octets | [8200] §4.5 | `max_frag = floor(available / 8) * 8` | `every fragment except the last is a multiple of 8 octets (RFC 8200 Section 4.5)`; `MTU arithmetic: the mandatory 1500-byte underlay case` |
| Upper-Layer header MUST be in the first fragment | [8200] §4.5 | The EtherIP header is the first 2 octets of the fragmentable part | `the first fragment starts with the EtherIP header (RFC 8200 Section 4.5)` |
| Fragmentable Part = EtherIP header + Ethernet frame | [8200] §4.5 as corrected by **Errata 5945** | `Fragmenter.emitFragments` treats the whole EtherIP datagram as the Fragmentable Part | `property: the reassembled EtherIP datagram equals the encapsulated one`; `docs/RFC-ANALYSIS.md` §6 |
| Fragments MUST NOT overlap | [8200] §4.5 | Fragments are consecutive slices of a non-overlapping range | `every fragment except the last is a multiple of 8 octets`; `emitFragments: exactly two fragments...` |
| Payload Length per fragment excludes the IPv6 header only | [8200] §4.5 | `payload_len = fragment_header_len + chunk_len` | `emitFragments: 9000-octet Ethernet frame over a 1500-octet underlay` |
| IPv6 header Next Header set to 44 in every fragment | [8200] §4.5 | `ipv6.writeHeader(..., 44, ...)` per fragment | `emitFragments: 9000-octet Ethernet frame over a 1500-octet underlay` |
| Identification unique among recently sent fragmented packets with the same (Source, Destination) | [8200] §4.5, [7739] §5.2 | `Tunnel.encapsulate` draws `frag_id_rng.random().int(u32)` per datagram | `distinct datagrams get distinct Identifications (RFC 8200 Section 4.5, RFC 7739)` (64 datagrams) |
| Identification unpredictable (anti-spoofing) | [7739] §3, §5.2 | PRNG seeded via `Options.fragment_id_seed`; fallback documented as predictable | `docs/RFC-ANALYSIS.md` §3.9; `src/tunnel.zig` `Options.fragment_id_seed` |
| Source-only fragmentation | [8200] §4.5, §5 | Implemented at tunnel ingress only; no router logic exists | `docs/RFC-ANALYSIS.md` §3.3; module docs in `fragment.zig` |
| IPv6 minimum link MTU is 1280 | [8200] §5 | `ipv6.min_link_mtu = 1280`; `config.validate` enforces it | `Config.validate rejects MTUs the standards forbid`; `MTU arithmetic: no 1500 is hard-coded anywhere` |
| Max fragment payload = largest multiple of 8 that fits the path MTU | [8200] §4.5 | `fragment.calculateFragmentPayloadSize` | `MTU arithmetic: the mandatory 1500-byte underlay case` (1448); `MTU arithmetic: no 1500 is hard-coded anywhere` (1280 → 1232, 9000 → 8952, 1491 → 1440) |
| Reassembled Payload Length must not exceed 65 535 | [8200] §4.5 error 3 | `addFragment` rejects `per_fragment_header_len + end > ipv6.max_payload_len`; `Config` caps `overlay_mtu` at 65 533 − reserved | `reassembly: fragments beyond the datagram limit are rejected (error 3)`; `reassembly: the 65 535 cap includes the Per-Fragment header octets`; `Config.validate rejects MTUs the standards forbid`; `Config derived quantities`; `emitFragments: rejects a datagram beyond the 16-bit Payload Length limit` |

## 4. IPv6 reassembly (RFC 8200 §4.5)

| Requirement | RFC | Implementation | Test |
|---|---|---|---|
| Key on (Source, Destination, Identification) | [8200] §4.5 | `reassembly.Key` and `KeyContext` | `reassembly: the key includes source, destination and identification (RFC 8200 4.5)` |
| Offset-0 + M-0 is a whole datagram: no reassembly | [8200] §4.5 | `Tunnel.handleFragment` short-circuits before `addFragment` | `reassembly: an empty atomic datagram is rejected`; `emitFragments: refuses to fragment something that already fits` |
| M-1 fragment length not a multiple of 8 → discard + ICMPv6 Param Prob Code 0 (Pointer = Payload Length) | [8200] §4.5 error 2 | `addFragment` + `Tunnel.queueIcmp`; `icmpv6.pointer_payload_length = 4` | `reassembly: M=1 fragment whose length is not a multiple of 8 is rejected (error 2)`; `writeError: Parameter Problem Code 0 pointing at the Payload Length field` |
| Length + offset beyond 65 535 → discard + ICMPv6 Param Prob Code 0 (Pointer = Fragment Offset) | [8200] §4.5 error 3 | `addFragment` + `Tunnel.queueIcmp`; `icmpv6.pointer_fragment_offset = 42` | `reassembly: fragments beyond the datagram limit are rejected (error 3)`; `writeError: Parameter Problem Code 0 pointing at the Fragment Offset field` |
| Incomplete after 60 s → abandon, discard all, ICMPv6 Time Exceeded Code 1 | [8200] §4.5 error 1 | `Reassembler.expireInto` measured from the **first** fragment; `Tunnel.expireReassemblies` queues the Time Exceeded when the offset-zero fragment was seen | `reassembly: incomplete datagrams time out (RFC 8200 Section 4.5 error 1)`; `reassembly: timeout measured from the FIRST arriving fragment, not the last`; `reassembly: expireInto reports abandoned datagrams so the caller can originate ICMPv6`; `tunnel: reassembly timeout is enforced`; `tunnel: RFC 8200 Section 4.5 error condition 1 -- an ICMPv6 Time Exceeded on reassembly timeout`; `tunnel: a timeout with no offset-zero fragment originates no ICMPv6`; `writeError: Time Exceeded Code 1 for reassembly timeout` |
| `reassembly_timeout_ms` ≤ 60 000 | [8200] §4.5 | `reassembly.max_timeout_ms`; `Config.validate` | `Config.validate rejects zero or out-of-range reassembly limits`; `Limits.validate rejects nonsense configuration` |
| Overlapping fragments → abandon whole reassembly, discard all, **no ICMP** | [8200] §4.5 error 5 | `addToContext` → `release(slot)` + `rejected = .Overlapping`, and `Tunnel.handleFragment` sends no ICMP for `Overlapping` | `reassembly: overlapping fragments abandon the whole datagram (RFC 8200 4.5 error 5)` |
| Exact duplicates MAY be dropped, keeping the rest | [8200] §4.5 | Fully-covered byte-identical ranges → `Outcome.duplicate` | `reassembly: duplicate fragments are dropped without destroying the context`; `reassembly: replay of a completed datagram is dropped, not re-queued` |
| Duplicate arriving first with M=1 then M=0 must still merge the metadata | RFC 8200 §4.5 (implied) | `addToContext` merges `total_len` / `have_first` before the duplicate check | `reassembly: multiple simultaneous reassemblies complete independently` |
| Reassembled packet has no Fragment header; PL computed from the last fragment | [8200] §4.5 | The reassembler returns the Fragmentable Part only; the tunnel parses it directly | `tunnel: 9000-octet overlay frame over a 1500-octet underlay round trips byte for byte` |
| Headers/Next Header may vary across fragments; only offset-zero fragment's value is used | [8200] §4.5 | Only the offset-zero fragment's Fragment-header Next Header is checked | `emitFragments: 9000-octet Ethernet frame over a 1500-octet underlay` |

## 5. ICMPv6 and PMTUD (RFC 4443, RFC 8201)

| Requirement | RFC | Implementation | Test |
|---|---|---|---|
| Packet Too Big: Type 2 | [4443] §3.2 | `icmpv6.type_packet_too_big = 2` | `ICMPv6 type and code constants match RFC 4443` |
| PTB Code set to 0 by the originator and **ignored by the receiver** | [4443] §3.2 | `parsePacketTooBig` does not validate the Code | `parsePacketTooBig: the Code field is ignored on receipt (RFC 4443 Section 3.2)` |
| PTB MTU is the next-hop link MTU as-is (no subtraction) | [4443] §3.2 | `PacketTooBig.mtu: u32`, used verbatim | `parsePacketTooBig: RFC 4443 Section 3.2 field extraction`; `docs/RFC-ANALYSIS.md` §4.1 |
| ICMPv6 checksum verified over the IPv6 pseudo-header | [4443] §2.1, [8200] §8.1 | `icmpv6.checksumValid` | `parsePacketTooBig: rejects truncated, informational and bad-checksum input` |
| Error messages quote as much as fits the minimum IPv6 MTU | [4443] §2.4 (c) | `icmpv6.writeError` truncates to `out.len`; the tunnel passes the **whole** received packet, not just its 40-octet header | `writeError: quotes only as much as fits (RFC 4443 Section 2.4 (c))`; `takeIcmp copies into the caller's buffer, never a stack frame` (asserts the message is longer than 48 octets) |
| Error messages MUST NOT be originated for a non-unique source | [4443] §2.4 (e.6) | `Tunnel.isUniqueNode` rejects the unspecified address and multicast | `tunnel: an ICMPv6 error is never originated for a non-unicast source (RFC 4443 2.4 (e.6))` |
| Informational messages silently discarded | [4443] §2.4 (b) | `parsePacketTooBig` returns `NotAnErrorMessage` for type ≥ 128 | `parsePacketTooBig: rejects truncated, informational and bad-checksum input` |
| Validate that a PTB corresponds to transmitted traffic | [8201] §4 | `correlatesWithSentTraffic_` checks the **quoted packet's** Source Address against this endpoint's tunnel address and its Next Header against a 64-entry ring of transmitted descriptors | `tunnel: a Packet Too Big with no matching transmitted packet is ignored (RFC 8201 Section 4)`; `tunnel: ICMPv6 Packet Too Big lowers the effective path MTU (RFC 8201)` |
| PTB reporting an MTU below 1280 MUST be discarded | [8201] §4 | `icmpv6.applyPacketTooBig` returns the current estimate unchanged | `applyPacketTooBig: RFC 8201 Section 4 rules` |
| PMTU MUST NOT be reduced below 1280 | [8201] §4 | `Pmtu.effective` clamps with `@max(discovered, 1280)` | `applyPacketTooBig: RFC 8201 Section 4 rules` |
| PMTU MUST be reduced on PTB | [8201] §4, §5.2 | `Tunnel.onPacketTooBig` | `tunnel: ICMPv6 Packet Too Big lowers the effective path MTU (RFC 8201)` |
| PMTU MUST NOT be **increased** in response to a PTB | [8201] §4 | `applyPacketTooBig(..., allow_increase = false)` | `applyPacketTooBig: RFC 8201 Section 4 rules` |
| Tentative PMTU = MTU field, or 1280 if larger; replace only if smaller | [8201] §5.2 | `icmpv6.applyPacketTooBig` | `applyPacketTooBig: RFC 8201 Section 4 rules` |
| PTB-based probe-for-increase not sooner than 5 min | [8201] §4 | `Pmtu.pmtu_probe_interval_ms = 10 min`, recorded but not enabled | `docs/RFC-ANALYSIS.md` §9 |
| `effective_path_mtu = min(configured, discovered)` | [8201] §5.2 | `Tunnel.effectivePathMtu` | `tunnel: ICMPv6 Packet Too Big lowers the effective path MTU (RFC 8201)`; `statistics rendering includes the PMTU fields` |
| No code path assumes MTU 1500 | [8201] §5 | Fragment and MSS budgets derive from `effective_path_mtu` | `fragmentation scales with the underlay MTU and is never hard-coded` (1280/1500/4000/9000/16000); `computeTargetMss: derived from the effective path MTU, never hard-coded` |
| ICMPv6 Param Prob Code 3, Pointer 0 for an incomplete first fragment | [8200] §4.5 error 4 | `icmpv6.writeError` with `first_fragment_incomplete` | `writeError: Parameter Problem Code 3 with Pointer 0 for an incomplete first fragment` |

## 6. Ethernet / VLAN

| Requirement | RFC | Implementation | Test |
|---|---|---|---|
| Complete Ethernet II frame, header = dst(6) + src(6) + type(2) | DIX (per [3378] §1) | `ethernet.parse`, `header_len = 14` | `parse: normal Ethernet II frame` |
| Minimum frame size | IEEE 802.3 | `ethernet.min_frame_len = 60` (14 + 46, excluding FCS) | `parse: minimum Ethernet frame` |
| IEEE 802.1Q tags inside the tunnelled frame | IEEE 802.1Q, [3378] §1/§2 | `ethernet.parse` tag walk, `writeVlanTci` | `parse: 802.1Q VLAN tagged frame`; `parse: DEI bit and priority are extracted from the TCI` |
| IEEE 802.1ad (QinQ) outer tag | IEEE 802.1ad | `ethernet.ether_type_qinq = 0x88a8`, same walk | `parse: QinQ double-tagged frame (802.1ad outer + 802.1Q inner)` |
| Tag stack depth bounded | [FEAT] hardening | `max_vlan_depth = 4` → `error.VlanStackTooDeep` | `parse: rejects tag stacks deeper than max_vlan_depth` |
| Truncated frames never panic | [FEAT] | `parse` returns errors only | `parse: truncated headers and tags never panic`; `fuzz: parse never panics on arbitrary input` |

## 7. TCP MSS clamping — implementation feature

| Requirement | RFC | Implementation | Test |
|---|---|---|---|
| Feature is optional and off by default | [FEAT] | `Config.mss_clamping_enabled = false` | `Config.validate: fragmentation disabled with a jumbo overlay is rejected`; `tunnel: 9000-octet ... ` (clamping disabled, still passes) |
| Safe MSS derived, never hard-coded | [FEAT], [8201] §5.1 | `mss_clamp.computeTargetMss` | `computeTargetMss: derived from the effective path MTU, never hard-coded` |
| `effective_inner_mtu = effective_path_mtu − 40 − 2` | [FEAT] | `mss_clamp.computeTargetMss` | `computeTargetMss: derived from the effective path MTU, never hard-coded` (1418 / 1398 / 1198 / 1178) |
| Only SYN (SYN set, ACK clear) | RFC 9293 §3.1 | `clampFrame` flag check | `clampFrame: non-SYN TCP packets are never modified` |
| MSS option layout: kind 2, length 4 | RFC 9293 §3.1 | `mss_clamp.findMssOption` | `findMssOption: RFC 9293 option layout` |
| NOP (1) and EOL (0) handling | RFC 9293 §3.1 | `findMssOption` | `findMssOption: RFC 9293 option layout` |
| Malformed option blocks rejected, not guessed | RFC 9293 §3.1 | `error.Malformed` (length < 2, overrun, wrong MSS length) | `findMssOption: malformed option blocks are rejected, not guessed at` |
| No MSS option → leave alone | RFC 9293 §3.1 (option optional) | `SkipReason.NoMssOption` | `clampFrame: a SYN with no MSS option is left alone` |
| MSS already ≤ target → leave alone | [FEAT] | `SkipReason.AlreadyWithinTarget` | `clampFrame: an MSS already below the clamp is left alone` |
| All unrelated options preserved byte for byte | [FEAT] | Only 2 MSS octets written | `clampFrame: IPv4 TCP SYN above the target is clamped and the checksum fixed` (byte-by-byte diff over the whole frame); `stress: MSS clamping never writes outside the MSS option` |
| TCP checksum recomputed over the IPv4 pseudo-header | RFC 9293 §3.1 | `checksum.recomputeTcpChecksum` | `clampFrame: IPv4 TCP SYN above the target is clamped and the checksum fixed` |
| TCP checksum recomputed over the IPv6 pseudo-header | RFC 8200 §8.1 | `checksum.accumulatePseudoHeader` | `recomputeTcpChecksum: IPv6 pseudo-header verification`; `clampFrame: IPv6 TCP SYN above the target is clamped` |
| Zero checksum transmitted as all ones | RFC 9293 §3.1 | `checksum.wireChecksum`, `recomputeTcpChecksum` | `RFC 1071: known checksum vectors` |
| VLAN + IPv4 + TCP supported | [FEAT] | `clampFrame` walks the VLAN stack | `clampFrame: VLAN-tagged IPv4 TCP SYN` |
| VLAN + IPv6 + TCP supported | [FEAT] | same | `clampFrame: VLAN-tagged IPv6 TCP SYN` |
| Inner IPv6 extension headers walked in order | [8200] §4 | `clampFrame` IPv6 branch | `clampFrame: inner IPv6 extension headers are walked in order (RFC 8200 Section 4)` |
| Fragmented inner SYN refused | [FEAT] correctness | Fragment header → `.unparseable` | `clampFrame: a fragmented inner IPv6 SYN is refused rather than mis-clamped` |
| Clamping never a substitute for fragmentation | [FEAT] | Independent code paths; a 9000-octet non-TCP frame is unaffected | `tunnel: 9000-octet overlay frame over a 1500-octet underlay round trips byte for byte` (clamping off) |

## 8. Robustness and resource bounds

| Requirement | Source | Implementation | Test |
|---|---|---|---|
| No unbounded `HashMap` for reassembly | [FEAT] | Capacity reserved once in `Reassembler.init` | `reassembly: multiple simultaneous reassemblies complete independently` |
| Bounded fragment memory | [FEAT] | One flat pool, one flat chunk array, one index | `reassembly: memory limit exhaustion evicts the oldest context` |
| `max_reassembly_packets` enforced | [FEAT] | `acquireSlot` evicts oldest; `Limits.validate` bounds it to the `u16` slot index | `reassembly: memory limit exhaustion evicts the oldest context`; `Limits.validate bounds max_packets to the slot index width` |
| `max_reassembly_bytes` enforced | [FEAT] | `Limits.validate` and `init` pool sizing | `Limits.validate rejects nonsense configuration` |
| `max_chunks` per datagram bounded | [FEAT] | `Context.insertChunk` returns `ChunkTableFull` | `reassembly: too many chunks for one datagram is bounded` |
| Expired entries reclaimed before eviction | [FEAT] | `addFragment` sweeps first | `reassembly: expired entries are reclaimed before eviction` |
| Fragment payload copied, not aliased | [FEAT] | `addToContext` memcpys into the context | `reassembly: fragment payload is copied, not aliased` |
| Completed datagram's buffer borrowed only until the next call | [FEAT] | Documented on `Outcome.complete` | `reassembly: multiple simultaneous reassemblies complete independently` (consumes each result before the next call) |
| No parser panics on malformed input | [FEAT] | Errors everywhere; no `unreachable` on network data | `fuzz: parseHeader never panics on arbitrary input`; `fuzz: parse never panics on arbitrary input` (EtherIP); `fuzz: parse never panics on arbitrary input` (Ethernet); `fuzz: addFragment never panics on arbitrary fragment data`; `fuzz: clampFrame never panics...`; `fuzz: checksum never panics on arbitrary input`; `fuzz: parsePacketTooBig never panics on arbitrary input`; `fuzz: an arbitrary IPv6 packet never crashes decapsulation` |
| Invariant `reassemble(fragment(frame)) == frame` | [FEAT] | — | `reassemble(fragment(frame)) == frame for every required frame size`; `property: arbitrary frame lengths round trip byte for byte`; `round trip with fragments delivered in reverse order`; `round trip with every fragment delivered twice`; `stress: randomised frame lengths always round trip`; `stress: randomised fragment orders always round trip` |
| Mutated fragment order never yields a different frame | [FEAT] | — | `fuzz: a mutated fragment set never produces a frame that differs from the input` |
| No allocation on the packet fast path | [FEAT] | Caller-owned `tx_scratch`/`rx_scratch`; callback sink | `Transport is a plain vtable: no allocation on the fast path`; design notes in `README.md` §15 |

## 9. Observability

| Requirement | Source | Implementation | Test |
|---|---|---|---|
| Counters exposed via a clean API | [FEAT] | `stats.Counters`, `stats.Snapshot`, `Tunnel.snapshot()` | `Counters covers every field required by the project brief` |
| `formatSnapshot` deterministic | [FEAT] | `stats.formatSnapshot` | `formatSnapshot emits every counter deterministically` |
| Reassembly timeout enforced on the receive path | [8200] §4.5 error 1 | `Tunnel.receivePacket` sweeps before parsing, so the ICMPv6 is never lost to a race | `tunnel: receivePacket itself enforces the reassembly timeout, so no message is lost` |
| Reassembly-timeout ICMPv6 quotes a correlatable Fragment header | [4443] §2.4 (c) | `ipv6PacketStub` rebuilds the IPv6 + Fragment headers with the real Identification | `tunnel: the reassembly-timeout ICMPv6 quotes a correlatable Fragment header` |
| No per-packet logging by default | [FEAT] | Default log level `.warn`; per-packet messages are `debug` | `src/main.zig` `--log-level`; `Tunnel` uses `log.debug` for per-packet events |
| Statistics rendering includes PMTU fields | [FEAT] | `Tunnel.writeStats` | `statistics rendering includes the PMTU fields (RFC 8201 observability)` |

## 10. Packet-capture compatibility

| Requirement | Source | Implementation | Test |
|---|---|---|---|
| Structure matches what Wireshark/tcpdump expect | [3378] §2, [8200] §4.5 | `src/platform.zig`, `src/main.zig` `emit-sample` | `emitted packets have the documented structure for Wireshark/tcpdump`; verified with `tcpdump -r`: `frag (0\|1448) ip-proto-97 1448` |
| pcap file is valid LINKTYPE_ETHERNET | [FEAT] | `writePcapGlobalHeader` | `emitted packets have the documented structure for Wireshark/tcpdump` |

---

## Intentional deviations and non-conformances

| Item | Nature | Rationale |
|---|---|---|
| `reassembly_timeout_ms` may be set **below** 60 000 | Conformant | RFC 8200 §4.5 requires abandonment *"within 60 seconds"*; a shorter value satisfies "within". Values above 60 000 are rejected. |
| Evict-oldest on a full reassembly table | Implementation-specific | No RFC specifies host resource policy. Eviction avoids a permanently pinned table. `docs/RFC-ANALYSIS.md` §5.8. |
| Recently-completed duplicate filter | Implementation-specific | No RFC addresses replays of already-delivered datagrams. Without it, each replay allocates a permanently-incomplete context. `docs/RFC-ANALYSIS.md` §5.7. |
| `reserved_per_fragment_ext_bytes` must be 0 | Implementation-specific, enforced | No RFC defines "tunnel overhead". RFC 8200 §4.5 requires the IPv6 header's Next Header to name the *first* Per-Fragment header, so reserving octets without supplying headers would emit packets a receiver must reject. `Config.validate` returns `ReservedExtensionBytesNotSupported`; the MTU arithmetic still accounts for a reserve for callers that encapsulate themselves (`fragment.calculateFragmentPayloadSize`). `docs/RFC-ANALYSIS.md` §5.4. |
| Outer Hop Limit default 64, Traffic Class 0, Flow Label 0 | Implementation-specific | RFC 8200 §3 defines the fields but not their values for this use. |
| Fragment-Identification fallback seed | Weaker than ideal | Without `Options.fragment_id_seed` the seed mixes the caller's clock and an address, which is predictable. Pass OS entropy in production. Documented on `Options.fragment_id_seed`. |
| PMTU probe-for-increase not implemented | Feature gap | RFC 8201 §4 *permits* omitting it; a tunnel that fragments anyway has no incentive to probe. The timer is recorded in `Pmtu`. |
| No IPv4 tunnel endpoints | By specification | The brief specifies IPv6-only. |
| No Jumbograms (RFC 2675) | Feature gap | Caps `overlay_mtu` at 65 533. `Payload Length == 0` with trailing octets is rejected rather than mis-parsed. |
| Reserved Per-Fragment extension octets are sent as zeros, not as whatever the scratch buffer held | Correctness fix | They count towards Payload Length, so transmitting stale scratch data would leak memory contents. Regression-tested in `emitFragments: reserved Per-Fragment octets are zero-filled, never stale scratch data`. |
| `Fragmenter` re-validates its scratch capacity at emit time | Correctness fix | `init` sizes for one MTU and `emitFragments` takes another. Regression-tested in `emitFragments: a larger MTU than the Fragmenter was built for is refused, not overflowed`. |
| `checksum.accumulate` folds every 4096 words | Correctness fix | A `u32` accumulator overflows past 131 076 octets. Regression-tested in `accumulate: a buffer far larger than the u32 accumulator is handled without overflow`. |
| `checksum.accumulate` uses saturating index arithmetic | Correctness fix | A slice length near `maxInt(usize)` would wrap `i + words_per_fold * 2`. |
| PTB correlation checks the quote, not the PTB source | Correctness fix | RFC 4443 §3.2 makes a PTB's source the on-path **router**, never the EtherIP peer; matching on the source would reject every genuine PTB while accepting spoofed ones. |
| `zig build test --fuzz` unusable on Zig 0.16.0 | Toolchain bug | `-ffuzz` fails to compile the compiler's own `test_runner.zig:566` (`builtin.StackTrace` vs `std.debug.StackTrace`). Unrelated to this package. Mitigated by 4 000-iteration randomised stress sweeps in `src/tests/tests.zig`. |