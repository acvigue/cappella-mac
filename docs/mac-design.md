# MAC design

cappella-mac is a scheduled (TDMA) MAC for DECT NR+ (ETSI TS 103 636) that runs on top of
Nordic's DECT PHY API (`nrf_modem_dect_phy`, modem firmware mfw-nr+ 2.0.0) instead of Nordic's
own MAC. It does not implement the ETSI DECT-2020 NR MAC: the air format below is its own and
does not interoperate with other DECT NR+ MACs.

Goals, in order:

1. **Bounded latency for small frames**: one-way ≤ 5-7 ms worst case for ≤ 64 B on a cluster of
   a few PTs, with no contention for scheduled traffic.
2. **Bulk throughput** when a link needs it, without breaking (1).
3. **Multi-hop**: relays that extend a cluster, with self-healing (backup parents, reroutes,
   islands that merge).
4. Robustness: channel selection, LBT, interference monitoring, announced channel moves,
   frequency hopping, link security.

Everything here is implemented in `src/` and exercised by the simulations in `tests/`. PHY
numbers come from [phy-timing.md](phy-timing.md).

## Contents

- [Air timing](#air-timing)
- [Roles and life cycle](#roles-and-life-cycle)
- [Air structure](#air-structure)
- [Plans](#plans)
- [PDU format](#pdu-format)
- [Association](#association)
- [Data path](#data-path)
- [Hybrid plans: guaranteed slots plus on-demand long bursts](#hybrid-plans-guaranteed-slots-plus-on-demand-long-bursts)
- [Bulk plans and plan switching](#bulk-plans-and-plan-switching)
- [Priority classes](#priority-classes)
- [Per-link MCS](#per-link-mcs)
- [Channel access](#channel-access)
- [Link security](#link-security)
- [Relays](#relays)
- [Root scan](#root-scan)
- [Failure detection](#failure-detection)
- [Commit timing and CPU](#commit-timing-and-cpu)
- [Simulation model](#simulation-model)
- [Not done, and why](#not-done-and-why)

## Air timing

ETSI TS 103 636, μ = 1:

| unit | duration | modem ticks (69.12 MHz) |
|---|---|---|
| frame | 10 ms | 691 200 |
| slot | 416.67 µs (24 per frame) | 28 800 |
| subslot (ss) | 208.33 µs (48 per frame) | 14 400 |

All scheduling is in modem time (`uint64_t` ticks). Every PHY operation has an absolute start
time and must reach the modem a lead time before it (TX 465 µs, RX 390 µs measured).

## Roles and life cycle

- **FT** (fixed termination) owns the schedule. It picks a carrier (scan or fixed), beacons once
  per frame, and receives the UL bursts of its PTs.
- **PT** (portable termination) searches (continuous RX) until it hears a beacon of its network,
  takes the frame timing from the beacon's receive time, associates in a free position, then
  runs its slots and re-syncs on every beacon.
- A PT can be promoted to FT, so a PT instance is sized like an FT (`struct tdma_mac`).

The library is **instance based**: the caller owns `struct tdma_mac` and the storage of its
peers (`struct tdma_mem`), and the platform is a struct of function pointers (`struct
tdma_port`). The host simulation runs many instances in one process; on the modem there is one,
or two for a relay. Every entry point is called from one context:

| call | when |
|---|---|
| `tdma_on_rx()` | a packet was received by one of the MAC's RX ops |
| `tdma_on_op_done()` | an op finished, was stopped or failed |
| `tdma_on_rssi()`, `tdma_on_pcc()` | RSSI and physical-header reports of scan / RSSI ops |
| `tdma_tick(now)` | time passed; returns when it wants to be called next |
| `tdma_send()` | queue an SDU for a peer |

## Air structure

Measured PHY constraints drive the layout (two ops on one radio need 225-285 µs between them,
so one subslot of gap always fails):

- **One DL burst per opportunity.** The FT sends one broadcast packet carrying the beacon (in the
  first burst of the frame) and the DL PDUs for every PT; each PT keeps the records addressed to
  its position.
- **One continuous FT RX per run of UL slots.** The UL bursts of all PTs (and the contention
  slot) sit 1 subslot apart inside one FT RX op; the FT tells them apart by start time. Verified
  with three PTs saturating every UL slot: 0 errors.
- **≥ 2 idle subslots between any two ops of one device.** `tdma_plan_validate()` rejects any
  plan that breaks this, for the FT and for every PT, plus the long-burst rules: 3 ss from the
  FT's UL-run RX to a long TX, 5 ss from a received long burst (≥ 5 ss) to the receiver's next
  op unless that op is another long RX 2 ss later (a "train").
- **No guard symbol.** A packet fills its N subslots; its GI is inside them. Sync accuracy is
  ±0.3 µs.
- **Payload sizes from the TBS table.** The modem pads or silently truncates to the transport
  block size of (MCS, subslots), so the MAC sizes every packet itself (`tdma_tbs()`). The largest
  transport block is 700 B (MCS 4 / 8 ss).
- **Just-in-time commits.** Every op goes to the PHY `TDMA_COMMIT_LEAD_TICKS` (1 ms) before it
  starts, so a burst carries whatever was queued until 1 ms before air and only 2-3 ops are ever
  in flight. Long bursts are committed 1.5 ms ahead (`nrf_modem_dect_phy_tx()` takes up to
  280 µs for 700 B).
- RX windows open 10 µs early and close 10 µs late.

## Plans

A plan is a table of slots (subslot, length, owner position, use) in `src/tdma_plan.c`; every
table passes the validator at build time of the tests. The FT announces its plan and MCS in the
beacon; PTs follow.

| id | name | PTs | period | layout (subslots) | use |
|---|---|---|---|---|---|
| 0 | A | 4 | 5 ms | DL 0-3 (209 B), UL 6/9/12/15, contention 18-19 | small packets, 4 PTs |
| 1 | 1x10 | 10 | 10 ms | DL 0-7, UL every 3 ss from 13 | many PTs, slow |
| 2 | B | 2 | 2.5 ms | DL 0-1, UL 4-5 / 7-8 | lowest latency (≤ 4.2 ms) |
| 3 | **H** | 2 | 5 ms | DL 0-2, UL 5 / 8, FLEX 13-18 (UL 12-18 when granted ahead) | default: small packets + long bursts |
| 4 | H4 | 4 | 10 ms | two DL / UL blocks, FLEX 38-42 | 3-4 PTs |
| 5 | T | 2 | 10 ms | H's first half, then a train of 3 × 8 ss | bulk, one PT, one direction |
| 6 | T2 | 2 | 10 ms | beacon 0-2, 4 × 8 ss in DL / UL patterns | bulk, one PT, both ways |
| 7 | T2D | 2 | 10 ms | 7 ss beacon burst + DL, 3 × 8 ss DL, UL 42-43 | bulk DL, one PT |
| 8 | BQ | 2 | 2.5 ms | H's guaranteed block every 12 ss, no FLEX | idle (lowest latency in the H family) |
| 9 | T4 | 4 | 10 ms | DL 0-3, UL 6/9/12/15, train 7 + 7 + 5 ss | bulk with 3-4 PTs |
| 10 | HG | 2 | 10 ms | H's guaranteed slots in a relay's blocks | a relay's child cluster |
| 11 | HGX | 1 | 10 ms | DL-first child plan | a relay with one child |

In every plan **the UL slot of a free position is also a contention opportunity**, and a
rebooted PT may use the slot the beacon still lists under its own short id. When all positions
are taken the beacon says FULL and a PT reports `ASSOC_FAILED(FULL)` without transmitting.

Worst-case one-way latency without loss or queueing is (largest gap between a flow's bursts) +
commit lead + burst air time + PDC; the tests assert it per plan and direction:

| plan | DL max / bound (µs) | UL max / bound (µs) |
|---|---|---|
| A | 7072 / 7074 | 6629 / 6632 |
| B | 4145 / 4147 | 4146 / 4147 |
| 1x10 | 12 882 / 12 907 | 11 631 / 11 632 |
| H | 6864 / 6865 | 6644 / 6647 |
| H4 | 7900 / 7907 | 7688 / 7689 |
| BQ | 4360 / 4370 | 4150 / 4370 |

So "≤ 5 ms worst case" holds for plans B and BQ (2 PTs); the 4-PT plans are about 7-8 ms. Eight
PTs at ≤ 5 ms do not fit one carrier: eight UL bursts with guards plus a DL burst need ~30 ss
within ~14 ss.

## PDU format

- **Physical header**: the MAC builds a packed 10-byte stand-in (`struct tdma_phy_hdr`:
  length, short network id, transmitter / receiver short ids, power, MCS) that the port maps
  onto the PHY's type 2 header (header format 1).
- **Short rd id** = low 16 bits of the 32-bit radio device id; the application keeps it unique
  per network and never 0 or 0xffff.
- A PHY payload is a sequence of **records** `u8 len, u8 addr, PDU[len]`; a zero `len` ends it,
  so the PHY's zero padding is harmless. A record longer than 254 B has a 4-byte header
  (0xff, addr, LE16 length). `addr` is the PT position (DL), the sender's position (UL), or 0xff.
- PDUs (little endian), each `type, flags, ...`:
  - **beacon**: network id, FT rd id, frame counter, plan id and MCS (4 bits each; the high
    nibbles announce the next plan), roster version, n × (short id, nonce); optional extensions:
    move (`TDMA_F_MOVE`), hop set (`TDMA_F_HOP`), security (`TDMA_F_BSEC`), retime
    (`TDMA_F_RETIME`), a tree extension (depth, grid offset, route record, position moves,
    application bytes, quiet window).
  - **data**: seq, ack, ack bitmap (8 or 16 bit), length; fragments add tag, byte offset and SDU
    length.
  - **ack-only**: ack and bitmap (`ACK_VALID`), optionally HOLD.
  - **assoc_req**: PT rd id, FT rd id, node number, nonce, flags (relay).
  - **grant** (hybrid plans): n × (position, flags, start subslot, length, MCS).
  - **status** (hybrid plans): queued bytes, the SNR and RSSI the PT measures on the FT's
    bursts, flags.
- Every decoder bounds-checks; fuzzing covers 200 000 random buffers plus garbage injected into
  running RX ops, under ASan and UBSan. Older decoders skip extension types they do not know.

## Association

- A PT syncs on the first beacon of its network (`cfg.ft_rd_filter = 0`), on one given FT, or on
  none (scan only, `TDMA_RD_BROADCAST`). `tdma_pt_set_target()` changes the target at run time,
  so an application can scan, pick and then join.
- A random backoff spread over 8 frames' worth of opportunities comes before each request; the
  PT then waits 3 beacons for its entry and gives up after 16 attempts
  (`ASSOC_FAILED(NO_RESPONSE)`).
- **Nonce.** Every sync session draws a random nonzero nonce, which the FT echoes in the beacon
  table; a PT is associated only when its short id appears there with its nonce. A known PT with
  a new nonce (it rebooted faster than the UL timeout) makes the FT emit `CHILD_REMOVED(REASSOC)`
  + `CHILD_ADDED` and reset the link, so stale sequence numbers cannot swallow data.

## Data path

- **Selective-repeat ARQ**, window 8 (plans A, B, 1x10: 8-bit bitmap) or 16 (hybrid plans:
  `TDMA_F_WIDE`). Every packet carries the sender's receive state.
- **Loss judgement**: a PDU counts as lost when a peer burst that started at least commit lead +
  250 µs after the PDU ended does not ack it (that burst was built after the peer must have seen
  the PDU); it is resent in the next own burst. A 20 ms RTO is the fallback. With no loss no test
  sees a single retransmission.
- **Give up** after 3 transmissions (`arq_max_tx`) or 100 ms after the first transmission
  (`tx_lifetime_ticks`), counted in `stats.sdu_tx_drop`.
- **PTs transmit in every own UL slot**; with nothing to send an ack-only PDU doubles as the
  liveness signal.
- **Fragmentation at build time.** SDUs (up to `TDMA_MAX_SDU`, 1280 B by default) are queued
  whole in 64-byte chunks; `link_build()` cuts a fragment as large as the room left in the burst
  (4-byte units, at least 16 B). A long burst carries one large fragment: SDU bytes are 92-95 %
  of what a long burst sends. An SDU that fits one guaranteed-burst PDU is never fragmented.
- **Concurrent reassembly**: byte-range bitmaps in a shared pool (`TDMA_RAS_SLOTS`, at most
  `TDMA_RAS_PER_LINK` per peer). A sender has `TDMA_TX_SDU_INFLIGHT` fragmented SDUs in flight
  (6 on the train plans) inside a tag window; fragmented SDUs are delivered in tag order.
  Saturated 1280 B both ways at 10 % loss: 0 duplicates, 0 misordered.
- **Queue limits**: `TDMA_TXQ_BYTES` per peer; plans without trains use 2 SDUs' worth, plan T 4,
  the whole-frame plans all of it (a deeper queue buys those plans nothing but delay). Only the
  first `TDMA_TXQ_BIG_LINKS` positions get the deep queues (the bulk plans have 2 positions).
- Return codes of `tdma_send()`: `-EMSGSIZE` above the maximum SDU, `-ENOBUFS` when the queue is
  full (nothing queued), `-ENOTCONN` when not associated or the destination is unknown.
  `tdma_send_room()` lets a sender wait for room without holding its own locks; a waiting bulk
  sender is counted in the queue report.
- **Backpressure** (`TDMA_F_HOLD`, `tdma_link_hold()`): the peer starts no new non-priority SDU
  towards us while the hold is heard; it lapses after 4 frames.

## Hybrid plans: guaranteed slots plus on-demand long bursts

Plans H and H4 keep a fixed set of guaranteed slots (the latency floor, which never moves) and
add **FLEX regions** that carry at most one long burst each, given out per opportunity:

- **Grant record**: every DL burst before a FLEX region carries a GRANT PDU saying who uses the
  region in this frame (DL or UL, MCS, length; SPEC = send only if there is data). The validator
  requires every region to start ≥ the FLEX commit lead + PDC after the end of its announcing DL
  burst, so a PT has decoded the grant before it commits.
- **Status record**: every PT UL burst carries its queued bytes; the FT keeps the newest and
  subtracts grants made since.
- **Who gets the region** (`ft_flex_decide()`): round robin over the flows (DL to PT k, UL from
  PT k) that have data waiting; else a speculative DL to a PT that just finished a bulk SDU (so a
  reply can go out in the same period); else a speculative UL grant, round robin. Length: the
  shortest burst that covers the demand, else the longest the region allows.
- **UL grants a DL period ahead** (`TDMA_GRANT_F_AHEAD`) for a PT in sustained bulk: it may then
  use an earlier extent of the region (plan H: 7 ss instead of 6).
- **Guaranteed slots stay guaranteed**: a FLEX region never overlaps one, so the bounds above
  hold under any bulk load (H, 64 B under 1000 B bulk on every link: max 6828 µs, bound 6865).

Fairness (all flows saturated with 1000 B for 10 s): H with 2 PTs gives each PT the same DL and
UL rate (Jain index 1.000); H4 with 4 PTs 0.999.

## Bulk plans and plan switching

- **Plan T**: plan H's first half (so H and T share every slot a PT commits before it has decoded
  the frame's beacon) and a train of three 8 ss regions for one PT in one direction. A long TX
  follows a long TX after the same 290 µs as short ones, and a receiver takes a long packet 2 ss
  after another one (measured), so trains need no extra gaps.
- **T2 / T2D** (whole frame, one PT): T2 has no UL slot; the frame after the beacon belongs to
  one PT as a pattern of DL and UL long bursts (UUUU, D5 UUU, D8 D5 UU, D8 D8 D5 U) announced
  one frame ahead; the FT picks the pattern whose DL share is closest to the DL share of what is
  waiting. T2D makes the beacon burst itself long (7 ss) and keeps a 2 ss UL slot.
- **T4**: the bulk plan of the 4-PT family.
- **BQ**: plan H's guaranteed block every 2.5 ms, no FLEX region: the idle plan.
- **Plan auto** (`cfg.plan_auto`): per PT, smoothed demand (SDU bytes queued to it and delivered
  from it per frame, EWMA 1/16). H → bulk plan after 5 frames ≥ 250 B per frame; back to H below
  450 B per frame for 3 frames; at least 20 frames per plan; H → BQ after 20 idle frames and back
  on the first frame that needs a long burst. T2 / T2D only with a single active PT, T with more.
  A switch is announced in 3 beacons and happens where the FT's scheduler enters that frame; PTs
  follow without re-associating (`tdma_plan_compatible()`).
- **Plan family by PT count** (`cfg.plan_multi`): the H family has 2 positions; with a second PT
  associated the FT announces H4 so a third can join, and goes back once one PT is left.

## Priority classes

- `tdma_send(..., prio)`: prio 0 = bulk, 1 = priority (an SDU that fits one PDU), 2 =
  `TDMA_PRIO_OWN` (a relay's own priority traffic ahead of forwarded priority SDUs, so a child's
  expedited traffic cannot take every one of the relay's UL bursts).
- Priority SDUs go behind earlier priority SDUs (FIFO) and ahead of the unsent fragments of a bulk
  SDU; they never go between two fragments.
- **Reserved room**: per peer, `TDMA_TXQ_PRIO_BYTES` (256 B) and 4 SDU entries on top of the bulk
  limit that only priority SDUs may take, so a small packet never waits for bulk queue room; wide
  links keep the last 2 places of the ARQ window for priority PDUs.
- The FT fills a shared DL burst with every PT's priority PDUs first, then one PDU per PT, then
  more data.

## Per-link MCS

Long bursts only (guaranteed slots stay at the network MCS from the beacon, because their
fragment size is fixed). The FT averages each PT's UL SNR (its own PCC SNR) and DL SNR (the PT's
status record), falling fast (1/2 per sample) and rising slowly (1/8). `tdma_mcs_select()` moves
up to MCS 1 / 2 / 3 / 4 once the average clears 6 / 9 / 12 / 16 dB, drops only 3 dB below the
current threshold, and steps down once after two missed demanded UL bursts in a row.

## Channel access

Region, band, channel set and power are the application's (the port checks them against the
modem's band list and power class). The MAC:

- **Channel selection** (cfg channel 0): a scan op per carrier (RX of any network with RSSI
  reporting, 10 frames each). Carriers are ranked: no other cluster; ≥ 75 % free or possible;
  all free; no cluster on a neighbouring carrier (band 9 carriers overlap); fewest busy; fewest
  possible; quietest. The preferred carrier (the last one used) wins when it is clean, so PTs
  that remember it find the cluster at once. Another network's payload does not decode on a scan
  op, but its physical header does: clusters are reported from headers and, when one of our
  beacons decodes, from the beacon (`TDMA_EVT_SCAN_CLUSTER`).
- **LBT**: the first beacon on a carrier goes out with the PHY's LBT (2 subslots, threshold = the
  busy level, -71 dBm); busy → back off 1-3 frames, 4 busy in a row → the next best carrier.
  Association requests use a 2-symbol LBT.
- **Monitor**: the FT measures carriers where none of its radios transmits (empty speculative UL
  regions, idle DL bursts, at worst a reserved long-burst region every 10 frames); guaranteed
  slots are never touched. Window 0.5 s; ≥ 25 % busy subslots on the own carrier, or every PT's
  SNR below 6 dB while the carrier is not quiet, triggers a move. Every 4 periods a region
  measures another carrier (move targets, the hop set).
- **Announced moves** (`tdma_ft_move()`): `TDMA_F_MOVE` (carrier, frame, hop mask) in the next 10
  beacons; from that frame every op of FT and PTs is on the new carrier and frame timing,
  positions and ARQ state stay. A PT that missed every announcement searches all carriers.
- **Frequency hopping** (`cfg.hop`): per frame, frame f is on `base + perm_c[f mod n]`, a
  Fisher-Yates permutation of the hop set drawn per cycle from a seed per FT session; every beacon
  carries the hop state, so a PT cannot drift. The hop set starts as the carriers the scan found
  usable and drops / takes back carriers by measured load (hysteresis against duty-cycled
  interferers). Retuning costs ≤ 10 µs, inside the 2-subslot rule, so hopping needs no plan
  change.

## Link security

The MAC builds the packet layout, the nonce and the AAD; the platform does the crypto behind
opaque key handles (`struct tdma_sec_ops` in `tdma_port.h`: derive, release, seal, open,
key_state, random), so the library has no crypto code. `NULL` = security off.

- **AES-128-CCM, one MIC per PHY packet** (`TDMA_SEC_MIC_LEN` = 4, 6 or 8), behind a 2-byte
  security header (version, key index, cleartext flag, body length). Overhead 6 B per burst with
  a 4-byte MIC. A forgery succeeds with probability 2⁻³² per attempt and every attempt costs a
  burst in a slot the victim listens in; ≥ 10 MIC failures within a second raise an alarm
  (`TDMA_EVT_SEC_ALARM`), in line with NIST SP 800-38C Appendix B for short tags.
- **Packet layout**: PHY header fields (network byte, short ids, length, MCS) are AAD; the
  security header is AAD; a cleartext first record (beacon, association request) is AAD; the rest
  is ciphertext; then the MIC.
- **Nonce** (13 bytes, not transmitted): transmitter long rd id, FT frame counter of the burst's
  frame, start subslot, zero padding. A device sends at most one packet per (frame, start
  subslot), different transmitters differ in the rd id, and every FT session uses its own key, so
  nonces never repeat. ARQ resends go into new bursts and are resealed. The simulator checks every
  seal for (key, nonce) reuse.
- **Sessions**: the FT draws a session random and takes a session counter the application persists
  (`cfg.sess_ctr`); the session key is `derive(key index, network id, FT rd id, counter, random)`.
  Beacons carry (counter, random, key index) in the security extension and are sealed with the DL
  records after them: nothing a PT does with a beacon (sync, scan result, position table, plan
  change) happens before the MIC verifies.
- **Freshness**: replays of data, acks and association requests fail on the nonce. A PT accepts a
  beacon only with a frame later than the last one of that session and within ±2 frames of its
  prediction, and only from a session counter ≥ the highest seen from that FT.
- **Key switch**: the FT announces "key index k (new session) from frame F" for
  `sec_announce_frames` beacons; PTs that hold the index pre-derive; the UL carries the key index,
  so the FT opens either key for a short grace period. A new session also starts before the frame
  counter wraps.
- **Deny list** (`tdma_sec_deny()`): an FT refuses association from these rd ids.
- **Development key flag** (`cfg.sec_devkey`): beacons say the network runs on a development key;
  a PT must have the same setting to join, so mixed networks fail visibly.
- **Cost model**: `seal_ticks_base` / `seal_ticks_per16` (and the open counterparts) make the MAC
  commit TX slots that much earlier, keep commits out of the time it verifies a received burst
  (`rx_clear()`), count it in the ARQ turnaround, and let a hybrid FT grant long bursts a DL
  period ahead when a PT could not verify the grant in time. Measured on an nRF9151 with the
  AES in a secure partition: ~230-290 µs per seal, 450 µs lead.
- Without security a PT keeps sync only on beacons; with security verified DL bursts from the FT
  also count (up to 3 × `beacon_miss_max` frames), and correct the frame timing.

[tdma_sec_ref.h](../include/cappella/tdma_sec_ref.h) is a reference implementation of the ops in
portable C (software AES, keys in RAM) for the simulations and for bring-up.

## Relays

A relay is a PT that also runs a **child cluster**: a second MAC instance (an FT on plan HG or
HGX) on the same radio and its own carrier, aligned to the parent's frames. The arbiter
(`tdma_relay.c`, `tdma_relay_away()`) gives the radio to one instance at a time in fixed blocks of
the frame, so the parent-side and child-side slots never collide; the port asks it before every
op (`tdma_port.away`), and a skipped slot is skipped before anything is built or sealed.

- **Tree**: a root cluster is depth 0, a node joined to a depth-d cluster has depth d + 1, at
  most `TDMA_MAX_DEPTH`; beacons carry the depth, the grid offset of the cluster's frame (HG: a
  root's frame + 19 ss, another HG frame + 14 ss) and a route record the application fills
  (`tdma_set_route()`, opaque to the MAC).
- **Storage**: a relay's two instances share one `struct tdma_mac_store` (`tdma_mem_split()`):
  peer 0 for the parent, two short-queue peers and three reassembly buffers for the children.
- **Pipelining**: a relay lets a received burst go before commits that can still start after it
  (`tdma_next_latest()`), so what the burst brought for the other instance is queued when the
  burst it is meant for is built; the relay's parent-side DL / beacon RX is committed early
  enough not to delay its child's PDC event. Measured: 2 hops up p99 9.9 ms, 3 hops up 13.1 ms.
- **HGX**: a relay in position 1 of a root's plan H / T whose cluster has exactly one child runs a
  DL-first child plan, switched with one announced frame (plan switch + retime); a second node
  that asks to join in an open frame makes the relay go back to HG for a while.
- **Self-healing support**: a fast reroute (`tdma_pt_set_target_ch()`: search one known carrier
  with a short backoff), **retime** (`TDMA_F_RETIME`: a cluster whose parent's grid differs shifts
  its frames at an announced frame, its children shift with it, no re-association), **position
  moves** (`TDMA_BEXT_PMOVE`, swap two PTs' positions at a frame), **backup probes**
  (`tdma_pt_probe()`: one 3 ss listen for another cluster's burst, in place of an own op), an
  island mode (the child cluster outlives its parent, depth 0, slow background search) and
  `tdma_ft_set_avoid()` (carriers ranked like occupied ones).
- Policy (which parent, when to reroute or merge) stays in the application; the MAC provides the
  mechanisms and the events.

## Root scan

`tdma_ft_scan(m, ch, flags)`: an FT (not a relay's child cluster) listens once on carrier `ch`
(0 = the next carrier of the set, round robin) for one frame + 4 ss, long enough for a 3 ss beacon
burst of any cluster at any offset from ours. The listen goes in place of the FT's own ops in
that time: the two beacons before it announce a quiet window (`TDMA_BEXT_QUIET`) and associated
PTs leave out exactly what the FT leaves out, so their data waits instead of going into a burst
nobody hears (no ARQ resend, no loss). Beacons heard are reported as `TDMA_EVT_FT_SCAN` with their
route record and application bytes (cleartext, not verified: information only), and the
carrier's cluster count in the channel table is refreshed. Refused (`-EBUSY`) on a bulk plan,
during the first beacon's LBT and while a move, retime, position move or plan switch is pending.

Simulation (`ft_scan`): two clusters on independent grids, 64 B priority probes both ways every
5-15 ms, one listen per 2.5 s: p99 unchanged (7.2 / 5.2 ms), the max grows by one window, 0 lost.

## Failure detection

- **PT**: sync is lost after `beacon_miss_max` (10) frames without a beacon (with security,
  verified DL bursts bridge up to 3×); also on a beacon that no longer lists it (`RELEASED`), a
  CLOSING flag, or a plan / MCS change it cannot follow. Detected 106 ms after the FT goes silent
  in the simulation.
- **FT**: frees a position after `ul_miss_max` (20) missed UL bursts (`CHILD_REMOVED(UL_TIMEOUT)`).
- **Queue safety net**: the link queue's invariants (entries, order, chunk partition) are checked
  at the entry and exit of every link call in host builds; on the target an inconsistent link is
  reset at its next build and counted (`stats.queue_resets`, never seen in tests).

## Commit timing and CPU

- **Lead per op kind**: `cfg.ul_lead_trim` (a PT's own UL slots) and `cfg.dl_lead_trim` (an FT's
  DL bursts but the beacon) cut the commit lead where the measured build + seal time leaves room;
  every tick is one-way latency.
- **Memoised commit leads**: `next_commit()` keeps the leads of the frame being scheduled and the
  next and recomputes one only when an input changed (plan, MCS, role, grants, security cost
  model, LBT state); host builds define `TDMA_CHECK_LEAD_MEMO`, which checks every memoised result
  against the full evaluation. This took the FT's MAC thread from 72 % to 38 % busy with 64 B
  probes on an nRF9151.
- **Build at -O2**: the Zephyr module builds the MAC at -O2 inside an -Os image (2-3 points of MAC
  thread time for ~11 KB), `tdma_plan.c` at -Os.
- **No floating point, no heap, no OS**: enforced by a test (`mac_is_freestanding`).
- Sizes (arm-none-eabi-gcc, Cortex-M33, -O2): ~23 KB of code; `struct tdma_mac` with its store
  ~42 KB with 4 positions and the default queues.

## Simulation model

`tests/sim/sim.c` is a deterministic multi-node simulator:

- one true clock; every node has its own modem clock with an offset and a drift (±20 ppm in the
  drift test, against < 0.03 ppm measured between two DKs);
- a fake PHY per node that enforces the measured contract: lead TX 465 µs / RX 390 µs; idle
  between ops TX→TX 285, TX→RX 245, RX→TX 225, RX→RX 240 µs (+10 µs across carriers); RX windows
  open ≥ 1 µs before the packet; exact TBS (longer payloads are a MAC bug); PDC latency 110-240
  µs; ±0.29 µs TX jitter; at most two frames ahead; a TX or short RX < 5 ss after a received long
  burst is flagged;
- a shared air with collisions, per-link SNR (an MCS needs 1 / 4 / 7 / 10 / 13 dB) and seeded
  loss; interferers per carrier (continuous or duty-cycled, neighbours 6 dB lower); RSSI and scan
  ops reported per subslot in 5 ms chunks; LBT;
- an optional security cost model (seal, open and busy time, as on an nRF9151).

Every network test asserts zero PHY-contract violations, zero port errors and zero late slots;
`phy_model` checks that the fake PHY really rejects each kind of violation.

## Not done, and why

- **HARQ**: the PHY's HARQ needs a feedback TX scheduled from inside the PCC callback and a
  retransmission of the same transport block. In these plans the retransmission can only go into
  the next FLEX region ≥ 5 ms later, which is decided before the feedback could be decoded; the
  feedback ops would cost ~40 % of a FLEX region; soft combining only pays off near an MCS's SNR
  limit, which per-link MCS avoids. ARQ alone covers loss.
- **CDMA / spreading**: the PHY is OFDM and exposes no waveform control; robustness comes from
  channel choice and hopping.
- **A second DL opportunity inside an UL train**: it costs 7 of the train's 38 subslots for a
  small latency gain under bulk.
- **The CLOSING beacon** (graceful FT shutdown) is parsed by PTs but not sent.
- **ETSI DECT-2020 NR MAC interoperability**: out of scope.
