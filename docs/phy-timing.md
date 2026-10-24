# PHY timing notes (nRF9151, mfw-nr+ 2.0.0)

What the MAC's schedule is built on. Measured with two nRF9151 DKs (NCS v3.4.1, board
`nrf9151dk/nrf9151/ns`, `CONFIG_NRF_MODEM_LINK_BINARY_DECT_PHY=y`), radio mode LOW_LATENCY,
MCS 0-4. The first round ran over the air about 10 cm apart (RSSI about -21 dBm, SNR about 22 dB
at 10 dBm) on carrier 1705 (band 9); the long-burst and train rounds over an SMA cable.

1 modem tick = 1 / 69.12 MHz = 14.47 ns. 1 subslot (ss) = 14 400 ticks = 208.33 µs.

## Summary for a scheduler

| item | value |
|---|---|
| PHY API on mfw-nr+ 2.0.0 (the MAC firmware) | works: init, configure, activate, TX, RX, RSSI, time, cancel |
| min lead, TX `start_time` − time of the last modem event | **465 µs** (455 µs fails, 460 µs about 50/50) |
| min lead, RX | **390 µs** |
| scheduled TX timing, seen by the peer's RX STF timestamp | ±0.29 µs (±20 ticks, the timestamp step), std 0.03-0.1 µs |
| relative clock drift FT → PT | 0.001-0.026 ppm (the PT's time base follows the received signal) |
| idle between two ops of one radio (from op 1's nominal end) | TX→TX **285 µs**, TX→RX **245 µs**, RX→TX **225 µs**, RX→RX **240 µs** |
| ⇒ on a subslot grid | **any two ops of one device ≥ 2 idle subslots apart** |
| other carrier for op 2 | at most +10 µs |
| RX window margin before the expected STF | ≥ 1 µs works (0 µs: 3 % missed); use 5-10 µs |
| PDC event after the end of a burst | 110-240 µs (grows with MCS and length) |
| reply scheduled from the PDC callback | UL start ≥ 650 µs after the DL end (4 ss on the grid) |
| largest transport block | 700 B (MCS 4 / 8 ss) |

## Gotchas on mfw-nr+ 2.0.0

- `capability_get()`, `band_get()` and `latency_get()` return `NOT_ALLOWED` (0x5) with a NULL
  pointer once the PHY is **activated**: query them between `init` and `configure` / `activate`.
- `data_size` does **not** have to match the TBS: shorter data is zero-padded and longer data
  silently **truncated** to the TBS of the header's `packet_length`; the RX always reports
  `len = TBS`. The MAC sizes its packets itself.
- A start time that is too early comes back as `0x1000 OP_START_TIME_LATE`; close to the limit
  you also get `0x1005 OP_TIMEOUT` or `0x1002 RF_START_TIME_LATE`. Never as a scheduling conflict.
- mfw-nr+ 2.0.0 carries both Nordic's DECT NR+ MAC and the PHY interface; operations are only
  rejected (`EVT_REJECT`) while the interface is claimed by Nordic's MAC.

## Capabilities and bands (mfw-nr+ 2.0.0)

| field | value |
|---|---|
| mcs_max | 4 |
| rx_spatial_streams / rx_tx_diversity | 1 / 1 |
| harq_process_count_max | 8 |
| harq_feedback_delay | 2 subslots |
| mu / beta | 1 / 1 |

Bands reported: 1 (carriers 1657-1677), 2 (1680-1700), 4 (525-551, band group 1, power class 3),
9 (1703-1711), 22 (1691-1711); power class 2 (max 21 dBm) on the 1.9 GHz bands. The nRF9151's TX
maximum is 20 dBm; the highest DECT power step below it is 19 dBm.

## Latency info (`nrf_modem_dect_phy_latency_get`, LOW_LATENCY)

| item | µs |
|---|---|
| scheduled_operation_transition | 375.0 |
| scheduled_operation_startup | 0 |
| receive.idle_to_active | 350.0 |
| receive.active_to_idle_rx | 179.9 |
| transmit.idle_to_active | 419.9 |
| transmit.active_to_idle | 109.9 |
| stack.configuration / activation | 103 000 / 43 000 |

The reported values are conservative: back-to-back ops worked 225-285 µs apart (below the 375 µs
transition), and the measured leads are `idle_to_active` plus about 40-45 µs of IPC.

## Payload per burst (TBS, physical header type 2)

Bytes of PHY payload for a packet of N subslots (`packet_length = N − 1`, length type subslots);
Nordic's table, ETSI TS 103 636-3 §5.3. N = 1..4 verified on air (every packet received with
`len` = TBS).

| MCS | 1 ss | 2 ss | 3 ss | 4 ss | 5 ss | 6 ss | 7 ss | 8 ss |
|---|---|---|---|---|---|---|---|---|
| 0 | 0 | 17 | 33 | 50 | 67 | 83 | 99 | 115 |
| 1 | 4 | 37 | 69 | 103 | 137 | 169 | 201 | 233 |
| 2 | 7 | 57 | 107 | 157 | 205 | 253 | 295 | 343 |
| 3 | 11 | 77 | 141 | 209 | 271 | 335 | 399 | 463 |
| 4 | 18 | 117 | 217 | 311 | 407 | 503 | 604 | 700 |

The packet fills its N subslots including its own guard interval; no extra guard is needed
between packets of different transmitters. 5600 bits (700 B) is the end of the table: MCS 3
reaches it at 11 ss and MCS 2 at 15 ss, and no longer packet exists.

## Lead time

On each `EVT_TIME` event a TX (MCS 1, 2 ss) or a single-shot RX (2 ss) was scheduled at
`evt->time + lead` from inside the event handler, 20 repetitions per step:

| op | always fails | partial | always OK |
|---|---|---|---|
| TX | ≤ 455 µs (0x1000 / 0x1005) | 460 µs: 9/20 | **≥ 465 µs** |
| RX | ≤ 385 µs | — | **≥ 390 µs** |

"Now" plus 465 µs is the hard floor for a TX. An application only knows "now" as an extrapolation
from the last event's time stamp, so the MAC commits ops 1 ms ahead.

COMPLETED event latency after the nominal end of the op: TX 41-43 µs, an RX that receives nothing
125 µs.

## Turnaround between ops on one radio

TX reference at T, op 1 at T + 2 ss + 1 ms, op 2 at `op1_start + op1_duration + gap`; each op 2 ss;
swept in 25 µs steps, then 5 µs around the edge.

| sequence | fails at | min working gap | error when too short |
|---|---|---|---|
| TX → TX | 280 µs | **285 µs** | 0x1000 (gap 0: 0x1005) |
| TX → RX | 240 µs | **245 µs** | 0x1000 |
| RX → TX | 220 µs | **225 µs** | 0x1002 |
| RX → RX | 235 µs | **240 µs** | 0x1000 |
| `nrf_modem_dect_phy_tx_rx` (RX relative to TX end) | 255 µs | 260 µs | 0x1000 |

When op 2 fails, op 1 is unaffected. An accepted TX goes out exactly when scheduled (±20 ticks at
the peer). `tx_rx` is not faster than two separate ops. Across carriers (1705 → 1711, 1703 →
1704) the limits grow by at most 10 µs, so per-frame hopping fits the 2-subslot rule.

## Timing accuracy and drift

- Continuous RX of a DL every 5 ms: receive time − expected after aligning on the first packet
  0..+0.29 µs; drift between the two boards -0.001 ppm; residual std 0.018 µs.
- The windowed PT pattern (re-sync on every DL, 2 ss + 2 × 5 µs windows, 30 s): drift -0.026 ppm,
  residual std 0.084 µs; the FT sees the PT's UL a constant 0.5-1.1 µs late (loop delay, no guard
  needed).
- So the PT's time base follows the received carrier: a PT that misses beacons for 100 ms drifts
  by nanoseconds.

## A two-board mini TDMA (5 ms period)

FT: DL at `t0 + k · 5 ms`, then a single-shot RX for the UL. PT: on each DL PDC, re-sync and
pre-schedule (2 periods ahead) an RX window and the UL TX.

| MCS | ss | bytes | gap DL end → UL | margin | frames | UL / DL ok | PDC after burst end |
|---|---|---|---|---|---|---|---|
| 2 | 2 | 57 | 417 µs | 5 µs | 6000 (30 s) | all / all | 135-156 µs |
| 2 | 2 | 57 | 255-300 µs | 10 µs | 400 each | all / all | |
| 2 | 2 | 57 | 240-250 µs | 10 µs | 400 each | 0 (FT TX→RX too short) / all | |
| 2 | 2 | 57 | 417 µs | 0 µs | 400 | all / 13 missed | |
| 0 / 1 / 3 / 4 | 2 | 17-117 | 417 µs | 5 µs | 400 each | all / all | 109-214 µs |
| 2 / 4 | 4 | 157 / 311 | 417 µs | 5 µs | 400 each | all / all | 210-237 µs |

A reply built from inside the DL's PDC callback (fresh data) needs ≥ 650 µs after the DL end
(640 µs: 0x1005 on almost all; ≤ 625 µs: 0x1000): the PDC latency plus the TX lead. PHY-level
RTT (FT DL start → UL decoded at the FT) is ≈ 1.4 ms pre-scheduled, ≈ 1.6 ms with a fresh-data
reply.

## Long bursts

| situation (MCS 4) | result |
|---|---|
| FT: UL-run RX, then a 7-8 ss / 0.6-0.7 kB TX 2 ss later | most TX fail (0x1005) |
| the same 3 ss later | no failure in > 1000 bursts |
| a 3 ss TX 3 ss after the end of a received 8 ss / 700 B burst | ~1 in 3 fail (0x1005) |
| under bulk for 10 s: a 3 ss DL TX 4 ss after a received full 7 ss UL burst | ~4 % fail |
| under bulk: a PT's 3 ss DL RX 4 ss after a received full 7 ss DL burst | ~16 % fail |
| both with 5 ss | no failure in > 10 000 bursts |
| `nrf_modem_dect_phy_tx()` call (application side, under load) | 17-76 B: up to ~120-225 µs; 0.5-0.7 kB: up to ~280 µs |
| PT: a 700 B TX 2 ss after its own 2 ss UL burst | works |

**Trains of long packets** (8 ss / 700 B, MCS 4, 100-120 trains per point, SMA cable):

| situation | result |
|---|---|
| one board: long TX → long TX, 208 / 260 µs idle | every 2nd TX fails (0x1000) |
| the same with 290 / 320 / 417 µs | 0 errors in 400 TX each, all received |
| receiver: one continuous RX op over trains of 3-4 packets 290-417 µs apart | all PDCs good |
| receiver: one RX op per packet, 2-5 ss apart, ops committed 1.0 ms (RX) / 1.5 ms (TX) ahead | all good at 2 ss, 0 op errors |

So a long TX follows a long TX after the same ~290 µs as short ones, and a receiver takes a long
packet 2 ss after another one; what needs 5 ss after a received long burst is a TX or the RX of a
short burst. The MAC's rules: 3 ss from an FT's UL-run RX to a long TX, 5 ss from a received long
burst (≥ 5 ss) to the receiver's next op unless that is another long RX (`TDMA_LRX_TO_TX_SS`),
long TX bursts committed 1.5 ms ahead.

## Quiet window

The modem fails an op it has accepted with `0x1005` (OP_TIMEOUT) when **another op request
reaches it ~0.23-0.6 ms before that op's start**. Every failing op of ~200 per 10 s (a PT's beacon
RX whose UL slot was committed ~0.4 ms before it) had a PHY call 200-600 µs before its start; no
op with a call < 200 µs or 0.8-1.6 ms before its start failed; the lead at the call was ≥ 1.5 ms
for all of them. The modem reports the failure ~230 µs before the start, where it sets the op up.

The nRF91 port therefore holds a PHY call that would land in `[start − 650 µs, start − 200 µs)` of
a pending op until `start − 200 µs`, as long as its own op still has the PHY lead + 150 µs
(`CONFIG_TDMA_NRF_QUIET_US` / `_QUIET_LATE_US`). Holding it to the start instead delayed the
reception of the running op (+0.24 ms on idle DL probes). Result: beacon RX op errors 68-98 → 0 per
10 s run under host-paced bulk, 0 FT losses in 22 runs in a row.

## Other effects seen on the modem

- An interrupt load on the application core (a UART driver polling for an idle line every few tens
  of µs under bulk) lengthened burst builds by ~200 µs and made bursts late: keep the MAC thread's
  path free of per-byte interrupts.
- Calls into a secure partition serialise: random numbers from the PSA RNG in another thread made a
  beacon seal wait 430-530 µs and miss its commit. Use a non-secure PRNG for application randomness.
- Spinlock owner validation (`CONFIG_SPIN_VALIDATE`) cost ~6 % of the CPU in the time base, the
  margin between 149 and 0 late long UL bursts on a PT receiving bulk at the same time.
- Copying whole packets through the event queue (two large `memcpy` per event with a size-optimised
  libc) cost hundreds of microseconds per event; the port copies a PDC payload once into a slab.

## Rules the MAC derives from this

1. No two ops of one device closer than 2 subslots; the plan validator enforces it.
2. One FT DL burst per opportunity (two FT TX bursts back to back cost 2 ss of dead air); one
   continuous FT RX over a run of UL bursts.
3. RX windows open 5-10 µs early.
4. Commit each op just in time, ~1 ms ahead (the payload is frozen when `nrf_modem_dect_phy_tx()`
   is called): every microsecond of lead is latency.
5. No extra guard symbols.
6. Long-burst gaps: 3 ss FT UL-run RX → long TX, 5 ss after a received long burst, 2 ss between the
   packets of a train.
7. The quiet window before every pending op.
