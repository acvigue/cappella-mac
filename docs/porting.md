# Porting to another PHY or OS

The MAC (`src/`, `include/cappella/tdma_mac.h`) is OS-free C99: no heap, no floating point, no
threads. Everything it needs from the platform is in
[`tdma_port.h`](../include/cappella/tdma_port.h). The nRF91 port
([`port/nrf_dect_phy/tdma_nrf.c`](../port/nrf_dect_phy/tdma_nrf.c)) and the simulator's fake PHY
([`tests/sim/sim.c`](../tests/sim/sim.c)) are two complete implementations to copy from.

## 1. What the PHY must offer

The air format assumes a DECT NR+ PHY (ETSI TS 103 636, μ = 1, 10 ms frames of 48 subslots)
with:

- **scheduled ops at an absolute time** in a free-running tick counter (the MAC's unit is the
  nRF91 modem tick, 69.12 MHz: `TDMA_TICKS_PER_SEC`; another clock must be converted in the port);
- TX of one packet of N subslots with a physical header that carries a short network id,
  transmitter and receiver short ids, MCS and power (type 2 header);
- RX over a window, reporting each packet with its receive (STF) time, RSSI and SNR, filtered by
  the short network id;
- optional: RSSI measurement ops and RX without a network filter (channel selection,
  monitoring), and LBT on TX;
- `rx_stop` of a running RX (the PT leaves its search RX when it hears a beacon).

The timing numbers of the PHY enter the MAC as compile-time constants in `tdma_mac.h`
(`TDMA_PHY_LEAD_TX_TICKS`, `TDMA_PHY_GAP_*`, `TDMA_LRX_TO_TX_SS`, `TDMA_COMMIT_LEAD_TICKS`, ...) and
as rules in the plan validator. Measure your PHY the way [phy-timing.md](phy-timing.md) describes
(lead, op-to-op gaps, PDC latency, TBS) and adjust them; `tdma_plan_validate()` and the simulator
(update its PHY model in `sim.c` to match) then tell you whether the plans still fit.

## 2. `struct tdma_port`

| member | contract |
|---|---|
| `ctx` | passed back to every call |
| `now(ctx)` | current modem time in ticks; must never run ahead of the real modem clock |
| `rx(ctx, handle, start, duration, channel)` | receive on `channel` from `start` (0: as soon as possible, only for the search RX) for `duration` ticks; 0 = accepted |
| `rx_stop(ctx, handle)` | stop an RX op early; its completion still follows |
| `tx(ctx, handle, start, channel, phy_hdr, hdr_len, payload, len, subslots, mcs, lbt_ticks, lbt_dbm)` | send one packet of `subslots` at `start`; `phy_hdr` is the MAC's packed header (decode it with `tdma_phy_hdr_decode()`); `len` never exceeds `tdma_tbs(mcs, subslots)`; with `lbt_ticks > 0` listen before talk (the window counts as part of the op) and complete with `TDMA_ERR_LBT_BUSY` when busy |
| `rssi(ctx, handle, start, duration, channel)` | optional: RSSI measurement, results through `tdma_on_rssi()` |
| `scan(ctx, handle, start, duration, channel)` | optional: RX of any network with RSSI; every valid header to `tdma_on_pcc()`, our packets to `tdma_on_rx()`, RSSI to `tdma_on_rssi()` |
| `deliver(ctx, src_rd_id, data, len)` | a complete SDU; `data` is valid during the call only |
| `sec`, `sec_ctx` | optional link security (below) |
| `trace(...)` | optional per-PDU debug trace |
| `away(ctx, start, dur)` | optional: nonzero when this instance must not use the radio then (a relay's arbiter, `tdma_relay_away()`) |

Rules:

- **Every call is non-blocking.** The MAC commits ops ~1 ms ahead; a port that sleeps in `tx()`
  makes bursts late.
- **Completions**: every accepted op completes exactly once through `tdma_on_op_done(m, handle,
  err)` (0, a negative errno, or `TDMA_ERR_LBT_BUSY`). Received packets come through
  `tdma_on_rx()` **before** the completion of the RX op that received them.
- **Handles** are the MAC's; map them to the PHY's own handles (the nRF port keeps an op table).
  After a new `tdma_init()` of the same instance, drop completions of ops from the old setup.
- An op that is refused (`rx`/`tx` return nonzero) never completes; an op whose completion was
  lost must be completed by the port (the nRF port reaps ops 30 ms after their end with
  `-ETIMEDOUT`), or the MAC waits for it forever.

## 3. The MAC thread

One context owns each `struct tdma_mac`. A minimal loop (this is what `tdma_nrf_runner.c` does):

```c
for (;;) {
	wait for a PHY event or until `next` (modem time), whichever comes first;
	lock();
	if (event) feed it: tdma_on_rx() / tdma_on_op_done() / tdma_on_rssi() / tdma_on_pcc();
	next = tdma_tick(&mac, port.now(port.ctx));
	unlock();
}
```

- Other threads call `tdma_send()`, `tdma_get_stats()` etc. under the same lock.
- The thread must run promptly at `next`: it commits ops 1 ms before air. On Zephyr the nRF port's
  runner uses a cooperative priority; a meta-IRQ priority is better when other cooperative
  threads can hold the CPU for more than a few hundred microseconds.
- Keep the event path short: copy a received payload once, hand messages to the thread, do no
  other work in the PHY's event handler.
- A relay runs two instances on one radio (`tdma_relay_init()`); its thread ticks both, calls
  `tdma_relay_sync()` before feeding the child instance and `tdma_relay_plan_step()` once per
  tick, and installs `tdma_port.away` = `tdma_relay_away()`.

## 4. Configuration

`struct tdma_cfg` holds the role, the radio device id (`rd_id`, unique; its low 16 bits are the
short id and must be unique per network, never 0 or 0xffff), the network id (low byte = short
network id, not 0), the carrier set (`ch_min..ch_max`, `ch_mask`), the plan and its options, the
event callback, and the storage (`cfg.mem`, usually `tdma_mem_of(&store)` of a static `struct
tdma_mac_store`). Zero means "default" for most numeric fields (`TDMA_DEF_*`), `TDMA_OFF` turns a
feature off.

Compile-time sizes (`TDMA_MAX_POSITIONS`, `TDMA_MAX_SDU`, queue sizes; on Zephyr the
`CONFIG_TDMA_MAC_*` options) change the layout of `struct tdma_mac`: build the library and
everything that includes `tdma_mac.h` with the same values (the CMake functions make them PUBLIC
definitions; on Zephyr they come from autoconf.h).

## 5. Link security

`struct tdma_sec_ops` (in `tdma_port.h`) keeps the crypto out of the MAC: the MAC builds the
nonce, the AAD and the packet layout, the platform derives session keys behind opaque handles and
seals / opens bursts with AES-128-CCM.

- `derive(ctx, key_idx, network_id, ft_rd, sess_ctr, sess_rand, &handle)`: a session key for
  that FT session; `TDMA_ERR_NOKEY` when the key index is not installed.
- `seal` / `open`: CCM with a 13-byte nonce and `TDMA_SEC_MIC_LEN`-byte tag, in place; `open`
  returns `-EBADMSG` on a MIC failure.
- `key_state`: which key index to run on and an announced switch.
- `random`: 32-bit random numbers (session random).
- `seal_ticks_base` / `seal_ticks_per16` (and `open_ticks_*`): a cost model. Measure your seal
  time; the MAC commits TX slots that much earlier and plans around the verify time of received
  bursts. Without it a slow AES makes bursts late.
- The FT persists its session counter (`cfg.sess_ctr`) so that sessions never repeat across
  reboots; both ends must agree on the session-key derivation.

[`tdma_sec_ref.h`](../include/cappella/tdma_sec_ref.h) is a portable reference implementation
(software AES, keys in RAM, SP 800-108 counter-mode CMAC KDF). It is slow and keeps keys in plain
memory: use it to bring a port up, then put the ops in front of a hardware AES and a protected key
store.

## 6. Bring-up checklist

1. Build the host tests and run them (`ctest`): they are the reference behaviour.
2. Implement `now`, `rx`, `rx_stop`, `tx`, `deliver`; leave `rssi` / `scan` NULL and use a fixed
   channel (`cfg.channel`) first.
3. Two boards, plan H, no security: `TDMA_EVT_FT_STARTED` on the FT, `TDMA_EVT_ASSOCIATED` on the
   PT. Watch `tdma_get_stats()`: `late_slots` and `port_errors` must stay 0, `bad_rx` near 0.
4. Count PHY errors per op kind and lead at the call (the nRF port's counters and error log show
   how); fix the constants until they are 0 under bulk both ways.
5. Add `rssi` / `scan` (channel selection, monitoring), then security with a measured cost model.
6. Two-instance relays last.

## 7. Zephyr

`zephyr/module.yml` makes the repository a Zephyr module: list it in your west manifest or add it
with `list(APPEND EXTRA_ZEPHYR_MODULES <path>)` before `find_package(Zephyr)`, then
`CONFIG_TDMA_MAC=y`. `CONFIG_TDMA_NRF_DECT_PHY=y` adds the nRF91 port and `CONFIG_TDMA_NRF_RUNNER=y`
the simple MAC thread. See [the sample](../samples/link_demo/README.md).
