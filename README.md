# cappella-mac

A scheduled (TDMA) MAC for **DECT NR+** that runs on Nordic's **DECT NR+ PHY API**
(`nrf_modem_dect_phy`, modem firmware **mfw-nr+ 2.0.0**) instead of Nordic's own MAC. It gives an
nRF91 bounded, low latency for small packets, high throughput for bulk transfers, and multi-hop
relaying, on one carrier or hopping over several.

- **Portable core**: C99, no heap, no floating point, no OS. The platform is one struct of
  function pointers (`struct tdma_port`).
- **nRF91 port included**: `port/nrf_dect_phy` runs the MAC on an nRF9151 / nRF9161 out of the
  box, as a Zephyr module for the nRF Connect SDK.
- **Tested on a host**: a deterministic multi-node simulator with a fake PHY that enforces the
  measured nRF91 timing; 95 simulation tests run under ASan and UBSan in CI.

Licensed under the [Mozilla Public License 2.0](LICENSE).

> cappella-mac has its own air format. It is not the ETSI DECT-2020 NR MAC and does not
> interoperate with Nordic's DECT NR+ MAC or other DECT NR+ stacks.

## Features

- **Slot plans**: frame layouts as data (`src/tdma_plan.c`), checked by a validator against the
  PHY's measured rules. Low-latency plans (B, BQ: ≤ 4.4 ms worst case for 2 PTs), hybrid plans
  with guaranteed slots plus on-demand long bursts (H, H4), bulk plans with trains of 700 B
  bursts (T, T2, T2D, T4), and child-cluster plans for relays (HG, HGX).
- **Automatic plan switching** by measured demand, announced in the beacon; PTs follow without
  re-associating.
- **ARQ and fragmentation**: selective repeat (window 8 / 16), fragments cut at burst build time,
  concurrent reassembly in a shared pool, SDUs up to 1280 B (configurable), in-order delivery.
- **Priority classes**: small priority SDUs bypass bulk in the queue and in the DL burst, with
  reserved queue room; a relay's own priority traffic goes before forwarded traffic.
- **Per-link MCS** for long bursts from the measured SNR, with hysteresis.
- **LBT** before the first beacon on a carrier and for association requests.
- **Channel selection, monitoring and moves**: RSSI scan at start, interference monitoring in
  idle parts of the frame, announced channel moves without re-association.
- **Frequency hopping** per frame over a measured hop set that adapts to interferers.
- **Relays**: a node can run a child cluster on a second MAC instance on the same radio; the
  arbiter shares the radio by frame blocks. Pipelined forwarding, backpressure, retiming,
  position moves, backup probes and fast reroute for self-healing trees.
- **Root scan**: a root listens for other clusters (beacons, route records) in an announced quiet
  window, without losing traffic.
- **Link security hooks**: AES-128-CCM per burst with a 4/6/8-byte MIC, implicit nonces, sealed
  beacons, session keys, announced key switches, a deny list, replay protection. The crypto is a
  port callback (`struct tdma_sec_ops`); a reference software implementation is included for
  the simulator and the sample.

## Measured performance

Two nRF9151 DKs (four for the multi-PT and multi-hop rows) connected by **SMA cables**, mfw-nr+
2.0.0, NCS v3.4.1, band 9, MCS 4, link security on (AES-128-CCM in a secure partition), plan H
with automatic plan switching. Throughput is MAC level: 1200 B SDUs handed to `tdma_send()` as
fast as the MAC takes them, counted on delivery. Latency is one-way, measured on the shared
frame clock: 64 B priority probes at randomised intervals (a fixed interval would lock to the 10
ms frame).

| measurement | result |
|---|---|
| throughput, one hop, PT → FT / FT → PT | **~256 / 247 kB/s** |
| throughput, one hop, both directions at once | 130 + 116 kB/s |
| latency, idle link, avg / p99 | 3.5-3.7 / 4.1-4.6 ms |
| latency **under bulk** on the same link, p99 | **~7.6 ms** |
| three PTs probing at once, p99; UL per PT, all saturating | 7.9-8.4 ms; 49 kB/s each (Jain 1.0) |
| 2 hops (one relay), p99 up / down | 9.9 / 11.1 ms |
| 3 hops (two relays), p99 up / down | 13.1 / 14.9 ms |
| PHY op errors over a full test battery | 0 |

In the simulator (same PHY model, no loss) the asserted worst cases for 64 B are 4.1 ms (plan B),
6.9 ms (plan H) and 7.9 ms (plan H4), and stay there under bulk load on every link. Range was
not tested beyond a bench; numbers over the air at distance will be lower.

## Architecture

```
 application (your protocol: routing, mesh policy, host interface, ...)
   |  tdma_send()  tdma_cfg  events (associated, child added, lost, moves, ...)
   v
 +------------------------------- cappella-mac (src/, OS-free C99) ------------------------+
 |  tdma_mac.c   FT / PT state machines, just-in-time scheduler, beacons, grants,          |
 |               plan switching, channel access (scan, LBT, monitor, moves, hopping),     |
 |               link security framing, root scan                                         |
 |  tdma_link.c  per-peer ARQ, queues, fragmentation, reassembly, priority                |
 |  tdma_plan.c  slot plans + validator          tdma_pdu.c  PDU / record codec            |
 |  tdma_relay.c two instances on one radio: block arbiter, plan / grid follow            |
 +-----------------------------------------------------------------------------------------+
   |  struct tdma_port: now, rx, rx_stop, tx (+LBT), rssi, scan, deliver, sec, away
   |  tdma_on_rx(), tdma_on_op_done(), tdma_on_rssi(), tdma_on_pcc(), tdma_tick()
   v
 +------------- port/nrf_dect_phy (Zephyr) -------------+   +---- tests/sim (host) -----+
 | event queue, modem time, op table, quiet window,     |   | multi-node simulator,     |
 | bring-up, dispatch; optional MAC thread (runner)     |   | fake PHY with the nRF91   |
 +------------------------------------------------------+   | timing, shared air, loss, |
   |  nrf_modem_dect_phy (mfw-nr+ 2.0.0)                    | interferers, crypto model |
   v                                                        +---------------------------+
 nRF91 modem
```

The MAC never blocks. Every PHY op is handed over just in time, 1 ms before it starts, so a burst
carries whatever was queued until then; the thread that owns the MAC calls `tdma_tick()` when the
MAC asks for it. Design: [docs/mac-design.md](docs/mac-design.md). PHY measurements behind the
schedule: [docs/phy-timing.md](docs/phy-timing.md).

## Repository layout

```
include/cappella/   public headers: tdma_mac.h, tdma_port.h, tdma_pdu.h, tdma_nrf.h,
                    tdma_nrf_runner.h, tdma_sec_ref.h, tdma_sec_ref_crypto.h
src/                the MAC
port/nrf_dect_phy/  the nRF91 port (Zephyr)
port/sec_ref/       reference AES-128-CCM / CMAC / KDF and struct tdma_sec_ops on top
zephyr/             module.yml, CMakeLists.txt, Kconfig
tests/              host simulation tests (CMake / CTest); tests/sim: simulator and harness
samples/link_demo/  two-board link / ping / throughput demo for nrf9151dk
docs/               design, PHY timing notes, porting guide
ci/                 lint script, cppcheck configuration
```

## Quick start

### Simulations on a host

Linux or macOS with CMake ≥ 3.20 and gcc or clang:

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build -j 8 --output-on-failure
```

With sanitizers: `cmake -S . -B build-san -DCAPPELLA_MAC_SANITIZE=ON -DCMAKE_C_COMPILER=clang`.
One test with its output: `build/tests/tdma_tests latency_a` (`all` runs every test and prints
the latency table). Lint: `ci/lint.sh` (clang-format 21.1.8, cppcheck).

### The sample on two nRF91 DKs

You need the nRF Connect SDK (the version in [NCS_VERSION](NCS_VERSION)) and the DECT NR+ modem
firmware mfw-nr+ 2.0.0 on both DKs (from Nordic; it is not part of this repository).

```sh
west build -b nrf9151dk/nrf9151/ns samples/link_demo
west flash
```

Flash the same image on both boards, connect a terminal to each, then:

```
board 1: link ft             board 2: link pt
                             (wait for "associated with FT ...")
board 2: link ping 20        board 2: link tput 10      board 1: link rx
```

See [samples/link_demo/README.md](samples/link_demo/README.md) for the band, carrier and power
settings. **Check your region's spectrum rules before you transmit.**

### Your own application

Add the module (`list(APPEND EXTRA_ZEPHYR_MODULES <path>/cappella-mac)` or a west manifest entry),
set `CONFIG_TDMA_MAC=y`, `CONFIG_TDMA_NRF_DECT_PHY=y`, and either use the runner
(`CONFIG_TDMA_NRF_RUNNER=y`, `cappella/tdma_nrf_runner.h`) or write your own MAC thread around
`tdma_nrf_msg_get()` / `tdma_nrf_dispatch()` / `tdma_tick()` (needed for relays).

## Porting to another PHY

The core needs scheduled TX / RX at absolute times, packet receive times, RSSI / SNR, and
completion events: see [docs/porting.md](docs/porting.md) for the `tdma_port` contract, the
threading rules, how to measure and enter your PHY's timing, and a bring-up checklist.

## Kconfig reference

| option | default | meaning |
|---|---|---|
| `CONFIG_TDMA_MAC` | n | build the MAC |
| `CONFIG_TDMA_MAC_MAX_POSITIONS` | 10 | PT positions per FT (each costs a peer link in `struct tdma_mac`) |
| `CONFIG_TDMA_MAC_MAX_SDU` | 1280 | largest SDU |
| `CONFIG_TDMA_MAC_TXQ_BYTES` | 7680 | SDU bytes queued per peer (the deep queues of the bulk plans) |
| `CONFIG_TDMA_MAC_TXQ_PRIO_BYTES` | 256 | extra queue room only priority SDUs may take |
| `CONFIG_TDMA_MAC_TXQ_SDUS` | 24 | SDUs queued per peer |
| `CONFIG_TDMA_MAC_TXQ_PDUS` | 20 | PDU descriptors per peer |
| `CONFIG_TDMA_MAC_RAS_SLOTS` | 7 | shared reassembly buffers |
| `CONFIG_TDMA_MAC_TX_SDU_INFLIGHT` | 2 | fragmented SDUs in flight per peer (both ends equal) |
| `CONFIG_TDMA_MAC_PDU_MAX` | 113 | largest single PDU |
| `CONFIG_TDMA_MAC_COMMIT_LEAD_US` | 1000 | ops reach the PHY this long before they start |
| `CONFIG_TDMA_MAC_SEC_MIC_LEN` | 4 | MIC bytes per secured burst (4, 6, 8) |
| `CONFIG_TDMA_SEC_REF` | n | the reference software security backend |
| `CONFIG_TDMA_NRF_DECT_PHY` | n | the nRF91 port |
| `CONFIG_TDMA_NRF_EVT_QUEUE` | 16 | PHY event queue depth (half as many 700 B RX buffers) |
| `CONFIG_TDMA_NRF_OPS` | 16 | PHY ops in flight |
| `CONFIG_TDMA_NRF_QUIET_US` / `_QUIET_LATE_US` | 650 / 200 | the PHY quiet window before each op |
| `CONFIG_TDMA_NRF_RUNNER` | n | a simple MAC thread for one instance |
| `CONFIG_TDMA_NRF_RUNNER_STACK_SIZE` / `_PRIO` | 3072 / 0 | its stack and cooperative priority |
| `CONFIG_TDMA_NRF_LOG_LEVEL` | default | the port's log level |

Everything else (plan, MCS, carriers, scan, LBT, monitor, hopping, timeouts, security options)
is run-time configuration in `struct tdma_cfg`; see `include/cappella/tdma_mac.h`.

## Limitations

- **Not interoperable** with the ETSI DECT-2020 NR MAC or Nordic's DECT NR+ MAC.
- Measured on a bench (SMA cable, ~10 cm); range, multipath and real-world interference are not
  characterised.
- One FT serves up to 10 PTs (plan 1x10); the low-latency plans serve 2, the 4-PT plans ~7-8 ms
  worst case. Eight PTs at ≤ 5 ms do not fit one carrier.
- No HARQ (ARQ only), no CLOSING beacon on FT shutdown.
- The nRF91 port is tuned for the nRF9151 at 64 MHz with the timings of mfw-nr+ 2.0.0; other
  modem firmware versions should be re-measured ([docs/phy-timing.md](docs/phy-timing.md)).
- Relays need an application-side MAC thread with two instances; the included runner drives one.
- Routing, mesh policy (which parent, when to reroute) and key management are the application's.
- The reference security backend is slow and keeps keys in RAM: for bring-up and tests only.
- The API is not yet stable (0.x): see [CHANGELOG.md](CHANGELOG.md).

## Contributing, security

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md)

## License

Mozilla Public License 2.0 ([LICENSE](LICENSE)). Files you add to the MAC must carry the MPL-2.0
header; your application code that only uses the headers may be under any license.
