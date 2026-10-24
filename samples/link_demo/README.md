# Link demo (nRF9151 DK)

Two nRF91 DKs on cappella-mac over the DECT NR+ PHY: one FT, one PT, a shell to start them,
ping, and measure throughput. It uses the nRF91 port and its single-instance MAC thread
(`CONFIG_TDMA_NRF_RUNNER`).

## Requirements

- Two nRF9151 DKs (nRF9161 DKs should work with a board overlay like the one in `boards/`).
- The DECT NR+ modem firmware **mfw-nr+ 2.0.0** on both, from Nordic (program it with the
  nRF Connect for Desktop Programmer or `nrfutil`; it is not part of this repository).
- The nRF Connect SDK version in [`NCS_VERSION`](../../NCS_VERSION).
- Antennas, or better an SMA cable with attenuation between the boards for a bench test.

## Radio settings

**Make sure the band, carriers and power are allowed where you run the demo.** Defaults
(`Kconfig`, override in `prj.conf` or with `-D`):

| option | default | |
|---|---|---|
| `CONFIG_LINK_DEMO_BAND` | 1 | 1880-1900 MHz (carriers 1657-1677); band 9 = 1920-1930 MHz (1703-1711) |
| `CONFIG_LINK_DEMO_CH_MIN` / `_CH_MAX` | 1657 / 1677 | the carrier set |
| `CONFIG_LINK_DEMO_CHANNEL` | 0 | FT carrier; 0 = the quietest by an RSSI scan |
| `CONFIG_LINK_DEMO_TX_POWER_DBM` | 4 | rounded down to a DECT power step, at most 19 |
| `CONFIG_LINK_DEMO_NETWORK_ID` | 0x0000a501 | both boards; low byte not 0 |
| `CONFIG_LINK_DEMO_PLAN` | 3 | plan H (docs/mac-design.md, "Plans") |
| `CONFIG_LINK_DEMO_PLAN_AUTO` | y | bulk plans under bulk traffic |
| `CONFIG_LINK_DEMO_ROLE_*` | none | role at boot; none = wait for the shell |

## Build and flash

```sh
west build -b nrf9151dk/nrf9151/ns samples/link_demo
west flash --dev-id <J-Link serial of board 1>
west flash --dev-id <J-Link serial of board 2>
```

With link security (the reference software AES-CCM, slow, keys in RAM):

```sh
west build -b nrf9151dk/nrf9151/ns samples/link_demo -- -DEXTRA_CONF_FILE=overlay-sec.conf
```

## Use

Open a terminal on each board's first VCOM port (115200 baud). After boot each prints
`link demo: ready, rd id 0x...`.

```
board 1> link ft
board 2> link pt
          ... <inf> link_demo: associated with FT 0x...
board 2> link ping 20
          20 x 32 B: 20 answered, RTT min <ms> avg <ms> max <ms> ms
board 2> link ping 20 1000
board 2> link tput 10
board 1> link rx
board 1> link status
```

| command | |
|---|---|
| `link ft [carrier]` | start as FT (no carrier / 0: scan for the quietest one) |
| `link pt` | start as PT: search, associate with the first FT of the network |
| `link stop` | stop the MAC |
| `link status` | state, carrier, plan, peer, MAC and PHY counters |
| `link ping [n] [len]` | n round trips to the peer (it echoes); ≤ 64 B go as priority SDUs |
| `link tput <s> [len]` | send len-byte SDUs (default 1200) to the peer for s seconds as fast as the MAC takes them |
| `link rx` | bytes received and the rate since the last call |
| `link key <32 hex>` / `off` | with `overlay-sec.conf`: the network key (index 0), used from the next start; same key on both boards |
| `link errlog [clear]` | the port's PHY op error log |

Ping RTT includes both directions, the echo and the shell; one-way latency is about half of it
minus a millisecond or so. Throughput: `link rx` on the receiving board gives the delivered
rate.

## Notes

- The image has no bootloader (NCS's partition layout without MCUboot); the flashable file is
  `build/link_demo/zephyr/tfm_merged.hex` (TF-M + application).
- The board overlay sizes the modem's shared memory for the DECT NR+ firmware.
- Untested on hardware in this exact form: the MAC and port are the ones measured in the
  top-level README, the sample's glue is new. Please report results.
