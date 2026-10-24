# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). Until 1.0 the API (`include/cappella/`) and the air
format may change in minor versions.

## [Unreleased]

## [0.1.0] - 2026-10-24

First public release.

### Added

- The MAC (`src/`): FT / PT state machines, just-in-time scheduler, slot plans A, 1x10, B, H, H4,
  T, T2, T2D, BQ, T4, HG, HGX with a plan validator, automatic plan switching, selective-repeat
  ARQ, fragmentation at build time, concurrent reassembly, priority classes, per-link MCS,
  channel selection, LBT, interference monitoring, announced moves, frequency hopping, link
  security framing (AES-128-CCM per burst through `struct tdma_sec_ops`), relays (two instances
  on one radio), root scan.
- The nRF91 port (`port/nrf_dect_phy/`) on `nrf_modem_dect_phy` (mfw-nr+ 2.0.0), with an optional
  single-instance MAC thread (`CONFIG_TDMA_NRF_RUNNER`).
- A reference software security backend (`port/sec_ref/`).
- Zephyr module (`zephyr/`), host build (CMake), 95 simulation tests (`tests/`).
- Sample `samples/link_demo` for two nRF9151 DKs.
- Documentation: MAC design, PHY timing notes, porting guide.
