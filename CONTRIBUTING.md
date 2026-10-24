# Contributing

Thanks for your interest. Bug reports, measurements on other boards or modem firmware, and
patches are welcome.

## Before you open a pull request

1. **Build and test on a host**:
   ```sh
   cmake -S . -B build && cmake --build build -j && ctest --test-dir build -j 8
   cmake -S . -B build-san -DCMAKE_C_COMPILER=clang -DCAPPELLA_MAC_SANITIZE=ON
   cmake --build build-san -j && ctest --test-dir build-san -j 8
   ```
   Builds use `-Wall -Wextra -Werror` (the MAC itself also `-Wpedantic -Wshadow -Wconversion`).
2. **Lint**: `ci/lint.sh` (clang-format 21.1.8 from `pip install clang-format==21.1.8`, and
   cppcheck). `ci/lint.sh --fix` formats in place.
3. **Build the sample** if you touched `port/` or `zephyr/`:
   `west build -b nrf9151dk/nrf9151/ns samples/link_demo` with the NCS version in `NCS_VERSION`;
   no compiler warnings.
4. **Add or extend a simulation test** for any behaviour change. Network tests must keep
   asserting zero PHY-contract violations, zero port errors and zero late slots.

## Rules for the MAC (`src/`, `include/cappella/tdma_*.h`)

- C99, no heap, no floating point, no OS headers (`mac_is_freestanding` checks it).
- Every entry point is non-blocking and runs in the caller's single MAC context.
- Compile-time sizes go through `#ifndef` defaults and `CONFIG_TDMA_MAC_*` Kconfig options.
- Changes to the air format need a version / flag so older decoders keep working, and a codec
  test.
- Timing rules come from measurements: if you change one, update the simulator's PHY model and
  `docs/phy-timing.md` with how you measured it.

## Commits and licensing

- One logical change per commit, with a message that says why.
- Every source file carries the MPL-2.0 header with `Copyright (c) <year> The cappella-mac
  authors`. By contributing you agree that your contribution is licensed under the MPL-2.0.
- Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).
- Do not commit keys, device serial numbers, or captures from networks you do not own.

## Reporting bugs

Open an issue with the board, NCS and modem firmware versions, the plan and configuration, and
the `link status` / `link errlog` output (or the counters of your application) from both ends.
Security issues: see [SECURITY.md](SECURITY.md).
