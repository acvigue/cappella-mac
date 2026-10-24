# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 The cappella-mac authors
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Zephyr build of the MAC (CONFIG_TDMA_MAC) and its nRF91 port
# (CONFIG_TDMA_NRF_DECT_PHY). The MAC sources are OS-free C99; the Kconfig sizes
# reach cappella/tdma_mac.h through the auto-included autoconf.h, so the
# application and the library always agree on struct tdma_mac's layout.

if(CONFIG_TDMA_MAC)
  set(CAPPELLA_MAC_DIR ${CMAKE_CURRENT_LIST_DIR}/..)
  if(NOT DEFINED TDMA_MAC_OPT_FLAGS)
    set(TDMA_MAC_OPT_FLAGS -O2)
  endif()

  zephyr_include_directories(${CAPPELLA_MAC_DIR}/include)

  zephyr_library_named(cappella_mac)
  zephyr_library_sources(
    ${CAPPELLA_MAC_DIR}/src/tdma_plan.c
    ${CAPPELLA_MAC_DIR}/src/tdma_pdu.c
    ${CAPPELLA_MAC_DIR}/src/tdma_link.c
    ${CAPPELLA_MAC_DIR}/src/tdma_mac.c
    ${CAPPELLA_MAC_DIR}/src/tdma_relay.c
  )
  # The MAC thread's hot path (next_commit, tick, burst build, reassembly) at
  # -O2 instead of the image's -Os (docs/mac-design.md, "CPU").
  zephyr_library_compile_options(${TDMA_MAC_OPT_FLAGS})
  # Plan tables and their validation run once per plan, not per slot: -Os.
  set_source_files_properties(${CAPPELLA_MAC_DIR}/src/tdma_plan.c PROPERTIES COMPILE_OPTIONS -Os)

  zephyr_library_sources_ifdef(CONFIG_TDMA_SEC_REF
    ${CAPPELLA_MAC_DIR}/port/sec_ref/tdma_sec_ref_crypto.c
    ${CAPPELLA_MAC_DIR}/port/sec_ref/tdma_sec_ref.c
  )

  if(CONFIG_TDMA_NRF_DECT_PHY)
    zephyr_library_named(cappella_mac_nrf)
    zephyr_library_sources(${CAPPELLA_MAC_DIR}/port/nrf_dect_phy/tdma_nrf.c)
    zephyr_library_sources_ifdef(CONFIG_TDMA_NRF_RUNNER
      ${CAPPELLA_MAC_DIR}/port/nrf_dect_phy/tdma_nrf_runner.c)
  endif()
endif()
