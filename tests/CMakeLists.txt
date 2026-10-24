# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 The cappella-mac authors
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Host simulation tests: a deterministic multi-node simulator (sim/) with a fake
# PHY that enforces the measured nRF91 DECT PHY timing, and the MAC on top.
# Built from the top-level CMakeLists.txt (CAPPELLA_MAC_TESTS).

set(CAPPELLA_TEST_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test_units.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test_net.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test_sec.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test_relay.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test_scan.c
)

# next_commit(): every memoised result is checked against the full evaluation.
cappella_mac_library(cappella_mac_check DEFINES TDMA_CHECK_LEAD_MEMO)
cappella_sim_add(tdma_tests cappella_mac_check ${CAPPELLA_TEST_SOURCES})

set(CAPPELLA_TESTS
  pdu phy_model pdu_fuzz plan link link_fuzz link_slots api
  assoc_1pt assoc_full assoc_10pt latency_a latency_b latency_1x10
  loss10 ft_loss pt_loss drift frag fuzz_rx stress
  hybrid_plan hybrid_small grant_ul flex_dl bulk_loss fair floor_bulk link_mcs echo throughput
  plan_switch lopsided plan_switch_t2 plan_switch_bq plan_paced plan_multi
  chan_select lbt chan_move move_cmd hop
  sec_vectors sec_basic sec_hw_model sec_wrong_key sec_rogue_ft sec_forged_ack sec_foreign
  sec_replay sec_tamper sec_ft_restart sec_counter_wrap sec_rekey sec_dup_id sec_timing
  sec_rx_busy sec_fuzz sec_devkey sec_deny sec_beacon_miss
  relay_plan relay_chain relay_pipe relay_pipe3 relay_hgx relay_hgx_reroute relay_ef_abuse
  relay_hold relay_reroute relay_retime relay_two relay_loss relay_renumber relay_depth
  relay_dynamic pos_compact backup_probe
  ft_scan)
foreach(t ${CAPPELLA_TESTS})
  add_test(NAME ${t} COMMAND tdma_tests ${t})
endforeach()

# A second SDU size keeps the sizing honest: the same library and tests with
# 1604-byte SDUs, a subset run.
cappella_mac_library(cappella_mac_sdu1604 DEFINES TDMA_MAX_SDU=1604 TDMA_CHECK_LEAD_MEMO)
cappella_sim_add(tdma_tests_sdu1604 cappella_mac_sdu1604 ${CAPPELLA_TEST_SOURCES})
foreach(t pdu link api frag fuzz_rx stress bulk_loss throughput plan_switch plan_switch_t2
    plan_switch_bq plan_paced lopsided sec_basic sec_fuzz relay_chain)
  add_test(NAME sdu1604_${t} COMMAND tdma_tests_sdu1604 ${t})
endforeach()

# The MAC sources must never pull in floating point, the heap or Zephyr.
add_test(NAME mac_is_freestanding
  COMMAND sh -c "! grep -nE '\\b(float|double)\\b|zephyr/|malloc|calloc|free\\(' \
${PROJECT_SOURCE_DIR}/src/*.c ${PROJECT_SOURCE_DIR}/src/*.h \
${PROJECT_SOURCE_DIR}/include/cappella/tdma_mac.h \
${PROJECT_SOURCE_DIR}/include/cappella/tdma_pdu.h \
${PROJECT_SOURCE_DIR}/include/cappella/tdma_port.h")
