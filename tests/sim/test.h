/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Minimal test harness shared by the test files. */

#ifndef TEST_H_
#define TEST_H_

#include <stdio.h>

extern int test_failures;
#include <stddef.h>
#include <stdint.h>
extern size_t test_sdu_shrink;
extern uint64_t test_slack_small, test_slack_bulk;

#define CHECK(cond, ...)                                                                           \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			test_failures++;                                                           \
			printf("    FAIL %s:%d: %s: ", __FILE__, __LINE__, #cond);                 \
			printf(__VA_ARGS__);                                                       \
			printf("\n");                                                              \
		}                                                                                  \
	} while (0)

/* Latency summary rows, printed by the latency tests and by "all". */
struct lat_row {
	char name[40];
	unsigned int sent;
	unsigned int delivered;
	unsigned int dropped;
	unsigned int dups;
	unsigned long long min, avg, p99, max; /* ticks */
	unsigned long long bound;              /* ticks, 0 = none */
	double pct_5ms;
};

void lat_table_add(const struct lat_row *r);
void lat_table_print(void);

void test_pdu(void);
void test_pdu_fuzz(void);
void test_plan(void);
void test_link(void);
void test_link_fuzz(void);
void test_link_slots(void);

void test_assoc_1pt(void);
void test_assoc_full(void);
void test_assoc_10pt(void);
void test_latency_a(void);
void test_latency_b(void);
void test_latency_1x10(void);
void test_loss10(void);
void test_ft_loss(void);
void test_pt_loss(void);
void test_drift(void);
void test_frag(void);
void test_api(void);
void test_fuzz_rx(void);
void test_stress(void);
void test_phy_model(void);
void test_hybrid_plan(void);
void test_hybrid_small(void);
void test_grant_ul(void);
void test_flex_dl(void);
void test_bulk_loss(void);
void test_fair(void);
void test_floor_bulk(void);
void test_link_mcs(void);
void test_echo(void);
void test_throughput(void);
void test_plan_switch(void);
void test_lopsided(void);
void test_plan_switch_t2(void);
void test_plan_switch_bq(void);
void test_plan_paced(void);
void test_plan_multi(void);
void test_chan_select(void);
void test_lbt(void);
void test_chan_move(void);
void test_move_cmd(void);
void test_hop(void);
void test_sec_vectors(void);
void test_sec_basic(void);
void test_sec_hw_model(void);
void test_sec_wrong_key(void);
void test_sec_rogue_ft(void);
void test_sec_forged_ack(void);
void test_sec_foreign(void);
void test_sec_replay(void);
void test_sec_tamper(void);
void test_sec_ft_restart(void);
void test_sec_counter_wrap(void);
void test_sec_rekey(void);
void test_sec_dup_id(void);
void test_sec_timing(void);
void test_sec_rx_busy(void);
void test_sec_fuzz(void);
void test_sec_devkey(void);
void test_sec_deny(void);
void test_sec_beacon_miss(void);
void test_relay_plan(void);
void test_relay_chain(void);
void test_relay_pipe(void);
void test_relay_pipe3(void);
void test_relay_hgx(void);
void test_relay_hgx_reroute(void);
void test_relay_ef_abuse(void);
void test_relay_hold(void);
void test_relay_reroute(void);
void test_relay_retime(void);
void test_ft_scan(void);
void test_pos_compact(void);
void test_backup_probe(void);
void test_relay_two(void);
void test_relay_loss(void);
void test_relay_renumber(void);
void test_relay_depth(void);
void test_relay_dynamic(void);

#endif /* TEST_H_ */
