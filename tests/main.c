/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Test runner: `tdma_tests [name|all]`. ctest runs every test by name. */

#include <stdio.h>
#include <string.h>

#include <cappella/tdma_mac.h>
#include "test.h"

struct test {
	const char *name;
	void (*fn)(void);
};

static const struct test tests[] = {
	{"pdu", test_pdu},
	{"phy_model", test_phy_model},
	{"pdu_fuzz", test_pdu_fuzz},
	{"plan", test_plan},
	{"link", test_link},
	{"link_fuzz", test_link_fuzz},
	{"link_slots", test_link_slots},
	{"api", test_api},
	{"assoc_1pt", test_assoc_1pt},
	{"assoc_full", test_assoc_full},
	{"assoc_10pt", test_assoc_10pt},
	{"latency_a", test_latency_a},
	{"latency_b", test_latency_b},
	{"latency_1x10", test_latency_1x10},
	{"loss10", test_loss10},
	{"ft_loss", test_ft_loss},
	{"pt_loss", test_pt_loss},
	{"drift", test_drift},
	{"frag", test_frag},
	{"fuzz_rx", test_fuzz_rx},
	{"stress", test_stress},
	{"hybrid_plan", test_hybrid_plan},
	{"hybrid_small", test_hybrid_small},
	{"grant_ul", test_grant_ul},
	{"flex_dl", test_flex_dl},
	{"bulk_loss", test_bulk_loss},
	{"fair", test_fair},
	{"floor_bulk", test_floor_bulk},
	{"link_mcs", test_link_mcs},
	{"echo", test_echo},
	{"throughput", test_throughput},
	{"plan_switch", test_plan_switch},
	{"lopsided", test_lopsided},
	{"plan_switch_t2", test_plan_switch_t2},
	{"plan_switch_bq", test_plan_switch_bq},
	{"plan_paced", test_plan_paced},
	{"plan_multi", test_plan_multi},
	{"chan_select", test_chan_select},
	{"lbt", test_lbt},
	{"chan_move", test_chan_move},
	{"move_cmd", test_move_cmd},
	{"hop", test_hop},
	{"sec_vectors", test_sec_vectors},
	{"sec_basic", test_sec_basic},
	{"sec_hw_model", test_sec_hw_model},
	{"sec_wrong_key", test_sec_wrong_key},
	{"sec_rogue_ft", test_sec_rogue_ft},
	{"sec_forged_ack", test_sec_forged_ack},
	{"sec_foreign", test_sec_foreign},
	{"sec_replay", test_sec_replay},
	{"sec_tamper", test_sec_tamper},
	{"sec_ft_restart", test_sec_ft_restart},
	{"sec_counter_wrap", test_sec_counter_wrap},
	{"sec_rekey", test_sec_rekey},
	{"sec_dup_id", test_sec_dup_id},
	{"sec_timing", test_sec_timing},
	{"sec_rx_busy", test_sec_rx_busy},
	{"sec_fuzz", test_sec_fuzz},
	{"sec_devkey", test_sec_devkey},
	{"sec_deny", test_sec_deny},
	{"sec_beacon_miss", test_sec_beacon_miss},
	{"relay_plan", test_relay_plan},
	{"relay_chain", test_relay_chain},
	{"relay_pipe", test_relay_pipe},
	{"relay_pipe3", test_relay_pipe3},
	{"relay_hgx", test_relay_hgx},
	{"relay_hgx_reroute", test_relay_hgx_reroute},
	{"relay_ef_abuse", test_relay_ef_abuse},
	{"relay_hold", test_relay_hold},
	{"relay_reroute", test_relay_reroute},
	{"relay_retime", test_relay_retime},
	{"relay_two", test_relay_two},
	{"relay_loss", test_relay_loss},
	{"relay_renumber", test_relay_renumber},
	{"relay_depth", test_relay_depth},
	{"relay_dynamic", test_relay_dynamic},
	{"ft_scan", test_ft_scan},
	{"pos_compact", test_pos_compact},
	{"backup_probe", test_backup_probe},
};

int main(int argc, char **argv)
{
	const char *want = argc > 1 ? argv[1] : "all";
	int ran = 0;

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		if (strcmp(want, "all") && strcmp(want, tests[i].name)) {
			continue;
		}
		int before = test_failures;

		printf("== %s\n", tests[i].name);
		tests[i].fn();
		printf("== %s: %s\n", tests[i].name, test_failures == before ? "PASS" : "FAIL");
		ran++;
	}
	lat_table_print();
	if (!ran) {
		printf("unknown test '%s'\n", want);
		return 2;
	}
	printf("\n%d test(s), %d failure(s)\n", ran, test_failures);
	return test_failures ? 1 : 0;
}
