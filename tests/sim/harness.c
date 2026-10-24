/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Shared test harness: failure count and the latency summary table. */

#include <stdio.h>

#include <cappella/tdma_mac.h>

#include "test.h"

int test_failures;

static struct lat_row rows[64];
static int n_rows;

void lat_table_add(const struct lat_row *r)
{
	if (n_rows < (int)(sizeof(rows) / sizeof(rows[0]))) {
		rows[n_rows++] = *r;
	}
}

#define US(t) ((unsigned long long)TDMA_TICKS_TO_US(t))

void lat_table_print(void)
{
	if (!n_rows) {
		return;
	}
	printf("\n%-28s %6s %6s %5s %4s | %22s | %22s | %22s | %22s | %7s | %6s\n", "flow set",
	       "sent", "dlvd", "drop", "dup", "min ticks (us)", "avg ticks (us)", "p99 ticks (us)",
	       "max ticks (us)", "bound us", "<=5ms");
	for (int i = 0; i < n_rows; i++) {
		const struct lat_row *r = &rows[i];
		char b[4][32];

		snprintf(b[0], sizeof(b[0]), "%llu (%llu)", r->min, US(r->min));
		snprintf(b[1], sizeof(b[1]), "%llu (%llu)", r->avg, US(r->avg));
		snprintf(b[2], sizeof(b[2]), "%llu (%llu)", r->p99, US(r->p99));
		snprintf(b[3], sizeof(b[3]), "%llu (%llu)", r->max, US(r->max));
		printf("%-28s %6u %6u %5u %4u | %22s | %22s | %22s | %22s | %7llu | %5.1f%%\n",
		       r->name, r->sent, r->delivered, r->dropped, r->dups, b[0], b[1], b[2], b[3],
		       r->bound ? US(r->bound) : 0ull, r->pct_5ms);
	}
	n_rows = 0;
}
