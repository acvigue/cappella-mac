/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Relay support (docs/mac-design.md "Relays"): the radio
 * arbiter between a relay's two MAC instances, the frame alignment of its
 * child cluster, and the storage split.
 *
 * Layout R1: seen from the up instance's frame under a root (plan H), the
 * radio belongs to up in the E blocks [0, 12) and [24, 36) and to down (the
 * child cluster, plan HG, TDMA_RELAY_ROOT_OFFSET_SS later; its blocks start at
 * its subslots 17 and 41) in the O blocks [12, 24) and [36, 48); under another
 * relay's cluster the same with that HG frame's blocks. Every op of an
 * instance must lie inside one of its blocks (TDMA_RELAY_TOL_TICKS of slack
 * for RX margins and timing jitter); the plans keep the PHY's gaps across a
 * block boundary (tdma_relay_plan_check()). The child's first beacon (LBT
 * before it) lies inside its block (the DL burst is last in it).
 */

#include <errno.h>
#include <string.h>

#include "tdma_internal.h"

void tdma_relay_init(struct tdma_relay *r, struct tdma_mac *up, struct tdma_mac *down)
{
	memset(r, 0, sizeof(*r));
	r->up = up;
	r->down = down;
}

bool tdma_relay_running(const struct tdma_relay *r)
{
	return r->down && r->down->state != TDMA_ST_IDLE;
}

/* Position of t in down's frame (ticks, [0, frame)). */
static int64_t dn_rel(const struct tdma_mac *dn, uint64_t t)
{
	int64_t d = (int64_t)(t - dn->ref_start) % (int64_t)TDMA_FRAME_TICKS;

	return d < 0 ? d + (int64_t)TDMA_FRAME_TICKS : d;
}

/*
 * Blocks are taken from down's frame whenever the child cluster runs: down
 * has [0, 12) and [24, 36) of its own frame, up the rest (= up's E blocks
 * while the two are aligned, down = up + tdma_relay_offset_ss()). Without a
 * parent (a reroute, an island) down runs on by itself, and while
 * a new parent's grid differs (until down's re-alignment, TDMA_F_RETIME) up
 * only gets what does not cut into down's blocks.
 */
int tdma_relay_away(struct tdma_relay *r, const struct tdma_mac *who, uint64_t start, uint32_t dur)
{
	const struct tdma_mac *up = r->up, *dn = r->down;
	const bool down = who == dn;
	const int64_t blk = (int64_t)TDMA_RELAY_BLOCK_SS * TDMA_SUBSLOT_TICKS;
	const int64_t tol = (int64_t)TDMA_RELAY_TOL_TICKS;
	bool up_on = up->state == TDMA_ST_ASSOCIATED || up->state == TDMA_ST_ASSOCIATING;
	bool dn_run = dn && dn->state != TDMA_ST_IDLE;
	uint64_t now;
	int64_t rel, end, bs, be;
	unsigned int b;
	int away = 0;

	if (start == 0) {
		/* as soon as possible (search, scan) */
		if (down) {
			away = 1;
		} else if (!dn_run) {
			away = dn && dn->n_ops ? 1 : 0;
		} else {
			/* the child cluster runs on: a search op between its blocks' ops */
			now = up->port.now(up->port.ctx);
			if (now < r->search_hold_until) {
				away = 1;
			} else if (dn->n_ops) {
				r->search_req = true; /* down commits nothing new; its ops drain */
				r->search_req_t = now;
				away = 1;
			} else {
				r->search_req = false;
				r->search_busy_until = now + dur + (uint64_t)tol;
				r->search_hold_until =
					r->search_busy_until +
					(uint64_t)(r->search_gap ? r->search_gap
								 : TDMA_RELAY_SEARCH_GAP) *
						TDMA_FRAME_TICKS;
				r->searches++;
			}
		}
		goto out;
	}
	if (!dn_run) {
		/* no child cluster: the radio is up's (down's last ops drain first) */
		away = down || (dn && dn->n_ops && !up_on);
		goto out;
	}
	if (down) {
		now = dn->port.now(dn->port.ctx);
		/*
		 * up asks again on every tick while it wants to search; a
		 * request it stopped renewing (it found its parent another way, or the
		 * child cluster stopped and started again meanwhile) lapses after two
		 * frames. It stayed set and held the child cluster's ops for good: a
		 * cluster that never beaconed (seen on hardware; reproduced in a mesh fuzz run).
		 */
		if (r->search_req && now - r->search_req_t > 2u * TDMA_FRAME_TICKS) {
			r->search_req = false;
			r->search_lapsed++;
		}
		if (r->search_req || now < r->search_busy_until) {
			away = 1; /* up's search has the radio (or is waiting for it) */
			goto out;
		}
	}
	/* down's blocks start at tdma_relay_origin_ss() of its frame (HG 17, HGX 45) */
	rel = dn_rel(dn, start) - (int64_t)tdma_relay_origin_ss(dn->plan) * TDMA_SUBSLOT_TICKS;
	if (rel < 0) {
		rel += (int64_t)TDMA_FRAME_TICKS;
	}
	if (rel > (int64_t)TDMA_FRAME_TICKS - tol) {
		rel -= (int64_t)TDMA_FRAME_TICKS; /* just before block 0 */
	}
	b = (unsigned int)((rel + tol) / blk);
	bs = (int64_t)b * blk;
	be = bs + blk;
	end = rel + (int64_t)dur;
	if ((b & 1u) != (down ? 0u : 1u) || rel < bs - tol || end > be + tol) {
		away = 1;
	}
out:
	if (away) {
		if (down) {
			r->away_down++;
		} else {
			r->away_up++;
		}
	}
	return away;
}

bool tdma_relay_ready(const struct tdma_relay *r)
{
	const struct tdma_mac *up = r->up;
	uint8_t depth = 0;

	if (up->state != TDMA_ST_ASSOCIATED || up->my_pos < 0) {
		return false;
	}
	tdma_tree(up, &depth, NULL);
	/* our own depth is the parent cluster's + 1; a child cluster would be one deeper */
	if (depth + 1u >= TDMA_MAX_DEPTH) {
		return false;
	}
	return tdma_relay_plan_check(up->plan, (uint8_t)up->my_pos, tdma_plan_get(TDMA_PLAN_HG),
				     NULL) == 0;
}

/*
 * The child cluster on up's grid (+ tdma_relay_offset_ss(), the same frame
 * numbers). without a parent it runs on by itself. With children,
 * a new parent whose grid differs by more than the tolerance (a merge, a
 * parent of another depth) is not jumped to: down announces the shift
 * (TDMA_F_RETIME, TDMA_RELAY_RETIME_AHEAD frames) so its children move with it,
 * and runs on by itself until then. A shift the parent announced is passed
 * on for the same frame.
 */
void tdma_relay_sync(struct tdma_relay *r)
{
	const struct tdma_mac *up = r->up;
	struct tdma_mac *dn = r->down;
	uint64_t target;
	uint32_t kids[1];
	int64_t d;

	if (up->state != TDMA_ST_ASSOCIATED && up->state != TDMA_ST_ASSOCIATING) {
		return;
	}
	target = up->ref_start +
		 (uint64_t)tdma_relay_offset_ss(up->plan, dn->plan) * TDMA_SUBSLOT_TICKS;
	if (dn->state != TDMA_ST_FT) {
		tdma_ft_follow(dn, target, up->ref_frame); /* (where it starts) */
		return;
	}
	if (up->retime_valid && !dn->retime_valid &&
	    tdma_ft_retime(dn, up->retime_frame, up->retime_delta) == 0) {
		r->retimes++;
	}
	if (dn->retime_valid) {
		return; /* runs on by itself until its shift */
	}
	d = (int64_t)(target - dn->ref_start) % (int64_t)TDMA_FRAME_TICKS;
	if (d < 0) {
		d += (int64_t)TDMA_FRAME_TICKS;
	}
	if (d > (int64_t)TDMA_RELAY_TOL_TICKS &&
	    d < (int64_t)TDMA_FRAME_TICKS - (int64_t)TDMA_RELAY_TOL_TICKS &&
	    tdma_children(dn, kids, 1)) {
		if (tdma_ft_retime(dn, dn->cur_frame + TDMA_RELAY_RETIME_AHEAD, (uint32_t)d) == 0) {
			r->retimes++;
		}
		return;
	}
	tdma_ft_follow(dn, target, up->ref_frame);
}

int tdma_mem_split(const struct tdma_mem *all, struct tdma_mem *pt, struct tdma_mem *relay,
		   uint8_t relay_peers, uint8_t relay_ras)
{
	uint8_t first, rbig;
	uint16_t off;

	if (!all->peers || relay_peers == 0 || relay_peers >= all->n_peers || relay_ras == 0 ||
	    relay_ras >= all->n_ras) {
		return -EINVAL;
	}
	first = (uint8_t)(all->n_peers - relay_peers);
	off = tdma_mem_chunks(first, all->n_big);
	rbig = (uint8_t)(all->n_big > first ? all->n_big - first : 0);
	*pt = (struct tdma_mem){
		.peers = all->peers,
		.n_peers = 1,
		.n_big = all->n_big ? 1 : 0,
		.qmem = all->qmem,
		.n_chunks = tdma_mem_chunks(1, all->n_big ? 1 : 0),
		.ras = all->ras,
		.n_ras = (uint8_t)(all->n_ras - relay_ras),
	};
	*relay = (struct tdma_mem){
		.peers = all->peers + first,
		.n_peers = relay_peers,
		.n_big = rbig,
		.qmem = all->qmem + off,
		.n_chunks = tdma_mem_chunks(relay_peers, rbig),
		.ras = all->ras + (all->n_ras - relay_ras),
		.n_ras = relay_ras,
	};
	if (off + relay->n_chunks > all->n_chunks || pt->n_chunks > off) {
		return -EINVAL;
	}
	return 0;
}

/*
 * may the child cluster run plan HGX? It has exactly one child and
 * that one does not relay, and no node asked to join lately (hgx_here(): up
 * also sits in position 1 of a root's plan H / T that HGX fits around).
 */
static bool hgx_fits(const struct tdma_relay *r, uint64_t now)
{
	const struct tdma_mac *dn = r->down;
	uint8_t n = 0;

	if (now < r->hgx_hold_until || dn->room_wanted) {
		return false;
	}
	for (uint8_t i = 0; i < TDMA_MAX_POSITIONS && i < dn->n_peers; i++) {
		if (dn->peers[i].rd_id) {
			if (dn->peers[i].relay) {
				return false;
			}
			n++;
		}
	}
	/*
	 * Exactly one: an empty relay cluster (an offer, a warm backup) stays on HG,
	 * the grid a relay that reroutes to it comes from (no shift for its cluster).
	 */
	return n == 1u;
}

static bool hgx_here(const struct tdma_relay *r)
{
	const struct tdma_mac *up = r->up;
	static const struct tdma_plan *checked;
	static bool fits_plan;

	if (up->state != TDMA_ST_ASSOCIATED || up->my_pos != 1 || !up->plan ||
	    (up->plan->id != TDMA_PLAN_H && up->plan->id != TDMA_PLAN_T)) {
		return false;
	}
	if (checked != up->plan) {
		/* (the check walks every op of both plans: once per parent plan, not per tick) */
		checked = up->plan;
		fits_plan =
			tdma_relay_plan_check(up->plan, 1, tdma_plan_get(TDMA_PLAN_HGX), NULL) == 0;
	}
	return fits_plan;
}

uint8_t tdma_relay_child_plan(const struct tdma_relay *r)
{
	return hgx_here(r) && r->up->port.now(r->up->port.ctx) >= r->hgx_hold_until ? TDMA_PLAN_HGX
										    : TDMA_PLAN_HG;
}

void tdma_relay_plan_step(struct tdma_relay *r)
{
	struct tdma_mac *up = r->up, *dn = r->down;
	uint64_t now;
	uint32_t f;
	bool fits, want;

	if (!dn || dn->state != TDMA_ST_FT || !dn->plan) {
		return;
	}
	now = dn->port.now(dn->port.ctx);
	if (dn->room_wanted) {
		/* a second node asked in an open frame: HG (two positions) for a while */
		dn->room_wanted = false;
		r->hgx_hold_until = now + TDMA_RELAY_HGX_HOLD_TICKS;
	}
	fits = hgx_fits(r, now);
	up->hgx_ok = fits; /* (status record: the root puts us in position 1) */
	up->child_hgx = dn->plan->id == TDMA_PLAN_HGX;
	if (up->state != TDMA_ST_ASSOCIATED) {
		r->up_since = 0;
		return; /* (a reroute, an island: the plan stays until we have a parent) */
	}
	if (!r->up_since) {
		r->up_since = now;
	}
	want = fits && hgx_here(r);
	dn->hgx_want = want;
	if (dn->psw_valid || dn->retime_valid || dn->pm_valid || dn->move_valid ||
	    up->retime_valid) {
		return;
	}
	f = dn->cur_frame + TDMA_RELAY_RETIME_AHEAD;
	if (want && dn->plan->id == TDMA_PLAN_HG) {
		if (dn->peers[1].rd_id) {
			(void)tdma_ft_pos_move(dn, 1, 0); /* HGX has position 0 only */
			return;
		}
		/* the child frame 4 ss earlier: 44 ss later, one frame number on (a new session) */
		if (tdma_ft_relay_switch(dn, TDMA_PLAN_HGX, f,
					 (TDMA_SUBSLOTS_PER_FRAME -
					  (TDMA_RELAY_ROOT_OFFSET_SS - TDMA_RELAY_HGX_OFFSET_SS)) *
						 TDMA_SUBSLOT_TICKS) == 0) {
			r->to_hgx++;
		}
	} else if (!want && dn->plan->id == TDMA_PLAN_HGX &&
		   (!fits || now - r->up_since >= TDMA_RELAY_HGX_GRACE_TICKS)) {
		/* (a new parent: the root may still move us to position 1) */
		const struct tdma_plan *pp = up->plan;
		uint32_t d = (uint32_t)((tdma_relay_offset_ss(pp, tdma_plan_get(TDMA_PLAN_HG)) +
					 TDMA_SUBSLOTS_PER_FRAME - TDMA_RELAY_HGX_OFFSET_SS) %
					TDMA_SUBSLOTS_PER_FRAME) *
			     TDMA_SUBSLOT_TICKS;

		if (tdma_ft_relay_switch(dn, TDMA_PLAN_HG, f, d) == 0) {
			r->to_hg++;
		}
	}
}
