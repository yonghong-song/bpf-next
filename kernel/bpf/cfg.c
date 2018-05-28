// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2018 Netronome Systems, Inc. */
/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <linux/bpf_verifier.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "cfg.h"

struct bb_node {
	struct list_head l;
	u16 head;
};

#define bb_prev(bb)		list_prev_entry(bb, l)
#define bb_next(bb)		list_next_entry(bb, l)
#define bb_first(bb_list)	list_first_entry(bb_list, struct bb_node, l)
#define bb_last(bb_list)	list_last_entry(bb_list, struct bb_node, l)
#define entry_bb(bb_list)	bb_first(bb_list)
#define exit_bb(bb_list)	bb_last(bb_list)

int subprog_append_bb(struct list_head *bb_list, int head)
{
	struct bb_node *new_bb, *bb;

	list_for_each_entry(bb, bb_list, l) {
		if (bb->head == head)
			return 0;
		else if (bb->head > head)
			break;
	}

	bb = bb_prev(bb);
	new_bb = kzalloc(sizeof(*new_bb), GFP_KERNEL);
	if (!new_bb)
		return -ENOMEM;

	new_bb->head = head;
	list_add(&new_bb->l, &bb->l);

	return 0;
}

int subprog_fini_bb(struct list_head *bb_list, int subprog_end)
{
	struct bb_node *bb = kzalloc(sizeof(*bb), GFP_KERNEL);

	if (!bb)
		return -ENOMEM;
	/* entry bb. */
	bb->head = -1;
	list_add(&bb->l, bb_list);

	bb = kzalloc(sizeof(*bb), GFP_KERNEL);
	if (!bb)
		return -ENOMEM;
	/* exit bb. */
	bb->head = subprog_end;
	list_add_tail(&bb->l, bb_list);

	return 0;
}

int subprog_init_bb(struct list_head *bb_list, int subprog_start)
{
	int ret;

	INIT_LIST_HEAD(bb_list);
	ret = subprog_append_bb(bb_list, subprog_start);
	if (ret < 0)
		return ret;

	return 0;
}

void subprog_free_bb(struct bpf_subprog_info *subprog, int end_idx)
{
	int i = 0;

	for (; i <= end_idx; i++) {
		struct list_head *bbs = &subprog[i].bbs;
		struct bb_node *bb, *tmp;

		list_for_each_entry_safe(bb, tmp, bbs, l) {
			list_del(&bb->l);
			kfree(bb);
		}
	}
}
