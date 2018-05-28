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

struct edge_node {
	struct list_head l;
	struct bb_node *src;
	struct bb_node *dst;
};

struct bb_node {
	struct list_head l;
	struct list_head e_prevs;
	struct list_head e_succs;
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

	INIT_LIST_HEAD(&new_bb->e_prevs);
	INIT_LIST_HEAD(&new_bb->e_succs);
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
	INIT_LIST_HEAD(&bb->e_prevs);
	INIT_LIST_HEAD(&bb->e_succs);
	list_add(&bb->l, bb_list);

	bb = kzalloc(sizeof(*bb), GFP_KERNEL);
	if (!bb)
		return -ENOMEM;
	/* exit bb. */
	bb->head = subprog_end;
	INIT_LIST_HEAD(&bb->e_prevs);
	INIT_LIST_HEAD(&bb->e_succs);
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

static struct bb_node *search_bb_with_head(struct list_head *bb_list, int head)
{
	struct bb_node *bb;

	list_for_each_entry(bb, bb_list, l) {
		if (bb->head == head)
			return bb;
	}

	return NULL;
}

int subprog_add_bb_edges(struct bpf_insn *insns, struct list_head *bb_list)
{
	struct bb_node *bb, *exit_bb;
	struct edge_node *edge;

	bb = entry_bb(bb_list);
	edge = kcalloc(2, sizeof(*edge), GFP_KERNEL);
	if (!edge)
		return -ENOMEM;
	edge->src = bb;
	edge->dst = bb_next(bb);
	list_add_tail(&edge->l, &bb->e_succs);
	edge[1].src = edge->src;
	edge[1].dst = edge->dst;
	list_add_tail(&edge[1].l, &edge[1].dst->e_prevs);

	exit_bb = exit_bb(bb_list);
	bb = bb_next(bb);
	list_for_each_entry_from(bb, &exit_bb->l, l) {
		bool has_fallthrough, only_has_fallthrough;
		bool has_branch, only_has_branch;
		struct bb_node *next_bb = bb_next(bb);
		int tail = next_bb->head - 1;
		struct bpf_insn insn;
		u8 code;

		edge = kcalloc(2, sizeof(*edge), GFP_KERNEL);
		if (!edge)
			return -ENOMEM;
		edge->src = bb;
		edge[1].src = bb;

		insn = insns[tail];
		code = insn.code;
		only_has_fallthrough = BPF_CLASS(code) != BPF_JMP ||
				       BPF_OP(code) == BPF_EXIT;
		has_fallthrough = only_has_fallthrough ||
				  (BPF_CLASS(code) == BPF_JMP &&
				   BPF_OP(code) != BPF_CALL &&
				   BPF_OP(code) != BPF_JA);
		only_has_branch = BPF_CLASS(code) == BPF_JMP &&
				  BPF_OP(code) == BPF_JA;
		has_branch = only_has_branch ||
			     (BPF_CLASS(code) == BPF_JMP &&
			      BPF_OP(code) != BPF_EXIT &&
			      BPF_OP(code) != BPF_CALL);

		if (has_fallthrough) {
			if (BPF_CLASS(code) == BPF_JMP &&
			    BPF_OP(code) == BPF_EXIT)
				next_bb = exit_bb;
			edge->dst = next_bb;
			edge[1].dst = next_bb;
			list_add_tail(&edge->l, &bb->e_succs);
			list_add_tail(&edge[1].l, &edge[1].dst->e_prevs);
			edge = NULL;
		}

		if (has_branch) {
			struct bb_node *tgt;

			if (!edge) {
				edge = kcalloc(2, sizeof(*edge), GFP_KERNEL);
				if (!edge)
					return -ENOMEM;
				edge->src = bb;
				edge[1].src = bb;
			}

			tgt = search_bb_with_head(bb_list,
						  tail + insn.off + 1);
			if (!tgt)
				return -EINVAL;

			edge->dst = tgt;
			edge[1].dst = tgt;
			list_add_tail(&edge->l, &bb->e_succs);
			list_add_tail(&edge[1].l, &tgt->e_prevs);
		}
	}

	return 0;
}

static void subprog_free_edge(struct bb_node *bb)
{
	struct list_head *succs = &bb->e_succs;
	struct edge_node *e, *tmp;

	/* prevs and succs are allocated as pair, succs is the start addr. */
	list_for_each_entry_safe(e, tmp, succs, l) {
		list_del(&e->l);
		kfree(e);
	}
}

void subprog_free_bb(struct bpf_subprog_info *subprog, int end_idx)
{
	int i = 0;

	for (; i <= end_idx; i++) {
		struct list_head *bbs = &subprog[i].bbs;
		struct bb_node *bb, *tmp, *exit;

		bb = entry_bb(bbs);
		exit = exit_bb(bbs);
		list_for_each_entry_safe_from(bb, tmp, &exit->l, l) {
			subprog_free_edge(bb);
			list_del(&bb->l);
			kfree(bb);
		}
	}
}
