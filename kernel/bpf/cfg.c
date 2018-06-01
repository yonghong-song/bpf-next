// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2018 Netronome Systems, Inc. */
/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <linux/bpf_verifier.h>
#include <linux/bsearch.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sort.h>

#include "cfg.h"
#include "disasm.h"

/* The size of cfg nodes matters, therefore we try to avoid using doubly linked
 * list and we try to use base + offset to address node, by this we only need
 * to keep offset.
 */
struct cfg_node_link {
	u16 offset;
	s8 idx;
};

static void *cfg_node_delink(struct cfg_node_allocator *allocator,
			     struct cfg_node_link *link)
{
	s8 idx = link->idx;

	if (idx == -1)
		return NULL;

	return allocator->base[idx] + link->offset;
}

struct cedge_node {
	struct cfg_node_link link;
	u8 caller_idx;
	u8 callee_idx;
};

struct edge_node {
	struct cfg_node_link link;
	struct bb_node *src;
	struct bb_node *dst;
};

struct bb_node {
	struct cfg_node_link link;
	struct cfg_node_link e_prevs;
	struct cfg_node_link e_succs;
	s16 head;
	u16 idx;
};

struct bb_node_stack {
	struct bb_node *bb;
	struct list_head list;
};

static const char * const bpf_loop_state_str[] = {
	[BPF_LOOP_UNKNOWN]	= "unknown",
	[BPF_LOOP_INVALID]	= "invalid",
	[BPF_LOOP_IMM]		= "imm",
	[BPF_LOOP_INC]		= "increasing",
	[BPF_LOOP_DEC]		= "decreasing",
};

struct bb_state_reg {
	int reg;	/* register number */
	int off;	/* offset in stack or unused */
	int size;	/* size in stack or unused */
	s64 smin_value; /* minimum possible (s64)value */
	s64 smax_value; /* maximum possible (s64)value */
	u64 umin_value; /* minimum possible (u64)value */
	u64 umax_value; /* maximum possible (u64)value */
	enum bpf_indvar_state state;
};

struct bb_state {
	struct bb_node *bb;
	struct list_head list;
	int insn;
	int insn_cnt;
	struct bb_state_reg src;
	struct bb_state_reg dst;
};

struct bpf_loop_info {
	struct list_head bb;
	int bb_num;
	int insn_cnt;
	int insn_entry;
	int insn_exit;
	struct bb_state_reg src;
	struct bb_state_reg dst;
	u16 idx;
	struct bpf_loop_info *next;
};

static u16 loop_idx;

static void bpf_clear_state(struct bb_state *s)
{
	s->insn = s->insn_cnt = 0;

	s->src.state = BPF_LOOP_UNKNOWN;
	s->src.reg = s->src.off = s->src.size = 0;

	s->dst.state = BPF_LOOP_UNKNOWN;
	s->dst.reg = s->src.off = s->src.size = 0;
}

#define entry_bb(bb_list)		(struct bb_node *)(*bb_list)
#define exit_bb(bb_list)		(struct bb_node *)(*(bb_list + 1))

static struct bb_node *bb_next(struct cfg_node_allocator *allocator,
			       struct bb_node *bb)
{
	return (struct bb_node *)cfg_node_delink(allocator, &bb->link);
}

void cfg_pretty_print(struct bpf_verifier_env *env,
		      struct cfg_node_allocator *allocator,
		      struct bpf_subprog_info *subprog)
{
	void **bb_list = (void **)&subprog->bbs;
	struct bb_node *bb, *exit_bb;

	bb = entry_bb(bb_list);
	exit_bb = exit_bb(bb_list);

	bpf_verifier_log_write(env, "CFG: ");
	while (bb && bb != exit_bb) {
		struct bb_node *next_bb = bb_next(allocator, bb);
		struct edge_node *e;

		e = cfg_node_delink(allocator, &bb->e_succs);
		while (e) {
			struct bb_node *dst = e->dst;
			int tail = next_bb->head - 1;
			struct bb_node *dst_next;
			int dst_tail;

			dst_next = bb_next(allocator, dst);
			dst_tail = dst_next ? dst_next->head - 1 : 65534;

			bpf_verifier_log_write(env, " %i[%i,%i] -> %i[%i,%i] ",
					       bb->idx, bb->head, tail, dst->idx, dst->head, dst_tail);
			e = cfg_node_delink(allocator, &e->link);
		}
		bb = bb_next(allocator, bb);
	}
	bpf_verifier_log_write(env, "\n");
}

void dom_pretty_print(struct bpf_verifier_env *env,
		      struct bpf_subprog_info *subprog)
{
	int lane_len, bb_num = subprog->bb_num - 2;
	int i, j;

	lane_len = BITS_TO_LONGS(bb_num);

	bpf_verifier_log_write(env, "DOM:\n");
	for (i = 0; i < bb_num; i++) {
		for (j = 0; j < bb_num; j++) {
			bpf_verifier_log_write(env, " %i ",
			    test_bit(j,
				     subprog->dtree + i * lane_len) ? 1 : 0);
		}
		bpf_verifier_log_write(env, "\n");
	}
	bpf_verifier_log_write(env, "\n");
}

struct dom_info {
	u16 *dfs_parent;
	u16 *dfs_order;
	struct bb_node **dfs_to_bb;
	/* immediate-dominator */
	u16 *idom;
	/* semi-dominator */
	u16 *sdom;
	u16 *bucket;
	u16 *next_bucket;
	/* best node during path compression. */
	u16 *best;
	/* ancestor along tree edge. */
	u16 *ancestor;
	/* size and child are used for tree balancing. */
	u16 *size;
	u16 *child;

	u16 dfsnum;
};

struct mem_frag {
	struct cfg_node_link link;
	void *p;
};

struct pool_head {
	u32 size;
	u32 used;
};

#define first_node_pool(pool_list)	\
	list_first_entry(pool_list, struct node_pool, l)

#define MEM_CHUNK_SIZE	(1024)

static int cfg_node_allocator_grow(struct cfg_node_allocator *allocator,
				   int min_grow_size)
{
	int s = min_grow_size, pool_cnt = allocator->pool_cnt;
	struct pool_head *pool;

	if (pool_cnt >= MAX_POOL_NUM)
		return -E2BIG;

	s += sizeof(struct pool_head);
	s = ALIGN(s, MEM_CHUNK_SIZE);
	if (s > U16_MAX)
		return -E2BIG;

	pool = kzalloc(s, GFP_KERNEL);
	if (!pool)
		return -ENOMEM;

	allocator->base[pool_cnt] = pool;
	pool->size = s;
	pool->used = sizeof(struct pool_head);
	allocator->pool_cnt++;

	return 0;
}

static int cfg_node_alloc(struct cfg_node_allocator *allocator,
			  struct mem_frag *frag, int size)
{
	int pool_idx = allocator->pool_cnt - 1;
	struct pool_head *pool;
	void *p;

	pool = allocator->base[pool_idx];
	if (pool->used + size > pool->size) {
		int ret = cfg_node_allocator_grow(allocator, size);

		if (ret < 0)
			return ret;

		pool_idx++;
		pool = allocator->base[pool_idx];
	}

	p = (void *)pool + pool->used;
	frag->p = p;
	frag->link.idx = pool_idx;
	frag->link.offset = pool->used;
	pool->used += size;

	return 0;
}

static int get_link_nodes(struct cfg_node_allocator *allocator,
			  struct mem_frag *frag, int num, int elem_size)
{
	int i, ret;
	struct cfg_node_link *link;

	ret = cfg_node_alloc(allocator, frag, num * elem_size);
	if (ret < 0)
		return ret;

	for (i = 0; i < num; i++) {
		link = frag->p + i * elem_size;
		link->idx = -1;
	}

	return 0;
}

static int get_bb_nodes(struct cfg_node_allocator *allocator,
			struct mem_frag *frag, int num)
{
	struct bb_node *bb;
	int i, ret;

	ret = get_link_nodes(allocator, frag, num, sizeof(struct bb_node));
	if (ret < 0)
		return ret;

	bb = frag->p;
	for (i = 0; i < num; i++) {
		bb[i].e_prevs.idx = -1;
		bb[i].e_succs.idx = -1;
	}

	return 0;
}

static int get_edge_nodes(struct cfg_node_allocator *allocator,
			  struct mem_frag *frag, int num)
{
	return get_link_nodes(allocator, frag, num, sizeof(struct edge_node));
}

static int get_single_cedge_node(struct cfg_node_allocator *allocator,
				 struct mem_frag *frag)
{
	return get_link_nodes(allocator, frag, 1, sizeof(struct cedge_node));
}

int cfg_node_allocator_init(struct cfg_node_allocator *allocator,
			    int bb_num_esti, int cedge_num_esti)
{
	int s = bb_num_esti * sizeof(struct bb_node), ret;

	s += 2 * bb_num_esti * sizeof(struct edge_node);
	s += cedge_num_esti * sizeof(struct cedge_node);

	allocator->pool_cnt = 0;
	ret = cfg_node_allocator_grow(allocator, s);
	if (ret < 0)
		return ret;

	return 0;
}

void cfg_node_allocator_free(struct cfg_node_allocator *allocator)
{
	int i, cnt = allocator->pool_cnt;

	for (i = 0; i < cnt; i++)
		kfree(allocator->base[i]);
}

int subprog_append_bb(struct cfg_node_allocator *allocator, void **bb_list,
		      int head)
{
	struct bb_node *cur = entry_bb(bb_list);
	struct bb_node *prev = cur;
	struct mem_frag frag;
	int ret;

	while (cur) {
		if (cur->head == head)
			return 0;
		else if (cur->head > head)
			break;
		prev = cur;
		cur = cfg_node_delink(allocator, &cur->link);
	}

	ret = get_bb_nodes(allocator, &frag, 1);
	if (ret < 0)
		return ret;

	cur = frag.p;
	cur->head = head;
	cur->link = prev->link;
	prev->link = frag.link;

	return 0;
}

int subprog_init_bb(struct cfg_node_allocator *allocator, void **bb_list,
		    int subprog_start, int subprog_end)
{
	struct bb_node **list_head = (struct bb_node **)bb_list;
	struct bb_node **list_tail = (struct bb_node **)(bb_list + 1);
	struct bb_node *entry_bb, *first_bb, *exit_bb;
	int ret, s = sizeof(struct bb_node);
	struct mem_frag frag;

	ret = get_bb_nodes(allocator, &frag, 3);
	if (ret < 0)
		return ret;

	entry_bb = frag.p;
	*list_head = entry_bb;
	entry_bb->head = -1;
	first_bb = frag.p + s;
	first_bb->head = subprog_start;
	exit_bb = frag.p + 2 * s;
	exit_bb->head = subprog_end;
	entry_bb->link.idx = frag.link.idx;
	entry_bb->link.offset = frag.link.offset + s;
	first_bb->link.idx = frag.link.idx;
	first_bb->link.offset = frag.link.offset + 2 * s;
	*list_tail = exit_bb;

	return 0;
}

static struct bb_node *search_bb_with_head(struct cfg_node_allocator *allocator,
					   void **bb_list, int head)
{
	struct bb_node *cur = entry_bb(bb_list);

	while (cur) {
		if (cur->head == head)
			return cur;

		cur = cfg_node_delink(allocator, &cur->link);
	}

	return NULL;
}

int subprog_add_bb_edges(struct cfg_node_allocator *allocator,
			 struct bpf_insn *insns, void **bb_list)
{
	struct bb_node *bb = entry_bb(bb_list), *exit_bb;
	struct edge_node *edge;
	struct mem_frag frag;
	int ret, bb_num;

	ret = get_edge_nodes(allocator, &frag, 2);
	if (ret < 0)
		return ret;
	edge = frag.p;
	edge->src = bb;
	edge->dst = bb_next(allocator, bb);
	bb->e_succs = frag.link;
	edge[1].src = edge->src;
	edge[1].dst = edge->dst;
	edge->dst->e_prevs = frag.link;
	bb->idx = -1;

	exit_bb = exit_bb(bb_list);
	exit_bb->idx = -2;
	bb = edge->dst;
	bb_num = 0;
	while (bb && bb != exit_bb) {
		struct bb_node *next_bb = bb_next(allocator, bb);
		bool has_fallthrough, only_has_fallthrough;
		bool has_branch, only_has_branch;
		int tail = next_bb->head - 1;
		struct bpf_insn insn;
		u8 code;

		bb->idx = bb_num++;

		ret = get_edge_nodes(allocator, &frag, 2);
		if (ret < 0)
			return ret;
		edge = frag.p;
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
			edge->link = bb->e_succs;
			bb->e_succs = frag.link;
			frag.link.offset += sizeof(struct edge_node);
			edge[1].link = next_bb->e_prevs;
			next_bb->e_prevs = frag.link;
			edge = NULL;
		}

		if (has_branch) {
			struct bb_node *tgt;

			if (!edge) {
				ret = get_edge_nodes(allocator, &frag, 2);
				if (ret < 0)
					return ret;
				edge = frag.p;
				edge->src = bb;
				edge[1].src = bb;
			}

			tgt = search_bb_with_head(allocator, bb_list,
						  tail + insn.off + 1);
			if (!tgt)
				return -EINVAL;

			edge->dst = tgt;
			edge[1].dst = tgt;
			edge->link = bb->e_succs;
			bb->e_succs = frag.link;
			frag.link.offset += sizeof(struct edge_node);
			edge[1].link = tgt->e_prevs;
			tgt->e_prevs = frag.link;
		}

		bb = bb_next(allocator, bb);
	}

	return bb_num + 2;
}

static int init_dom_info(struct bpf_subprog_info *subprog, struct dom_info *di)
{
	u16 *p, bb_num, i;

	di->dfs_parent = NULL;
	di->dfs_to_bb = NULL;

	bb_num = subprog->bb_num;
	p = kcalloc(10 * bb_num, sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	di->dfs_parent = p;
	di->dfs_order = di->dfs_parent + bb_num;
	di->idom = di->dfs_order + bb_num;
	di->sdom = di->idom + bb_num;
	di->bucket = di->sdom + bb_num;
	di->next_bucket = di->bucket + bb_num;
	di->best = di->next_bucket + bb_num;
	di->ancestor = di->best + bb_num;
	di->size = di->ancestor + bb_num;
	di->child = di->size + bb_num;
	di->dfs_to_bb = kcalloc(bb_num, sizeof(struct bb_node *), GFP_KERNEL);
	di->dfsnum = 1;

	for (i = 0; i < bb_num; i++) {
		di->size[i] = 1;
		di->best[i] = i;
		di->sdom[i] = i;
	}

	return 0;
}

static void compress_path(struct dom_info *di, unsigned int v)
{
	unsigned int parent = di->ancestor[v];

	if (di->ancestor[parent]) {
		compress_path(di, parent);

		if (di->sdom[di->best[parent]] < di->sdom[di->best[v]])
			di->best[v] = di->best[parent];

		di->ancestor[v] = di->ancestor[parent];
	}
}

static unsigned int eval(struct dom_info *di, unsigned int v)
{
	unsigned int ancestor = di->ancestor[v];

	/* v is root. */
	if (!ancestor)
		return di->best[v];

	/* compress path */
	compress_path(di, v);
	ancestor = di->ancestor[v];

	if (di->sdom[di->best[ancestor]] >= di->sdom[di->best[v]])
		return di->best[v];
	else
		return di->best[ancestor];
}

/* Re-balancing the tree before linking. */
static void link(struct dom_info *di, unsigned int v, unsigned int w)
{
	unsigned int s = w;

	while (di->sdom[di->best[w]] < di->sdom[di->best[di->child[s]]]) {
		if (di->size[s] + di->size[di->child[di->child[s]]] >=
			2 * di->size[di->child[s]]) {
			di->ancestor[di->child[s]] = s;
			di->child[s] = di->child[di->child[s]];
		} else {
			di->size[di->child[s]] = di->size[s];
			di->ancestor[s] = di->child[s];
			s = di->child[s];
		}
	}

	di->best[s] = di->best[w];
	di->size[v] += di->size[w];
	if (di->size[v] < 2 * di->size[w]) {
		unsigned int t = s;

		s = di->child[v];
		di->child[v] = t;
	}

	while (s) {
		di->ancestor[s] = v;
		s = di->child[s];
	}
}

static void
calc_idoms(struct cfg_node_allocator *allocator,
	   struct bpf_subprog_info *subprog, struct dom_info *di, bool reverse)
{
	u16 entry_bb_fake_idx = subprog->bb_num - 2, idx, w, k, par;
	void **bb_list = (void **)&subprog->bbs;
	struct bb_node *entry_bb;

	if (reverse)
		entry_bb = exit_bb(bb_list);
	else
		entry_bb = entry_bb(bb_list);
	idx = di->dfsnum - 1;

	while (idx > 1) {
		struct bb_node *bb = di->dfs_to_bb[idx];
		struct edge_node *e;

		par = di->dfs_parent[idx];
		k = idx;

		if (reverse)
			e = cfg_node_delink(allocator, &bb->e_succs);
		else
			e = cfg_node_delink(allocator, &bb->e_prevs);

		while (e) {
			struct bb_node *b;
			u16 k1;

			if (reverse)
				b = e->dst;
			else
				b = e->src;

			e = cfg_node_delink(allocator, &e->link);

			if (b == entry_bb)
				k1 = di->dfs_order[entry_bb_fake_idx];
			else
				k1 = di->dfs_order[b->idx];

			if (k1 > idx)
				k1 = di->sdom[eval(di, k1)];
			if (k1 < k)
				k = k1;
		}

		di->sdom[idx] = k;
		link(di, par, idx);
		di->next_bucket[idx] = di->bucket[k];
		di->bucket[k] = idx;

		for (w = di->bucket[par]; w; w = di->next_bucket[w]) {
			k = eval(di, w);
			if (di->sdom[k] < di->sdom[w])
				di->idom[w] = k;
			else
				di->idom[w] = par;
		}
		di->bucket[par] = 0;
		idx--;
	}

	di->idom[1] = 0;
	for (idx = 2; idx <= di->dfsnum - 1; idx++)
		if (di->idom[idx] != di->sdom[idx])
			di->idom[idx] = di->idom[di->idom[idx]];
}

static int
calc_dfs_tree(struct bpf_verifier_env *env,
	      struct cfg_node_allocator *allocator,
	      struct bpf_subprog_info *subprog, struct dom_info *di,
	      bool reverse)
{
	u16 bb_num = subprog->bb_num, sp = 0, idx, parent_idx, i;
	void **bb_list = (void **)&subprog->bbs;
	u16 entry_bb_fake_idx = bb_num - 2;
	struct bb_node *entry_bb, *exit_bb;
	struct edge_node **stack, *e;

	di->dfs_order[entry_bb_fake_idx] = di->dfsnum;

	stack = kmalloc_array(bb_num - 1, sizeof(struct edge_node *),
			      GFP_KERNEL);
	if (!stack)
		return -ENOMEM;

	if (reverse) {
		entry_bb = exit_bb(bb_list);
		exit_bb = entry_bb(bb_list);
		di->dfs_to_bb[di->dfsnum++] = exit_bb;
		e = cfg_node_delink(allocator, &entry_bb->e_prevs);
	} else {
		entry_bb = entry_bb(bb_list);
		exit_bb = exit_bb(bb_list);
		di->dfs_to_bb[di->dfsnum++] = entry_bb;
		e = cfg_node_delink(allocator, &entry_bb->e_succs);
	}

	while (1) {
		struct bb_node *bb_dst, *bb_src;

		while (e) {
			if (reverse) {
				bb_dst = e->src;
				if (bb_dst == exit_bb ||
				    di->dfs_order[bb_dst->idx]) {
					e = cfg_node_delink(allocator,
							    &e->link);
					continue;
				}
				bb_src = e->dst;
			} else {
				bb_dst = e->dst;
				if (bb_dst == exit_bb ||
				    di->dfs_order[bb_dst->idx]) {
					e = cfg_node_delink(allocator,
							    &e->link);
					continue;
				}
				bb_src = e->src;
			}

			if (bb_src != entry_bb)
				parent_idx = di->dfs_order[bb_src->idx];
			else
				parent_idx = di->dfs_order[entry_bb_fake_idx];

			idx = di->dfsnum++;
			di->dfs_order[bb_dst->idx] = idx;
			di->dfs_to_bb[idx] = bb_dst;
			di->dfs_parent[idx] = parent_idx;

			stack[sp++] = e;
			if (reverse)
				e = cfg_node_delink(allocator,
						    &bb_dst->e_prevs);
			else
				e = cfg_node_delink(allocator,
						    &bb_dst->e_succs);
		}

		if (!sp)
			break;

		e = stack[--sp];
		e = cfg_node_delink(allocator, &e->link);
	}

	kfree(stack);

	for (i = 0; i < bb_num - 2; i++) {
		if (!di->dfs_order[i]) {
			bpf_verifier_log_write(env, "cfg - unreachable insn\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int idoms_to_doms(struct bpf_subprog_info *subprog, struct dom_info *di)
{
	int bb_num, i, end_index, bb, bb_idom, lane_len;
	unsigned long *bitmap;

	bb_num = subprog->bb_num - 2;
	lane_len = BITS_TO_LONGS(bb_num);
	bitmap = kcalloc(bb_num, lane_len * sizeof(long), GFP_KERNEL);
	subprog->dtree = bitmap;
	if (!subprog->dtree)
		return -ENOMEM;
	subprog->dtree_avail = true;
	end_index = di->dfs_order[bb_num];

	for (i = 1; i <= di->dfsnum - 1; i++) {
		if (i == end_index)
			continue;

		bb = di->dfs_to_bb[i]->idx;
		if (di->idom[i] && di->idom[i] != end_index) {
			bb_idom = di->dfs_to_bb[di->idom[i]]->idx;
			bitmap_copy(bitmap + bb * lane_len,
				    bitmap + bb_idom * lane_len, bb_num);
		}

		bitmap_set(bitmap + bb * lane_len, bb, 1);
	}

	return 0;
}

/* Build domination information using Lengauer and Tarjan algorithm.
 *
 *   1. dfs on cfg to assign dfs-num for each node(bb).
 *   2. calculate semi-dominator and calculate immediate dominator when
 *      possible.
 *   3. calculate immediate dominator not finished during step 2.
 *   4. build domination bitmap using immediate dominator information.
 *
 * See:
 *   A fast algorithm for finding dominators in a flowgraph.
 *     - 1979, by T Lengauer and R Tarjan
 *
 *   Especially, Appendix B: The Complete Dominators Algorithms.
 *
 * The implementation also referenced GNU GCC 3.0.
 */

int subprog_build_dom_info(struct bpf_verifier_env *env,
			   struct cfg_node_allocator *allocator,
			   struct bpf_subprog_info *subprog)
{
	struct dom_info di;
	int ret;

	ret = init_dom_info(subprog, &di);
	if (ret < 0)
		goto free_dominfo;

	ret = calc_dfs_tree(env, allocator, subprog, &di, false);
	if (ret < 0)
		goto free_dominfo;

	calc_idoms(allocator, subprog, &di, false);
	ret = idoms_to_doms(subprog, &di);
	if (ret < 0)
		goto free_dominfo;

	ret = 0;

free_dominfo:
	kfree(di.dfs_parent);

	return ret;
}

static bool bb_search(struct bb_node *bb, struct bpf_loop_info *loop)
{
	struct bb_node_stack *i;

	list_for_each_entry(i, &loop->bb, list) {
		if (i->bb->idx == bb->idx)
			return true;
	}
	return false;
}

void bpf_state_set_invalid(struct bb_state *state)
{
	state->src.state = BPF_LOOP_INVALID;
	state->dst.state = BPF_LOOP_INVALID;
}

void bpf_state_set_stx(struct bb_state *state, const struct bpf_insn *insn)
{
	int size = bpf_size_to_bytes(BPF_SIZE(insn->code));

	/* BPF_MEM | <size> | BPF_STX: *(size *) (dst_reg + off) = src_reg */
	if (state->dst.reg == insn->dst_reg) {
		state->dst.reg = insn->src_reg;
		state->dst.off = insn->off;
		state->dst.size = size;
	} else if (state->src.reg == insn->dst_reg) {
		state->src.reg = insn->src_reg;
		state->src.off = insn->off;
		state->src.size = size;
	}
}

static void bpf_state_set_ldx(struct bpf_verifier_env *env,
			      struct bb_state *state, const struct bpf_insn *insn)
{
	int off = insn->off;
	int size = bpf_size_to_bytes(BPF_SIZE(insn->code));

	/* BPF_MEM | <size> | BPF_LDX:  dst_reg = *(size *) (src_reg + off) */
	if (state->dst.reg == insn->src_reg && state->dst.off == off) {
		if (state->dst.size != size) {
			bpf_verifier_log_write(env,
					       "Loop tracing (dst) through BPF_LDX with mismatch sizes unsupported (%i != %i)\n",
					       state->dst.size, size);
			bpf_state_set_invalid(state);
			return;
		}
		state->dst.reg = insn->dst_reg;
	} else if (state->src.reg == insn->dst_reg && state->dst.off == off) {
		if (state->src.size != size) {
			bpf_verifier_log_write(env,
					       "Loop tracing (src) through BPF_LDX with mismatch sizes unsupported (%i != %i)\n",
					       state->src.size, size);
			bpf_state_set_invalid(state);
			return;
		}
		state->src.reg = insn->dst_reg;
	}
}

void bpf_state_set_xadd(struct bb_state *state, const struct bpf_insn *insn)
{
	/* Bail out on XADD programs for the moment */
	bpf_state_set_invalid(state);
}

static void _bpf_state_set_add(struct bpf_verifier_env *env,
			       struct bb_state_reg *reg,
			       const struct bpf_insn *insn, bool add)
{
	int sign;

	/* Currently, only basic induction variables are supported. So we
	 * require "reg += const" this limitation is artificial and we can support
	 * more complex linear statements 'x += y' and 'x = x + a y' with additional
	 * verifier effort. However, lets see if this is actually needed before
	 * we add recursive path search for n-order induction variables.
	 */
	if (BPF_SRC(insn->code) == BPF_K) {
		/* BPF_ADD/BPF_NEG by zero is a NOP just return */
		if (insn->imm == 0)
			return;

		if (add)
			sign = insn->imm < 0 ? BPF_LOOP_DEC : BPF_LOOP_INC;
		else
			sign = insn->imm < 0 ? BPF_LOOP_INC : BPF_LOOP_DEC;
	} else {
		reg->state = BPF_LOOP_INVALID;
		return;
	}

	if (reg->state == BPF_LOOP_UNKNOWN)
		reg->state = sign;
	else if (reg->state == BPF_LOOP_INC && sign == BPF_LOOP_INC)
		reg->state = BPF_LOOP_INC;
	else if (reg->state == BPF_LOOP_DEC && sign == BPF_LOOP_DEC)
		reg->state = BPF_LOOP_DEC;
	else
		reg->state = BPF_LOOP_INVALID;
}

static void bpf_state_set_add(struct bpf_verifier_env *env,
			      struct bb_state *state,
			      const struct bpf_insn *insn)
{
	if (state->dst.reg == insn->dst_reg) {
		_bpf_state_set_add(env, &state->dst, insn, true);
	} else if (state->src.reg == insn->dst_reg) {
		_bpf_state_set_add(env, &state->src, insn, true);
	} else {
		bpf_state_set_invalid(state);
		WARN_ON_ONCE(1);
	}
}

static void bpf_state_set_sub(struct bpf_verifier_env *env,
			      struct bb_state *state,
			      const struct bpf_insn *insn)
{
	if (state->dst.reg == insn->dst_reg) {
		_bpf_state_set_add(env, &state->dst, insn, false);
	} else if (state->src.reg == insn->dst_reg) {
		_bpf_state_set_add(env, &state->src, insn, false);
	} else {
		bpf_state_set_invalid(state);
		WARN_ON_ONCE(1);
	}
}

static void _bpf_state_set_move(struct bb_state_reg *reg, const struct bpf_insn *insn)
{
	if (BPF_SRC(insn->code) == BPF_K) {
		u64 uimm = insn->imm;
		s64 simm = (s64)insn->imm;

		reg->state = BPF_LOOP_IMM;
		reg->reg = -1;

		reg->smin_value = simm;
		reg->smax_value = simm;
		reg->umin_value = uimm;
		reg->umax_value = uimm;
	} else {
		reg->reg  = insn->src_reg;
	}
}
void bpf_state_set_mov(struct bb_state *state, const struct bpf_insn *insn)
{

	if (state->dst.reg == insn->dst_reg) {
		_bpf_state_set_move(&state->dst, insn);
	} else if (state->src.reg == insn->dst_reg) {
		_bpf_state_set_move(&state->src, insn);
	} else {
		bpf_state_set_invalid(state);
		WARN_ON_ONCE(1);
	}
}

void bpf_loop_state(struct bpf_verifier_env *env,
		    int i, const struct bpf_insn *insn, struct bb_state *state)
{
	u8 class = BPF_CLASS(insn->code);

	if (class == BPF_ALU || class == BPF_ALU64) {
		u8 opcode;

		if (state->src.reg != insn->dst_reg &&
		    state->dst.reg != insn->dst_reg)
			return;

		opcode = BPF_OP(insn->code);
		switch (opcode) {
		case BPF_ADD:
			bpf_state_set_add(env, state, insn);
			break;
		case BPF_SUB:
			bpf_state_set_sub(env, state, insn);
			break;
		case BPF_MOV:
			bpf_state_set_mov(state, insn);
			break;
		case BPF_DIV:
		case BPF_OR:
		case BPF_AND:
		case BPF_LSH:
		case BPF_RSH:
		case BPF_MOD:
		case BPF_XOR:
		case BPF_ARSH:
		case BPF_END:
		default:
			bpf_verifier_log_write(env,
					      "%i: BPF_ALU%s: unsupported opcode (%u) invalidate state\n",
					       i, class == BPF_ALU ? "" : "64",
					       opcode);
			bpf_state_set_invalid(state);
			break;
		}
	} else if (class == BPF_STX) {
		u8 mode = BPF_MODE(insn->code);

		switch (mode) {
		case BPF_MEM:
			/* BPF_MEM | <size> | BPF_STX */
			bpf_state_set_stx(state, insn);
			break;
		case BPF_XADD:
			/* BPF_XADD | BPF_W | BPF_STX */
			/* BPF_XADD | BPF_DW | BPF_STX */
			bpf_state_set_xadd(state, insn);
			break;
		default:
			bpf_verifier_log_write(env,
					       "%i: BPF_STX: unsupported mode (%u) invalidate state\n",
					       i, mode);
			bpf_state_set_invalid(state);
		}
	} else if (class == BPF_ST) {
		/* Unsupported at the moment */
		bpf_verifier_log_write(env, "%i: BPF_ST: unsupported class invalidate state\n", i);
		bpf_state_set_invalid(state);
	} else if (class == BPF_LDX) {
		u8 mode = BPF_MODE(insn->code);

		if (mode != BPF_MEM) {
			bpf_verifier_log_write(env,
					      "%i: BPF_LDX: unsupported mode (%u) invalidate state\n",
					      i, mode);
			bpf_state_set_invalid(state);
		} else {
			/* BPF_MEM | <size> | BPF_LDX */
			bpf_state_set_ldx(env, state, insn);
		}
	} else if (class == BPF_LD) {
		/* Unsupported at the moment */
		bpf_verifier_log_write(env, "%i: BPF_LD: unsupported class invalidate state\n", i);
		bpf_state_set_invalid(state);
	} else if (class == BPF_JMP) {
		; // Jumps are verified by CFG
	} else {
		/* If we do not understand instruction invalidate state */
		bpf_verifier_log_write(env, "%i: %u: unknown class invalidate state\n", i, class);
		bpf_state_set_invalid(state);
	}
}

/* bit noisy at the moment duplicates with print_regs */
static void bpf_print_loop_info(struct bpf_verifier_env *env,
				struct bpf_loop_info *loop)
{
	struct bpf_reg_state *regs, *src_reg = NULL, *dst_reg = NULL;

	regs = cur_regs(env);
	if (loop->src.reg >= 0)
		src_reg = &regs[loop->src.reg];
	if (loop->dst.reg >= 0)
		dst_reg = &regs[loop->dst.reg];

	bpf_verifier_log_write(env,
			       "Loop %i: (%i:ty(%i))src.state(%s) (%i:ty(%i))dst.state(%s): R%d(%llu:%llu,%lld:%lld) R%d(%llu:%llu,%lld:%lld)\n",
			       loop->idx,
			       loop->src.reg, src_reg ? src_reg->type : -1,
			       bpf_loop_state_str[loop->src.state],
			       loop->dst.reg, dst_reg ? dst_reg->type : -1,
			       bpf_loop_state_str[loop->dst.state],
			       loop->src.reg,
			       src_reg ? src_reg->umin_value : loop->src.umin_value,
			       src_reg ? src_reg->umax_value : loop->src.umax_value,
			       src_reg ? src_reg->smin_value : loop->src.smin_value,
			       src_reg ? src_reg->smax_value : loop->src.smax_value,
			       loop->dst.reg,
			       dst_reg ? dst_reg->umin_value : loop->dst.umin_value,
			       dst_reg ? dst_reg->umax_value : loop->dst.umax_value,
			       dst_reg ? dst_reg->smin_value : loop->dst.smin_value,
			       dst_reg ? dst_reg->smax_value : loop->dst.smax_value);
}

static bool bpf_op_sign(u8 op)
{
	switch (op) {
	case BPF_JNE:
	case BPF_JGT:
	case BPF_JGE:
		return false;
	case BPF_JSGT:
	case BPF_JSGE:
		return true;
	default:
		return false;
	}
}

/* Verify conditions necessary to ensure increasing/decreasing loop induction
 * variables will in fact terminate.
 *
 * 1. Increasing/decreasing variables _must_ be paired with a bounded variable
 *    in this case BPF_LOOP_IMM type.
 * 2. Increasing/decreasing variables _must_ have a "known" worst case starting
 *    bound. For example if an increasing variable has no min value we can not
 *    say it will actually terminate. So test increasing variables have mins
 *    and decreasing variables have maxs.
 * 3. The known min/max bound must match the comparison sign
 *
 * After this we know that a loop will increase or decrease and eventually
 * terminate.
 */
static int bpf_cfg_valid_bounds(struct bpf_verifier_env *env, u8 op,
				struct bpf_reg_state *src_reg,
				struct bpf_reg_state *dst_reg,
				struct bpf_loop_info *loop)
{
	bool sign = bpf_op_sign(op);

	switch (loop->src.state) {
	/*
	 * dev note: improve verbose messaging, and maybe refactor the
	 * switch stmt
	 */
	case BPF_LOOP_IMM:
		if (!dst_reg) {
			bpf_verifier_log_write(env, "internal cfg error: missing dst_reg LOOP_IMM!\n");
			return -1;
		}

		if (loop->dst.state == BPF_LOOP_INC) {
			if (sign && dst_reg->smin_value == S64_MIN) {
				bpf_verifier_log_write(env,
						       "increasing loop induction variable (towarads imm) unbounded min value\n");
				return -1;
			}
		} else if (loop->dst.state == BPF_LOOP_DEC) {
			if ((sign && dst_reg->smax_value == S64_MAX) ||
			    (!sign && dst_reg->umax_value == U64_MAX)) {
				bpf_verifier_log_write(env,
						       "decreasing loop induction variable (towards imm) unbounded max value\n");
				return -1;
			}
		} else {
			return -1;
		}
		break;
	case BPF_LOOP_INC:
		if (loop->dst.state != BPF_LOOP_IMM) {
			bpf_verifier_log_write(env,
					       "increasing loop induction variable not towards imm\n");
			return -1;
		}

		if (!src_reg) {
			bpf_verifier_log_write(env, "internal cfg error: missing src_reg LOOP_INC!\n");
			return -1;
		}

		if (sign && src_reg->smin_value == S64_MIN) {
			bpf_verifier_log_write(env,
					       "increasing loop induction variable unbounded min value\n");
			return -1;
		}
		break;
	case BPF_LOOP_DEC:
		if (loop->dst.state != BPF_LOOP_IMM) {
			bpf_verifier_log_write(env,
					       "decreasing loop induction variable not towards imm\n");
			return -1;
		}

		if (!src_reg) {
			bpf_verifier_log_write(env, "internal cfg error: missing src_reg LOOP_DEC!\n");
			return -1;
		}

		if ((sign && src_reg->smax_value == S64_MAX) ||
		    (!sign && src_reg->umax_value == U64_MAX)) {
			bpf_verifier_log_write(env,
					       "decreasing loop induction variable unbounded max value\n");
			return -1;
		}
		break;
	default:
		bpf_verifier_log_write(env, "loop state unknown/invalid\n");
		return -1;
	}
	return 0;
}

/* Before calling bpf_cfg_deduce_bounds we ensured the loop does in fact
 * terminate. (Because increasing/decreasing towards a constant) But, if
 * left as is each iteration of the loop will be a new state. This is a
 * result of the loop induction variable, by definition, being incremented
 * or decremented by a constant each iteration of the loop.
 *
 * To resolve this we know the worst case iteration count and the step
 * of each iteration so we know the expected range of the indvar. Here
 * we calculate and set the min/max to the worst case range.
 */
static int bpf_cfg_deduce_bounds(struct bpf_verifier_env *env, u8 op,
				 struct bpf_reg_state *src_reg,
				 struct bpf_reg_state *dst_reg,
				 struct bpf_loop_info *loop)
{
	int err = 0;

	/* Need to consider overflow cases? */
	/* Need to consider step > 1 */
	if (loop->src.state == BPF_LOOP_INC) {
		switch (op) {
		case BPF_JNE:
		case BPF_JGT:
		case BPF_JGE:
		case BPF_JSGT:
		case BPF_JSGE:
			src_reg->umax_value = loop->dst.umax_value;
			src_reg->smax_value = loop->dst.smax_value;
			src_reg->smax_value = loop->dst.smax_value;
			src_reg->umax_value = loop->dst.umax_value;
			break;
		default:
			bpf_verifier_log_write(env, "src.state INC, invalid opcode %u", op);
			err = -1;
			break;
		}
		src_reg->var_off = tnum_range(src_reg->umin_value,
					      src_reg->umax_value);
	} else if (loop->src.state == BPF_LOOP_DEC) {
		switch (op) {
		case BPF_JNE:
		case BPF_JGT:
		case BPF_JGE:
		case BPF_JSGT:
		case BPF_JSGE:
			src_reg->umin_value = loop->dst.umin_value;
			src_reg->smin_value = loop->dst.smin_value;
			break;
		default:
			bpf_verifier_log_write(env, "src.state INC, invalid opcode %u", op);
			err = -1;
			break;
		}
		src_reg->var_off = tnum_range(src_reg->umin_value,
					      src_reg->umax_value);
	} else if (loop->dst.state == BPF_LOOP_INC) {
		switch (op) {
		case BPF_JNE:
		case BPF_JGT:
		case BPF_JGE:
		case BPF_JSGT:
		case BPF_JSGE:
			dst_reg->umax_value = loop->src.umax_value;
			dst_reg->smax_value = loop->src.smax_value;
			break;
		default:
			bpf_verifier_log_write(env, "dst.state INC, invalid opcode %u", op);
			err = -1;
			break;
		}
		dst_reg->var_off = tnum_range(dst_reg->umin_value,
					      dst_reg->umax_value);
	} else if (loop->dst.state == BPF_LOOP_DEC) {
		switch (op) {
		case BPF_JNE:
		case BPF_JLT:
		case BPF_JLE:
		case BPF_JSLT:
		case BPF_JSLE:
			dst_reg->umin_value = loop->src.umin_value;
			dst_reg->smin_value = loop->src.smin_value;
			break;
		default:
			bpf_verifier_log_write(env, "dst.state DEC, invalid opcode %u", op);
			err = -1;
			break;
		}
		dst_reg->var_off = tnum_range(dst_reg->umin_value,
					      dst_reg->umax_value);
	} else {
		bpf_verifier_log_write(env, "internal cfg error: unknown src|dst state\n");
		err = -1;
	}

	return err;
}

static int bb_stack_push(struct bb_node *node, struct bpf_loop_info *loop)
{
	struct bb_node_stack *n;

	n = kzalloc(sizeof(struct bb_node_stack), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	n->bb = node;
	list_add(&n->list, &loop->bb);
	return 0;
}

static struct bb_node *bb_stack_pop(struct bpf_loop_info *loop)
{
	struct bb_node *bb = NULL;
	struct bb_node_stack *n;

	n = list_first_entry_or_null(&loop->bb, struct bb_node_stack, list);
	if (n) {
		list_del(&n->list);
		bb = n->bb;
	}
	kfree(n);
	return bb;
}

static void bpf_free_loop(struct bpf_loop_info *loop)
{
	struct bb_node *bb = bb_stack_pop(loop);

	while (bb)
		bb = bb_stack_pop(loop);
	kfree(loop);
}

/* CFG verified the loop is normal and that either src or dst is a
 * basic loop induction variable but we still need to ensure min/max
 * values will guarentee termination and that trip count is reasonable.
 *
 * There are a few cases that need to be handled. First the easy case, if the
 * CFG loop scan found that one of the registers is an IMM value then we need
 * only verify that the other register has a min or max value depending on
 * increasing/decreasing induction variable. The more complicated case is when
 * the loop scan has yet to resolve one of the registers bounds. (Note having
 * two unknowns is not valid because we would have no guarantees the loop
 * induction variable is increasing or decreasing) At this point we need to
 * lookup the register and verify it does have a known min/max value without
 * these bounds we can not make any statement about termination.
 *
 * Then we make a worse case instruction count analysis and when the loop
 * latch is completed this will be added to the total instruction count.
 *
 * Finally, with worst case insn count completed and valid bounds go ahead
 * and mark the register with the induction type indicator.
*/
int bpf_check_loop_header(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_reg_state *regs, *src_reg = NULL, *dst_reg = NULL;
	struct bpf_insn *insn = env->prog->insnsi;
	struct bpf_loop_info *loop;
	int err = 0;
	u8 op;

	loop = env->insn_aux_data[insn_idx].loop;
	if (!loop)
		return 0;

	regs = cur_regs(env);
	if (loop->src.reg >= 0)
		src_reg = &regs[loop->src.reg];
	if (loop->dst.reg >= 0)
		dst_reg = &regs[loop->dst.reg];

	op = BPF_OP(insn[loop->insn_exit].code);

	/* If one of the states is unknown we have some options. We could
	 * try to do a path walk backwards and see if the value is valid.
	 * Or we could look at the bounds here and see if we can infer
	 * anything from that.
	 *
	 * What I've found from experimentation is usually due to stack
	 * spilling and operations that leave the variable in unknown
	 * state we don't learn much here.
	 *
	 * At one point I tried some code to walk back in the tree but
	 * I didn't like that very much either. Right now my working
	 * assumption is we can make the bounds tracking good enough
	 * to avoid walking back through the tree.
	 */
	if (loop->dst.state == BPF_LOOP_UNKNOWN ||
	    loop->src.state == BPF_LOOP_UNKNOWN) {
		bpf_verifier_log_write(env, "bpf loop unknown state!\n");
		return -1;
	}

	err = bpf_cfg_valid_bounds(env, op, src_reg, dst_reg, loop);
	if (err) {
		bpf_verifier_log_write(env, "bpf cfg loop has invalid bounds!\n");
		return -1;
	}

	/* At this point the bounds are valid */

	/* We are going to push worse case bounds on to the loop induction
	 * variable this way when we run symbolic execution we check validity
	 * of min and max values. This allows the state pruning logic to have
	 * a chance at pruning the state.
	 *
	 * At the moment we only track the loop induction variables any other
	 * induction variables in the loop (linear or otherwise) will force
	 * the loop to iterate through every case presumably exploding the
	 * state complexity. E.g. simple example is the following,
	 *
	 *   for (i = 0, j = 0; i < const; i++, j++) { ... }
	 *
	 * Improving the induction variable logic can catch the above case
	 * and many more.
	 */
	err = bpf_cfg_deduce_bounds(env, op, src_reg, dst_reg, loop);
	if (err) {
		bpf_verifier_log_write(env, "bpf cfg loop could not deduce bounds!\n");
		return -1;
	}

	bpf_print_loop_info(env, loop);

	/* Instruction count is being used as an approximation for runtime.
	 * Loops have the potential to iterative many times over a single
	 * set of instructions. To account for this charge instruction count
	 * limits the worst case path times the worst case number of iterations.
	 */
	// tbd

	/* Mark insn for indvar tracking informs the execution engine when
	 * it can avoid updating bounds on an insn. This is required to
	 * allow the pruning logic to eventually prune the loop state.
	 */
	if (loop->dst.state == BPF_LOOP_DEC ||
	    loop->dst.state == BPF_LOOP_INC)
		dst_reg->indvar = loop->dst.state;
	else if (loop->src.state == BPF_LOOP_DEC ||
		 loop->src.state == BPF_LOOP_INC)
		src_reg->indvar = loop->src.state;

	/* Loop _will_ terminate remove reference and let the state pruning
	 * do its job.
	 */
	env->insn_aux_data[insn_idx].loop = NULL;
	bpf_free_loop(loop);
	return 1;
}

static int bpf_is_valid_loop_state(struct bpf_loop_info *loop)
{
	if (loop->src.state == BPF_LOOP_INVALID ||
	    loop->dst.state == BPF_LOOP_INVALID)
		return -1;

	switch (loop->src.state) {
	case BPF_LOOP_UNKNOWN:
	case BPF_LOOP_IMM:
		if (loop->dst.state == BPF_LOOP_INC ||
		    loop->dst.state == BPF_LOOP_DEC)
			return 0;
		break;
	case BPF_LOOP_DEC:
	case BPF_LOOP_INC:
		if (loop->dst.state == BPF_LOOP_UNKNOWN ||
		    loop->dst.state == BPF_LOOP_IMM)
			return 0;
		break;
	}

	return -1;
}

static void bb_state_stack_push(struct bb_state *state, struct list_head *stack)
{
	list_add(&state->list, stack);
}

static struct bb_state *bb_state_stack_pop(struct list_head *stack)
{
	struct bb_state *s;

	s = list_first_entry_or_null(stack, struct bb_state, list);
	if (s)
		list_del(&s->list);
	return s;
}

static int build_loop_info(struct bpf_verifier_env *env,
			   struct cfg_node_allocator *allocator,
			   struct bpf_subprog_info *subprog,
			   struct bb_node *head,
			   struct bb_node *tail)
{
	struct bpf_insn *insns = env->prog->insnsi;
	bool has_branch, only_has_branch;
	struct list_head bb_state_stack;
	struct bb_state *state = NULL;
	struct bpf_loop_info *loop;
	struct bb_node *next_bb;
	struct bpf_insn *insn;
	int err = 0;
	u8 code;

	loop = kzalloc(sizeof(struct bpf_loop_info), GFP_KERNEL);
	if (!loop)
		return -ENOMEM;

	loop->src.state = BPF_LOOP_UNKNOWN;
	loop->dst.state = BPF_LOOP_UNKNOWN;
	loop->idx = loop_idx++;
	INIT_LIST_HEAD(&loop->bb);
	INIT_LIST_HEAD(&bb_state_stack);

	state = kzalloc(sizeof(struct bb_state), GFP_KERNEL);
	if (!state) {
		kfree(loop);
		return -ENOMEM;
	}

	/* Initialize stack for path walk. To track the loop induction
	 * variable we will walk all paths back from the last instruction
	 * to the first instruction in the loop.
	 */
	next_bb = bb_next(allocator, head);
	state->bb = head;
	state->insn = next_bb->head - 1;
	insn = &insns[state->insn];
	code = insn->code;
	if (BPF_SRC(insn->code) == BPF_K) {
		_bpf_state_set_move(&state->src, insn);
	} else {
		state->src.state = BPF_LOOP_UNKNOWN;
		state->src.reg = insn->src_reg;
	}
	state->dst.state = BPF_LOOP_UNKNOWN;
	state->dst.reg = insn->dst_reg;
	state->insn_cnt = 0;

	bb_state_stack_push(state, &bb_state_stack);
	err = bb_stack_push(tail, loop);
	if (err)
		goto out;

	loop->insn_entry = tail->head;
	loop->insn_exit = next_bb->head - 1;

	/* This is a pattern match on the loop type we expect loops
	 * of the form,
	 *
	 *   header
	 *   ...
	 *   if (r1 > r2) goto header
	 *   ...
	 *
	 * Where the jump is not a BPF_JA instruction. However sometimes
	 * we get loops like the following,
	 *
	 *  header
	 *  ...
	 *  if (r1 > r2) goto out_of_loop
	 *  ...
	 *  goto header
	 *
	 *  Here the bounding condition is inside the loop and not in the
	 *  last BB. Presumably we can handle these as well with additional
	 *  searching to find the latch element. However it makes the scanning
	 *  a bit more painful. For simplicity test if tail is valid latch and
	 *  throw out other constructs.
	 *
	 *  TBD handle nested loops.
	 */
	only_has_branch = BPF_CLASS(code) == BPF_JMP &&
			  BPF_OP(code) == BPF_JA;
	if (only_has_branch) {
		bpf_verifier_log_write(env,
				       "non-terminating loop detected e(%i->%i)\n",
				       head->idx, tail->idx);
		return -EINVAL;
	}

	has_branch = only_has_branch ||
		     (BPF_CLASS(code) == BPF_JMP &&
		      BPF_OP(code) != BPF_EXIT &&
		      BPF_OP(code) != BPF_CALL);
	if (!has_branch) {
		bpf_verifier_log_write(env,
				       "loop without branches (class %i op %i), must be a verifier bug? e(%i->%i)\n",
				       BPF_CLASS(code), BPF_OP(code), head->idx, tail->idx);
		return -EINVAL;
	}


	/* With a valid branch then either src or dst register must be monotonic for
	 * the loop to terminate. To detect this do a path walk through the loop and
	 * ensure that monotonic property holds in each path.
	 */
	state = bb_state_stack_pop(&bb_state_stack);
	while (state) {
		int bb_tail, bb_head;
		struct edge_node *e;
		struct bb_node *bb;
		bool found;

		bb = state->bb;
		found = bb_search(bb, loop);
		if (!found)
			bb_stack_push(bb, loop);
		next_bb = bb_next(allocator, bb);
		bb_tail = next_bb->head - 1;
		bb_head = bb->head;

		while (bb_tail >= bb_head) {
			bpf_loop_state(env, bb_tail, &insns[bb_tail], state);
			bb_tail--;
			state->insn_cnt++;
		}

		if (state->src.state == BPF_LOOP_INVALID ||
		    state->dst.state == BPF_LOOP_INVALID) {
			bpf_verifier_log_write(env,
					       "Detected BPF_LOOP_INVALID state\n");
			goto out;
		}

		/* If this is the last node in the loop ensure the loop states
		 * have not changed with paths. For example, it would be invalid
		 * to have two paths one where the induction variable increases
		 * and another where it decreases. If the state is invalid abort
		 * now because if any single path fails the loop is invalid.
		 *
		 * Finally, assuming state is valid continue processing stack
		 * giving the next path trace.
		 */
		if (bb == tail) {
			if (state->src.state != loop->src.state &&
			    loop->src.state != BPF_LOOP_UNKNOWN) {
				bpf_verifier_log_write(env,
						       "Paths (src) do not align %i != %i\n",
						       state->src.state,
						       loop->src.state);

				goto out;
			}
			if (state->dst.state != loop->dst.state &&
			    loop->dst.state != BPF_LOOP_UNKNOWN) {
				bpf_verifier_log_write(env,
						       "Paths (dst) do not align %i != %i\n",
						       state->src.state,
						       loop->src.state);
				goto out;
			}

			if (loop->insn_cnt < state->insn_cnt)
				loop->insn_cnt = state->insn_cnt;

			loop->dst = state->dst;
			loop->src = state->src;

			bpf_clear_state(state);
			kfree(state);
			state = bb_state_stack_pop(&bb_state_stack);
			continue;
		}

		e = cfg_node_delink(allocator, &bb->e_prevs);
		while (e) {
			struct bb_node *src = e->src;
			struct bb_state *old = state;
			struct bb_state *new;

			new = kzalloc(sizeof(struct bb_state), GFP_KERNEL);
			if (!state)
				goto out;

			next_bb = bb_next(allocator, src);

			*new = *old;
			new->bb = src;
			new->insn = next_bb->head - 1;
			bb_state_stack_push(new, &bb_state_stack);

			e = cfg_node_delink(allocator, &e->link);
		}
		kfree(state);
		state = bb_state_stack_pop(&bb_state_stack);
	}
	if (bpf_is_valid_loop_state(loop))
		goto out;

	bpf_verifier_log_write(env,
			      "Loop detected e(%i->%i) insn(%i) src_state(R%i:%s) dst_state(R%i:%s)\n",
			       head->idx, tail->idx, loop->insn_cnt,
			       loop->src.reg,
			       bpf_loop_state_str[loop->src.state],
			       loop->dst.reg,
			       bpf_loop_state_str[loop->dst.state]);
	env->insn_aux_data[loop->insn_entry].loop = loop;
	return 0;
out:
	while (state) {
		kfree(state);
		state = bb_state_stack_pop(&bb_state_stack);
	}
	bpf_free_loop(loop);
	return -1;
}

int subprog_has_loop(struct bpf_verifier_env *env,
		     struct cfg_node_allocator *allocator,
		     struct bpf_subprog_info *subprog)
{
	int lane_len = BITS_TO_LONGS(subprog->bb_num - 2);
	struct bb_node *bb, *entry_bb, *exit_bb;
	void **bb_list = (void **)&subprog->bbs;
	struct edge_node *e;
	int err = 0;

	entry_bb = entry_bb(bb_list);
	exit_bb = exit_bb(bb_list);
	bb = bb_next(allocator, entry_bb);
	while (bb && bb != exit_bb) {
		e = cfg_node_delink(allocator, &bb->e_prevs);
		while (e) {
			struct bb_node *latch = e->src;

			if (latch != entry_bb &&
			    test_bit(bb->idx,
				     subprog->dtree + latch->idx * lane_len)) {
				err = build_loop_info(env, allocator, subprog, latch, bb);
				if (err)
					return err;
			}

			e = cfg_node_delink(allocator, &e->link);
		}

		bb = bb_next(allocator, bb);
	}

	return 0;
}

/* We don't want to do any further loop bounds analysis for irreducible loop,
 * so just reject programs containing it.
 *
 * The current DOM based loop detection can't detect irreducible loop. We'd
 * use the algorithm given by Eric Stoltz to detect it. The algorithm requires
 * DOM info.
 *
 * Algorithm pseudo code:
 *
 *   test_dom(a,b) returns TRUE if a dominates b
 *   push( v ) pushes v onto a reverse topologically-sorted stack
 *
 *   top_sort( entry node )
 *
 *   top_sort( node v ) {
 *	mark_visited( v );
 *	Visit all successors s of v {
 *		if (mark_visited(s) && !pushed(s) && !test_dom(s, v)) {
 *			Irreducible_Graph = TRUE;
 *			Exit -- no need to continue now!
 *		}
 *		if(!mark_visited(s))
 *			top_sort( s );
 *	}
 *	push( v );
 *   }
 */
int subprog_has_irreduciable_loop(struct cfg_node_allocator *allocator,
				  struct bpf_subprog_info *subprog)
{
	u16 bb_num = subprog->bb_num - 2, sp = 0, *status;
	void **bb_list = (void **)&subprog->bbs;
	struct edge_node **stack, *e, *prev_e;
	int lane_len = BITS_TO_LONGS(bb_num);
	struct bb_node *entry_bb, *exit_bb;
	int found = 0;

	stack = kmalloc_array(bb_num, sizeof(struct edge_node *), GFP_KERNEL);
	if (!stack)
		return -ENOMEM;

	status = kcalloc(bb_num, sizeof(u16), GFP_KERNEL);
	if (!status)
		return -ENOMEM;

	entry_bb = entry_bb(bb_list);
	exit_bb = exit_bb(bb_list);
	e = cfg_node_delink(allocator, &entry_bb->e_succs);
	prev_e = e;

	while (1) {
		struct bb_node *bb_dst;

		while (e) {
			bb_dst = e->dst;

			if (bb_dst == exit_bb ||
			    status[bb_dst->idx] == DFS_NODE_EXPLORED) {
				prev_e = e;
				e = cfg_node_delink(allocator, &e->link);
				continue;
			}

			if (status[bb_dst->idx] == DFS_NODE_EXPLORING) {
				u16 src_idx = e->src->idx;
				unsigned long *bb_map;

				bb_map = subprog->dtree + src_idx * lane_len;
				if (!test_bit(bb_dst->idx, bb_map)) {
					found = 1;
					goto free_and_ret;
				} else {
					prev_e = e;
					e = cfg_node_delink(allocator,
							    &e->link);
					continue;
				}
			}

			status[bb_dst->idx] = DFS_NODE_EXPLORING;
			stack[sp++] = e;
			/* e should never be NULL as it couldn't be exit_bb. */
			e = cfg_node_delink(allocator, &bb_dst->e_succs);
		}

		if (prev_e->src != entry_bb)
			status[prev_e->src->idx] = DFS_NODE_EXPLORED;

		if (!sp)
			break;

		e = stack[--sp];
		prev_e = e;
		e = cfg_node_delink(allocator, &e->link);
	}

free_and_ret:
	kfree(stack);
	kfree(status);

	return found;
}

static int cmp_subprogs(const void *a, const void *b)
{
	return ((struct bpf_subprog_info *)a)->start -
	       ((struct bpf_subprog_info *)b)->start;
}

int find_subprog(struct bpf_verifier_env *env, int off)
{
	struct bpf_subprog_info *p;

	p = bsearch(&off, env->subprog_info, env->subprog_cnt,
		    sizeof(env->subprog_info[0]), cmp_subprogs);
	if (!p)
		return -ENOENT;
	return p - env->subprog_info;
}

int add_subprog(struct bpf_verifier_env *env, int off)
{
	int insn_cnt = env->prog->len;
	int ret;

	if (off >= insn_cnt || off < 0) {
		bpf_verifier_log_write(env, "call to invalid destination\n");
		return -EINVAL;
	}
	ret = find_subprog(env, off);
	if (ret >= 0)
		return 0;
	if (env->subprog_cnt >= BPF_MAX_SUBPROGS) {
		bpf_verifier_log_write(env, "too many subprograms\n");
		return -E2BIG;
	}
	env->subprog_info[env->subprog_cnt++].start = off;
	sort(env->subprog_info, env->subprog_cnt,
	     sizeof(env->subprog_info[0]), cmp_subprogs, NULL);
	return 0;
}

struct callee_iter {
	struct cedge_node *head;
	struct cedge_node *callee;
};

static bool ci_end_p(struct callee_iter *ci)
{
	return !ci->callee;
}

static void ci_next(struct cfg_node_allocator *allocator,
		    struct callee_iter *ci)
{
	struct cedge_node *c = ci->callee;

	ci->callee = cfg_node_delink(allocator, &c->link);
}

int cgraph_check_recursive_unreachable(struct bpf_verifier_env *env,
				       struct cfg_node_allocator *allocator,
				       struct bpf_subprog_info *subprog)
{
	int sp = 0, idx = 0, ret, *status;
	struct callee_iter *stack, ci;
	struct cedge_node *callee;

	stack = kmalloc_array(64, sizeof(struct callee_iter), GFP_KERNEL);
	if (!stack)
		return -ENOMEM;
	status = kcalloc(env->subprog_cnt, sizeof(int), GFP_KERNEL);
	if (!status) {
		kfree(stack);
		return -ENOMEM;
	}
	ci.head = subprog->callees;
	ci.callee = subprog->callees;
	status[0] = DFS_NODE_EXPLORING;

	while (1) {
		while (!ci_end_p(&ci)) {
			callee = ci.callee;
			idx = callee->callee_idx;
			if (status[idx] == DFS_NODE_EXPLORING) {
				bpf_verifier_log_write(env, "cgraph - recursive call\n");
				ret = -EINVAL;
				goto err_free;
			}

			status[idx] = DFS_NODE_EXPLORING;

			if (sp == 64) {
				bpf_verifier_log_write(env, "cgraph - call frame too deep\n");
				ret = -EINVAL;
				goto err_free;
			}

			stack[sp++] = ci;
			ci.head = subprog[idx].callees;
			ci.callee = subprog[idx].callees;
		}

		if (ci.head)
			status[ci.head->caller_idx] = DFS_NODE_EXPLORED;
		else
			/* leaf func. */
			status[idx] = DFS_NODE_EXPLORED;

		if (!sp)
			break;

		ci = stack[--sp];
		ci_next(allocator, &ci);
	}

	for (idx = 0; idx < env->subprog_cnt; idx++)
		if (status[idx] != DFS_NODE_EXPLORED) {
			bpf_verifier_log_write(env, "cgraph - unreachable subprog\n");
			ret = -EINVAL;
			goto err_free;
		}

	ret = 0;
err_free:
	kfree(status);
	kfree(stack);
	return ret;
}

int subprog_append_callee(struct bpf_verifier_env *env,
			  struct cfg_node_allocator *allocator,
			  void **callees_list, int caller_idx, int off)
{
	int callee_idx = find_subprog(env, off), ret;
	struct cedge_node *new_callee, *callee;
	struct mem_frag frag;

	if (callee_idx < 0)
		return callee_idx;

	callee = (struct cedge_node *)*callees_list;
	while (callee) {
		if (callee->callee_idx == callee_idx)
			return 0;

		callee = cfg_node_delink(allocator, &callee->link);
	}

	ret = get_single_cedge_node(allocator, &frag);
	if (ret < 0)
		return ret;

	new_callee = frag.p;
	new_callee->caller_idx = caller_idx;
	new_callee->callee_idx = callee_idx;
	callee = (struct cedge_node *)*callees_list;
	if (!callee) {
		*callees_list = new_callee;
	} else {
		new_callee->link = callee->link;
		callee->link = frag.link;
	}

	return 0;
}

void subprog_free(struct bpf_subprog_info *subprog, int end_idx)
{
	int i = 0;

	for (; i <= end_idx; i++) {
		if (subprog[i].dtree_avail)
			kfree(subprog[i].dtree);
	}
}
