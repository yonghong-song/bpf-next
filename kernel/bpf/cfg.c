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

#define entry_bb(bb_list)		(struct bb_node *)(*bb_list)
#define exit_bb(bb_list)		(struct bb_node *)(*(bb_list + 1))

static struct bb_node *bb_next(struct cfg_node_allocator *allocator,
			       struct bb_node *bb)
{
	return (struct bb_node *)cfg_node_delink(allocator, &bb->link);
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

bool subprog_has_loop(struct cfg_node_allocator *allocator,
		      struct bpf_subprog_info *subprog)
{
	int lane_len = BITS_TO_LONGS(subprog->bb_num - 2);
	struct bb_node *bb, *entry_bb, *exit_bb;
	void **bb_list = (void **)&subprog->bbs;
	struct edge_node *e;

	entry_bb = entry_bb(bb_list);
	exit_bb = exit_bb(bb_list);
	bb = bb_next(allocator, entry_bb);
	while (bb && bb != exit_bb) {
		e = cfg_node_delink(allocator, &bb->e_prevs);
		while (e) {
			struct bb_node *latch = e->src;

			if (latch != entry_bb &&
			    test_bit(bb->idx,
				     subprog->dtree + latch->idx * lane_len))
				return true;

			e = cfg_node_delink(allocator, &e->link);
		}

		bb = bb_next(allocator, bb);
	}

	return false;
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
