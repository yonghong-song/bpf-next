// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2018 Netronome Systems, Inc. */
/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#ifndef __BPF_CFG_H__
#define __BPF_CFG_H__

#define MAX_POOL_NUM	32

struct cfg_node_allocator {
	void *base[MAX_POOL_NUM];
	u8 pool_cnt;
};

int add_subprog(struct bpf_verifier_env *env, int off);
void cfg_node_allocator_free(struct cfg_node_allocator *allocator);
int cfg_node_allocator_init(struct cfg_node_allocator *allocator,
			    int bb_num_esti, int cedge_num_esti);
int cgraph_check_recursive_unreachable(struct bpf_verifier_env *env,
				       struct cfg_node_allocator *allocator,
				       struct bpf_subprog_info *subprog);
int find_subprog(struct bpf_verifier_env *env, int off);
int subprog_add_bb_edges(struct cfg_node_allocator *allocator,
			 struct bpf_insn *insns, void **bb_list);
int subprog_append_bb(struct cfg_node_allocator *allocator,
		      void **bb_list, int head);
int subprog_append_callee(struct bpf_verifier_env *env,
			  struct cfg_node_allocator *allocator,
			  void **callees, int caller_idx, int off);
int subprog_build_dom_info(struct bpf_verifier_env *env,
			   struct cfg_node_allocator *allocator,
			   struct bpf_subprog_info *subprog);
bool subprog_has_loop(struct cfg_node_allocator *allocator,
		      struct bpf_subprog_info *subprog);
int subprog_has_irreduciable_loop(struct cfg_node_allocator *allocator,
				  struct bpf_subprog_info *subprog);
void cfg_pretty_print(struct bpf_verifier_env *env,
		      struct cfg_node_allocator *allocator,
		      struct bpf_subprog_info *subprog);
void dom_pretty_print(struct bpf_verifier_env *env,
		      struct bpf_subprog_info *subprog);
int subprog_init_bb(struct cfg_node_allocator *allocator, void **bb_list,
		    int subprog_start, int subprog_end);
void subprog_free(struct bpf_subprog_info *subprog, int end_idx);

#define DFS_NODE_EXPLORING	1
#define DFS_NODE_EXPLORED	2

#endif
