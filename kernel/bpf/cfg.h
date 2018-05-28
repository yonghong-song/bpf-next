// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2018 Netronome Systems, Inc. */
/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#ifndef __BPF_CFG_H__
#define __BPF_CFG_H__

struct cfg_node_allocator {
	struct list_head pools;
	struct node_pool *cur_free_pool;
};

int add_subprog(struct bpf_verifier_env *env, int off);
void cfg_node_allocator_free(struct cfg_node_allocator *allocator);
int cfg_node_allocator_init(struct cfg_node_allocator *allocator,
			    int bb_num_esti, int cedge_num_esti);
int cgraph_check_recursive_unreachable(struct bpf_verifier_env *env,
				       struct bpf_subprog_info *subprog);
int find_subprog(struct bpf_verifier_env *env, int off);
int subprog_add_bb_edges(struct cfg_node_allocator *allocator,
			 struct bpf_insn *insns, struct list_head *bb_list);
int subprog_append_bb(struct cfg_node_allocator *allocator,
		      struct list_head *bb_list, int head);
int subprog_append_callee(struct bpf_verifier_env *env,
			  struct cfg_node_allocator *allocator,
			  struct list_head *bb_list, int caller_idx, int off);
int subprog_build_dom_info(struct bpf_verifier_env *env,
			   struct bpf_subprog_info *subprog);
int subprog_fini_bb(struct cfg_node_allocator *allocator,
		    struct list_head *bb_list, int subprog_end);
bool subprog_has_loop(struct bpf_subprog_info *subprog);
int subprog_init_bb(struct cfg_node_allocator *allocator,
		    struct list_head *bb_list, int subprog_start);
void subprog_free(struct bpf_subprog_info *subprog, int end_idx);

#endif
