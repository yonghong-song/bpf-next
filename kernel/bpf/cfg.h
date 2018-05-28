// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2018 Netronome Systems, Inc. */
/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#ifndef __BPF_CFG_H__
#define __BPF_CFG_H__

int subprog_add_bb_edges(struct bpf_insn *insns, struct list_head *bb_list);
int subprog_append_bb(struct list_head *bb_list, int head);
int subprog_build_dom_info(struct bpf_verifier_env *env,
			   struct bpf_subprog_info *subprog);
int subprog_fini_bb(struct list_head *bb_list, int subprog_end);
bool subprog_has_loop(struct bpf_subprog_info *subprog);
int subprog_init_bb(struct list_head *bb_list, int subprog_start);
void subprog_free(struct bpf_subprog_info *subprog, int end_idx);

#endif
