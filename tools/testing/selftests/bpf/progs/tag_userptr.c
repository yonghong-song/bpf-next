// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 test9_result = 0;

SEC("fentry/bpf_fentry_test9")
int BPF_PROG(test91, union bpf_attr *uattr)
{
        if (uattr->test.cpu == 0)
		test9_result = 1;
	return 0;
}

SEC("fentry/bpf_fentry_test9")
int BPF_PROG(test92, union bpf_attr *uattr)
{
	__u32 cpu;
	int ret;

	ret = bpf_probe_read_user(&cpu, sizeof(cpu), &uattr->test.cpu);
	if (ret == 0 && cpu == 0)
		test9_result = 1;
	return 0;
}
