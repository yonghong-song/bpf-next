/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2018 Covalent IO
 */
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"
#include "test_iptunnel_common.h"
#include "bpf_endian.h"

int _version SEC("version") = 1;
SEC("classifier_tc_loop1")
int _tc_loop(struct __sk_buff *ctx)
{
	void *data      = (void *)(unsigned long)ctx->data;
	void *data_end  = (void *)(unsigned long)ctx->data_end;
	 __u8 i = 0, j = 0, k = 0, *p;

	 p = data;
	 if (data + 101 > data_end)
		 return TC_ACT_OK;

#pragma nounroll
	while (i < 100) {
		k += p[i];
		p[i] = k;
		i++;
	}
	ctx->mark = k;

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
