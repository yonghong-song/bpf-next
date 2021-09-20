// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include "tag.skel.h"
#include "tag_userptr.skel.h"

static void test_kernel_btf_tag(void)
{
	struct tag *skel;

	skel = tag__open_and_load();
	if (!ASSERT_OK_PTR(skel, "btf_tag"))
		return;

	if (skel->rodata->skip_tests) {
		printf("%s:SKIP: btf_tag attribute not supported with clang", __func__);
		test__skip();
	}

	tag__destroy(skel);
}

static void test_userptr(void)
{
	struct tag_userptr *skel;
	int err;

	skel = tag_userptr__open();
	if (!ASSERT_OK_PTR(skel, "userptr"))
		return;

	/* disable prog test91 and load should succeed */
	bpf_program__set_autoload(skel->progs.test91, false);

	err = tag_userptr__load(skel);
	if (!ASSERT_OK(err, "tag__load"))
		goto cleanup;

	/* try to load all progs including test91 should fail. */
	tag_userptr__destroy(skel);
	skel = tag_userptr__open_and_load();
	if (ASSERT_ERR_PTR(skel, "userptr"))
		return;
cleanup:
	tag_userptr__destroy(skel);
}

void test_btf_tag(void)
{
	if (test__start_subtest("kernel_btf_tag"))
		test_kernel_btf_tag();
	if (test__start_subtest("userptr"))
		test_userptr();
}
