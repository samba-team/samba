/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2019      Michael Hanselmann <public@hansmi.ch>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "includes.h"
#include "lib/replace/replace.h"
#include "system/filesys.h"
#include "lib/util/samba_util.h"
#include "registry/regfio.h"

struct test_ctx {
	char *tmp_regfile;
	int tmp_regfile_fd;
	REGF_FILE *rb;
};

static int setup_context(void **state)
{
	struct test_ctx *test_ctx;

	test_ctx = talloc_zero(NULL, struct test_ctx);
	assert_non_null(test_ctx);

	test_ctx->tmp_regfile_fd  = -1;

	*state = test_ctx;

	return 0;
}

static int setup_context_tempfile(void **state)
{
	struct test_ctx *test_ctx;
	int ret;

	ret = setup_context(state);

	if (ret == 0) {
		test_ctx = talloc_get_type_abort(*state, struct test_ctx);

		test_ctx->tmp_regfile = talloc_strdup(test_ctx, "/tmp/regfio.XXXXXX");
		assert_non_null(test_ctx->tmp_regfile);

		test_ctx->tmp_regfile_fd = mkstemp(test_ctx->tmp_regfile);
		assert_return_code(test_ctx->tmp_regfile_fd, errno);
	}

	return ret;
}

static int teardown_context(void **state)
{
	struct test_ctx *test_ctx =
		talloc_get_type_abort(*state, struct test_ctx);

	if (test_ctx->rb) {
		regfio_close(test_ctx->rb);
	}

	if (test_ctx->tmp_regfile) {
		unlink(test_ctx->tmp_regfile);
	}

	if (test_ctx->tmp_regfile_fd != -1) {
		close(test_ctx->tmp_regfile_fd);
	}

	talloc_free(test_ctx);

	return 0;
}

static void open_testfile(struct test_ctx *test_ctx, const char *filename)
{
	char *path;

	path = talloc_asprintf(test_ctx, "%s/testdata/samba3/%s", SRCDIR, filename);
	assert_non_null(path);

	test_ctx->rb = regfio_open(path, O_RDONLY, 0600);
	assert_non_null(test_ctx->rb);
}

static void test_regfio_open_new_file(void **state)
{
	struct test_ctx *test_ctx =
		talloc_get_type_abort(*state, struct test_ctx);
	REGF_NK_REC *root;
	struct regval_ctr *values;
	struct regsubkey_ctr *subkeys;
	WERROR werr;

	test_ctx->rb = regfio_open(test_ctx->tmp_regfile,
				   O_RDWR | O_CREAT | O_TRUNC, 0600);
	assert_non_null(test_ctx->rb);

	root = regfio_rootkey(test_ctx->rb);
	assert_null(root);

	werr = regsubkey_ctr_init(NULL, &subkeys);
	assert_true(W_ERROR_IS_OK(werr));

	werr = regval_ctr_init(subkeys, &values);
	assert_true(W_ERROR_IS_OK(werr));

	/* Write root key */
	regfio_write_key(test_ctx->rb, "", values, subkeys, NULL, NULL);

	root = regfio_rootkey(test_ctx->rb);
	assert_non_null(root);
	assert_memory_equal(root->header, "nk", sizeof(root->header));
	assert_int_equal(root->key_type, NK_TYPE_ROOTKEY);
}

static void test_regfio_corrupt_hbin(void **state)
{
	struct test_ctx *test_ctx =
		talloc_get_type_abort(*state, struct test_ctx);
	REGF_NK_REC *root;

	open_testfile(test_ctx, "regfio_corrupt_hbin1.dat");

	root = regfio_rootkey(test_ctx->rb);
	assert_null(root);
}

static void test_regfio_corrupt_lf_subkeys(void **state)
{
	struct test_ctx *test_ctx =
		talloc_get_type_abort(*state, struct test_ctx);
	REGF_NK_REC *root, *subkey;

	open_testfile(test_ctx, "regfio_corrupt_lf_subkeys.dat");

	root = regfio_rootkey(test_ctx->rb);
	assert_non_null(root);

	root->subkey_index = 0;
	while ((subkey = regfio_fetch_subkey(test_ctx->rb, root))) {
	}
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_regfio_open_new_file,
						setup_context_tempfile,
						teardown_context),
		cmocka_unit_test_setup_teardown(test_regfio_corrupt_hbin,
						setup_context,
						teardown_context),
		cmocka_unit_test_setup_teardown(test_regfio_corrupt_lf_subkeys,
						setup_context,
						teardown_context),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
