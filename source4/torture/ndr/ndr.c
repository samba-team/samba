/*
   Unix SMB/CIFS implementation.
   test suite for winreg ndr operations

   Copyright (C) Jelmer Vernooij 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/ndr/ndr.h"
#include "torture/ndr/proto.h"
#include "../lib/util/dlinklist.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_misc.h"

struct ndr_pull_test_data {
	DATA_BLOB data;
	DATA_BLOB data_context;
	size_t struct_size;
	ndr_pull_flags_fn_t pull_fn;
	ndr_push_flags_fn_t push_fn;
	ndr_print_fn_t print_fn;
	ndr_print_function_t print_function;
	int ndr_flags;
	int flags;
	enum ndr_err_code ndr_err;
};

static enum ndr_err_code torture_ndr_push_struct_blob_flags(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, uint32_t flags, uint32_t ndr_flags, const void *p, ndr_push_flags_fn_t fn)
{
	struct ndr_push *ndr;
	ndr = ndr_push_init_ctx(mem_ctx);
	NDR_ERR_HAVE_NO_MEMORY(ndr);

	ndr->flags |= ndr_flags;

	NDR_CHECK(fn(ndr, flags, p));

	*blob = ndr_push_blob(ndr);
	talloc_steal(mem_ctx, blob->data);
	talloc_free(ndr);

	return NDR_ERR_SUCCESS;
}

static bool torture_ndrdump(struct torture_context *tctx,
			    struct ndr_pull *ndr,
			    const struct ndr_pull_test_data *data,
			    uint32_t flags,
			    void *ds,
			    const char *name)
{
	struct ndr_print *ndr_print;
	const char *name_raw;
	uint32_t ndr_flags = data->ndr_flags | flags;

	ndr_print = talloc_zero(tctx, struct ndr_print);
	torture_assert(tctx, ndr_print, "out of memory");

	if (DEBUGLEVEL >= 10) {
		ndr_print->print = ndr_print_debug_helper;
	} else {
		ndr_print->print = ndr_print_string_helper;
	}

	ndr_print->depth = 1;

	torture_assert(tctx, ndr_flags, "no flags have been set");

	if (ndr_flags & (NDR_BUFFERS|NDR_SCALARS)) {
		data->print_fn(ndr_print, name, ds);
	} else {
		data->print_function(ndr_print, name, ndr_flags, ds);
	}

	name_raw = talloc_asprintf(tctx, "%s (RAW DATA)", name);
	torture_assert(tctx, name_raw, "out of memory");

	ndr_print_DATA_BLOB(ndr_print, name_raw, data->data);

	talloc_free(ndr_print);

	return true;
}

static bool wrap_ndr_pullpush_test(struct torture_context *tctx,
				   struct torture_tcase *tcase,
				   struct torture_test *test)
{
	bool (*check_fn) (struct torture_context *ctx, void *data) = test->fn;
	const struct ndr_pull_test_data *data = (const struct ndr_pull_test_data *)test->data;
	struct ndr_pull *ndr = ndr_pull_init_blob(&(data->data), tctx);
	void *ds = talloc_zero_size(ndr, data->struct_size);
	bool ret = true;
	uint32_t highest_ofs;

	torture_assert(tctx, data, "out of memory");
	torture_assert(tctx, ndr, "out of memory");
	torture_assert(tctx, ds, "out of memory");

	ndr->flags |= data->flags;

	ndr->flags |= LIBNDR_FLAG_REF_ALLOC;

	torture_assert_ndr_success(tctx, data->pull_fn(ndr, data->ndr_flags, ds),
				   "pulling");

	if (ndr->offset > ndr->relative_highest_offset) {
		highest_ofs = ndr->offset;
	} else {
		highest_ofs = ndr->relative_highest_offset;
	}

	torture_assert(tctx, highest_ofs == ndr->data_size,
				   talloc_asprintf(tctx,
					   "%d unread bytes", ndr->data_size - highest_ofs));

	if (check_fn != NULL) {
		ret = check_fn(tctx, ds);
	} else {
		ret = true;
	}

	torture_ndrdump(tctx, ndr, data, data->ndr_flags, ds, "ds");

	if (data->push_fn != NULL) {
		DATA_BLOB outblob;
		torture_assert_ndr_success(tctx, torture_ndr_push_struct_blob_flags(&outblob, ndr, data->ndr_flags, ndr->flags, ds, data->push_fn), "pushing");
		torture_assert_data_blob_equal(tctx, outblob, data->data, "ndr push compare");
	}

	talloc_free(ndr);
	return ret;
}

_PUBLIC_ struct torture_test *_torture_suite_add_ndr_pullpush_test(
	struct torture_suite *suite,
	const char *name,
	ndr_pull_flags_fn_t pull_fn,
	ndr_push_flags_fn_t push_fn,
	ndr_print_fn_t print_fn,
	ndr_print_function_t print_function,
	DATA_BLOB db,
	size_t struct_size,
	int ndr_flags,
	int flags,
	bool (*check_fn) (struct torture_context *ctx, void *data))
{
	struct torture_test *test;
	struct torture_tcase *tcase;
	struct ndr_pull_test_data *data;

	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_ndr_pullpush_test;

	data = talloc_zero(test, struct ndr_pull_test_data);
	data->data = db;
	data->ndr_flags = ndr_flags;
	data->flags = flags;
	data->struct_size = struct_size;
	data->pull_fn = pull_fn;
	data->push_fn = push_fn;
	data->print_fn = print_fn;
	data->print_function = print_function;

	test->data = data;
	test->fn = check_fn;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test);

	return test;
}


static bool wrap_ndr_inout_pull_test(struct torture_context *tctx,
				     struct torture_tcase *tcase,
				     struct torture_test *test)
{
	bool (*check_fn) (struct torture_context *ctx, void *data) = test->fn;
	const struct ndr_pull_test_data *data = (const struct ndr_pull_test_data *)test->data;
	void *ds = talloc_zero_size(tctx, data->struct_size);
	struct ndr_pull *ndr;
	uint32_t highest_ofs;
	bool ret = false;

	torture_assert(tctx, data, "out of memory");
	torture_assert(tctx, ds, "out of memory");

	/* handle NDR_IN context */

	ndr = ndr_pull_init_blob(&(data->data_context), tctx);
	torture_assert(tctx, ndr, "ndr init failed");

	ndr->flags |= data->flags;
	ndr->flags |= LIBNDR_FLAG_REF_ALLOC;

	torture_assert_ndr_success(tctx,
		data->pull_fn(ndr, NDR_IN, ds),
		"ndr pull of context failed");

	if (ndr->offset > ndr->relative_highest_offset) {
		highest_ofs = ndr->offset;
	} else {
		highest_ofs = ndr->relative_highest_offset;
	}

	torture_assert(tctx, highest_ofs == ndr->data_size,
		talloc_asprintf(tctx, "%d unread bytes", ndr->data_size - highest_ofs));

	torture_ndrdump(tctx, ndr, data, NDR_IN, ds, "ds");

	talloc_free(ndr);

	/* handle NDR_OUT */

	ndr = ndr_pull_init_blob(&(data->data), tctx);
	torture_assert(tctx, ndr, "ndr init failed");

	ndr->flags |= data->flags;
	ndr->flags |= LIBNDR_FLAG_REF_ALLOC;

	torture_assert_ndr_success(tctx,
		data->pull_fn(ndr, NDR_OUT, ds),
		"ndr pull failed");

	if (ndr->offset > ndr->relative_highest_offset) {
		highest_ofs = ndr->offset;
	} else {
		highest_ofs = ndr->relative_highest_offset;
	}

	torture_assert(tctx, highest_ofs == ndr->data_size,
		talloc_asprintf(tctx, "%d unread bytes", ndr->data_size - highest_ofs));

	if (check_fn) {
		ret = check_fn(tctx, ds);
	} else {
		ret = true;
	}

	torture_ndrdump(tctx, ndr, data, NDR_OUT, ds, "ds");

	talloc_free(ndr);

	return ret;
}

_PUBLIC_ struct torture_test *_torture_suite_add_ndr_pull_inout_test(
					struct torture_suite *suite,
					const char *name,
					ndr_pull_flags_fn_t pull_fn,
					ndr_print_function_t print_function,
					DATA_BLOB db_in,
					DATA_BLOB db_out,
					size_t struct_size,
					int flags,
					bool (*check_fn) (struct torture_context *ctx, void *data))
{
	struct torture_test *test;
	struct torture_tcase *tcase;
	struct ndr_pull_test_data *data;

	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_ndr_inout_pull_test;
	data = talloc_zero(test, struct ndr_pull_test_data);
	data->data = db_out;
	data->data_context = db_in;
	data->ndr_flags = 0;
	data->flags = flags;
	data->struct_size = struct_size;
	data->pull_fn = pull_fn;
	data->print_function = print_function;
	test->data = data;
	test->fn = check_fn;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test);

	return test;
}

static bool wrap_ndr_pull_invalid_data_test(struct torture_context *tctx,
					    struct torture_tcase *tcase,
					    struct torture_test *test)
{
	const struct ndr_pull_test_data *data = (const struct ndr_pull_test_data *)test->data;
	struct ndr_pull *ndr = ndr_pull_init_blob(&(data->data), tctx);
	void *ds = talloc_zero_size(ndr, data->struct_size);
	bool ret = true;

	torture_assert(tctx, data, "out of memory");
	torture_assert(tctx, ndr, "out of memory");
	torture_assert(tctx, ds, "out of memory");

	ndr->flags |= data->flags;

	ndr->flags |= LIBNDR_FLAG_REF_ALLOC;

	torture_assert_ndr_err_equal(
		tctx,
		data->pull_fn(ndr, data->ndr_flags, ds),
		NDR_ERR_BUFSIZE,
		"pulling invalid data");

	talloc_free(ndr);
	return ret;
}

_PUBLIC_ struct torture_test *_torture_suite_add_ndr_pull_invalid_data_test(
	struct torture_suite *suite,
	const char *name,
	ndr_pull_flags_fn_t pull_fn,
	DATA_BLOB db,
	size_t struct_size,
	int ndr_flags,
	int flags,
	enum ndr_err_code ndr_err)
{
	struct torture_test *test;
	struct torture_tcase *tcase;
	struct ndr_pull_test_data *data;

	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_ndr_pull_invalid_data_test;

	data = talloc_zero(test, struct ndr_pull_test_data);
	data->data = db;
	data->ndr_flags = ndr_flags;
	data->flags = flags;
	data->struct_size = struct_size;
	data->pull_fn = pull_fn;
	data->ndr_err = ndr_err;

	test->data = data;
	test->fn = NULL;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test);

	return test;
}

static bool test_check_string_terminator(struct torture_context *tctx)
{
	struct ndr_pull *ndr;
	DATA_BLOB blob;
	TALLOC_CTX *mem_ctx = tctx;

	/* Simple test */
	blob = strhex_to_data_blob(tctx, "0000");

	ndr = ndr_pull_init_blob(&blob, mem_ctx);

	torture_assert_ndr_success(tctx, ndr_check_string_terminator(ndr, 1, 2),
				   "simple check_string_terminator test failed");

	torture_assert(tctx, ndr->offset == 0,
		"check_string_terminator did not reset offset");

	if (NDR_ERR_CODE_IS_SUCCESS(ndr_check_string_terminator(ndr, 1, 3))) {
		torture_fail(tctx, "check_string_terminator checked beyond string boundaries");
	}

	torture_assert(tctx, ndr->offset == 0,
		"check_string_terminator did not reset offset");

	talloc_free(ndr);

	blob = strhex_to_data_blob(tctx, "11220000");
	ndr = ndr_pull_init_blob(&blob, mem_ctx);

	torture_assert_ndr_success(tctx,
		ndr_check_string_terminator(ndr, 4, 1),
		"check_string_terminator failed to recognize terminator");

	torture_assert_ndr_success(tctx,
		ndr_check_string_terminator(ndr, 3, 1),
		"check_string_terminator failed to recognize terminator");

	if (NDR_ERR_CODE_IS_SUCCESS(ndr_check_string_terminator(ndr, 2, 1))) {
		torture_fail(tctx, "check_string_terminator erroneously reported terminator");
	}

	torture_assert(tctx, ndr->offset == 0,
		"check_string_terminator did not reset offset");
	return true;
}

static bool test_guid_from_string_valid(struct torture_context *tctx)
{
	/* FIXME */
	return true;
}

static bool test_guid_from_string_null(struct torture_context *tctx)
{
	struct GUID guid;
	torture_assert_ntstatus_equal(tctx, NT_STATUS_INVALID_PARAMETER,
				      GUID_from_string(NULL, &guid),
				      "NULL failed");
	return true;
}

static bool test_guid_from_string_invalid(struct torture_context *tctx)
{
	struct GUID g1;
	bool failed = false;
	int i;
	const char *bad_guids[] = {
		"bla",
		"",
		/*
		"00000001-0002-0003-0405-060708090a0b",  correct
		*/
		"00000001-0002-0003-0405-060708090a0b1", /* too long */
		"00000001-0002-0003-0405-060708090a0",  /* too short */
		"00000001-0002-0003-0405--060708090a0",  /* negative */
		"00000001-0002-0003--0405-060708090a0",  /* negative */
		"-0000001-0002-0003-0405-060708090a0b",  /* negative */
		"-0000001-0002-0003-04-5-060708090a0b",  /* negative */
		"d0000001-0002-0003-0405-060708090a-b",  /* negative */
		"00000001-  -2-0003-0405-060708090a0b",  /* negative, space */
		"00000001-0002-0003-0405- 060708090a0",  /* whitespace */
		" 0000001-0002-0003--0405-060708090a0",  /* whitespace */
		"00000001-0002-0003--0405-060708090a ",  /* whitespace */
		"0000001-00002-0003-04050-60708090a0b",  /* misshapen */
		"00000010-0002-0003-04050-60708090a0b",  /* misshapen */
		"00000001-0002-0003-0405-0z0708090a0b",  /* bad char */
		"00000001-00x2-0x03-0405-060708090a0b",  /* bad char (00x) */
		"0x000001-0002-0003-0405-060708090a0b",  /* 0x char */
		"00000001-0x02-0x03-0405-060708090a0b",  /* 0x char */
	};

	for (i = 0; i < ARRAY_SIZE(bad_guids); i++) {
		NTSTATUS status = GUID_from_string(bad_guids[i], &g1);
		if (! NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			torture_comment(tctx, "bad guid %s parsed as OK\n",
					bad_guids[i]);
			failed = true;
		}
	}
	if (failed) {
		torture_fail(tctx, "wrongly allowing invalid guids");
	}
	return true;
}

static bool test_guid_from_string(struct torture_context *tctx)
{
	struct GUID g1, exp;
	/* we are asserting all these guids are valid and equal */
	const char *guids[4] = {
		"00000001-0002-0003-0405-060708090a0b",
		"{00000001-0002-0003-0405-060708090a0b}",
		"{00000001-0002-0003-0405-060708090a0B}", /* mixed */
		"00000001-0002-0003-0405-060708090A0B",   /* upper */
	};
	int i;

	torture_assert_ntstatus_ok(tctx,
				   GUID_from_string(guids[0], &g1),
				   "invalid return code");
	exp.time_low = 1;
	exp.time_mid = 2;
	exp.time_hi_and_version = 3;
	exp.clock_seq[0] = 4;
	exp.clock_seq[1] = 5;
	exp.node[0] = 6;
	exp.node[1] = 7;
	exp.node[2] = 8;
	exp.node[3] = 9;
	exp.node[4] = 10;
	exp.node[5] = 11;

	for (i = 1; i < ARRAY_SIZE(guids); i++) {
		torture_assert_ntstatus_ok(tctx,
					   GUID_from_string(guids[i], &g1),
					   "invalid return code");
		torture_assert(tctx, GUID_equal(&g1, &exp),
			       "UUID parsed incorrectly");
	}
	return true;
}

static bool test_guid_string_valid(struct torture_context *tctx)
{
	struct GUID g;
	g.time_low = 1;
	g.time_mid = 2;
	g.time_hi_and_version = 3;
	g.clock_seq[0] = 4;
	g.clock_seq[1] = 5;
	g.node[0] = 6;
	g.node[1] = 7;
	g.node[2] = 8;
	g.node[3] = 9;
	g.node[4] = 10;
	g.node[5] = 11;
	torture_assert_str_equal(tctx, "00000001-0002-0003-0405-060708090a0b",
				 GUID_string(tctx, &g),
				 "parsing guid failed");
	return true;
}

static bool test_guid_string2_valid(struct torture_context *tctx)
{
	struct GUID g;
	g.time_low = 1;
	g.time_mid = 2;
	g.time_hi_and_version = 3;
	g.clock_seq[0] = 4;
	g.clock_seq[1] = 5;
	g.node[0] = 6;
	g.node[1] = 7;
	g.node[2] = 8;
	g.node[3] = 9;
	g.node[4] = 10;
	g.node[5] = 11;
	torture_assert_str_equal(tctx, "{00000001-0002-0003-0405-060708090a0b}",
				 GUID_string2(tctx, &g),
				 "parsing guid failed");
	return true;
}

static bool test_guid_into_blob(struct torture_context *tctx)
{
	enum ndr_err_code ndr_err;
	static const char exp_guid[16] =
		{ 0x1, 0x0, 0x0, 0x0,
		  0x2, 0x0, 0x3, 0x0,
		  0x4, 0x5, 0x6, 0x7,
		  0x8, 0x9, 0xa, 0xb };
	DATA_BLOB exp = data_blob_const(exp_guid, 16);
	char ndr_guid[16] =
		{ 0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0, 0x0 };
	DATA_BLOB b = data_blob_const(ndr_guid, 16);
	struct GUID guid;
	guid.time_low = 1;
	guid.time_mid = 2;
	guid.time_hi_and_version = 3;
	guid.clock_seq[0] = 4;
	guid.clock_seq[1] = 5;
	guid.node[0] = 6;
	guid.node[1] = 7;
	guid.node[2] = 8;
	guid.node[3] = 9;
	guid.node[4] = 10;
	guid.node[5] = 11;
	
	ndr_err = ndr_push_struct_into_fixed_blob(&b, &guid,
						  (ndr_push_flags_fn_t)ndr_push_GUID);
	torture_assert_ndr_err_equal(tctx, ndr_err, NDR_ERR_SUCCESS,
				     "wrong NDR error");
	torture_assert_data_blob_equal(tctx, b, exp,
				       "GUID packed wrongly");

	return true;
}

/* Really a test of ndr_push_struct_into_fixed_blob error handling */
static bool test_guid_into_long_blob(struct torture_context *tctx)
{
	enum ndr_err_code ndr_err;
	char ndr_guid[17] =
		{ 0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0, 0x0, 0x0 };
	DATA_BLOB b = data_blob_const(ndr_guid, 17);
	struct GUID guid;
	guid.time_low = 1;
	guid.time_mid = 2;
	guid.time_hi_and_version = 3;
	guid.clock_seq[0] = 4;
	guid.clock_seq[1] = 5;
	guid.node[0] = 6;
	guid.node[1] = 7;
	guid.node[2] = 8;
	guid.node[3] = 9;
	guid.node[4] = 10;
	guid.node[5] = 11;

	torture_assert(tctx, b.data != NULL, "data_blob_talloc failed");
	ndr_err = ndr_push_struct_into_fixed_blob(
		&b, &guid, (ndr_push_flags_fn_t)ndr_push_GUID);
	torture_assert_ndr_err_equal(tctx, ndr_err, NDR_ERR_BUFSIZE,
				     "wrong NDR error");

	return true;
}

static bool test_guid_into_short_blob(struct torture_context *tctx)
{
	enum ndr_err_code ndr_err;
	char ndr_guid[15] =
		{ 0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0 };
	DATA_BLOB b = data_blob_const(ndr_guid, 15);
	struct GUID guid;
	guid.time_low = 1;
	guid.time_mid = 2;
	guid.time_hi_and_version = 3;
	guid.clock_seq[0] = 4;
	guid.clock_seq[1] = 5;
	guid.node[0] = 6;
	guid.node[1] = 7;
	guid.node[2] = 8;
	guid.node[3] = 9;
	guid.node[4] = 10;
	guid.node[5] = 11;

	ndr_err = ndr_push_struct_into_fixed_blob(
		&b, &guid, (ndr_push_flags_fn_t)ndr_push_GUID);
	torture_assert_ndr_err_equal(tctx, ndr_err, NDR_ERR_BUFSIZE,
				     "wrong NDR error");

	return true;
}

static bool test_compare_uuid(struct torture_context *tctx)
{
	struct GUID g1, g2;
	ZERO_STRUCT(g1); ZERO_STRUCT(g2);
	torture_assert_int_equal(tctx, 0, GUID_compare(&g1, &g2),
				 "GUIDs not equal");
	g1.time_low = 1;
	torture_assert_int_equal(tctx, 1, GUID_compare(&g1, &g2),
				 "GUID diff invalid");

	g1.time_low = 10;
	torture_assert_int_equal(tctx, 1, GUID_compare(&g1, &g2),
				 "GUID diff invalid");

	g1.time_low = 0;
	g1.clock_seq[1] = 20;
	torture_assert_int_equal(tctx, 1, GUID_compare(&g1, &g2),
				 "GUID diff invalid");

	g1.time_low = ~0;
	torture_assert_int_equal(tctx, 1, GUID_compare(&g1, &g2),
				 "GUID diff invalid");

	g1.time_low = 0;
	g2.time_low = ~0;
	torture_assert_int_equal(tctx, -1, GUID_compare(&g1, &g2),
				 "GUID diff invalid");
	return true;
}

struct torture_suite *torture_local_ndr(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "ndr");

	torture_suite_add_suite(suite, ndr_winreg_suite(suite));
	torture_suite_add_suite(suite, ndr_atsvc_suite(suite));
	torture_suite_add_suite(suite, ndr_lsa_suite(suite));
	torture_suite_add_suite(suite, ndr_epmap_suite(suite));
	torture_suite_add_suite(suite, ndr_dfs_suite(suite));
	torture_suite_add_suite(suite, ndr_dfsblob_suite(suite));
	torture_suite_add_suite(suite, ndr_netlogon_suite(suite));
	torture_suite_add_suite(suite, ndr_drsuapi_suite(suite));
	torture_suite_add_suite(suite, ndr_spoolss_suite(suite));
	torture_suite_add_suite(suite, ndr_winspool_suite(suite));
	torture_suite_add_suite(suite, ndr_ntprinting_suite(suite));
	torture_suite_add_suite(suite, ndr_samr_suite(suite));
	torture_suite_add_suite(suite, ndr_drsblobs_suite(suite));
	torture_suite_add_suite(suite, ndr_dnsp_suite(suite));
	torture_suite_add_suite(suite, ndr_nbt_suite(suite));
	torture_suite_add_suite(suite, ndr_ntlmssp_suite(suite));
	torture_suite_add_suite(suite, ndr_backupkey_suite(suite));
	torture_suite_add_suite(suite, ndr_witness_suite(suite));
	torture_suite_add_suite(suite, ndr_clusapi_suite(suite));
	torture_suite_add_suite(suite, ndr_negoex_suite(suite));
	torture_suite_add_suite(suite, ndr_string_suite(suite));
	torture_suite_add_suite(suite, ndr_krb5pac_suite(suite));
	torture_suite_add_suite(suite, ndr_cabinet_suite(suite));
	torture_suite_add_suite(suite, ndr_charset_suite(suite));
	torture_suite_add_suite(suite, ndr_svcctl_suite(suite));

	torture_suite_add_simple_test(suite, "string terminator",
				      test_check_string_terminator);

	torture_suite_add_simple_test(suite, "guid_from_string_null",
				      test_guid_from_string_null);

	torture_suite_add_simple_test(suite, "guid_from_string",
				      test_guid_from_string);

	torture_suite_add_simple_test(suite, "guid_from_string_invalid",
				      test_guid_from_string_invalid);

	torture_suite_add_simple_test(suite, "guid_string_valid",
				      test_guid_string_valid);

	torture_suite_add_simple_test(suite, "guid_string2_valid",
				      test_guid_string2_valid);

	torture_suite_add_simple_test(suite, "guid_from_string_valid",
				      test_guid_from_string_valid);

	torture_suite_add_simple_test(suite, "compare_uuid",
				      test_compare_uuid);

	torture_suite_add_simple_test(suite, "guid_into_blob",
				      test_guid_into_blob);

	torture_suite_add_simple_test(suite, "guid_into_short_blob",
				      test_guid_into_short_blob);

	torture_suite_add_simple_test(suite, "guid_into_long_blob",
				      test_guid_into_long_blob);

	return suite;
}

