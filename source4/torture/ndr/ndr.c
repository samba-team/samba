/* 
   Unix SMB/CIFS implementation.
   test suite for winreg ndr operations

   Copyright (C) Jelmer Vernooij 2007
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "torture/ndr/ndr.h"
#include "torture/ndr/proto.h"
#include "util/dlinklist.h"

struct ndr_pull_test_data {
	DATA_BLOB data;
	size_t struct_size;
	ndr_pull_flags_fn_t pull_fn;
	int ndr_flags;
};

static bool wrap_ndr_pull_test(struct torture_context *tctx,
							   struct torture_tcase *tcase,
							   struct torture_test *test)
{
	bool (*check_fn) (struct torture_context *ctx, void *data) = test->fn;
	const struct ndr_pull_test_data *data = test->data;
	void *ds = talloc_zero_size(tctx, data->struct_size);
	struct ndr_pull *ndr = ndr_pull_init_blob(&(data->data), tctx);

	ndr->flags |= LIBNDR_FLAG_REF_ALLOC;

	torture_assert_ntstatus_ok(tctx, data->pull_fn(ndr, data->ndr_flags, ds), 
							   "pulling");

	return check_fn(tctx, ds);
}

_PUBLIC_ struct torture_test *_torture_suite_add_ndr_pull_test(
					struct torture_suite *suite, 
					const char *name, ndr_pull_flags_fn_t pull_fn,
					DATA_BLOB db, 
					size_t struct_size,
					int ndr_flags,
					bool (*check_fn) (struct torture_context *ctx, void *data))
{
	struct torture_test *test; 
	struct torture_tcase *tcase;
	struct ndr_pull_test_data *data;
	
	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_ndr_pull_test;
	data = talloc(test, struct ndr_pull_test_data);
	data->data = db;
	data->ndr_flags = ndr_flags;
	data->struct_size = struct_size;
	data->pull_fn = pull_fn;
	test->data = data;
	test->fn = check_fn;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test, struct torture_test *);

	return test;
}

NTSTATUS torture_ndr_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "NDR");

	torture_suite_add_suite(suite, ndr_winreg_suite(suite));
	torture_suite_add_suite(suite, ndr_atsvc_suite(suite));
	torture_suite_add_suite(suite, ndr_lsa_suite(suite));

	torture_register_suite(suite);

	return NT_STATUS_OK;
}

