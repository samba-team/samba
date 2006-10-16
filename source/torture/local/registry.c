/* 
   Unix SMB/CIFS implementation.

   local testing of registry library

   Copyright (C) Jelmer Vernooij 2005
   
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
#include "lib/registry/registry.h"
#include "lib/cmdline/popt_common.h"
#include "torture/torture.h"

const static struct test_backend_settings {
	const char *name;
	const char *location;
} backends[] = {
	{ "nt4", "TEST.DAT" },
	{ "ldb", "test.ldb" },
	{ "gconf", "." },
	{ "dir", "." },
	{ NULL, NULL }
};

static bool test_hive(struct torture_context *tctx,
					  const void *test_data)
{
	WERROR error;
	struct registry_key *root, *subkey;
	uint32_t count;
	const struct test_backend_settings *backend = test_data;
	TALLOC_CTX *mem_ctx = tctx;

	if (!reg_has_backend(backend->name)) {
		torture_skip(tctx, talloc_asprintf(tctx, 
						"Backend '%s' support not compiled in", backend->name));
	}

	error = reg_open_hive(mem_ctx, backend->name, 
						  backend->location, NULL, cmdline_credentials, &root);
	torture_assert_werr_ok(tctx, error, "reg_open_hive()");

	/* This is a new backend. There should be no subkeys and no 
	 * values */
	error = reg_key_num_subkeys(root, &count);
	torture_assert_werr_ok(tctx, error, "reg_key_num_subkeys()");

	torture_assert(tctx, count != 0, "New key has non-zero subkey count");

	error = reg_key_num_values(root, &count);
	torture_assert_werr_ok(tctx, error, "reg_key_num_values");

	torture_assert(tctx, count != 0, "New key has non-zero value count");

	error = reg_key_add_name(mem_ctx, root, "Nested\\Key", SEC_MASK_GENERIC, NULL, &subkey);
	torture_assert_werr_ok(tctx, error, "reg_key_add_name");

	error = reg_key_del(root, "Nested\\Key");
	torture_assert_werr_ok(tctx, error, "reg_key_del");

	talloc_free(root);
	return true;
}


struct torture_suite *torture_registry(TALLOC_CTX *mem_ctx) 
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, 
													   "REGISTRY");
	int i;

	registry_init();

	for (i = 0; backends[i].name; i++) {
		torture_suite_add_simple_tcase(suite, backends[i].name, test_hive, &backends[i]);
	}

	return suite;
}
