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
#include "torture/ui.h"

static bool test_hive(struct torture_context *parent_ctx, const char *backend, const char *location)
{
	WERROR error;
	struct registry_key *root, *subkey;
	uint32_t count;
	struct torture_test *ctx = torture_test(parent_ctx, "test_hive", backend);
	
	if (!reg_has_backend(backend)) {
		torture_skip(ctx, "Backend '%s' support not compiled in", backend);
		return True;
	}

	error = reg_open_hive(ctx, backend, location, NULL, cmdline_credentials, &root);
	torture_assert_werr_ok(ctx, error, "reg_open_hive()");

	/* This is a new backend. There should be no subkeys and no 
	 * values */
	error = reg_key_num_subkeys(root, &count);
	torture_assert_werr_ok(ctx, error, "reg_key_num_subkeys()");

	torture_assert(ctx, count != 0, "New key has non-zero subkey count");

	error = reg_key_num_values(root, &count);
	torture_assert_werr_ok(ctx, error, "reg_key_num_values");

	torture_assert(ctx, count != 0, "New key has non-zero value count");

	error = reg_key_add_name(ctx, root, "Nested\\Key", SEC_MASK_GENERIC, NULL, &subkey);
	torture_assert_werr_ok(ctx, error, "reg_key_add_name");

	error = reg_key_del(root, "Nested\\Key");
	torture_assert_werr_ok(ctx, error, "reg_key_del");

	talloc_free(root);

	torture_ok(ctx);

	return True;
}

BOOL torture_registry(struct torture_context *torture) 
{
	BOOL ret = True;

	registry_init();

	ret &= test_hive(torture, "nt4", "TEST.DAT");
	ret &= test_hive(torture, "ldb", "test.ldb");
	ret &= test_hive(torture, "gconf", ".");
	ret &= test_hive(torture, "dir", ".");

	return ret;
}
