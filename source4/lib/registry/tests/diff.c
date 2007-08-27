/* 
   Unix SMB/CIFS implementation.

   local testing of registry diff functionality

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
#include "lib/registry/registry.h"
#include "lib/cmdline/popt_common.h"
#include "torture/torture.h"
#include "librpc/gen_ndr/winreg.h"

static bool test_generate_diff(struct torture_context *test)
{
	/* WERROR reg_generate_diff(struct registry_context *ctx1, 
				  struct registry_context *ctx2, 
				  const struct reg_diff_callbacks *callbacks,
				  void *callback_data)
				  */
	return true;
}


static bool test_diff_load(struct torture_context *test)
{
	/* WERROR reg_diff_load(const char *filename, const struct reg_diff_callbacks *callbacks, void *callback_data) */

	return true;
}

static bool test_diff_apply(struct torture_context *test)
{
	/* _PUBLIC_ WERROR reg_diff_apply (const char *filename, struct registry_context *ctx) */

	return true;
}

static const char *added_key = NULL;

static WERROR test_add_key (void *callback_data, const char *key_name)
{
	added_key = talloc_strdup(callback_data, key_name);

	return WERR_OK;
}

static bool test_generate_diff_key_add(struct torture_context *test)
{
	struct reg_diff_callbacks cb;
	struct registry_key rk;

	return true;

	ZERO_STRUCT(cb);

	cb.add_key = test_add_key;

	if (W_ERROR_IS_OK(reg_generate_diff_key(&rk, NULL, "bla", &cb, test)))
		return false;

	torture_assert_str_equal(test, added_key, "bla", "key added");

	return true;
}

static bool test_generate_diff_key_null(struct torture_context *test)
{
	struct reg_diff_callbacks cb;

	ZERO_STRUCT(cb);

	if (!W_ERROR_IS_OK(reg_generate_diff_key(NULL, NULL, "", &cb, NULL)))
		return false;

	return true;
}

struct torture_suite *torture_registry_diff(TALLOC_CTX *mem_ctx) 
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, 
													   "DIFF");
	torture_suite_add_simple_test(suite, "test_generate_diff_key_add", test_generate_diff_key_add);
	torture_suite_add_simple_test(suite, "test_generate_diff_key_null", test_generate_diff_key_null);
	torture_suite_add_simple_test(suite, "test_diff_apply", test_diff_apply);
	torture_suite_add_simple_test(suite, "test_generate_diff", test_generate_diff);
	torture_suite_add_simple_test(suite, "test_diff_load", test_diff_load);
	return suite;
}
