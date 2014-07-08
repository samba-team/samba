/*
   Unix SMB/CIFS implementation.

   Copyright (C) Ralph Boehme 2014

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
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "../lib/util/dlinklist.h"

#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"

#include "torture/util.h"
#include "torture/smbtorture.h"
#include "torture/vfs/proto.h"
#include "torture/smb2/proto.h"

static bool wrap_2ns_smb2_test(struct torture_context *torture_ctx,
			       struct torture_tcase *tcase,
			       struct torture_test *test)
{
	bool (*fn) (struct torture_context *, struct smb2_tree *, struct smb2_tree *);
	bool ret = false;

	struct smb2_tree *tree1;
	struct smb2_tree *tree2;
	TALLOC_CTX *mem_ctx = talloc_new(torture_ctx);

	if (!torture_smb2_con_sopt(torture_ctx, "share1", &tree1)) {
		torture_fail(torture_ctx,
		    "Establishing SMB2 connection failed\n");
		goto done;
	}

	talloc_steal(mem_ctx, tree1);

	if (!torture_smb2_con_sopt(torture_ctx, "share2", &tree2)) {
		torture_fail(torture_ctx,
		    "Establishing SMB2 connection failed\n");
		goto done;
	}

	talloc_steal(mem_ctx, tree2);

	fn = test->fn;

	ret = fn(torture_ctx, tree1, tree2);

done:
	/* the test may already have closed some of the connections */
	talloc_free(mem_ctx);

	return ret;
}

/*
 * Run a test with 2 connected trees, Share names to connect are taken
 * from option strings "torture:share1" and "torture:share2"
 */
struct torture_test *torture_suite_add_2ns_smb2_test(struct torture_suite *suite,
						     const char *name,
						     bool (*run)(struct torture_context *,
								 struct smb2_tree *,
								 struct smb2_tree *))
{
	struct torture_test *test;
	struct torture_tcase *tcase;

	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_2ns_smb2_test;
	test->fn = run;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test, struct torture_test *);

	return test;
}

NTSTATUS torture_vfs_init(void)
{
	struct torture_suite *suite = torture_suite_create(
		talloc_autofree_context(), "vfs");

	suite->description = talloc_strdup(suite, "VFS modules tests");

	torture_suite_add_suite(suite, torture_vfs_fruit());

	torture_register_suite(suite);

	return NT_STATUS_OK;
}
