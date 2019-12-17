/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Jelmer Vernooij 2006

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
#include "libcli/smb2/smb2.h"

#include "torture/smbtorture.h"
#include "torture/smb2/proto.h"
#include "../lib/util/dlinklist.h"

static bool wrap_simple_1smb2_test(struct torture_context *torture_ctx,
				   struct torture_tcase *tcase,
				   struct torture_test *test)
{
	bool (*fn) (struct torture_context *, struct smb2_tree *);
	bool ret;
	struct smb2_tree *tree1;
	TALLOC_CTX *mem_ctx = talloc_new(torture_ctx);

	if (!torture_smb2_connection(torture_ctx, &tree1)) {
		torture_fail(torture_ctx,
			    "Establishing SMB2 connection failed\n");
		return false;
	}

	/*
	 * This is a trick:
	 * The test might close the connection. If we steal the tree context
	 * before that and free the parent instead of tree directly, we avoid
	 * a double free error.
	 */
	talloc_steal(mem_ctx, tree1);

	fn = test->fn;

	ret = fn(torture_ctx, tree1);

	talloc_free(mem_ctx);

	return ret;
}

struct torture_test *torture_suite_add_1smb2_test(struct torture_suite *suite,
						  const char *name,
						  bool (*run)(struct torture_context *,
							      struct smb2_tree *))
{
	struct torture_test *test;
	struct torture_tcase *tcase;

	tcase = torture_suite_add_tcase(suite, name);

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_simple_1smb2_test;
	test->fn = run;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test);

	return test;
}


static bool wrap_simple_2smb2_test(struct torture_context *torture_ctx,
				   struct torture_tcase *tcase,
				   struct torture_test *test)
{
	bool (*fn) (struct torture_context *, struct smb2_tree *, struct smb2_tree *);
	bool ret = false;

	struct smb2_tree *tree1;
	struct smb2_tree *tree2;
	TALLOC_CTX *mem_ctx = talloc_new(torture_ctx);

	if (!torture_smb2_connection(torture_ctx, &tree1)) {
		torture_fail(torture_ctx,
		    "Establishing SMB2 connection failed\n");
		goto done;
	}

	talloc_steal(mem_ctx, tree1);

	if (!torture_smb2_connection(torture_ctx, &tree2)) {
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


struct torture_test *torture_suite_add_2smb2_test(struct torture_suite *suite,
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
	test->run = wrap_simple_2smb2_test;
	test->fn = run;
	test->dangerous = false;

	DLIST_ADD_END(tcase->tests, test);

	return test;
}

NTSTATUS torture_smb2_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "smb2");
	torture_suite_add_simple_test(suite, "connect", torture_smb2_connect);
	torture_suite_add_suite(suite, torture_smb2_scan_init(suite));
	torture_suite_add_suite(suite, torture_smb2_getinfo_init(suite));
	torture_suite_add_simple_test(suite, "setinfo", torture_smb2_setinfo);
	torture_suite_add_suite(suite, torture_smb2_lock_init(suite));
	torture_suite_add_suite(suite, torture_smb2_read_init(suite));
	torture_suite_add_suite(suite, torture_smb2_aio_delay_init(suite));
	torture_suite_add_suite(suite, torture_smb2_create_init(suite));
	torture_suite_add_suite(suite, torture_smb2_twrp_init(suite));
	torture_suite_add_suite(suite, torture_smb2_fileid_init(suite));
	torture_suite_add_suite(suite, torture_smb2_acls_init(suite));
	torture_suite_add_suite(suite, torture_smb2_notify_init(suite));
	torture_suite_add_suite(suite, torture_smb2_notify_inotify_init(suite));
	torture_suite_add_suite(suite,
		torture_smb2_notify_disabled_init(suite));
	torture_suite_add_suite(suite, torture_smb2_durable_open_init(suite));
	torture_suite_add_suite(suite,
		torture_smb2_durable_open_disconnect_init(suite));
	torture_suite_add_suite(suite,
		torture_smb2_durable_v2_open_init(suite));
	torture_suite_add_suite(suite,
		torture_smb2_durable_v2_delay_init(suite));
	torture_suite_add_suite(suite, torture_smb2_dir_init(suite));
	torture_suite_add_suite(suite, torture_smb2_lease_init(suite));
	torture_suite_add_suite(suite, torture_smb2_compound_init(suite));
	torture_suite_add_suite(suite, torture_smb2_compound_find_init(suite));
	torture_suite_add_suite(suite, torture_smb2_oplocks_init(suite));
	torture_suite_add_suite(suite, torture_smb2_kernel_oplocks_init(suite));
	torture_suite_add_suite(suite, torture_smb2_streams_init(suite));
	torture_suite_add_suite(suite, torture_smb2_ioctl_init(suite));
	torture_suite_add_simple_test(suite, "set-sparse-ioctl",
				      test_ioctl_set_sparse);
	torture_suite_add_simple_test(suite, "zero-data-ioctl",
				      test_ioctl_zero_data);
	torture_suite_add_suite(suite, torture_smb2_rename_init(suite));
	torture_suite_add_1smb2_test(suite, "bench-oplock", test_smb2_bench_oplock);
	torture_suite_add_suite(suite, torture_smb2_sharemode_init(suite));
	torture_suite_add_1smb2_test(suite, "hold-oplock", test_smb2_hold_oplock);
	torture_suite_add_suite(suite, torture_smb2_session_init(suite));
	torture_suite_add_suite(suite, torture_smb2_replay_init(suite));
	torture_suite_add_simple_test(suite, "dosmode", torture_smb2_dosmode);
	torture_suite_add_simple_test(suite, "maxfid", torture_smb2_maxfid);
	torture_suite_add_simple_test(suite, "hold-sharemode",
				      torture_smb2_hold_sharemode);
	torture_suite_add_simple_test(suite, "check-sharemode",
				      torture_smb2_check_sharemode);
	torture_suite_add_suite(suite, torture_smb2_crediting_init(suite));

	torture_suite_add_suite(suite, torture_smb2_doc_init(suite));
	torture_suite_add_suite(suite, torture_smb2_multichannel_init(suite));
	torture_suite_add_suite(suite, torture_smb2_samba3misc_init(suite));
	torture_suite_add_suite(suite, torture_smb2_timestamps_init(suite));
	torture_suite_add_suite(suite, torture_smb2_timestamp_resolution_init(suite));
	torture_suite_add_1smb2_test(suite, "openattr", torture_smb2_openattrtest);
	torture_suite_add_1smb2_test(suite, "winattr", torture_smb2_winattrtest);
	torture_suite_add_1smb2_test(suite, "sdread", torture_smb2_sdreadtest);
	torture_suite_add_suite(suite, torture_smb2_readwrite_init(suite));
	torture_suite_add_1smb2_test(suite, "maximum_allowed", torture_smb2_maximum_allowed);
	torture_suite_add_1smb2_test(suite, "mangle", torture_smb2_mangle);
	torture_suite_add_1smb2_test(suite, "tcon", run_tcon_test);
	torture_suite_add_1smb2_test(suite, "mkdir", torture_smb2_mkdir);

	torture_suite_add_suite(suite, torture_smb2_charset(suite));
	torture_suite_add_1smb2_test(suite, "secleak", torture_smb2_sec_leak);
	torture_suite_add_1smb2_test(suite, "session-id", run_sessidtest);
	torture_suite_add_suite(suite, torture_smb2_deny_init(suite));

	suite->description = talloc_strdup(suite, "SMB2-specific tests");

	torture_register_suite(ctx, suite);

	return NT_STATUS_OK;
}
