/*
   Unix SMB/CIFS implementation.

   test timestamps

   Copyright (C) Ralph Boehme 2019

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
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"

#define BASEDIR "smb2-timestamps"

static bool test_time_t(struct torture_context *tctx,
			struct smb2_tree *tree,
			const char *fname,
			time_t t)
{
	char *filename = NULL;
	struct smb2_create cr;
	struct smb2_handle handle = {{0}};
	struct smb2_handle testdirh = {{0}};
	struct timespec ts = { .tv_sec = t };
	uint64_t nttime;
	union smb_fileinfo gi;
	union smb_setfileinfo si;
	struct smb2_find find;
	unsigned int count;
	union smb_search_data *d;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");

	filename = talloc_asprintf(tctx, "%s\\%s", BASEDIR, fname);
	torture_assert_not_null_goto(tctx, filename, ret, done,
				     "talloc_asprintf failed\n");

	cr = (struct smb2_create) {
		.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = filename,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	si = (union smb_setfileinfo) {
		.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION,
		.basic_info.in.file.handle = handle,
	};

	nttime = full_timespec_to_nt_time(&ts);
	si.basic_info.in.create_time = nttime;
	si.basic_info.in.write_time = nttime;
	si.basic_info.in.change_time = nttime;

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	gi = (union smb_fileinfo) {
		.generic.level = SMB_QFILEINFO_BASIC_INFORMATION,
		.generic.in.file.handle = handle,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");

	torture_comment(tctx, "Got: create: %s, write: %s, change: %s\n",
			nt_time_string(tctx, gi.basic_info.out.create_time),
			nt_time_string(tctx, gi.basic_info.out.write_time),
			nt_time_string(tctx, gi.basic_info.out.change_time));

	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      gi.basic_info.out.create_time,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      gi.basic_info.out.write_time,
				      ret, done,
				      "Wrong write time\n");
	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      gi.basic_info.out.change_time,
				      ret, done,
				      "Wrong change time\n");

	find = (struct smb2_find) {
		.in.file.handle = testdirh,
		.in.pattern = fname,
		.in.max_response_size = 0x1000,
		.in.level = SMB2_FIND_ID_BOTH_DIRECTORY_INFO,
	};

	status = smb2_find_level(tree, tree, &find, &count, &d);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_find_level failed\n");

	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      d[0].id_both_directory_info.create_time,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      d[0].id_both_directory_info.write_time,
				      ret, done,
				      "Wrong write time\n");
	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      d[0].id_both_directory_info.change_time,
				      ret, done,
				      "Wrong change time\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

	cr = (struct smb2_create) {
		.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS,
		.in.fname = filename,
	};

	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle = cr.out.file.handle;

	gi = (union smb_fileinfo) {
		.generic.level = SMB_QFILEINFO_BASIC_INFORMATION,
		.generic.in.file.handle = handle,
	};

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");

	torture_comment(tctx, "Got: create: %s, write: %s, change: %s\n",
			nt_time_string(tctx, gi.basic_info.out.create_time),
			nt_time_string(tctx, gi.basic_info.out.write_time),
			nt_time_string(tctx, gi.basic_info.out.change_time));

	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      gi.basic_info.out.create_time,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      gi.basic_info.out.write_time,
				      ret, done,
				      "Wrong write time\n");
	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      gi.basic_info.out.change_time,
				      ret, done,
				      "Wrong change time\n");

	find = (struct smb2_find) {
		.in.continue_flags = SMB2_CONTINUE_FLAG_RESTART,
		.in.file.handle = testdirh,
		.in.pattern = fname,
		.in.max_response_size = 0x1000,
		.in.level = SMB2_FIND_ID_BOTH_DIRECTORY_INFO,
	};

	status = smb2_find_level(tree, tree, &find, &count, &d);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_find_level failed\n");

	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      d[0].id_both_directory_info.create_time,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      d[0].id_both_directory_info.write_time,
				      ret, done,
				      "Wrong write time\n");
	torture_assert_u64_equal_goto(tctx,
				      nttime,
				      d[0].id_both_directory_info.change_time,
				      ret, done,
				      "Wrong change time\n");

	status = smb2_util_close(tree, handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(handle);

done:
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, handle);
	}
	if (!smb2_util_handle_empty(testdirh)) {
		smb2_util_close(tree, testdirh);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

static bool test_time_t_100000000000(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	return test_time_t(tctx, tree, "test_time_t_100000000000.txt",
			   100000000000 /* >> INT32_MAX */);
}

static bool test_time_t_10000000000(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	return test_time_t(tctx, tree, "test_time_t_10000000000.txt",
			   10000000000 /* >> INT32_MAX */);
}

static bool test_time_t_4294967295(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	return test_time_t(tctx, tree, "test_time_t_4294967295.txt",
			   4294967295 /* INT32_MAX */);
}

static bool test_time_t_1(struct torture_context *tctx,
			  struct smb2_tree *tree)
{
	return test_time_t(tctx, tree, "test_time_t_1.txt", 1);
}

static bool test_time_t_0(struct torture_context *tctx,
			  struct smb2_tree *tree)
{
	return test_time_t(tctx, tree, "test_time_t_0.txt", 0);
}

static bool test_time_t_minus_1(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	return test_time_t(tctx, tree, "test_time_t_-1.txt", -1);
}

static bool test_time_t_minus_2(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	return test_time_t(tctx, tree, "test_time_t_-2.txt", -2);
}

static bool test_time_t_1968(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	return test_time_t(tctx, tree, "test_time_t_1968.txt",
			   -63158400 /* 1968 */);
}

/*
   basic testing of SMB2 timestamps
*/
struct torture_suite *torture_smb2_timestamps_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "timestamps");

	torture_suite_add_1smb2_test(suite, "time_t_100000000000", test_time_t_100000000000);
	torture_suite_add_1smb2_test(suite, "time_t_10000000000", test_time_t_10000000000);
	torture_suite_add_1smb2_test(suite, "time_t_4294967295", test_time_t_4294967295);
	torture_suite_add_1smb2_test(suite, "time_t_1", test_time_t_1);
	torture_suite_add_1smb2_test(suite, "time_t_0", test_time_t_0);
	torture_suite_add_1smb2_test(suite, "time_t_-1", test_time_t_minus_1);
	torture_suite_add_1smb2_test(suite, "time_t_-2", test_time_t_minus_2);
	torture_suite_add_1smb2_test(suite, "time_t_1968", test_time_t_1968);

	suite->description = talloc_strdup(suite, "SMB2 timestamp tests");

	return suite;
}
