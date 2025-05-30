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
#define FNAME "testfile.dat"

static bool test_close_no_attrib(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	const char *filename = BASEDIR "/" FNAME;
	struct smb2_create cr;
	struct smb2_handle handle = {{0}};
	struct smb2_handle testdirh = {{0}};
	struct smb2_close c;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree, testdirh);

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

	c = (struct smb2_close) {
		.in.file.handle = handle,
	};

	status = smb2_close(tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(handle);

	torture_assert_u64_equal_goto(tctx, c.out.create_time, NTTIME_OMIT,
				      ret, done, "Unexpected create time\n");
	torture_assert_u64_equal_goto(tctx, c.out.access_time, NTTIME_OMIT,
				      ret, done, "Unexpected access time\n");
	torture_assert_u64_equal_goto(tctx, c.out.write_time, NTTIME_OMIT,
				      ret, done, "Unexpected write time\n");
	torture_assert_u64_equal_goto(tctx, c.out.size, 0,
				      ret, done, "Unexpected size\n");
	torture_assert_u64_equal_goto(tctx, c.out.file_attr, 0,
				      ret, done, "Unexpected attributes\n");

done:
	if (!smb2_util_handle_empty(handle)) {
		smb2_util_close(tree, handle);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

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
				      gi.basic_info.out.create_time,
				      nttime,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      gi.basic_info.out.write_time,
				      nttime,
				      ret, done,
				      "Wrong write time\n");

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
				      d[0].id_both_directory_info.create_time,
				      nttime,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      d[0].id_both_directory_info.write_time,
				      nttime,
				      ret, done,
				      "Wrong write time\n");

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
				      gi.basic_info.out.create_time,
				      nttime,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      gi.basic_info.out.write_time,
				      nttime,
				      ret, done,
				      "Wrong write time\n");

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
				      d[0].id_both_directory_info.create_time,
				      nttime,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      d[0].id_both_directory_info.write_time,
				      nttime,
				      ret, done,
				      "Wrong write time\n");

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

static bool test_time_t_15032385535(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	return test_time_t(tctx, tree, "test_time_t_15032385535.txt",
			   15032385535 /* >> INT32_MAX, limit on ext */);
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

static bool test_freeze_thaw(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	const char *filename = BASEDIR "\\test_freeze_thaw";
	struct smb2_create cr;
	struct smb2_handle handle = {{0}};
	struct smb2_handle testdirh = {{0}};
	struct timespec ts = { .tv_sec = time(NULL) };
	uint64_t nttime;
	union smb_fileinfo gi;
	union smb_setfileinfo si;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);

	status = torture_smb2_testdir(tree, BASEDIR, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");

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

	/*
	 * Step 1:
	 * First set timestamps of testfile to current time
	 */

	nttime = full_timespec_to_nt_time(&ts);
	si.basic_info.in.create_time = nttime;
	si.basic_info.in.write_time = nttime;

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	gi = (union smb_fileinfo) {
		.generic.level = SMB_QFILEINFO_BASIC_INFORMATION,
		.generic.in.file.handle = handle,
	};

	/*
	 * Step 2:
	 * Verify timestamps are indeed set to the value in "nttime".
	 */

	status = smb2_getinfo_file(tree, tctx, &gi);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");

	torture_comment(tctx, "Got: create: %s, write: %s, change: %s\n",
			nt_time_string(tctx, gi.basic_info.out.create_time),
			nt_time_string(tctx, gi.basic_info.out.write_time),
			nt_time_string(tctx, gi.basic_info.out.change_time));

	torture_assert_u64_equal_goto(tctx,
				      gi.basic_info.out.create_time,
				      nttime,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      gi.basic_info.out.write_time,
				      nttime,
				      ret, done,
				      "Wrong write time\n");

	/*
	 * Step 3:
	 * First set timestamps with NTTIME_FREEZE, must not change any
	 * timestamp value.
	 */

	si.basic_info.in.create_time = NTTIME_FREEZE;
	si.basic_info.in.write_time = NTTIME_FREEZE;

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	gi = (union smb_fileinfo) {
		.generic.level = SMB_QFILEINFO_BASIC_INFORMATION,
		.generic.in.file.handle = handle,
	};

	/*
	 * Step 4:
	 * Verify timestamps are unmodified from step 2.
	 */

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
				      gi.basic_info.out.create_time,
				      nttime,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      gi.basic_info.out.write_time,
				      nttime,
				      ret, done,
				      "Wrong write time\n");

	/*
	 * Step 5:
	 * First set timestamps with NTTIME_THAW, must not change any timestamp
	 * value.
	 */

	si.basic_info.in.create_time = NTTIME_THAW;
	si.basic_info.in.write_time = NTTIME_THAW;

	status = smb2_setinfo_file(tree, &si);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	gi = (union smb_fileinfo) {
		.generic.level = SMB_QFILEINFO_BASIC_INFORMATION,
		.generic.in.file.handle = handle,
	};

	/*
	 * Step 6:
	 * Verify timestamps are unmodified from step 2.
	 */

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
				      gi.basic_info.out.create_time,
				      nttime,
				      ret, done,
				      "Wrong create time\n");
	torture_assert_u64_equal_goto(tctx,
				      gi.basic_info.out.write_time,
				      nttime,
				      ret, done,
				      "Wrong write time\n");

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

static bool test_delayed_write_vs_seteof(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	struct smb2_create cr;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	NTTIME create_time;
	NTTIME set_time;
	NTTIME latest_time;
	union smb_fileinfo finfo;
	union smb_setfileinfo setinfo;
	struct smb2_close c;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	torture_comment(tctx, "Open file-handle 1\n");

	cr = (struct smb2_create) {
		.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.share_access       = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname              = BASEDIR "\\" FNAME,
	};
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h1 = cr.out.file.handle;
	create_time = cr.out.create_time;
	sleep(1);

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	torture_comment(tctx, "Setinfo EOF on file-handle 1,"
			" should update writetime\n");

	setinfo = (union smb_setfileinfo) {
		.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION,
	};
	setinfo.end_of_file_info.in.file.handle = h1;
	setinfo.end_of_file_info.in.size = 0; /* same size! */

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	torture_comment(tctx, "Check writetime has been updated "
			"by the setinfo EOF\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");
	if (!(finfo.all_info.out.write_time > create_time)) {
		ret = false;
		torture_fail_goto(tctx, done, "setinfo EOF hasn't updated writetime\n");
	}

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	torture_comment(tctx, "Write to file-handle 1\n");

	status = smb2_util_write(tree, h1, "s", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	torture_comment(tctx, "Check writetime has been updated\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	torture_assert_nttime_not_equal(tctx,
					finfo.all_info.out.write_time,
					create_time,
					"Writetime not updated\n");
	latest_time = finfo.all_info.out.write_time;

	torture_comment(tctx, "Setinfo EOF on file-handle 1,"
			" should update writetime\n");

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	setinfo = (union smb_setfileinfo) {
		.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION,
	};
	setinfo.end_of_file_info.in.file.handle = h1;
	setinfo.end_of_file_info.in.size = 1; /* same size! */

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	torture_comment(tctx, "Check writetime has been updated "
			"by the setinfo EOF\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");
	if (!(finfo.all_info.out.write_time > latest_time)) {
		ret = false;
		torture_fail_goto(tctx, done, "setinfo EOF hasn't updated writetime\n");
	}

	torture_comment(tctx, "Open file-handle 2\n");

	cr = (struct smb2_create) {
		.in.desired_access     = SEC_FILE_WRITE_ATTRIBUTE,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.share_access       = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname              = BASEDIR "\\" FNAME,
	};
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h2 = cr.out.file.handle;

	torture_comment(tctx, "Set write time on file-handle 2\n");

	setinfo = (union smb_setfileinfo) {
		.generic.level = SMB_QFILEINFO_BASIC_INFORMATION,
	};
	setinfo.generic.in.file.handle = h2;
	unix_to_nt_time(&set_time, time(NULL) + 86400);
	setinfo.basic_info.in.write_time = set_time;

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	status = smb2_util_close(tree, h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(h2);

	torture_comment(tctx, "Close file-handle 1, write-time should not be updated\n");

	c = (struct smb2_close) {
		.in.file.handle = h1,
		.in.flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION,
	};

	status = smb2_close(tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(h1);

	torture_assert_nttime_equal(tctx,
				    c.out.write_time,
				    set_time,
				    "Writetime != set_time (wrong!)\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

static bool test_delayed_write_vs_flush(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	struct smb2_create cr;
	struct smb2_handle h1 = {{0}};
	union smb_fileinfo finfo;
	struct smb2_flush f;
	struct smb2_close c;
	NTTIME create_time;
	NTTIME write_time;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	torture_comment(tctx, "Open file-handle 1\n");

	cr = (struct smb2_create) {
		.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.share_access       = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname              = BASEDIR "\\" FNAME,
	};
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h1 = cr.out.file.handle;
	create_time = cr.out.create_time;
	sleep(1);

	torture_comment(tctx, "Write to file-handle 1\n");

	status = smb2_util_write(tree, h1, "s", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	torture_comment(tctx, "Check writetime has been updated\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	torture_assert_nttime_not_equal(tctx,
					finfo.all_info.out.write_time,
					create_time,
					"Writetime not updated\n");
	write_time = finfo.all_info.out.write_time;

	torture_comment(tctx, "Flush file, "
			"there should be no pending writetime update\n");

	f = (struct smb2_flush) {
		.in.file.handle = h1,
	};

	status = smb2_flush(tree, &f);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"flush failed\n");

	torture_comment(tctx, "Check writetime has not been updated "
			"by the flush\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	torture_assert_nttime_equal(tctx,
				    finfo.all_info.out.write_time,
				    write_time,
				    "Writetime updated\n");

	torture_comment(tctx, "Close file-handle 1, write-time should not be updated\n");

	c = (struct smb2_close) {
		.in.file.handle = h1,
		.in.flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION,
	};

	status = smb2_close(tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(h1);

	torture_assert_nttime_equal(tctx,
				    c.out.write_time,
				    write_time,
				    "writetime updated\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

static bool test_delayed_write_vs_setbasic_do(struct torture_context *tctx,
					      struct smb2_tree *tree,
					      union smb_setfileinfo *setinfo)
{
	char *path = NULL;
	struct smb2_create cr;
	struct smb2_handle h1 = {{0}};
	NTTIME create_time;
	NTTIME write_time;
	union smb_fileinfo finfo;
	NTSTATUS status;
	bool ret = true;

	torture_comment(tctx, "Create testfile\n");

	path = talloc_asprintf(tree, BASEDIR "\\" FNAME ".%" PRIu32,
			       generate_random());
	torture_assert_not_null_goto(tctx, path, ret, done, "OOM\n");

	cr = (struct smb2_create) {
		.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED,
		.in.create_disposition = NTCREATEX_DISP_CREATE,
		.in.share_access       = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname              = path,
	};
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h1 = cr.out.file.handle;
	create_time = cr.out.create_time;

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	torture_comment(tctx, "Write to file\n");

	status = smb2_util_write(tree, h1, "s", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	torture_comment(tctx, "Get timestamps\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	write_time = finfo.all_info.out.write_time;
	torture_assert_nttime_not_equal_goto(tctx,
					     write_time,
					     create_time,
					     ret, done,
					     "Writetime == create_time (wrong!)\n");
	torture_comment(tctx, "Set timestamps\n");

	setinfo->basic_info.in.file.handle = h1;
	status = smb2_setinfo_file(tree, setinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	torture_comment(tctx, "Check timestamps\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	torture_assert_nttime_equal_goto(tctx,
					 finfo.all_info.out.write_time,
					 write_time,
					 ret, done,
					 "Writetime changed\n");

	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(h1);

	status = smb2_util_unlink(tree, path);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

done:
	TALLOC_FREE(path);
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	return ret;
}

static bool test_delayed_write_vs_setbasic(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	struct smb2_handle h1 = {{0}};
	union smb_setfileinfo setinfo;
	time_t t = time(NULL) - 86400;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	/*
	 * As there are no delayed updated with modern write behaviour,
	 * setting atime/ctime/btime doesn't trigger anything.
	 */
	torture_comment(tctx, "Test: setting all-0 timestamps\n");

	setinfo = (union smb_setfileinfo) {
		.generic.level = RAW_SFILEINFO_BASIC_INFORMATION,
	};
	ret = test_delayed_write_vs_setbasic_do(tctx, tree, &setinfo);
	torture_assert_goto(tctx, ret, ret, done, "failed");

	torture_comment(tctx, "Test: setting create_time flushes?\n");
	unix_to_nt_time(&setinfo.basic_info.in.create_time, t);
	ret = test_delayed_write_vs_setbasic_do(tctx, tree, &setinfo);
	torture_assert_goto(tctx, ret, ret, done, "failed");

	torture_comment(tctx, "Test: setting access_time flushes?\n");
	setinfo.basic_info.in.create_time = 0;
	unix_to_nt_time(&setinfo.basic_info.in.access_time, t);
	ret = test_delayed_write_vs_setbasic_do(tctx, tree, &setinfo);
	torture_assert_goto(tctx, ret, ret, done, "failed");

	torture_comment(tctx, "Test: setting change_time flushes?\n");
	setinfo.basic_info.in.access_time = 0;
	unix_to_nt_time(&setinfo.basic_info.in.change_time, t);
	ret = test_delayed_write_vs_setbasic_do(tctx, tree, &setinfo);
	torture_assert_goto(tctx, ret, ret, done, "failed");

done:
	smb2_deltree(tree, BASEDIR);
	return ret;
}

static bool test_delayed_1write(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	struct smb2_create cr;
	struct smb2_handle h1 = {{0}};
	union smb_fileinfo finfo;
	struct smb2_close c;
	NTTIME create_time;
	NTTIME write_time;
	NTTIME close_time;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	torture_comment(tctx, "Open file-handle 1\n");

	cr = (struct smb2_create) {
		.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.share_access       = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname              = BASEDIR "\\" FNAME,
	};
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h1 = cr.out.file.handle;
	create_time = cr.out.create_time;
	sleep(1);

	torture_comment(tctx, "Write to file-handle 1\n");

	status = smb2_util_write(tree, h1, "s", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");
	sleep(3);

	torture_comment(tctx, "Check writetime has been updated\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");
	write_time = finfo.all_info.out.write_time;

	if (!(write_time > create_time)) {
		ret = false;
		torture_fail_goto(tctx, done,
				  "Write-time not updated (wrong!)\n");
	}

	torture_comment(tctx, "Close file-handle 1\n");
	sleep(1);

	c = (struct smb2_close) {
		.in.file.handle = h1,
		.in.flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION,
	};

	status = smb2_close(tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(h1);
	close_time = c.out.write_time;

	torture_assert_nttime_equal(tctx, close_time, write_time,
				    "Writetime != close_time (wrong!)\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

static bool test_delayed_2write(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	struct smb2_create cr;
	struct smb2_handle h1 = {{0}};
	union smb_fileinfo finfo;
	struct smb2_close c;
	NTTIME create_time;
	NTTIME write_time;
	NTTIME write_time2;
	NTTIME close_time;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	status = smb2_util_close(tree, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	torture_comment(tctx, "Open file\n");

	cr = (struct smb2_create) {
		.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.share_access       = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname              = BASEDIR "\\" FNAME,
	};
	status = smb2_create(tree, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h1 = cr.out.file.handle;
	create_time = cr.out.create_time;
	sleep(1);

	torture_comment(tctx, "Write to file\n");

	status = smb2_util_write(tree, h1, "s", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");
	sleep(3);

	torture_comment(tctx, "Check writetime has been updated\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");
	write_time = finfo.all_info.out.write_time;

	if (!(write_time > create_time)) {
		ret = false;
		torture_fail_goto(tctx, done,
				  "Write-time not updated (wrong!)\n");
	}

	torture_comment(tctx, "Write a second time\n");

	status = smb2_util_write(tree, h1, "s", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");
	sleep(3);

	torture_comment(tctx, "Check writetime has also been updated\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");
	write_time2 = finfo.all_info.out.write_time;

	torture_assert_nttime_not_equal(tctx, write_time2, write_time,
					"second write updated write-time (wrong!)\n");

	torture_comment(tctx, "Close file-handle 1\n");
	sleep(2);

	torture_comment(tctx, "Check writetime has not been updated\n");

	c = (struct smb2_close) {
		.in.file.handle = h1,
		.in.flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION,
	};

	status = smb2_close(tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(h1);
	close_time = c.out.write_time;

	if (close_time != write_time2) {
		ret = false;
		torture_fail_goto(tctx, done,
				  "Write-time updated (wrong!)\n");
	}

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

static bool getinfo_both(struct torture_context *tctx,
			 struct smb2_tree *tree,
			 struct smb2_handle *h1,
			 const char *p,
			 NTTIME *mtime,
			 NTTIME *ctime)
{
	union smb_fileinfo finfo;
	union smb_fileinfo pinfo;
	struct smb2_create cr;
	struct smb2_handle h2 = {0};
	NTSTATUS status;
	bool ret = true;

	if (h1 != NULL) {
		finfo = (union smb_fileinfo) {
			.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
			.generic.in.file.handle = *h1,
		};
		status = smb2_getinfo_file(tree, tree, &finfo);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"getinfo failed\n");
	}

	cr = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_ATTRIBUTE,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = p,
	};
	status = smb2_create(tree, tree, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h2 = cr.out.file.handle;

	pinfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h2,
	};
	status = smb2_getinfo_file(tree, tree, &pinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"getinfo failed\n");

	status = smb2_util_close(tree, h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"close failed\n");
	ZERO_STRUCT(h2);

	if (h1 != NULL) {
		torture_assert_nttime_equal_goto(tctx,
						 finfo.all_info.out.write_time,
						 pinfo.all_info.out.write_time,
						 ret, done,
						 "times don't match");
	}

	*mtime = pinfo.all_info.out.write_time;
	if (ctime != NULL) {
		*ctime = pinfo.all_info.out.change_time;
	}

done:
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	return ret;
}

/*
 * | Time | Handle 1               | Handle 2               |
 * |------+------------------------+------------------------|
 * |    1 | Create file            | Open file              |
 * |      | Check Handle Time = 1  | Check Handle Time = 1  |
 * |      | Check Path Time = 1    | Check Path Time = 1    |
 * |    2 | Write                  |                        |
 * |    3 | Check Handle Time = 2  | Check Handle Time = 2  |
 * |      | Check Path Time = 2    | Check Path Time = 2    |
 * |    4 | Set Sticky Time = 99   |                        |
 * |    5 | Check Handle Time = 99 | Check Handle Time = 99 |
 * |      | Check Path Time = 99   | Check Path Time = 99   |
 * |    6 | Write                  |                        |
 * |    7 | Check Handle Time = 99 | Check Handle Time = 99 |
 * |      | Check Path Time = 99   | Check Path Time = 99   |
 * |    8 |                        | Write                  |
 * |    9 | Check Handle Time = 8  | Check Handle Time = 8  |
 * |      | Check Path Time = 8    | Check Path Time = 8    |
 * |   10 | Write                  |                        |
 * |   11 | Check Handle Time = 8  | Check Handle Time = 8  |
 * |      | Check Path Time = 8    | Check Path Time = 8    |
 * |   12 | Close                  | Close                  |
 * |   13 | Check Path Time = 8    | Check Path Time = 8    |
 */
static bool test_modern_write_time_update1(struct torture_context *tctx,
					   struct smb2_tree *tree1,
					   struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_modern_write_time_update1";
	struct smb2_create cr;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	union smb_setfileinfo setinfo;
	NTTIME lasttime, currenttime1, currenttime2;
	time_t stickytime = time(NULL) + 86400;
	NTTIME stickynttime;
	NTSTATUS status;
	bool ret = true;

	unix_to_nt_time(&stickynttime, stickytime);

	smb2_deltree(tree1, BASEDIR);
	status = torture_smb2_testdir(tree1, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	/* 1 */

	smb2_generic_create(&cr, NULL, false, fname,
			    NTCREATEX_DISP_CREATE,
			    smb2_util_oplock_level(""), 0, 0);
	status = smb2_create(tree1, tree1, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h1 = cr.out.file.handle;

	smb2_generic_create(&cr, NULL, false, fname,
			    NTCREATEX_DISP_OPEN,
			    smb2_util_oplock_level(""), 0, 0);
	status = smb2_create(tree2, tree2, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h2 = cr.out.file.handle;

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");
	lasttime = currenttime1;

	/* 2 */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	status = smb2_util_write(tree1, h1, "1", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	/* 3 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_not_equal_goto(tctx,
					     currenttime1,
					     lasttime,
					     ret, done,
					     "bad time\n");
	lasttime = currenttime1;

	/* 4 */

	setinfo = (union smb_setfileinfo) {
		.generic.level = SMB_QFILEINFO_BASIC_INFORMATION,
	};
	setinfo.basic_info.in.file.handle = h1;
	setinfo.basic_info.in.write_time = stickynttime;

	status = smb2_setinfo_file(tree1, &setinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 5 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 stickynttime,
					 ret, done,
					 "bad time\n");
	lasttime = currenttime1;

	/* 6 */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	status = smb2_util_write(tree1, h1, "1", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	/* 7 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 stickynttime,
					 ret, done,
					 "bad time\n");

	/* 8 */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	status = smb2_util_write(tree2, h2, "1", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	/* 9 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_not_equal_goto(tctx,
					     currenttime1,
					     stickynttime,
					     ret, done,
					     "bad time\n");
	lasttime = currenttime1;

	/* 10 */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	status = smb2_util_write(tree1, h1, "1", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	/* 11 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 lasttime,
					 ret, done,
					 "bad time\n");

	/* 12 */

	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	status = smb2_util_close(tree2, h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	/* 13 */

	ret = getinfo_both(tctx, tree1, NULL, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, NULL, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 lasttime,
					 ret, done,
					 "bad time\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}
	smb2_deltree(tree1, BASEDIR);
	return ret;
}


/*
 * Test setting filesize and allocation info vs sticky mtime
 *
 * | Time | Handle 1               | Handle 2               |
 * |------+------------------------+------------------------|
 * |    1 | Create file            | Open file              |
 * |      | Check Handle Time = 1  | Check Handle Time = 1  |
 * |      | Check Path Time = 1    | Check Path Time = 1    |
 * |    2 | Set Filesize 0         |                        |
 * |    3 | Check Handle Time = 2  | Check Handle Time = 2  |
 * |      | Check Path Time = 2    | Check Path Time = 2    |
 * |    4 | Set Allocation Size = 0|                        |
 * |    5 | Check Handle Time = 4  | Check Handle Time = 4  |
 * |      | Check Path Time = 4    | Check Path Time = 4    |
 * |    6 | Set Filesize 1         |                        |
 * |    7 | Check Handle Time = 6  | Check Handle Time = 6  |
 * |      | Check Path Time = 6    | Check Path Time = 6    |
 * |    8 | Set Allocation Size = 4096|                     |
 * |    9 | Check Handle Time = 8  | Check Handle Time = 8  |
 * |      | Check Path Time = 8    | Check Path Time = 8    |
 * |   10 | Set Sticky Time = 99   |                        |
 * |   11 | Check Handle Time = 99 | Check Handle Time = 99 |
 * |      | Check Path Time = 99   | Check Path Time = 99   |
 * |   12 | Set Filesize           |                        |
 * |   13 | Check Handle Time = 99 | Check Handle Time = 99 |
 * |      | Check Path Time = 99   | Check Path Time = 99   |
 * |   14 | Set Allocation Size    |                        |
 * |   15 | Check Handle Time = 99 | Check Handle Time = 99 |
 * |      | Check Path Time = 99   | Check Path Time = 99   |
 * |   16 |                        | Set Filesize           |
 * |   17 | Check Handle Time = 16 | Check Handle Time = 16 |
 * |      | Check Path Time = 16   | Check Path Time = 16   |
 * |   18 |                        | Set Allocation Size    |
 * |   19 | Check Handle Time = 18 | Check Handle Time = 18 |
 * |      | Check Path Time = 18   | Check Path Time = 18   |
 * |   20 |                        | Shrink Allocation Size |
 * |   21 | Check Handle Time = 20 | Check Handle Time = 20 |
 * |      | Check Path Time = 20   | Check Path Time = 20   |
 * |   22 | Close                  | Close                  |
 * |   23 | Check Path Time = 20   | Check Path Time = 20   |
 */
static bool test_modern_write_time_update2(struct torture_context *tctx,
					   struct smb2_tree *tree1,
					   struct smb2_tree *tree2)
{
	const char *fname = BASEDIR "\\test_modern_write_time_update2";
	struct smb2_create cr;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	union smb_setfileinfo basicinfo;
	union smb_setfileinfo eofinfo;
	union smb_setfileinfo allocinfo;
	NTTIME lasttime, currenttime1, currenttime2, ctime1, ctime2;
	off_t size = 0;
	size_t alloccount = 0;
	off_t allocsize = 4096;
	time_t stickytime = time(NULL) + 86400;
	NTTIME stickynttime;
	NTSTATUS status;
	bool ret = true;

	unix_to_nt_time(&stickynttime, stickytime);
	basicinfo = (union smb_setfileinfo) {
		.generic.level = SMB_SFILEINFO_BASIC_INFORMATION,
	};
	eofinfo = (union smb_setfileinfo) {
		.generic.level = SMB_SFILEINFO_END_OF_FILE_INFORMATION,
	};
	allocinfo = (union smb_setfileinfo) {
		.generic.level = SMB_SFILEINFO_ALLOCATION_INFORMATION,
	};

	smb2_deltree(tree1, BASEDIR);
	status = torture_smb2_testdir(tree1, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	/* 1 */

	smb2_generic_create(&cr, NULL, false, fname,
			    NTCREATEX_DISP_CREATE,
			    smb2_util_oplock_level(""), 0, 0);
	status = smb2_create(tree1, tree1, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h1 = cr.out.file.handle;

	smb2_generic_create(&cr, NULL, false, fname,
			    NTCREATEX_DISP_OPEN,
			    smb2_util_oplock_level(""), 0, 0);
	status = smb2_create(tree2, tree2, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h2 = cr.out.file.handle;

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");
	lasttime = currenttime1;

	/* 2: same size */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	eofinfo.end_of_file_info.in.file.handle = h1;
	eofinfo.end_of_file_info.in.size = size;

	status = smb2_setinfo_file(tree1, &eofinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 3 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_not_equal_goto(tctx,
					     currenttime1,
					     lasttime,
					     ret, done,
					     "bad time\n");
	lasttime = currenttime1;

	/* 4: same size */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	allocinfo.allocation_info.in.file.handle = h1;
	allocinfo.allocation_info.in.alloc_size = 0;

	status = smb2_setinfo_file(tree1, &allocinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 5 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, &ctime1);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, &ctime2);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");
	torture_assert_nttime_equal_goto(tctx, ctime1, ctime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 lasttime,
					 ret, done,
					 "bad time\n");
	torture_assert_nttime_not_equal_goto(tctx,
					     ctime1,
					     lasttime,
					     ret, done,
					     "bad time\n");
	lasttime = currenttime1;

	/* 6: grow size */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	eofinfo.end_of_file_info.in.file.handle = h1;
	eofinfo.end_of_file_info.in.size = ++size;

	status = smb2_setinfo_file(tree1, &eofinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 7 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_not_equal_goto(tctx,
					     currenttime1,
					     lasttime,
					     ret, done,
					     "bad time\n");
	lasttime = currenttime1;

	/* 8: grow size */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	allocinfo.allocation_info.in.file.handle = h1;
	allocinfo.allocation_info.in.alloc_size = ++alloccount * allocsize;

	status = smb2_setinfo_file(tree1, &allocinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 9 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, &ctime1);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, &ctime2);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");
	torture_assert_nttime_equal_goto(tctx, ctime1, ctime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 lasttime,
					 ret, done,
					 "bad time\n");
	torture_assert_nttime_not_equal_goto(tctx,
					     ctime1,
					     lasttime,
					     ret, done,
					     "bad time\n");
	lasttime = currenttime1;

	/* 10 */

	basicinfo.basic_info.in.file.handle = h1;
	basicinfo.basic_info.in.write_time = stickynttime;

	status = smb2_setinfo_file(tree1, &basicinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 11 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 stickynttime,
					 ret, done,
					 "bad time\n");
	lasttime = currenttime1;

	/* 12 */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	eofinfo.end_of_file_info.in.file.handle = h1;
	eofinfo.end_of_file_info.in.size = ++size;

	status = smb2_setinfo_file(tree1, &eofinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 13 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 stickynttime,
					 ret, done,
					 "bad time\n");

	/* 14 */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	allocinfo.allocation_info.in.file.handle = h1;
	allocinfo.allocation_info.in.alloc_size = ++alloccount * allocsize;

	status = smb2_setinfo_file(tree1, &allocinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 15 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 stickynttime,
					 ret, done,
					 "bad time\n");

	/* 16 */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	eofinfo.end_of_file_info.in.file.handle = h2;
	eofinfo.end_of_file_info.in.size = ++size;

	status = smb2_setinfo_file(tree2, &eofinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 17 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_not_equal_goto(tctx,
					     currenttime1,
					     stickynttime,
					     ret, done,
					     "bad time\n");
	lasttime = currenttime1;

	/* 18 */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	allocinfo.allocation_info.in.file.handle = h2;
	allocinfo.allocation_info.in.alloc_size = ++alloccount * allocsize;

	status = smb2_setinfo_file(tree2, &allocinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 19 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, &ctime1);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, &ctime2);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");
	torture_assert_nttime_equal_goto(tctx, ctime1, ctime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 lasttime,
					 ret, done,
					 "bad time\n");
	torture_assert_nttime_not_equal_goto(tctx,
					     ctime1,
					     lasttime,
					     ret, done,
					     "bad time\n");
	lasttime = currenttime1;

	/* 20: shrink allocation size, should update mtime+ctime */

	/* Bypass possible filesystem granularity */
	smb_msleep(20);

	allocinfo.allocation_info.in.file.handle = h2;
	allocinfo.allocation_info.in.alloc_size = 0;

	status = smb2_setinfo_file(tree2, &allocinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	/* 21 */

	ret = getinfo_both(tctx, tree1, &h1, fname, &currenttime1, &ctime1);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, &h2, fname, &currenttime2, &ctime2);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");
	torture_assert_nttime_equal_goto(tctx, ctime1, ctime2,
					 ret, done, "bad times");

	torture_assert_nttime_not_equal_goto(tctx,
					     currenttime1,
					     lasttime,
					     ret, done,
					     "bad time\n");
	torture_assert_nttime_not_equal_goto(tctx,
					     ctime1,
					     lasttime,
					     ret, done,
					     "bad time\n");
	lasttime = currenttime1;

	/* 22 */

	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	status = smb2_util_close(tree2, h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	/* 23 */

	ret = getinfo_both(tctx, tree1, NULL, fname, &currenttime1, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	ret = getinfo_both(tctx, tree2, NULL, fname, &currenttime2, NULL);
	torture_assert_goto(tctx, ret, ret, done, "getinfo_both failed");
	torture_assert_nttime_equal_goto(tctx, currenttime1, currenttime2,
					 ret, done, "bad times");

	torture_assert_nttime_equal_goto(tctx,
					 currenttime1,
					 lasttime,
					 ret, done,
					 "bad time\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}
	smb2_deltree(tree1, BASEDIR);
	return ret;
}

/*
   basic testing of SMB2 timestamps
*/
struct torture_suite *torture_smb2_timestamps_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "timestamps");

	torture_suite_add_1smb2_test(suite, "test_close_not_attrib", test_close_no_attrib);
	torture_suite_add_1smb2_test(suite, "time_t_15032385535", test_time_t_15032385535);
	torture_suite_add_1smb2_test(suite, "time_t_10000000000", test_time_t_10000000000);
	torture_suite_add_1smb2_test(suite, "time_t_4294967295", test_time_t_4294967295);
	torture_suite_add_1smb2_test(suite, "time_t_1", test_time_t_1);
	torture_suite_add_1smb2_test(suite, "time_t_0", test_time_t_0);
	torture_suite_add_1smb2_test(suite, "time_t_-1", test_time_t_minus_1);
	torture_suite_add_1smb2_test(suite, "time_t_-2", test_time_t_minus_2);
	torture_suite_add_1smb2_test(suite, "time_t_1968", test_time_t_1968);
	torture_suite_add_1smb2_test(suite, "freeze-thaw", test_freeze_thaw);

	/*
	 * Testing of delayed write-time updates
	 */
	torture_suite_add_1smb2_test(suite, "delayed-write-vs-seteof", test_delayed_write_vs_seteof);
	torture_suite_add_1smb2_test(suite, "delayed-write-vs-flush", test_delayed_write_vs_flush);
	torture_suite_add_1smb2_test(suite, "delayed-write-vs-setbasic", test_delayed_write_vs_setbasic);
	torture_suite_add_1smb2_test(suite, "delayed-1write", test_delayed_1write);
	torture_suite_add_1smb2_test(suite, "delayed-2write", test_delayed_2write);
	torture_suite_add_2smb2_test(suite, "modern_write_time_update-1", test_modern_write_time_update1);
	torture_suite_add_2smb2_test(suite, "modern_write_time_update-2", test_modern_write_time_update2);

	suite->description = talloc_strdup(suite, "SMB2 timestamp tests");

	return suite;
}

/*
 * This test shows that Windows has a timestamp resolution of ~15ms. When so
 * when a smaller amount of time than that has passed it's not necessarily
 * detectable on a Windows 2019 and newer who implement immediate timestamp
 * updates.
 *
 * Note that this test relies on a low latency SMB connection. Even with a low
 * latency connection of eg 1m there's a chance of 1/15 that the first part of
 * the test expecting no timestamp change fails as the writetime is updated.
 *
 * Due to this timing dependency this test is skipped in Samba CI, but it is
 * preserved here for future SMB2 timestamps behaviour archealogists.
 *
 * See also: https://lists.samba.org/archive/cifs-protocol/2019-December/003358.html
 */
static bool test_timestamp_resolution1(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	union smb_fileinfo finfo1;
	const char *fname = BASEDIR "\\" FNAME;
	struct smb2_create cr;
	struct smb2_handle h = {{0}};
	struct smb2_close cl;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, BASEDIR);
	status = torture_smb2_testdir(tree, BASEDIR, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	status = smb2_util_close(tree, h );
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");

	torture_comment(tctx, "Write without delay, expect no "
			"write-time change\n");

	smb2_generic_create(&cr, NULL, false, fname,
			    NTCREATEX_DISP_CREATE,
			    smb2_util_oplock_level(""), 0, 0);
	status = smb2_create(tree, tree, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h = cr.out.file.handle;

	finfo1 = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h,
	};
	status = smb2_getinfo_file(tree, tree, &finfo1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	status = smb2_util_write(tree, h, "123456789", 0, 9);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	cl = (struct smb2_close) {
		.in.file.handle = h,
		.in.flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION,
	};

	status = smb2_close(tree, &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(h);

	torture_comment(tctx, "Initial: %s\nClose: %s\n",
			nt_time_string(tctx, finfo1.basic_info.out.write_time),
			nt_time_string(tctx, cl.out.write_time));

	torture_assert_u64_equal_goto(tctx,
				      finfo1.basic_info.out.write_time,
				      cl.out.write_time,
				      ret, done,
				      "Write time changed (wrong!)\n");

	torture_comment(tctx, "Write with 20 ms delay, expect "
			"write-time change\n");

	smb2_generic_create(&cr, NULL, false, fname,
			    NTCREATEX_DISP_OPEN,
			    smb2_util_oplock_level(""), 0, 0);
	status = smb2_create(tree, tree, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h = cr.out.file.handle;

	finfo1 = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h,
	};
	status = smb2_getinfo_file(tree, tree, &finfo1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	smb_msleep(20);

	status = smb2_util_write(tree, h, "123456789", 0, 9);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	cl = (struct smb2_close) {
		.in.file.handle = h,
		.in.flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION,
	};

	status = smb2_close(tree, &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(h);

	torture_comment(tctx, "Initial: %s\nClose: %s\n",
			nt_time_string(tctx, finfo1.basic_info.out.write_time),
			nt_time_string(tctx, cl.out.write_time));

	torture_assert_u64_not_equal_goto(
		tctx,
		finfo1.basic_info.out.write_time,
		cl.out.write_time,
		ret, done,
		"Write time did not change (wrong!)\n");

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

/*
   basic testing of SMB2 timestamps
*/
struct torture_suite *torture_smb2_timestamp_resolution_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "timestamp_resolution");

	torture_suite_add_1smb2_test(suite, "resolution1", test_timestamp_resolution1);

	suite->description = talloc_strdup(suite, "SMB2 timestamp tests");

	return suite;
}
