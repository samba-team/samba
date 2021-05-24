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
	torture_assert_u64_equal_goto(tctx, c.out.change_time, NTTIME_OMIT,
				      ret, done, "Unexpected change time\n");
	torture_assert_u64_equal_goto(tctx, c.out.alloc_size, 0,
				      ret, done, "Unexpected allocation size\n");
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

static bool test_delayed_write_vs_seteof(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	struct smb2_create cr;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	NTTIME create_time;
	NTTIME set_time;
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

	torture_comment(tctx, "Write to file-handle 1\n");

	status = smb2_util_write(tree, h1, "s", 0, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"write failed\n");

	torture_comment(tctx, "Check writetime hasn't been updated\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	torture_assert_nttime_equal(tctx,
				    finfo.all_info.out.write_time,
				    create_time,
				    "Writetime != set_time (wrong!)\n");

	torture_comment(tctx, "Setinfo EOF on file-handle 1,"
			" should flush pending writetime update\n");

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
	if (!(finfo.all_info.out.write_time > create_time)) {
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
	NTTIME flush_time;
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

	torture_comment(tctx, "Check writetime hasn't been updated\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	torture_assert_nttime_equal(tctx,
				    finfo.all_info.out.write_time,
				    create_time,
				    "Writetime != create_time (wrong!)\n");

	torture_comment(tctx, "Flush file, "
			"should flush pending writetime update\n");

	f = (struct smb2_flush) {
		.in.file.handle = h1,
	};

	status = smb2_flush(tree, &f);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"flush failed\n");

	torture_comment(tctx, "Check writetime has been updated "
			"by the setinfo EOF\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");

	flush_time = finfo.all_info.out.write_time;
	if (!(flush_time > create_time)) {
		ret = false;
		torture_fail_goto(tctx, done, "flush hasn't updated writetime\n");
	}

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
				    flush_time,
				    "writetime != flushtime (wrong!)\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, BASEDIR);
	return ret;
}

static bool test_delayed_write_vs_setbasic_do(struct torture_context *tctx,
					      struct smb2_tree *tree,
					      union smb_setfileinfo *setinfo,
					      bool expect_update)
{
	char *path = NULL;
	struct smb2_create cr;
	struct smb2_handle h1 = {{0}};
	NTTIME create_time;
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

	torture_assert_nttime_equal(tctx,
				    finfo.all_info.out.write_time,
				    create_time,
				    "Writetime != create_time (wrong!)\n");

	torture_comment(tctx, "Set timestamps\n");

	setinfo->end_of_file_info.in.file.handle = h1;
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

	if (expect_update) {
		if (!(finfo.all_info.out.write_time > create_time)) {
			ret = false;
			torture_fail_goto(tctx, done, "setinfo basicinfo "
					  "hasn't updated writetime\n");
		}
	} else {
		if (finfo.all_info.out.write_time != create_time) {
			ret = false;
			torture_fail_goto(tctx, done, "setinfo basicinfo "
					  "hasn't updated writetime\n");
		}
	}

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
	 * Yes, this is correct, tested against Windows 2016: even if all
	 * timestamp fields are 0, a pending write time is flushed.
	 */
	torture_comment(tctx, "Test: setting all-0 timestamps flushes?\n");

	setinfo = (union smb_setfileinfo) {
		.generic.level = RAW_SFILEINFO_BASIC_INFORMATION,
	};
	ret = test_delayed_write_vs_setbasic_do(tctx, tree, &setinfo, true);
	if (ret != true) {
		goto done;
	}

	torture_comment(tctx, "Test: setting create_time flushes?\n");
	unix_to_nt_time(&setinfo.basic_info.in.create_time, t);
	ret = test_delayed_write_vs_setbasic_do(tctx, tree, &setinfo, true);
	if (ret != true) {
		goto done;
	}

	torture_comment(tctx, "Test: setting access_time flushes?\n");
	unix_to_nt_time(&setinfo.basic_info.in.access_time, t);
	ret = test_delayed_write_vs_setbasic_do(tctx, tree, &setinfo, true);
	if (ret != true) {
		goto done;
	}

	torture_comment(tctx, "Test: setting change_time flushes?\n");
	unix_to_nt_time(&setinfo.basic_info.in.change_time, t);
	ret = test_delayed_write_vs_setbasic_do(tctx, tree, &setinfo, true);
	if (ret != true) {
		goto done;
	}

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
	struct timespec now;
	NTTIME send_close_time;
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

	torture_comment(tctx, "Check writetime has NOT been updated\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tree, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo failed\n");
	write_time2 = finfo.all_info.out.write_time;

	torture_assert_nttime_equal(tctx, write_time2, write_time,
				    "second write updated write-time (wrong!)\n");

	torture_comment(tctx, "Close file-handle 1\n");
	sleep(2);

	now = timespec_current();
	send_close_time = full_timespec_to_nt_time(&now);

	c = (struct smb2_close) {
		.in.file.handle = h1,
		.in.flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION,
	};

	status = smb2_close(tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"close failed\n");
	ZERO_STRUCT(h1);
	close_time = c.out.write_time;

	if (!(close_time > send_close_time)) {
		ret = false;
		torture_fail_goto(tctx, done,
				  "Write-time not updated (wrong!)\n");
	}

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, BASEDIR);
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

	/*
	 * Testing of delayed write-time udpates
	 */
	torture_suite_add_1smb2_test(suite, "delayed-write-vs-seteof", test_delayed_write_vs_seteof);
	torture_suite_add_1smb2_test(suite, "delayed-write-vs-flush", test_delayed_write_vs_flush);
	torture_suite_add_1smb2_test(suite, "delayed-write-vs-setbasic", test_delayed_write_vs_setbasic);
	torture_suite_add_1smb2_test(suite, "delayed-1write", test_delayed_1write);
	torture_suite_add_1smb2_test(suite, "delayed-2write", test_delayed_2write);

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
