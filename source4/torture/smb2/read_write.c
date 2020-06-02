/*
   Unix SMB/CIFS implementation.
   SMB read/write torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
   Copyright (C) David Mulder 2019

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
#include "torture/smbtorture.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"

#define CHECK_STATUS(_status, _expected) \
	torture_assert_ntstatus_equal_goto(torture, _status, _expected, \
		 ret, done, "Incorrect status")

#define CHECK_VALUE(v, correct) \
	torture_assert_int_equal_goto(torture, v, correct, \
		 ret, done, "Incorrect value")

#define FNAME "smb2_writetest.dat"

static bool run_smb2_readwritetest(struct torture_context *tctx,
				   struct smb2_tree *t1, struct smb2_tree *t2)
{
	const char *lockfname = "torture2.lck";
	struct smb2_create f1 = {0};
	struct smb2_create f2 = {0};
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	int i;
	uint8_t buf[131072];
	bool correct = true;
	NTSTATUS status;
	int ret = 0;

	ret = smb2_deltree(t1, lockfname);
	torture_assert(tctx, ret != -1, "unlink failed");

	f1.in.desired_access = SEC_FILE_ALL;
	f1.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			     NTCREATEX_SHARE_ACCESS_WRITE;
	f1.in.create_disposition = FILE_CREATE;
	f1.in.fname = lockfname;

	status = smb2_create(t1, tctx, &f1);
	torture_assert_ntstatus_ok_goto(tctx, status, correct, done,
		talloc_asprintf(tctx, "first open read/write of %s failed (%s)",
		lockfname, nt_errstr(status)));
	h1 = f1.out.file.handle;

	f2.in.desired_access = SEC_FILE_READ_DATA;
	f2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			     NTCREATEX_SHARE_ACCESS_WRITE;
	f2.in.create_disposition = FILE_OPEN;
	f2.in.fname = lockfname;

	status = smb2_create(t2, tctx, &f2);
	torture_assert_ntstatus_ok_goto(tctx, status, correct, done,
		talloc_asprintf(tctx, "second open read-only of %s failed (%s)",
		lockfname, nt_errstr(status)));
	h2 = f2.out.file.handle;

	torture_comment(tctx, "Checking data integrity over %d ops\n",
			torture_numops);

	for (i = 0; i < torture_numops; i++) {
		struct smb2_write w = {0};
		struct smb2_read r = {0};
		size_t buf_size = ((unsigned int)random()%(sizeof(buf)-1))+ 1;

		if (i % 10 == 0) {
			if (torture_setting_bool(tctx, "progress", true)) {
				torture_comment(tctx, "%d\r", i); fflush(stdout);
			}
		}

		generate_random_buffer(buf, buf_size);

		w.in.file.handle = h1;
		w.in.offset = 0;
		w.in.data.data = buf;
		w.in.data.length = buf_size;

		status = smb2_write(t1, &w);
		if (!NT_STATUS_IS_OK(status) || w.out.nwritten != buf_size) {
			torture_comment(tctx, "write failed (%s)\n",
					nt_errstr(status));
			torture_result(tctx, TORTURE_FAIL,
				       "wrote %d, expected %d\n",
				       (int)w.out.nwritten, (int)buf_size);
			correct = false;
			goto done;
		}

		r.in.file.handle = h2;
		r.in.offset = 0;
		r.in.length = buf_size;
		status = smb2_read(t2, tctx, &r);
		if (!NT_STATUS_IS_OK(status) || r.out.data.length != buf_size) {
			torture_comment(tctx, "read failed (%s)\n",
					nt_errstr(status));
			torture_result(tctx, TORTURE_FAIL,
				       "read %d, expected %d\n",
				       (int)r.out.data.length, (int)buf_size);
			correct = false;
			goto done;
		}

		torture_assert_mem_equal_goto(tctx, r.out.data.data, buf,
			buf_size, correct, done, "read/write compare failed\n");
	}

	status = smb2_util_close(t2, h2);
	torture_assert_ntstatus_ok_goto(tctx, status, correct, done,
		talloc_asprintf(tctx, "close failed (%s)", nt_errstr(status)));
	ZERO_STRUCT(h2);

	status = smb2_util_close(t1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, correct, done,
		talloc_asprintf(tctx, "close failed (%s)", nt_errstr(status)));
	ZERO_STRUCT(h1);

done:
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(t2, h2);
	}
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(t1, h1);
	}

	status = smb2_util_unlink(t1, lockfname);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "unlink failed (%s)", nt_errstr(status));
	}

	return correct;
}


static bool run_smb2_wrap_readwritetest(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	return run_smb2_readwritetest(tctx, tree1, tree1);
}

static bool test_rw_invalid(struct torture_context *torture, struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle h;
	uint8_t buf[64*1024];
	struct smb2_read rd;
	struct smb2_write w = {0};
	union smb_setfileinfo sfinfo;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(buf);

	smb2_util_unlink(tree, FNAME);

	status = torture_smb2_testfile(tree, FNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* set delete-on-close */
	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.disposition_info.in.delete_on_close = 1;
	sfinfo.generic.in.file.handle = h;
	status = smb2_setinfo_file(tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = 10;
	rd.in.offset = 0;
	rd.in.min_count = 1;

	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(rd.out.data.length, 10);

	rd.in.min_count = 0;
	rd.in.length = 10;
	rd.in.offset = sizeof(buf);
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

	rd.in.min_count = 0;
	rd.in.length = 0;
	rd.in.offset = sizeof(buf);
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(rd.out.data.length, 0);

	rd.in.min_count = 0;
	rd.in.length = 1;
	rd.in.offset = INT64_MAX - 1;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

	rd.in.min_count = 0;
	rd.in.length = 0;
	rd.in.offset = INT64_MAX;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(rd.out.data.length, 0);

	rd.in.min_count = 0;
	rd.in.length = 1;
	rd.in.offset = INT64_MAX;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	rd.in.min_count = 0;
	rd.in.length = 0;
	rd.in.offset = (uint64_t)INT64_MAX + 1;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	rd.in.min_count = 0;
	rd.in.length = 0;
	rd.in.offset = (uint64_t)INT64_MIN;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	rd.in.min_count = 0;
	rd.in.length = 0;
	rd.in.offset = (uint64_t)(int64_t)-1;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	rd.in.min_count = 0;
	rd.in.length = 0;
	rd.in.offset = (uint64_t)(int64_t)-2;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	rd.in.min_count = 0;
	rd.in.length = 0;
	rd.in.offset = (uint64_t)(int64_t)-3;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	w.in.file.handle = h;
	w.in.offset = (int64_t)-1;
	w.in.data.data = buf;
	w.in.data.length = ARRAY_SIZE(buf);

	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	w.in.file.handle = h;
	w.in.offset = (int64_t)-2;
	w.in.data.data = buf;
	w.in.data.length = ARRAY_SIZE(buf);

	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	w.in.file.handle = h;
	w.in.offset = INT64_MIN;
	w.in.data.data = buf;
	w.in.data.length = 1;

	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	w.in.file.handle = h;
	w.in.offset = INT64_MIN;
	w.in.data.data = buf;
	w.in.data.length = 0;
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	w.in.file.handle = h;
	w.in.offset = INT64_MAX;
	w.in.data.data = buf;
	w.in.data.length = 0;
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(w.out.nwritten, 0);

	w.in.file.handle = h;
	w.in.offset = INT64_MAX;
	w.in.data.data = buf;
	w.in.data.length = 1;
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	w.in.file.handle = h;
	w.in.offset = (uint64_t)INT64_MAX + 1;
	w.in.data.data = buf;
	w.in.data.length = 0;
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	w.in.file.handle = h;
	w.in.offset = 0xfffffff0000; /* MAXFILESIZE */
	w.in.data.data = buf;
	w.in.data.length = 1;
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	w.in.file.handle = h;
	w.in.offset = 0xfffffff0000 - 1; /* MAXFILESIZE - 1 */
	w.in.data.data = buf;
	w.in.data.length = 1;
	status = smb2_write(tree, &w);
	if (TARGET_IS_SAMBA3(torture) || TARGET_IS_SAMBA4(torture)) {
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_VALUE(w.out.nwritten, 1);
	} else {
		CHECK_STATUS(status, NT_STATUS_DISK_FULL);
	}

	w.in.file.handle = h;
	w.in.offset = 0xfffffff0000; /* MAXFILESIZE */
	w.in.data.data = buf;
	w.in.data.length = 0;
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(w.out.nwritten, 0);

done:
	talloc_free(tmp_ctx);
	return ret;
}

struct torture_suite *torture_smb2_readwrite_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "rw");

	torture_suite_add_2smb2_test(suite, "rw1", run_smb2_readwritetest);
	torture_suite_add_2smb2_test(suite, "rw2", run_smb2_wrap_readwritetest);
	torture_suite_add_1smb2_test(suite, "invalid", test_rw_invalid);

	suite->description = talloc_strdup(suite, "SMB2 Samba4 Read/Write");

	return suite;
}
