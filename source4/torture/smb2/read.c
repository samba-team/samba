/* 
   Unix SMB/CIFS implementation.

   SMB2 read test suite

   Copyright (C) Andrew Tridgell 2008
   
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
#include <tevent.h>

#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "../libcli/smb/smbXcli_base.h"
#include "librpc/gen_ndr/ndr_ioctl.h"


#define CHECK_STATUS(_status, _expected) \
	torture_assert_ntstatus_equal_goto(torture, _status, _expected, \
		 ret, done, "Incorrect status")

#define CHECK_VALUE(v, correct) \
	torture_assert_int_equal_goto(torture, v, correct, \
		 ret, done, "Incorrect value")

#define FNAME "smb2_readtest.dat"
#define DNAME "smb2_readtest.dir"

static bool test_read_eof(struct torture_context *torture, struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle h;
	uint8_t buf[64*1024];
	struct smb2_read rd;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(buf);

	smb2_util_unlink(tree, FNAME);

	status = torture_smb2_testfile(tree, FNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length      = 5;
	rd.in.offset      = 0;
	status = smb2_read(tree, tree, &rd);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

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

	rd.in.min_count = 1;
	rd.in.length = 0;
	rd.in.offset = sizeof(buf);
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

	rd.in.min_count = 0;
	rd.in.length = 2;
	rd.in.offset = sizeof(buf) - 1;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(rd.out.data.length, 1);

	rd.in.min_count = 2;
	rd.in.length = 1;
	rd.in.offset = sizeof(buf) - 1;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

	rd.in.min_count = 0x10000;
	rd.in.length = 1;
	rd.in.offset = 0;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

	rd.in.min_count = 0x10000 - 2;
	rd.in.length = 1;
	rd.in.offset = 0;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

	rd.in.min_count = 10;
	rd.in.length = 5;
	rd.in.offset = 0;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

done:
	talloc_free(tmp_ctx);
	return ret;
}


static bool test_read_position(struct torture_context *torture, struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle h;
	uint8_t buf[64*1024];
	struct smb2_read rd;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	union smb_fileinfo info;

	ZERO_STRUCT(buf);

	smb2_util_unlink(tree, FNAME);

	status = torture_smb2_testfile(tree, FNAME, &h);
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

	info.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	info.generic.in.file.handle = h;

	status = smb2_getinfo_file(tree, tmp_ctx, &info);
	CHECK_STATUS(status, NT_STATUS_OK);
	if (torture_setting_bool(torture, "windows", false)) {
		CHECK_VALUE(info.all_info2.out.position, 0);
	} else {
		CHECK_VALUE(info.all_info2.out.position, 10);
	}

	
done:
	talloc_free(tmp_ctx);
	return ret;
}

static bool test_read_dir(struct torture_context *torture, struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle h;
	struct smb2_read rd;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	status = torture_smb2_testdir(tree, DNAME, &h);
	if (!NT_STATUS_IS_OK(status)) {
		printf(__location__ " Unable to create test directory '%s' - %s\n", DNAME, nt_errstr(status));
		return false;
	}

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = 10;
	rd.in.offset = 0;
	rd.in.min_count = 1;

	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_INVALID_DEVICE_REQUEST);
	
	rd.in.min_count = 11;
	status = smb2_read(tree, tmp_ctx, &rd);
	CHECK_STATUS(status, NT_STATUS_INVALID_DEVICE_REQUEST);

	rd.in.length = 0;
	rd.in.min_count = 2592;
	status = smb2_read(tree, tmp_ctx, &rd);
	if (torture_setting_bool(torture, "windows", false)) {
		CHECK_STATUS(status, NT_STATUS_END_OF_FILE);
	} else {
		CHECK_STATUS(status, NT_STATUS_INVALID_DEVICE_REQUEST);
	}

	rd.in.length = 0;
	rd.in.min_count = 0;
	rd.in.channel = 0;
	status = smb2_read(tree, tmp_ctx, &rd);
	if (torture_setting_bool(torture, "windows", false)) {
		CHECK_STATUS(status, NT_STATUS_OK);
	} else {
		CHECK_STATUS(status, NT_STATUS_INVALID_DEVICE_REQUEST);
	}
	
done:
	talloc_free(tmp_ctx);
	return ret;
}

static bool test_read_access(struct torture_context *torture,
			     struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle h;
	uint8_t buf[64 * 1024];
	struct smb2_read rd;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(buf);

	/* create a file */
	smb2_util_unlink(tree, FNAME);

	status = torture_smb2_testfile(tree, FNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, h);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* open w/ READ access - success */
	status = torture_smb2_testfile_access(
	    tree, FNAME, &h, SEC_FILE_READ_ATTRIBUTE | SEC_FILE_READ_DATA);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = 5;
	rd.in.offset = 0;
	status = smb2_read(tree, tree, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, h);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* open w/ EXECUTE access - success */
	status = torture_smb2_testfile_access(
	    tree, FNAME, &h, SEC_FILE_READ_ATTRIBUTE | SEC_FILE_EXECUTE);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = 5;
	rd.in.offset = 0;
	status = smb2_read(tree, tree, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, h);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* open without READ or EXECUTE access - access denied */
	status = torture_smb2_testfile_access(tree, FNAME, &h,
					      SEC_FILE_READ_ATTRIBUTE);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = 5;
	rd.in.offset = 0;
	status = smb2_read(tree, tree, &rd);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	status = smb2_util_close(tree, h);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	talloc_free(tmp_ctx);
	return ret;
}

/*
   basic regression test for BUG 14607
   https://bugzilla.samba.org/show_bug.cgi?id=14607
*/
static bool test_read_bug14607(struct torture_context *torture,
				struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle h;
	uint8_t buf[64 * 1024];
	struct smb2_read rd;
	uint32_t timeout_msec;
	DATA_BLOB out_input_buffer = data_blob_null;
	DATA_BLOB out_output_buffer = data_blob_null;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	uint8_t *data = NULL;
	uint32_t data_length = 0;

	memset(buf, 0x1f, ARRAY_SIZE(buf));

	/* create a file */
	smb2_util_unlink(tree, FNAME);

	status = torture_smb2_testfile(tree, FNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = ARRAY_SIZE(buf);
	rd.in.offset = 0;
	status = smb2_read(tree, tree, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(rd.out.data.length, ARRAY_SIZE(buf));
	torture_assert_mem_equal_goto(torture, rd.out.data.data,
				      buf, ARRAY_SIZE(buf),
				      ret, done,
				      "Invalid content smb2_read");

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	status = smb2cli_read(tree->session->transport->conn,
			      timeout_msec,
			      tree->session->smbXcli,
			      tree->smbXcli,
			      rd.in.length,
			      rd.in.offset,
			      h.data[0],
			      h.data[1],
			      rd.in.min_count,
			      rd.in.remaining,
			      tmp_ctx,
			      &data, &data_length);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(data_length, ARRAY_SIZE(buf));
	torture_assert_mem_equal_goto(torture, data,
				      buf, ARRAY_SIZE(buf),
				      ret, done,
				      "Invalid content smb2cli_read");

	status = smb2cli_ioctl(tree->session->transport->conn,
			       timeout_msec,
			       tree->session->smbXcli,
			       tree->smbXcli,
			       UINT64_MAX, /* in_fid_persistent */
			       UINT64_MAX, /* in_fid_volatile */
			       FSCTL_SMBTORTURE_GLOBAL_READ_RESPONSE_BODY_PADDING8,
			       0, /* in_max_input_length */
			       NULL, /* in_input_buffer */
			       1, /* in_max_output_length */
			       NULL, /* in_output_buffer */
			       SMB2_IOCTL_FLAG_IS_FSCTL,
			       tmp_ctx,
			       &out_input_buffer,
			       &out_output_buffer);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_FS_DRIVER_REQUIRED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_DEVICE_REQUEST))
	{
		torture_comment(torture,
				"FSCTL_SMBTORTURE_GLOBAL_READ_RESPONSE_BODY_PADDING8: %s\n",
				nt_errstr(status));
		torture_skip(torture, "server doesn't support FSCTL_SMBTORTURE_GLOBAL_READ_RESPONSE_BODY_PADDING8\n");
	}
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SMBTORTURE_GLOBAL_READ_RESPONSE_BODY_PADDING8");

	torture_assert_int_equal(torture, out_output_buffer.length, 0,
				 "output length");

	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = ARRAY_SIZE(buf);
	rd.in.offset = 0;
	status = smb2_read(tree, tree, &rd);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(rd.out.data.length, ARRAY_SIZE(buf));
	torture_assert_mem_equal_goto(torture, rd.out.data.data,
				      buf, ARRAY_SIZE(buf),
				      ret, done,
				      "Invalid content after padding smb2_read");

	status = smb2cli_read(tree->session->transport->conn,
			      timeout_msec,
			      tree->session->smbXcli,
			      tree->smbXcli,
			      rd.in.length,
			      rd.in.offset,
			      h.data[0],
			      h.data[1],
			      rd.in.min_count,
			      rd.in.remaining,
			      tmp_ctx,
			      &data, &data_length);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(data_length, ARRAY_SIZE(buf));
	torture_assert_mem_equal_goto(torture, data,
				      buf, ARRAY_SIZE(buf),
				      ret, done,
				      "Invalid content after padding smb2cli_read");

	status = smb2_util_close(tree, h);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	talloc_free(tmp_ctx);
	return ret;
}

/* 
   basic testing of SMB2 read
*/
struct torture_suite *torture_smb2_read_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "read");

	torture_suite_add_1smb2_test(suite, "eof", test_read_eof);
	torture_suite_add_1smb2_test(suite, "position", test_read_position);
	torture_suite_add_1smb2_test(suite, "dir", test_read_dir);
	torture_suite_add_1smb2_test(suite, "access", test_read_access);
	torture_suite_add_1smb2_test(suite, "bug14607",
				     test_read_bug14607);

	suite->description = talloc_strdup(suite, "SMB2-READ tests");

	return suite;
}

static bool test_aio_cancel(struct torture_context *tctx,
			    struct smb2_tree *tree)
{
	struct smb2_handle h;
	uint8_t buf[64 * 1024];
	struct smb2_read r;
	struct smb2_request *req = NULL;
	int rc;
	NTSTATUS status;
	bool ret = true;

	ZERO_STRUCT(buf);

	smb2_util_unlink(tree, FNAME);

	status = torture_smb2_testfile(tree, FNAME, &h);
	torture_assert_ntstatus_ok_goto(
		tctx,
		status,
		ret,
		done,
		"torture_smb2_testfile failed\n");

	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	torture_assert_ntstatus_ok_goto(
		tctx,
		status,
		ret,
		done,
		"smb2_util_write failed\n");

	status = smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(
		tctx,
		status,
		ret,
		done,
		"smb2_util_close failed\n");

	status = torture_smb2_testfile_access(
		tree, FNAME, &h, SEC_RIGHTS_FILE_ALL);
	torture_assert_ntstatus_ok_goto(
		tctx,
		status,
		ret,
		done,
		"torture_smb2_testfile_access failed\n");

	r = (struct smb2_read) {
		.in.file.handle = h,
		.in.length      = 1,
		.in.offset      = 0,
		.in.min_count   = 1,
	};

	req = smb2_read_send(tree, &r);
	torture_assert_goto(
		tctx,
		req != NULL,
		ret,
		done,
		"smb2_read_send failed\n");

	while (!req->cancel.can_cancel) {
		rc = tevent_loop_once(tctx->ev);
		torture_assert_goto(
			tctx,
			rc == 0,
			ret,
			done,
			"tevent_loop_once failed\n");
	}

	status = smb2_cancel(req);
	torture_assert_ntstatus_ok_goto(
		tctx,
		status,
		ret,
		done,
		"smb2_cancel failed\n");

	status = smb2_read_recv(req, tree, &r);
	torture_assert_ntstatus_ok_goto(
		tctx,
		status,
		ret,
		done,
		"smb2_read_recv failed\n");

	status = smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(
		tctx,
		status,
		ret,
		done,
		"smb2_util_close failed\n");

done:
	smb2_util_unlink(tree, FNAME);
	return ret;
}

/*
 * aio testing against share with VFS module "delay_inject"
 */
struct torture_suite *torture_smb2_aio_delay_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "aio_delay");

	torture_suite_add_1smb2_test(suite, "aio_cancel", test_aio_cancel);

	suite->description = talloc_strdup(suite, "SMB2 delayed aio tests");

	return suite;
}
