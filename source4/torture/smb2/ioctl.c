/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 ioctl operations

   Copyright (C) David Disseldorp 2011

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
#include "librpc/gen_ndr/security.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "librpc/gen_ndr/ndr_ioctl.h"

#define FNAME	"testfsctl.dat"
#define FNAME2	"testfsctl2.dat"

/*
   basic testing of SMB2 shadow copy calls
*/
static bool test_ioctl_get_shadow_copy(struct torture_context *torture,
				       struct smb2_tree *tree)
{
	struct smb2_handle h;
	uint8_t buf[100];
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	smb2_util_unlink(tree, FNAME);

	status = torture_smb2_testfile(tree, FNAME, &h);
	if (!NT_STATUS_IS_OK(status)) {
		printf("create write\n");
		return false;
	}

	ZERO_ARRAY(buf);
	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	if (!NT_STATUS_IS_OK(status)) {
		printf("failed write\n");
		return false;
	}

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle = h;
	ioctl.smb2.in.function = FSCTL_SRV_ENUM_SNAPS;
	ioctl.smb2.in.max_response_size = 16;
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("FSCTL_SRV_ENUM_SNAPS failed\n");
		return false;
	}

	return true;
}

/*
   basic testing of the SMB2 server side copy ioctls
*/
static bool test_ioctl_req_resume_key(struct torture_context *torture,
				      struct smb2_tree *tree)
{
	struct smb2_handle h;
	uint8_t buf[100];
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct req_resume_key_rsp res_key;
	enum ndr_err_code ndr_ret;

	smb2_util_unlink(tree, FNAME);

	status = torture_smb2_testfile(tree, FNAME, &h);
	if (!NT_STATUS_IS_OK(status)) {
		printf("create write\n");
		return false;
	}

	ZERO_ARRAY(buf);
	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	if (!NT_STATUS_IS_OK(status)) {
		printf("failed write\n");
		return false;
	}

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle = h;
	ioctl.smb2.in.function = FSCTL_SRV_REQUEST_RESUME_KEY;
	ioctl.smb2.in.max_response_size = 32;
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("FSCTL_SRV_REQUEST_RESUME_KEY failed\n");
		return false;
	}

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx, &res_key,
			(ndr_pull_flags_fn_t)ndr_pull_req_resume_key_rsp);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return false;
	}

	ndr_print_debug((ndr_print_fn_t)ndr_print_req_resume_key_rsp, "yo", &res_key);

	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk(struct torture_context *torture,
				  struct smb2_tree *tree)
{
	struct smb2_handle h;
	struct smb2_handle h2;
	uint8_t buf[100];
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct req_resume_key_rsp res_key;
	struct srv_copychunk chunk;
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;

	smb2_util_unlink(tree, FNAME);
	smb2_util_unlink(tree, FNAME2);

	status = torture_smb2_testfile(tree, FNAME, &h);
	if (!NT_STATUS_IS_OK(status)) {
		printf("create write\n");
		return false;
	}

	ZERO_ARRAY(buf);
	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	if (!NT_STATUS_IS_OK(status)) {
		printf("failed write\n");
		return false;
	}

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle = h;
	ioctl.smb2.in.function = FSCTL_SRV_REQUEST_RESUME_KEY;
	/* Allow for Key + ContextLength + Context */
	ioctl.smb2.in.max_response_size = 32;
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("FSCTL_SRV_REQUEST_RESUME_KEY failed\n");
		return false;
	}

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx, &res_key,
			(ndr_pull_flags_fn_t)ndr_pull_req_resume_key_rsp);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return false;
	}

	status = torture_smb2_testfile(tree, FNAME2, &h2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("create write\n");
		return false;
	}

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle = h2;
	ioctl.smb2.in.function = FSCTL_SRV_COPYCHUNK;
	ioctl.smb2.in.max_response_size = 12;	/* FIXME */
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	ZERO_STRUCT(chunk);
	chunk.source_off = 0;
	chunk.target_off = 0;
	chunk.length = 100;

	ZERO_STRUCT(cc_copy);
	memcpy(cc_copy.source_key, res_key.resume_key, ARRAY_SIZE(cc_copy.source_key));
	cc_copy.chunk_count = 1;
	cc_copy.chunks = &chunk;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return false;
	}

	/* request a copy of all src file data (via a single chunk desc) */
	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("FSCTL_SRV_COPYCHUNK failed\n");
		return false;
	}

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return false;
	}
	if (cc_rsp.chunks_written != 1) {
		printf("fail, expected 1 chunk, got %u\n", cc_rsp.chunks_written);
		return false;
	}
	if (cc_rsp.chunk_bytes_written != 0) {
		printf("fail, expected 0 chunk bytes remaining, got %u\n",
		       cc_rsp.chunk_bytes_written);
		return false;
	}
	if (cc_rsp.total_bytes_written != 100) {
		printf("fail, expected 100 total bytes, got %u\n",
		       cc_rsp.total_bytes_written);
		return false;
	}

	talloc_free(tmp_ctx);
	return true;
}

/*
   basic testing of SMB2 ioctls
*/
struct torture_suite *torture_smb2_ioctl_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "ioctl");

	torture_suite_add_1smb2_test(suite, "shadow_copy", test_ioctl_get_shadow_copy);
	torture_suite_add_1smb2_test(suite, "req_resume_key", test_ioctl_req_resume_key);
	torture_suite_add_1smb2_test(suite, "copy_chunk", test_ioctl_copy_chunk);

	suite->description = talloc_strdup(suite, "SMB2-IOCTL tests");

	return suite;
}

