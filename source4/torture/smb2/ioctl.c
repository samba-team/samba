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
	torture_assert_ntstatus_ok(torture, status, "create write");

	ZERO_ARRAY(buf);
	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	torture_assert_ntstatus_ok(torture, status, "write");

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle = h;
	ioctl.smb2.in.function = FSCTL_SRV_ENUM_SNAPS;
	ioctl.smb2.in.max_response_size = 16;
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SRV_ENUM_SNAPS");

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
	torture_assert_ntstatus_ok(torture, status, "create write");

	ZERO_ARRAY(buf);
	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	torture_assert_ntstatus_ok(torture, status, "write");

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle = h;
	ioctl.smb2.in.function = FSCTL_SRV_REQUEST_RESUME_KEY;
	ioctl.smb2.in.max_response_size = 32;
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SRV_REQUEST_RESUME_KEY");

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx, &res_key,
			(ndr_pull_flags_fn_t)ndr_pull_req_resume_key_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_req_resume_key_rsp");

	ndr_print_debug((ndr_print_fn_t)ndr_print_req_resume_key_rsp, "yo", &res_key);

	talloc_free(tmp_ctx);
	return true;
}

static uint64_t patt_hash(uint64_t off)
{
	return off;
}

static bool check_pattern(struct torture_context *torture,
			  struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
			  struct smb2_handle h, uint64_t off, uint64_t len,
			  uint64_t patt_off)
{
	uint64_t i;
	struct smb2_read r;
	NTSTATUS status;

	ZERO_STRUCT(r);
	r.in.file.handle = h;
	r.in.length      = len;
	r.in.offset      = off;
	status = smb2_read(tree, mem_ctx, &r);
	torture_assert_ntstatus_ok(torture, status, "read");

	torture_assert_u64_equal(torture, r.out.data.length, len,
				 "read data len mismatch");

	for (i = 0; i <= len - 8; i += 8, patt_off += 8) {
		uint64_t data = BVAL(r.out.data.data, i);
		torture_assert_u64_equal(torture, data, patt_hash(patt_off),
					 talloc_asprintf(torture, "read data "
							 "pattern bad at %llu\n",
							 (unsigned long long)i));
	}

	talloc_free(r.out.data.data);
	return true;
}

static bool test_setup_copy_chunk(struct torture_context *torture,
				  struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
				  uint32_t nchunks,
				  struct smb2_handle *src_h,
				  uint64_t src_size,
				  struct smb2_handle *dest_h,
				  uint64_t dest_size,
				  struct srv_copychunk_copy *cc_copy,
				  union smb_ioctl *ioctl)
{
	struct req_resume_key_rsp res_key;
	NTSTATUS status;
	enum ndr_err_code ndr_ret;
	uint64_t i;
	uint8_t *buf = talloc_zero_size(mem_ctx, MAX(src_size, dest_size));
	if (buf == NULL) {
		printf("no mem for file data buffer\n");
		return false;
	}

	smb2_util_unlink(tree, FNAME);
	smb2_util_unlink(tree, FNAME2);

	status = torture_smb2_testfile(tree, FNAME, src_h);
	torture_assert_ntstatus_ok(torture, status, "create write");

	if (src_size > 0) {
		for (i = 0; i <= src_size - 8; i += 8) {
			SBVAL(buf, i, patt_hash(i));
		}
		status = smb2_util_write(tree, *src_h, buf, 0, src_size);
		torture_assert_ntstatus_ok(torture, status, "src write");
	}

	status = torture_smb2_testfile(tree, FNAME2, dest_h);
	torture_assert_ntstatus_ok(torture, status, "create write");

	if (dest_size > 0) {
		for (i = 0; i <= src_size - 8; i += 8) {
			SBVAL(buf, i, patt_hash(i));
		}
		status = smb2_util_write(tree, *dest_h, buf, 0, dest_size);
		torture_assert_ntstatus_ok(torture, status, "dest write");
	}

	ZERO_STRUCTPN(ioctl);
	ioctl->smb2.level = RAW_IOCTL_SMB2;
	ioctl->smb2.in.file.handle = *src_h;
	ioctl->smb2.in.function = FSCTL_SRV_REQUEST_RESUME_KEY;
	/* Allow for Key + ContextLength + Context */
	ioctl->smb2.in.max_response_size = 32;
	ioctl->smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, mem_ctx, &ioctl->smb2);
	torture_assert_ntstatus_ok(torture, status,
				   "FSCTL_SRV_REQUEST_RESUME_KEY");


	ndr_ret = ndr_pull_struct_blob(&ioctl->smb2.out.out, mem_ctx, &res_key,
			(ndr_pull_flags_fn_t)ndr_pull_req_resume_key_rsp);

	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_req_resume_key_rsp");

	ZERO_STRUCTPN(ioctl);
	ioctl->smb2.level = RAW_IOCTL_SMB2;
	ioctl->smb2.in.file.handle = *dest_h;
	ioctl->smb2.in.function = FSCTL_SRV_COPYCHUNK;
	ioctl->smb2.in.max_response_size = sizeof(struct srv_copychunk_rsp);
	ioctl->smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	ZERO_STRUCTPN(cc_copy);
	memcpy(cc_copy->source_key, res_key.resume_key, ARRAY_SIZE(cc_copy->source_key));
	cc_copy->chunk_count = nchunks;
	cc_copy->chunks = talloc_zero_array(mem_ctx, struct srv_copychunk, nchunks);
	if (cc_copy->chunks == NULL) {
		printf("not enough memory to allocate %u chunks\n", nchunks);
		return false;
	}

	return true;
}


static bool check_copy_chunk_rsp(struct torture_context *torture,
				 struct srv_copychunk_rsp *cc_rsp,
				 uint32_t ex_chunks_written,
				 uint32_t ex_chunk_bytes_written,
				 uint32_t ex_total_bytes_written)
{
	torture_assert_int_equal(torture, cc_rsp->chunks_written,
				 ex_chunks_written, "num chunks");
	torture_assert_int_equal(torture, cc_rsp->chunk_bytes_written,
				 ex_chunk_bytes_written, "chunk bytes written");
	torture_assert_int_equal(torture, cc_rsp->total_bytes_written,
				 ex_total_bytes_written, "chunk total bytes");
	return true;
}

static bool test_ioctl_copy_chunk_simple(struct torture_context *torture,
					 struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	bool ok;

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1, /* 1 chunk */
				   &src_h, 4096, /* fill 4096 byte src file */
				   &dest_h, 0,	/* 0 byte dest file */
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		return false;
	}

	/* copy all src file data (via a single chunk desc) */
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SRV_COPYCHUNK");

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");

	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  1,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  4096); /* total bytes written */
	if (!ok) {
		return false;
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 0);
	if (!ok) {
		return false;
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_multi(struct torture_context *torture,
					struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	bool ok;

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   2, /* chunks */
				   &src_h, 8192, /* src file */
				   &dest_h, 0,	/* dest file */
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		return false;
	}

	/* copy all src file data via two chunks */
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	cc_copy.chunks[1].source_off = 4096;
	cc_copy.chunks[1].target_off = 4096;
	cc_copy.chunks[1].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SRV_COPYCHUNK");

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");

	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  2,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  8192);	/* total bytes written */
	if (!ok) {
		return false;
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_tiny(struct torture_context *torture,
				       struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	bool ok;

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   2, /* chunks */
				   &src_h, 100, /* src file */
				   &dest_h, 0,	/* dest file */
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		return false;
	}

	/* copy all src file data via two chunks, sub block size chunks */
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 50;

	cc_copy.chunks[1].source_off = 50;
	cc_copy.chunks[1].target_off = 50;
	cc_copy.chunks[1].length = 50;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SRV_COPYCHUNK");

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");

	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  2,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  100);	/* total bytes written */
	if (!ok) {
		return false;
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 100, 0);
	if (!ok) {
		return false;
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_over(struct torture_context *torture,
				       struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	bool ok;

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   2, /* chunks */
				   &src_h, 8192, /* src file */
				   &dest_h, 4096, /* dest file */
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		return false;
	}

	/* first chunk overwrites existing dest data */
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	/* second chunk overwrites the first */
	cc_copy.chunks[1].source_off = 4096;
	cc_copy.chunks[1].target_off = 0;
	cc_copy.chunks[1].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SRV_COPYCHUNK");

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");

	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  2,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  8192); /* total bytes written */
	if (!ok) {
		return false;
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 4096);
	if (!ok) {
		return false;
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_append(struct torture_context *torture,
				       struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	bool ok;

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   2, /* chunks */
				   &src_h, 4096, /* src file */
				   &dest_h, 0,	/* dest file */
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		return false;
	}

	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	/* second chunk appends the same data to the first */
	cc_copy.chunks[1].source_off = 0;
	cc_copy.chunks[1].target_off = 4096;
	cc_copy.chunks[1].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SRV_COPYCHUNK");

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");

	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  2,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  8192); /* total bytes written */
	if (!ok) {
		return false;
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 0);
	if (!ok) {
		return false;
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 4096, 4096, 0);
	if (!ok) {
		return false;
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

/*
   basic testing of SMB2 ioctls
*/
struct torture_suite *torture_smb2_ioctl_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "ioctl");

	torture_suite_add_1smb2_test(suite, "shadow_copy",
				     test_ioctl_get_shadow_copy);
	torture_suite_add_1smb2_test(suite, "req_resume_key",
				     test_ioctl_req_resume_key);
	torture_suite_add_1smb2_test(suite, "copy_chunk_simple",
				     test_ioctl_copy_chunk_simple);
	torture_suite_add_1smb2_test(suite, "copy_chunk_multi",
				     test_ioctl_copy_chunk_multi);
	torture_suite_add_1smb2_test(suite, "copy_chunk_tiny",
				     test_ioctl_copy_chunk_tiny);
	torture_suite_add_1smb2_test(suite, "copy_chunk_overwrite",
				     test_ioctl_copy_chunk_over);
	torture_suite_add_1smb2_test(suite, "copy_chunk_append",
				     test_ioctl_copy_chunk_append);

	suite->description = talloc_strdup(suite, "SMB2-IOCTL tests");

	return suite;
}

