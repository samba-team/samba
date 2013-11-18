/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 ioctl operations

   Copyright (C) David Disseldorp 2011-2013

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
#define DNAME	"testfsctl_dir"

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
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)
	 || NT_STATUS_EQUAL(status, NT_STATUS_INVALID_DEVICE_REQUEST)) {
		torture_skip(torture, "FSCTL_SRV_ENUM_SNAPS not supported\n");
	}
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

static bool test_setup_create_fill(struct torture_context *torture,
				   struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
				   const char *fname,
				   struct smb2_handle *fh,
				   uint64_t size,
				   uint32_t desired_access,
				   uint32_t file_attributes)
{
	struct smb2_create io;
	NTSTATUS status;
	uint64_t i;
	uint8_t *buf = talloc_zero_size(mem_ctx, size);
	torture_assert(torture, (buf != NULL), "no memory for file data buf");

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(io);
	io.in.desired_access = desired_access;
	io.in.file_attributes = file_attributes;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	if (file_attributes & FILE_ATTRIBUTE_DIRECTORY) {
		io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	}
	io.in.fname = fname;

	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "file create");

	*fh = io.out.file.handle;

	if (size > 0) {
		uint64_t cur_off = 0;
		for (i = 0; i <= size - 8; i += 8) {
			SBVAL(buf, i, patt_hash(i));
		}
		while (size > 0) {
			uint64_t io_sz = MIN(1024 * 1024, size);
			status = smb2_util_write(tree, *fh,
						 buf + cur_off, cur_off, io_sz);
			torture_assert_ntstatus_ok(torture, status, "file write");

			size -= io_sz;
			cur_off += io_sz;
		}
	}
	return true;
}

static bool test_setup_copy_chunk(struct torture_context *torture,
				  struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
				  uint32_t nchunks,
				  struct smb2_handle *src_h,
				  uint64_t src_size,
				  uint32_t src_desired_access,
				  struct smb2_handle *dest_h,
				  uint64_t dest_size,
				  uint32_t dest_desired_access,
				  struct srv_copychunk_copy *cc_copy,
				  union smb_ioctl *ioctl)
{
	struct req_resume_key_rsp res_key;
	bool ok;
	NTSTATUS status;
	enum ndr_err_code ndr_ret;

	ok = test_setup_create_fill(torture, tree, mem_ctx, FNAME,
				    src_h, src_size, src_desired_access,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "src file create fill");

	ok = test_setup_create_fill(torture, tree, mem_ctx, FNAME2,
				    dest_h, dest_size, dest_desired_access,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "dest file create fill");

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
	torture_assert(torture, (cc_copy->chunks != NULL), "no memory for chunks");

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
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* 0 byte dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
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
		torture_fail(torture, "bad copy chunk response data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
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
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
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
		torture_fail(torture, "bad copy chunk response data");
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
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
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
		torture_fail(torture, "bad copy chunk response data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 100, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
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
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 4096, /* dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
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
		torture_fail(torture, "bad copy chunk response data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 4096);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
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
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
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
		torture_fail(torture, "bad copy chunk response data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 4096, 4096, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_limits(struct torture_context *torture,
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
				   1, /* chunks */
				   &src_h, 4096, /* src file */
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	/* send huge chunk length request */
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = UINT_MAX;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret, "marshalling request");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_INVALID_PARAMETER,
				      "bad oversize chunk response");

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret, "unmarshalling response");

	torture_comment(torture, "limit max chunks, got %u\n",
			cc_rsp.chunks_written);
	torture_comment(torture, "limit max chunk len, got %u\n",
			cc_rsp.chunk_bytes_written);
	torture_comment(torture, "limit max total bytes, got %u\n",
			cc_rsp.total_bytes_written);

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_src_lck(struct torture_context *torture,
					  struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle src_h2;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	bool ok;
	struct smb2_lock lck;
	struct smb2_lock_element el[1];

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1, /* chunks */
				   &src_h, 4096, /* src file */
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	/* open and lock the copychunk src file */
	status = torture_smb2_testfile(tree, FNAME, &src_h2);
	torture_assert_ntstatus_ok(torture, status, "2nd src open");

	lck.in.lock_count	= 0x0001;
	lck.in.lock_sequence	= 0x00000000;
	lck.in.file.handle	= src_h2;
	lck.in.locks		= el;
	el[0].offset		= cc_copy.chunks[0].source_off;
	el[0].length		= cc_copy.chunks[0].length;
	el[0].reserved		= 0;
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE;

	status = smb2_lock(tree, &lck);
	torture_assert_ntstatus_ok(torture, status, "lock");

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	/*
	 * 2k12 & Samba return lock_conflict, Windows 7 & 2k8 return success...
	 *
	 * Edgar Olougouna @ MS wrote:
	 * Regarding the FSCTL_SRV_COPYCHUNK and STATUS_FILE_LOCK_CONFLICT
	 * discrepancy observed between Windows versions, we confirm that the
	 * behavior change is expected.
	 *
	 * CopyChunk in Windows Server 2012 use regular Readfile/Writefile APIs
	 * to move the chunks from the source to the destination.
	 * These ReadFile/WriteFile APIs go through the byte-range lock checks,
	 * and this explains the observed STATUS_FILE_LOCK_CONFLICT error.
	 *
	 * Prior to Windows Server 2012, CopyChunk used mapped sections to move
	 * the data. And byte range locks are not enforced on mapped I/O, and
	 * this explains the STATUS_SUCCESS observed on Windows Server 2008 R2.
	 */
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_FILE_LOCK_CONFLICT,
				      "FSCTL_SRV_COPYCHUNK locked");

	/* should get cc response data with the lock conflict status */
	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");
	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  0,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  0);	/* total bytes written */

	lck.in.lock_count	= 0x0001;
	lck.in.lock_sequence	= 0x00000001;
	lck.in.file.handle	= src_h2;
	lck.in.locks		= el;
	el[0].offset		= cc_copy.chunks[0].source_off;
	el[0].length		= cc_copy.chunks[0].length;
	el[0].reserved		= 0;
	el[0].flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	torture_assert_ntstatus_ok(torture, status, "unlock");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status,
				   "FSCTL_SRV_COPYCHUNK unlocked");

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
		torture_fail(torture, "bad copy chunk response data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}

	smb2_util_close(tree, src_h2);
	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_dest_lck(struct torture_context *torture,
					   struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	struct smb2_handle dest_h2;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	bool ok;
	struct smb2_lock lck;
	struct smb2_lock_element el[1];

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1, /* chunks */
				   &src_h, 4096, /* src file */
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 4096,	/* dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	/* open and lock the copychunk dest file */
	status = torture_smb2_testfile(tree, FNAME2, &dest_h2);
	torture_assert_ntstatus_ok(torture, status, "2nd src open");

	lck.in.lock_count	= 0x0001;
	lck.in.lock_sequence	= 0x00000000;
	lck.in.file.handle	= dest_h2;
	lck.in.locks		= el;
	el[0].offset		= cc_copy.chunks[0].target_off;
	el[0].length		= cc_copy.chunks[0].length;
	el[0].reserved		= 0;
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE;

	status = smb2_lock(tree, &lck);
	torture_assert_ntstatus_ok(torture, status, "lock");

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_FILE_LOCK_CONFLICT,
				      "FSCTL_SRV_COPYCHUNK locked");

	lck.in.lock_count	= 0x0001;
	lck.in.lock_sequence	= 0x00000001;
	lck.in.file.handle	= dest_h2;
	lck.in.locks		= el;
	el[0].offset		= cc_copy.chunks[0].target_off;
	el[0].length		= cc_copy.chunks[0].length;
	el[0].reserved		= 0;
	el[0].flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	torture_assert_ntstatus_ok(torture, status, "unlock");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status,
				   "FSCTL_SRV_COPYCHUNK unlocked");

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
		torture_fail(torture, "bad copy chunk response data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}

	smb2_util_close(tree, dest_h2);
	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_bad_key(struct torture_context *torture,
					  struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	enum ndr_err_code ndr_ret;
	bool ok;

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1,
				   &src_h, 4096,
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	/* overwrite the resume key with a bogus value */
	memcpy(cc_copy.source_key, "deadbeefdeadbeefdeadbeef", 24);

	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	/* Server 2k12 returns NT_STATUS_OBJECT_NAME_NOT_FOUND */
	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_OBJECT_NAME_NOT_FOUND,
				      "FSCTL_SRV_COPYCHUNK");

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_src_is_dest(struct torture_context *torture,
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
				   1,
				   &src_h, 8192,
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	/* the source is also the destination */
	ioctl.smb2.in.file.handle = src_h;

	/* non-overlapping */
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 4096;
	cc_copy.chunks[0].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status,
				   "FSCTL_SRV_COPYCHUNK");

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
		torture_fail(torture, "bad copy chunk response data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, src_h, 0, 4096, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}
	ok = check_pattern(torture, tree, tmp_ctx, src_h, 4096, 4096, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

/*
 * Test a single-chunk copychunk request, where the source and target ranges
 * overlap, and the SourceKey refers to the same target file. E.g:
 *
 * Initial State
 * -------------
 * 	File:		src_and_dest
 * 	Offset:		0123456789
 * 	Data:		abcdefghij
 *
 * Request
 * -------
 * 	FSCTL_SRV_COPYCHUNK(src_and_dest)
 * 	SourceKey = SRV_REQUEST_RESUME_KEY(src_and_dest)
 * 	ChunkCount = 1
 * 	Chunks[0].SourceOffset = 0
 * 	Chunks[0].TargetOffset = 4
 * 	Chunks[0].Length = 6
 *
 * Resultant State
 * ---------------
 * 	File:		src_and_dest
 * 	Offset:		0123456789
 * 	Data:		abcdabcdef
 *
 * The resultant contents of src_and_dest is dependent on the server's
 * copy algorithm. In the above example, the server uses an IO buffer
 * large enough to hold the entire six-byte source data before writing
 * to TargetOffset. If the server were to use a four-byte IO buffer and
 * started reads/writes from the lowest offset, then the two overlapping
 * bytes in the above example would be overwritten before being read. The
 * resultant file contents would be abcdabcdab.
 *
 * Windows 2008r2 appears to use a 2048 byte copy buffer, overlapping bytes
 * after this offset are written before being read. Windows 2012 on the
 * other hand appears to use a buffer large enough to hold its maximum
 * supported chunk size (1M). Samba currently uses a 64k copy buffer by
 * default (vfs_cc_state.buf).
 *
 * This test uses an 8-byte overlap at 2040-2048, so that it passes against
 * Windows 2008r2, 2012 and Samba servers. Note, 2008GM fails, as it appears
 * to use a different copy algorithm to 2008r2.
 */
static bool
test_ioctl_copy_chunk_src_is_dest_overlap(struct torture_context *torture,
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

	/* exceed the vfs_default copy buffer */
	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1,
				   &src_h, 2048 * 2,
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	/* the source is also the destination */
	ioctl.smb2.in.file.handle = src_h;

	/* 8 bytes overlap between source and target ranges */
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 2048 - 8;
	cc_copy.chunks[0].length = 2048;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status,
				   "FSCTL_SRV_COPYCHUNK");

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");

	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  1,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  2048); /* total bytes written */
	if (!ok) {
		torture_fail(torture, "bad copy chunk response data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, src_h, 0, 2048 - 8, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}
	ok = check_pattern(torture, tree, tmp_ctx, src_h, 2048 - 8, 2048, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_bad_access(struct torture_context *torture,
					     struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	enum ndr_err_code ndr_ret;
	bool ok;

	/* no read permission on src */
	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1, /* 1 chunk */
				   &src_h, 4096, /* fill 4096 byte src file */
				   SEC_RIGHTS_FILE_WRITE,
				   &dest_h, 0,	/* 0 byte dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_ACCESS_DENIED,
				      "FSCTL_SRV_COPYCHUNK");

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);

	/* no write permission on dest */
	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1, /* 1 chunk */
				   &src_h, 4096, /* fill 4096 byte src file */
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* 0 byte dest file */
				   (SEC_RIGHTS_FILE_READ
				    | SEC_RIGHTS_FILE_EXECUTE),
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_ACCESS_DENIED,
				      "FSCTL_SRV_COPYCHUNK");

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);

	/* no read permission on dest */
	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1, /* 1 chunk */
				   &src_h, 4096, /* fill 4096 byte src file */
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* 0 byte dest file */
				   (SEC_RIGHTS_FILE_WRITE
				    | SEC_RIGHTS_FILE_EXECUTE),
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	/*
	 * FSCTL_SRV_COPYCHUNK requires read permission on dest,
	 * FSCTL_SRV_COPYCHUNK_WRITE on the other hand does not.
	 */
	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_ACCESS_DENIED,
				      "FSCTL_SRV_COPYCHUNK");

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);

	return true;
}

static bool test_ioctl_copy_chunk_write_access(struct torture_context *torture,
					       struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	enum ndr_err_code ndr_ret;
	bool ok;

	/* no read permission on dest with FSCTL_SRV_COPYCHUNK_WRITE */
	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1, /* 1 chunk */
				   &src_h, 4096, /* fill 4096 byte src file */
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* 0 byte dest file */
				   (SEC_RIGHTS_FILE_WRITE
				    | SEC_RIGHTS_FILE_EXECUTE),
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	ioctl.smb2.in.function = FSCTL_SRV_COPYCHUNK_WRITE;
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status,
				   "FSCTL_SRV_COPYCHUNK_WRITE");

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);

	return true;
}

static bool test_ioctl_copy_chunk_src_exceed(struct torture_context *torture,
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
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* 0 byte dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	/* Request copy where off + length exceeds size of src */
	cc_copy.chunks[0].source_off = 1024;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_INVALID_VIEW_SIZE,
				      "FSCTL_SRV_COPYCHUNK oversize");

	/* Request copy where length exceeds size of src */
	cc_copy.chunks[0].source_off = 1024;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 3072;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_ok(torture, status,
				   "FSCTL_SRV_COPYCHUNK just right");

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_pull_srv_copychunk_rsp");

	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  1,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  3072); /* total bytes written */
	if (!ok) {
		torture_fail(torture, "bad copy chunk response data");
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 3072, 1024);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool
test_ioctl_copy_chunk_src_exceed_multi(struct torture_context *torture,
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
				   2, /* 2 chunks */
				   &src_h, 8192, /* fill 8192 byte src file */
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* 0 byte dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	/* Request copy where off + length exceeds size of src */
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;

	cc_copy.chunks[1].source_off = 4096;
	cc_copy.chunks[1].target_off = 4096;
	cc_copy.chunks[1].length = 8192;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_INVALID_VIEW_SIZE,
				      "FSCTL_SRV_COPYCHUNK oversize");
	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, tmp_ctx,
				       &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_ndr_success(torture, ndr_ret, "unmarshalling response");

	/* first chunk should still be written */
	ok = check_copy_chunk_rsp(torture, &cc_rsp,
				  1,	/* chunks written */
				  0,	/* chunk bytes unsuccessfully written */
				  4096); /* total bytes written */
	if (!ok) {
		torture_fail(torture, "bad copy chunk response data");
	}
	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 0, 4096, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_copy_chunk_sparse_dest(struct torture_context *torture,
					      struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	struct smb2_read r;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	bool ok;
	int i;

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1, /* 1 chunk */
				   &src_h, 4096, /* fill 4096 byte src file */
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* 0 byte dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	/* copy all src file data (via a single chunk desc) */
	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 4096;
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
		torture_fail(torture, "bad copy chunk response data");
	}

	/* check for zeros in first 4k */
	ZERO_STRUCT(r);
	r.in.file.handle = dest_h;
	r.in.length      = 4096;
	r.in.offset      = 0;
	status = smb2_read(tree, tmp_ctx, &r);
	torture_assert_ntstatus_ok(torture, status, "read");

	torture_assert_u64_equal(torture, r.out.data.length, 4096,
				 "read data len mismatch");

	for (i = 0; i < 4096; i++) {
		torture_assert(torture, (r.out.data.data[i] == 0),
			       "sparse did not pass class");
	}

	ok = check_pattern(torture, tree, tmp_ctx, dest_h, 4096, 4096, 0);
	if (!ok) {
		torture_fail(torture, "inconsistent file data");
	}

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

/*
 * set the ioctl MaxOutputResponse size to less than
 * sizeof(struct srv_copychunk_rsp)
 */
static bool test_ioctl_copy_chunk_max_output_sz(struct torture_context *torture,
						struct smb2_tree *tree)
{
	struct smb2_handle src_h;
	struct smb2_handle dest_h;
	NTSTATUS status;
	union smb_ioctl ioctl;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	struct srv_copychunk_copy cc_copy;
	enum ndr_err_code ndr_ret;
	bool ok;

	ok = test_setup_copy_chunk(torture, tree, tmp_ctx,
				   1, /* 1 chunk */
				   &src_h, 4096, /* fill 4096 byte src file */
				   SEC_RIGHTS_FILE_ALL,
				   &dest_h, 0,	/* 0 byte dest file */
				   SEC_RIGHTS_FILE_ALL,
				   &cc_copy,
				   &ioctl);
	if (!ok) {
		torture_fail(torture, "setup copy chunk error");
	}

	cc_copy.chunks[0].source_off = 0;
	cc_copy.chunks[0].target_off = 0;
	cc_copy.chunks[0].length = 4096;
	/* req is valid, but use undersize max_response_size */
	ioctl.smb2.in.max_response_size = sizeof(struct srv_copychunk_rsp) - 1;

	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, tmp_ctx,
				       &cc_copy,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_ndr_success(torture, ndr_ret,
				   "ndr_push_srv_copychunk_copy");

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_INVALID_PARAMETER,
				      "FSCTL_SRV_COPYCHUNK");

	smb2_util_close(tree, src_h);
	smb2_util_close(tree, dest_h);
	talloc_free(tmp_ctx);
	return true;
}

static NTSTATUS test_ioctl_compress_fs_supported(struct torture_context *torture,
						 struct smb2_tree *tree,
						 TALLOC_CTX *mem_ctx,
						 struct smb2_handle *fh,
						 bool *compress_support)
{
	NTSTATUS status;
	union smb_fsinfo info;

	ZERO_STRUCT(info);
	info.generic.level = RAW_QFS_ATTRIBUTE_INFORMATION;
	info.generic.handle = *fh;
	status = smb2_getinfo_fs(tree, tree, &info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (info.attribute_info.out.fs_attr & FILE_FILE_COMPRESSION) {
		*compress_support = true;
	} else {
		*compress_support = false;
	}
	return NT_STATUS_OK;
}

static NTSTATUS test_ioctl_compress_get(struct torture_context *torture,
					TALLOC_CTX *mem_ctx,
					struct smb2_tree *tree,
					struct smb2_handle fh,
					uint16_t *_compression_fmt)
{
	union smb_ioctl ioctl;
	struct compression_state cmpr_state;
	enum ndr_err_code ndr_ret;
	NTSTATUS status;

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle = fh;
	ioctl.smb2.in.function = FSCTL_GET_COMPRESSION;
	ioctl.smb2.in.max_response_size = sizeof(struct compression_state);
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, mem_ctx, &ioctl.smb2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ndr_ret = ndr_pull_struct_blob(&ioctl.smb2.out.out, mem_ctx,
				       &cmpr_state,
			(ndr_pull_flags_fn_t)ndr_pull_compression_state);

	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	*_compression_fmt = cmpr_state.format;
	return NT_STATUS_OK;
}

static NTSTATUS test_ioctl_compress_set(struct torture_context *torture,
					TALLOC_CTX *mem_ctx,
					struct smb2_tree *tree,
					struct smb2_handle fh,
					uint16_t compression_fmt)
{
	union smb_ioctl ioctl;
	struct compression_state cmpr_state;
	enum ndr_err_code ndr_ret;
	NTSTATUS status;

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle = fh;
	ioctl.smb2.in.function = FSCTL_SET_COMPRESSION;
	ioctl.smb2.in.max_response_size = 0;
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	cmpr_state.format = compression_fmt;
	ndr_ret = ndr_push_struct_blob(&ioctl.smb2.in.out, mem_ctx,
				       &cmpr_state,
			(ndr_push_flags_fn_t)ndr_push_compression_state);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = smb2_ioctl(tree, mem_ctx, &ioctl.smb2);
	return status;
}

static bool test_ioctl_compress_file_flag(struct torture_context *torture,
					    struct smb2_tree *tree)
{
	struct smb2_handle fh;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	bool ok;
	uint16_t compression_fmt;

	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    FNAME, &fh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "setup compression file");

	status = test_ioctl_compress_fs_supported(torture, tree, tmp_ctx, &fh,
						  &ok);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FS");
	if (!ok) {
		smb2_util_close(tree, fh);
		torture_skip(torture, "FS compression not supported\n");
	}

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, fh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_NONE),
		       "initial compression state not NONE");

	status = test_ioctl_compress_set(torture, tmp_ctx, tree, fh,
					 COMPRESSION_FORMAT_DEFAULT);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SET_COMPRESSION");

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, fh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_LZNT1),
		       "invalid compression state after set");

	smb2_util_close(tree, fh);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_compress_dir_inherit(struct torture_context *torture,
					    struct smb2_tree *tree)
{
	struct smb2_handle dirh;
	struct smb2_handle fh;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	uint16_t compression_fmt;
	bool ok;
	char path_buf[PATH_MAX];

	smb2_deltree(tree, DNAME);
	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    DNAME, &dirh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_DIRECTORY);
	torture_assert(torture, ok, "setup compression directory");

	status = test_ioctl_compress_fs_supported(torture, tree, tmp_ctx, &dirh,
						  &ok);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FS");
	if (!ok) {
		smb2_util_close(tree, dirh);
		smb2_deltree(tree, DNAME);
		torture_skip(torture, "FS compression not supported\n");
	}

	/* set compression on parent dir, then check for inheritance */
	status = test_ioctl_compress_set(torture, tmp_ctx, tree, dirh,
					 COMPRESSION_FORMAT_LZNT1);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SET_COMPRESSION");

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, dirh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_LZNT1),
		       "invalid compression state after set");

	snprintf(path_buf, PATH_MAX, "%s\\%s", DNAME, FNAME);
	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    path_buf, &fh, 4096, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "setup compression file");

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, fh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_LZNT1),
		       "compression attr not inherited by new file");

	/* check compressed data is consistent */
	ok = check_pattern(torture, tree, tmp_ctx, fh, 0, 4096, 0);

	/* disable dir compression attr, file should remain compressed */
	status = test_ioctl_compress_set(torture, tmp_ctx, tree, dirh,
					 COMPRESSION_FORMAT_NONE);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SET_COMPRESSION");

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, fh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_LZNT1),
		       "file compression attr removed after dir change");
	smb2_util_close(tree, fh);

	/* new files should no longer inherit compression attr */
	snprintf(path_buf, PATH_MAX, "%s\\%s", DNAME, FNAME2);
	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    path_buf, &fh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "setup file");

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, fh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_NONE),
		       "compression attr present on new file");

	smb2_util_close(tree, fh);
	smb2_util_close(tree, dirh);
	smb2_deltree(tree, DNAME);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_compress_invalid_format(struct torture_context *torture,
					       struct smb2_tree *tree)
{
	struct smb2_handle fh;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	bool ok;
	uint16_t compression_fmt;

	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    FNAME, &fh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "setup compression file");

	status = test_ioctl_compress_fs_supported(torture, tree, tmp_ctx, &fh,
						  &ok);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FS");
	if (!ok) {
		smb2_util_close(tree, fh);
		torture_skip(torture, "FS compression not supported\n");
	}

	status = test_ioctl_compress_set(torture, tmp_ctx, tree, fh,
					 0x0042); /* bogus */
	torture_assert_ntstatus_equal(torture, status,
				      NT_STATUS_INVALID_PARAMETER,
				      "invalid FSCTL_SET_COMPRESSION");

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, fh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_NONE),
		       "initial compression state not NONE");

	smb2_util_close(tree, fh);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_compress_invalid_buf(struct torture_context *torture,
					    struct smb2_tree *tree)
{
	struct smb2_handle fh;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	bool ok;
	union smb_ioctl ioctl;

	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    FNAME, &fh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "setup compression file");

	status = test_ioctl_compress_fs_supported(torture, tree, tmp_ctx, &fh,
						  &ok);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FS");
	if (!ok) {
		smb2_util_close(tree, fh);
		torture_skip(torture, "FS compression not supported\n");
	}

	ZERO_STRUCT(ioctl);
	ioctl.smb2.level = RAW_IOCTL_SMB2;
	ioctl.smb2.in.file.handle = fh;
	ioctl.smb2.in.function = FSCTL_GET_COMPRESSION;
	ioctl.smb2.in.max_response_size = 0;	/* no room for rsp data */
	ioctl.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;

	status = smb2_ioctl(tree, tmp_ctx, &ioctl.smb2);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_USER_BUFFER)
	 && !NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		/* neither Server 2k12 nor 2k8r2 response status */
		torture_assert(torture, true,
			       "invalid FSCTL_SET_COMPRESSION");
	}

	smb2_util_close(tree, fh);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_compress_query_file_attr(struct torture_context *torture,
						struct smb2_tree *tree)
{
	struct smb2_handle fh;
	union smb_fileinfo io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	bool ok;

	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    FNAME, &fh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "setup compression file");

	status = test_ioctl_compress_fs_supported(torture, tree, tmp_ctx, &fh,
						  &ok);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FS");
	if (!ok) {
		smb2_util_close(tree, fh);
		torture_skip(torture, "FS compression not supported\n");
	}

	ZERO_STRUCT(io);
	io.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	io.generic.in.file.handle = fh;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FILE");

	torture_assert(torture,
		((io.all_info2.out.attrib & FILE_ATTRIBUTE_COMPRESSED) == 0),
		       "compression attr before set");

	status = test_ioctl_compress_set(torture, tmp_ctx, tree, fh,
					 COMPRESSION_FORMAT_DEFAULT);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SET_COMPRESSION");

	ZERO_STRUCT(io);
	io.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	io.generic.in.file.handle = fh;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FILE");

	torture_assert(torture,
		       (io.basic_info.out.attrib & FILE_ATTRIBUTE_COMPRESSED),
		       "no compression attr after set");

	smb2_util_close(tree, fh);
	talloc_free(tmp_ctx);
	return true;
}

/*
 * Specify FILE_ATTRIBUTE_COMPRESSED on creation, Windows does not retain this
 * attribute.
 */
static bool test_ioctl_compress_create_with_attr(struct torture_context *torture,
						 struct smb2_tree *tree)
{
	struct smb2_handle fh2;
	union smb_fileinfo io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	uint16_t compression_fmt;
	bool ok;

	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    FNAME2, &fh2, 0, SEC_RIGHTS_FILE_ALL,
			(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_COMPRESSED));
	torture_assert(torture, ok, "setup compression file");

	status = test_ioctl_compress_fs_supported(torture, tree, tmp_ctx, &fh2,
						  &ok);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FS");
	if (!ok) {
		smb2_util_close(tree, fh2);
		torture_skip(torture, "FS compression not supported\n");
	}

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, fh2,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_NONE),
		       "initial compression state not NONE");

	ZERO_STRUCT(io);
	io.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	io.generic.in.file.handle = fh2;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FILE");

	torture_assert(torture,
		((io.all_info2.out.attrib & FILE_ATTRIBUTE_COMPRESSED) == 0),
		       "incorrect compression attr");

	smb2_util_close(tree, fh2);
	talloc_free(tmp_ctx);
	return true;
}

static bool test_ioctl_compress_inherit_disable(struct torture_context *torture,
						struct smb2_tree *tree)
{
	struct smb2_handle fh;
	struct smb2_handle dirh;
	char path_buf[PATH_MAX];
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	bool ok;
	uint16_t compression_fmt;

	struct smb2_create io;

	smb2_deltree(tree, DNAME);
	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    DNAME, &dirh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_DIRECTORY);
	torture_assert(torture, ok, "setup compression directory");

	status = test_ioctl_compress_fs_supported(torture, tree, tmp_ctx, &dirh,
						  &ok);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FS");
	if (!ok) {
		smb2_util_close(tree, dirh);
		smb2_deltree(tree, DNAME);
		torture_skip(torture, "FS compression not supported\n");
	}

	/* set compression on parent dir, then check for inheritance */
	status = test_ioctl_compress_set(torture, tmp_ctx, tree, dirh,
					 COMPRESSION_FORMAT_LZNT1);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_SET_COMPRESSION");

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, dirh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_LZNT1),
		       "invalid compression state after set");
	smb2_util_close(tree, dirh);

	snprintf(path_buf, PATH_MAX, "%s\\%s", DNAME, FNAME);
	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    path_buf, &fh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "setup compression file");

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, fh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_LZNT1),
		       "compression attr not inherited by new file");
	smb2_util_close(tree, fh);

	snprintf(path_buf, PATH_MAX, "%s\\%s", DNAME, FNAME2);

	/* NO_COMPRESSION option should block inheritance */
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.create_options = NTCREATEX_OPTIONS_NO_COMPRESSION;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.fname = path_buf;

	status = smb2_create(tree, tmp_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "file create");

	fh = io.out.file.handle;

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, fh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_NONE),
		       "compression attr inherited by NO_COMPRESSION file");
	smb2_util_close(tree, fh);


	snprintf(path_buf, PATH_MAX, "%s\\%s", DNAME, DNAME);
	ZERO_STRUCT(io);
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.create_options = (NTCREATEX_OPTIONS_NO_COMPRESSION
				| NTCREATEX_OPTIONS_DIRECTORY);
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.fname = path_buf;

	status = smb2_create(tree, tmp_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "dir create");

	dirh = io.out.file.handle;

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, dirh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_NONE),
		       "compression attr inherited by NO_COMPRESSION dir");
	smb2_util_close(tree, dirh);
	smb2_deltree(tree, DNAME);

	talloc_free(tmp_ctx);
	return true;
}

/* attempting to set compression via SetInfo should not stick */
static bool test_ioctl_compress_set_file_attr(struct torture_context *torture,
					      struct smb2_tree *tree)
{
	struct smb2_handle fh;
	struct smb2_handle dirh;
	union smb_fileinfo io;
	union smb_setfileinfo set_io;
	uint16_t compression_fmt;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	bool ok;

	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    FNAME, &fh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_NORMAL);
	torture_assert(torture, ok, "setup compression file");

	status = test_ioctl_compress_fs_supported(torture, tree, tmp_ctx, &fh,
						  &ok);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FS");
	if (!ok) {
		smb2_util_close(tree, fh);
		torture_skip(torture, "FS compression not supported\n");
	}

	ZERO_STRUCT(io);
	io.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	io.generic.in.file.handle = fh;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FILE");

	torture_assert(torture,
		((io.basic_info.out.attrib & FILE_ATTRIBUTE_COMPRESSED) == 0),
		       "compression attr before set");

	ZERO_STRUCT(set_io);
	set_io.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	set_io.basic_info.in.file.handle = fh;
	set_io.basic_info.in.create_time = io.basic_info.out.create_time;
	set_io.basic_info.in.access_time = io.basic_info.out.access_time;
	set_io.basic_info.in.write_time = io.basic_info.out.write_time;
	set_io.basic_info.in.change_time = io.basic_info.out.change_time;
	set_io.basic_info.in.attrib = (io.basic_info.out.attrib
						| FILE_ATTRIBUTE_COMPRESSED);
	status = smb2_setinfo_file(tree, &set_io);
	torture_assert_ntstatus_ok(torture, status, "SMB2_SETINFO_FILE");

	ZERO_STRUCT(io);
	io.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	io.generic.in.file.handle = fh;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FILE");

	torture_assert(torture,
		((io.basic_info.out.attrib & FILE_ATTRIBUTE_COMPRESSED) == 0),
		"compression attr after set");

	smb2_util_close(tree, fh);
	smb2_deltree(tree, DNAME);
	ok = test_setup_create_fill(torture, tree, tmp_ctx,
				    DNAME, &dirh, 0, SEC_RIGHTS_FILE_ALL,
				    FILE_ATTRIBUTE_DIRECTORY);
	torture_assert(torture, ok, "setup compression directory");

	ZERO_STRUCT(io);
	io.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	io.generic.in.file.handle = dirh;
	status = smb2_getinfo_file(tree, tmp_ctx, &io);
	torture_assert_ntstatus_ok(torture, status, "SMB2_GETINFO_FILE");

	torture_assert(torture,
		((io.basic_info.out.attrib & FILE_ATTRIBUTE_COMPRESSED) == 0),
		       "compression attr before set");

	ZERO_STRUCT(set_io);
	set_io.generic.level = RAW_FILEINFO_BASIC_INFORMATION;
	set_io.basic_info.in.file.handle = dirh;
	set_io.basic_info.in.create_time = io.basic_info.out.create_time;
	set_io.basic_info.in.access_time = io.basic_info.out.access_time;
	set_io.basic_info.in.write_time = io.basic_info.out.write_time;
	set_io.basic_info.in.change_time = io.basic_info.out.change_time;
	set_io.basic_info.in.attrib = (io.basic_info.out.attrib
						| FILE_ATTRIBUTE_COMPRESSED);
	status = smb2_setinfo_file(tree, &set_io);
	torture_assert_ntstatus_ok(torture, status, "SMB2_SETINFO_FILE");

	status = test_ioctl_compress_get(torture, tmp_ctx, tree, dirh,
					 &compression_fmt);
	torture_assert_ntstatus_ok(torture, status, "FSCTL_GET_COMPRESSION");

	torture_assert(torture, (compression_fmt == COMPRESSION_FORMAT_NONE),
		       "dir compression set after SetInfo");

	smb2_util_close(tree, dirh);
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
	torture_suite_add_1smb2_test(suite, "copy_chunk_limits",
				     test_ioctl_copy_chunk_limits);
	torture_suite_add_1smb2_test(suite, "copy_chunk_src_lock",
				     test_ioctl_copy_chunk_src_lck);
	torture_suite_add_1smb2_test(suite, "copy_chunk_dest_lock",
				     test_ioctl_copy_chunk_dest_lck);
	torture_suite_add_1smb2_test(suite, "copy_chunk_bad_key",
				     test_ioctl_copy_chunk_bad_key);
	torture_suite_add_1smb2_test(suite, "copy_chunk_src_is_dest",
				     test_ioctl_copy_chunk_src_is_dest);
	torture_suite_add_1smb2_test(suite, "copy_chunk_src_is_dest_overlap",
				     test_ioctl_copy_chunk_src_is_dest_overlap);
	torture_suite_add_1smb2_test(suite, "copy_chunk_bad_access",
				     test_ioctl_copy_chunk_bad_access);
	torture_suite_add_1smb2_test(suite, "copy_chunk_write_access",
				     test_ioctl_copy_chunk_write_access);
	torture_suite_add_1smb2_test(suite, "copy_chunk_src_exceed",
				     test_ioctl_copy_chunk_src_exceed);
	torture_suite_add_1smb2_test(suite, "copy_chunk_src_exceed_multi",
				     test_ioctl_copy_chunk_src_exceed_multi);
	torture_suite_add_1smb2_test(suite, "copy_chunk_sparse_dest",
				     test_ioctl_copy_chunk_sparse_dest);
	torture_suite_add_1smb2_test(suite, "copy_chunk_max_output_sz",
				     test_ioctl_copy_chunk_max_output_sz);
	torture_suite_add_1smb2_test(suite, "compress_file_flag",
				     test_ioctl_compress_file_flag);
	torture_suite_add_1smb2_test(suite, "compress_dir_inherit",
				     test_ioctl_compress_dir_inherit);
	torture_suite_add_1smb2_test(suite, "compress_invalid_format",
				     test_ioctl_compress_invalid_format);
	torture_suite_add_1smb2_test(suite, "compress_invalid_buf",
				     test_ioctl_compress_invalid_buf);
	torture_suite_add_1smb2_test(suite, "compress_query_file_attr",
				     test_ioctl_compress_query_file_attr);
	torture_suite_add_1smb2_test(suite, "compress_create_with_attr",
				     test_ioctl_compress_create_with_attr);
	torture_suite_add_1smb2_test(suite, "compress_inherit_disable",
				     test_ioctl_compress_inherit_disable);
	torture_suite_add_1smb2_test(suite, "compress_set_file_attr",
				     test_ioctl_compress_set_file_attr);

	suite->description = talloc_strdup(suite, "SMB2-IOCTL tests");

	return suite;
}

