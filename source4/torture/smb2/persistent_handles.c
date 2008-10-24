/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 persistent file handles

   Copyright (C) Stefan Metzmacher 2008

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

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s got 0x%x - should be 0x%x\n", \
				__location__, #v, (int)v, (int)correct); \
		ret = false; \
	}} while (0)

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": Incorrect status %s - should be %s", \
		       nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

/* 
   basic testing of SMB2 persistent file handles
   regarding the position information on the handle
*/
bool torture_smb2_persistent_handles1(struct torture_context *tctx,
				      struct smb2_tree *tree1,
				      struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle h1, h2;
	struct smb2_create io1, io2;
	NTSTATUS status;
	const char *fname = "persistent_handles.dat";
	DATA_BLOB b;
	union smb_fileinfo qfinfo;
	union smb_setfileinfo sfinfo;
	bool ret = true;
	uint64_t pos;

	smb2_util_unlink(tree1, fname);

	ZERO_STRUCT(io1);
	io1.in.security_flags		= 0x00;
	io1.in.oplock_level		= SMB2_OPLOCK_LEVEL_BATCH;
	io1.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	io1.in.create_flags		= 0x00000000;
	io1.in.reserved			= 0x00000000;
	io1.in.desired_access		= SEC_RIGHTS_FILE_ALL;
	io1.in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	io1.in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
					  NTCREATEX_SHARE_ACCESS_WRITE |
					  NTCREATEX_SHARE_ACCESS_DELETE;
	io1.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	io1.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	io1.in.fname			= fname;

	b = data_blob_talloc(mem_ctx, NULL, 16);
	SBVAL(b.data, 0, 0);
	SBVAL(b.data, 8, 0);

	status = smb2_create_blob_add(tree1, &io1.in.blobs,
				      SMB2_CREATE_TAG_DHNQ,
				      b);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);
	/*CHECK_VAL(io1.out.reserved, 0);*/
	CHECK_VAL(io1.out.create_action, NTCREATEX_ACTION_CREATED);
	CHECK_VAL(io1.out.alloc_size, 0);
	CHECK_VAL(io1.out.size, 0);
	CHECK_VAL(io1.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.reserved2, 0);

	/* TODO: check extra blob content */

	h1 = io1.out.file.handle;

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0);
	pos = qfinfo.position_information.out.position;
	torture_comment(tctx, "position: %llu\n",
			(unsigned long long)pos);

	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_POSITION_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	sfinfo.position_information.in.position = 0x1000;
	status = smb2_setinfo_file(tree1, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0x1000);
	pos = qfinfo.position_information.out.position;
	torture_comment(tctx, "position: %llu\n",
			(unsigned long long)pos);

	talloc_free(tree1);
	tree1 = NULL;

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree2, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);

	ZERO_STRUCT(io2);
	io2.in.fname = fname;

	b = data_blob_talloc(tctx, NULL, 16);
	SBVAL(b.data, 0, h1.data[0]);
	SBVAL(b.data, 8, h1.data[1]);

	status = smb2_create_blob_add(tree2, &io2.in.blobs,
				      SMB2_CREATE_TAG_DHNC,
				      b);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);
	CHECK_VAL(io2.out.reserved, 0x00);
	CHECK_VAL(io2.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io2.out.alloc_size, 0);
	CHECK_VAL(io2.out.size, 0);
	CHECK_VAL(io2.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.reserved2, 0);

	h2 = io2.out.file.handle;

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h2;
	status = smb2_getinfo_file(tree2, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0x1000);
	pos = qfinfo.position_information.out.position;
	torture_comment(tctx, "position: %llu\n",
			(unsigned long long)pos);

	smb2_util_close(tree2, h2);

	talloc_free(mem_ctx);

	smb2_util_unlink(tree2, fname);
done:
	return ret;
}
