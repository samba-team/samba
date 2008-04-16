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
#include "param/param.h"

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
	struct smb2_create io;
	NTSTATUS status;
	const char *fname = "persistent_handles.dat";
	DATA_BLOB b;
	union smb_fileinfo qfinfo;
	union smb_setfileinfo sfinfo;
	bool ret = true;

	ZERO_STRUCT(io);
	io.in.security_flags		= 0x00;
	io.in.oplock_level		= SMB2_OPLOCK_LEVEL_BATCH;
	io.in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	io.in.create_flags		= 0x00000000;
	io.in.reserved			= 0x00000000;
	io.in.desired_access		= SEC_RIGHTS_FILE_READ;
	io.in.file_attributes		= 0x00000000;
	io.in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
					  NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	io.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	io.in.fname			= fname;

	b = data_blob_talloc(mem_ctx, NULL, 16);
	SBVAL(b.data, 0, 0);
	SBVAL(b.data, 8, 0);

	status = smb2_create_blob_add(tree1, &io.in.blobs,
				      SMB2_CREATE_TAG_DHNQ,
				      b);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	h1 = io.out.file.handle;

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0);
	printf("position: %llu\n",
	       (unsigned long long)qfinfo.position_information.out.position);

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
	printf("position: %llu\n",
	       (unsigned long long)qfinfo.position_information.out.position);

	talloc_free(tree1);
	tree1 = NULL;

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree2, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);

	ZERO_STRUCT(io);
	io.in.fname = fname;

	b = data_blob_talloc(tctx, NULL, 16);
	SBVAL(b.data, 0, h1.data[0]);
	SBVAL(b.data, 8, h1.data[1]);

	status = smb2_create_blob_add(tree2, &io.in.blobs,
				      SMB2_CREATE_TAG_DHNC,
				      b);
	CHECK_STATUS(status, NT_STATUS_OK);
	if (!NT_STATUS_IS_OK(status)) {
		printf("create1 failed - %s\n", nt_errstr(status));
		return false;
	}

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	h2 = io.out.file.handle;

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h2;
	status = smb2_getinfo_file(tree2, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0x1000);
	printf("position: %llu\n",
	       (unsigned long long)qfinfo.position_information.out.position);

	talloc_free(mem_ctx);

done:
	return ret;
}
