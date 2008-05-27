/* 
   Unix SMB/CIFS implementation.

   SMB2 create test suite

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
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_security.h"

#define FNAME "test_create.dat"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		return false; \
	}} while (0)

#define CHECK_EQUAL(v, correct) do { \
	if (v != correct) { \
		printf("(%s) Incorrect value for %s 0x%08x - should be 0x%08x\n", \
		       __location__, #v, v, correct); \
		return false; \
	}} while (0)

/*
  test some interesting combinations found by gentest
 */
bool torture_smb2_create_gentest(struct torture_context *torture, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);
	uint32_t access_mask, file_attributes, denied_mask;

	ZERO_STRUCT(io);
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes    = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = FNAME;

	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.create_options = 0xF0000000;
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	io.in.create_options = 0x00100000;
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_NOT_SUPPORTED);

	io.in.create_options = 0xF0100000;
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_NOT_SUPPORTED);

	io.in.create_options = 0;

	io.in.file_attributes = FILE_ATTRIBUTE_DEVICE;
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	io.in.file_attributes = FILE_ATTRIBUTE_VOLUME;
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.file_attributes = FILE_ATTRIBUTE_VOLUME;
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
	
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.desired_access = 0x08000000;
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	io.in.desired_access = 0x04000000;
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.file_attributes = 0;
	access_mask = 0;
	{
		int i;
		for (i=0;i<32;i++) {
			io.in.desired_access = 1<<i;
			status = smb2_create(tree, tmp_ctx, &io);
			if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
				access_mask |= io.in.desired_access;
			} else {
				CHECK_STATUS(status, NT_STATUS_OK);
				status = smb2_util_close(tree, io.out.file.handle);
				CHECK_STATUS(status, NT_STATUS_OK);
			}
		}
	}

	CHECK_EQUAL(access_mask, 0x0df0fe00);

	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes = 0;
	access_mask = 0;
	denied_mask = 0;
	{
		int i;
		for (i=0;i<32;i++) {
			io.in.file_attributes = 1<<i;
			smb2_deltree(tree, FNAME);
			status = smb2_create(tree, tmp_ctx, &io);
			if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
				file_attributes |= io.in.file_attributes;
			} else if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
				denied_mask |= io.in.file_attributes;
			} else {
				CHECK_STATUS(status, NT_STATUS_OK);
				status = smb2_util_close(tree, io.out.file.handle);
				CHECK_STATUS(status, NT_STATUS_OK);
			}
		}
	}

	CHECK_EQUAL(file_attributes, 0xffff87c8);
	CHECK_EQUAL(denied_mask, 0x4000);

	smb2_deltree(tree, FNAME);

	ZERO_STRUCT(io);
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes    = 0;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = FNAME ":stream1";
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.fname = FNAME;
	io.in.file_attributes = 0x8040;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ;
	status = smb2_create(tree, tmp_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	talloc_free(tmp_ctx);
	
	return true;
}

/* 
   basic testing of SMB2 create calls
*/
bool torture_smb2_create(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	bool ret = true;

	if (!torture_smb2_connection(torture, &tree)) {
		return false;
	}

	ret &= torture_smb2_create_gentest(torture, tree);

	smb2_deltree(tree, FNAME);

	talloc_free(mem_ctx);

	return ret;
}
