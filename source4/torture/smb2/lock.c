/* 
   Unix SMB/CIFS implementation.

   SMB2 lock test suite

   Copyright (C) Stefan Metzmacher 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

#include "torture/torture.h"
#include "torture/smb2/proto.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d - should be %d\n", \
		       __location__, #v, v, correct); \
		ret = False; \
		goto done; \
	}} while (0)

static BOOL test_valid_request(TALLOC_CTX *mem_ctx, struct smb2_tree *tree)
{
	BOOL ret = True;
	NTSTATUS status;
	struct smb2_handle h;
	uint8_t buf[200];
	struct smb2_lock lck;

	ZERO_STRUCT(buf);

	status = torture_smb2_testfile(tree, "lock1.txt", &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_write(tree, h, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_OK);

	lck.in.unknown1		= 0x0000;
	lck.in.unknown2		= 0x00000000;
	lck.in.file.handle	= h;
	lck.in.offset		= 0x0000000000000000;
	lck.in.count		= 0x0000000000000000;
	lck.in.unknown5		= 0x0000000000000000;
	lck.in.flags		= 0x00000000;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	lck.in.unknown1		= 0x0001;
	lck.in.unknown2		= 0x00000000;
	lck.in.file.handle	= h;
	lck.in.offset		= 0;
	lck.in.count		= 0;
	lck.in.unknown5		= 0x00000000;
	lck.in.flags		= SMB2_LOCK_FLAG_NONE;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	lck.in.file.handle.data[0] +=1;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	lck.in.file.handle.data[0] -=1;

	lck.in.unknown1		= 0x0001;
	lck.in.unknown2		= 0xFFFFFFFF;
	lck.in.file.handle	= h;
	lck.in.offset		= UINT64_MAX;
	lck.in.count		= UINT64_MAX;
	lck.in.unknown5		= 0x00000000;
	lck.in.flags		= SMB2_LOCK_FLAG_EXCLUSIV;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	lck.in.unknown1		= 0x0001;
	lck.in.unknown2		= 0x12345678;
	lck.in.file.handle	= h;
	lck.in.offset		= UINT32_MAX;
	lck.in.count		= UINT32_MAX;
	lck.in.unknown5		= 0x87654321;
	lck.in.flags		= SMB2_LOCK_FLAG_EXCLUSIV;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_LOCK_NOT_GRANTED);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	lck.in.flags		= 0x00000000;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	lck.in.flags		= 0x00000001;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	lck.in.unknown1		= 0x0001;
	lck.in.unknown2		= 0x87654321;
	lck.in.file.handle	= h;
	lck.in.offset		= 0x00000000FFFFFFFF;
	lck.in.count		= 0x00000000FFFFFFFF;
	lck.in.unknown5		= 0x12345678;
	lck.in.flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	lck.in.unknown1		= 0x0001;
	lck.in.unknown2		= 0x12345678;
	lck.in.file.handle	= h;
	lck.in.offset		= 0x00000000FFFFFFFF;
	lck.in.count		= 0x00000000FFFFFFFF;
	lck.in.unknown5		= 0x00000000;
	lck.in.flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_RANGE_NOT_LOCKED);

done:
	return ret;
}

/* basic testing of SMB2 locking
*/
BOOL torture_smb2_lock(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	BOOL ret = True;

	if (!torture_smb2_connection(mem_ctx, &tree)) {
		return False;
	}

	ret &= test_valid_request(mem_ctx, tree);

	talloc_free(mem_ctx);

	return ret;
}
