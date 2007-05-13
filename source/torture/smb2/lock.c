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

#include "librpc/gen_ndr/ndr_security.h"

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

static BOOL test_valid_request(struct torture_context *torture, struct smb2_tree *tree)
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

static BOOL test_block_write(struct torture_context *torture, struct smb2_tree *tree)
{
	BOOL ret = True;
	NTSTATUS status;
	struct smb2_handle h1, h2;
	uint8_t buf[200];
	struct smb2_lock lck;
	struct smb2_create cr;
	struct smb2_write wr;
	const char *fname = "lock2.txt";

	ZERO_STRUCT(buf);

	status = torture_smb2_testfile(tree, fname, &h1);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_write(tree, h1, buf, 0, ARRAY_SIZE(buf));
	CHECK_STATUS(status, NT_STATUS_OK);

	lck.in.unknown1		= 0x0001;
	lck.in.unknown2		= 0x00000000;
	lck.in.file.handle	= h1;
	lck.in.offset		= 0;
	lck.in.count		= ARRAY_SIZE(buf)/2;
	lck.in.unknown5		= 0x00000000;
	lck.in.flags		= SMB2_LOCK_FLAG_EXCLUSIV;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	lck.in.unknown1		= 0x0001;
	lck.in.unknown2		= 0x00000000;
	lck.in.file.handle	= h1;
	lck.in.offset		= ARRAY_SIZE(buf)/2;
	lck.in.count		= ARRAY_SIZE(buf)/2;
	lck.in.unknown5		= 0x00000000;
	lck.in.flags		= SMB2_LOCK_FLAG_EXCLUSIV;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	ZERO_STRUCT(cr);
	cr.in.oplock_flags = 0;
	cr.in.access_mask = SEC_RIGHTS_FILE_ALL;
	cr.in.file_attr   = FILE_ATTRIBUTE_NORMAL;
	cr.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	cr.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	cr.in.create_options = 0;
	cr.in.fname = fname;

	status = smb2_create(tree, tree, &cr);
	CHECK_STATUS(status, NT_STATUS_OK);

	h2 = cr.out.file.handle;


	ZERO_STRUCT(wr);
	wr.in.file.handle = h1;
	wr.in.offset      = ARRAY_SIZE(buf)/2;
	wr.in.data        = data_blob_const(buf, ARRAY_SIZE(buf)/2);

	status = smb2_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(wr);
	wr.in.file.handle = h2;
	wr.in.offset      = ARRAY_SIZE(buf)/2;
	wr.in.data        = data_blob_const(buf, ARRAY_SIZE(buf)/2);

	status = smb2_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_FILE_LOCK_CONFLICT);

	lck.in.unknown1		= 0x0001;
	lck.in.unknown2		= 0x00000000;
	lck.in.file.handle	= h1;
	lck.in.offset		= ARRAY_SIZE(buf)/2;
	lck.in.count		= ARRAY_SIZE(buf)/2;
	lck.in.unknown5		= 0x00000000;
	lck.in.flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(lck.out.unknown1, 0);

	ZERO_STRUCT(wr);
	wr.in.file.handle = h2;
	wr.in.offset      = ARRAY_SIZE(buf)/2;
	wr.in.data        = data_blob_const(buf, ARRAY_SIZE(buf)/2);

	status = smb2_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	return ret;
}

/* basic testing of SMB2 locking
*/
struct torture_suite *torture_smb2_lock_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "LOCK");

	torture_suite_add_1smb2_test(suite, "VALID-REQUEST", test_valid_request);
	torture_suite_add_1smb2_test(suite, "BLOCK-WRITE", test_block_write);

	suite->description = talloc_strdup(suite, "SMB2-LOCK tests");

	return suite;
}

