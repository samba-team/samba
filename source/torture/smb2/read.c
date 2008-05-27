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

#include "torture/torture.h"
#include "torture/smb2/proto.h"

#include "librpc/gen_ndr/ndr_security.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d - should be %d\n", \
		       __location__, #v, v, correct); \
		ret = false; \
		goto done; \
	}} while (0)

static bool test_read(struct torture_context *torture, struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle h;
	uint8_t buf[70000];
	struct smb2_read rd;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(buf);

	status = torture_smb2_testfile(tree, "lock1.txt", &h);
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

/* basic testing of SMB2 read
*/
struct torture_suite *torture_smb2_read_init(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "READ");

	torture_suite_add_1smb2_test(suite, "READ", test_read);

	suite->description = talloc_strdup(suite, "SMB2-READ tests");

	return suite;
}

