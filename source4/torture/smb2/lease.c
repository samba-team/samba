/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 leases

   Copyright (C) Zachary Loafman 2009

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

static void smb2_lease_create(struct smb2_create *io, struct smb2_lease *ls,
                              bool dir, const char *name, uint64_t leasekey,
                              uint32_t leasestate)
{
	ZERO_STRUCT(*io);
	io->in.security_flags		= 0x00;
	io->in.oplock_level		= SMB2_OPLOCK_LEVEL_LEASE;
	io->in.impersonation_level	= NTCREATEX_IMPERSONATION_IMPERSONATION;
	io->in.create_flags		= 0x00000000;
	io->in.reserved			= 0x00000000;
	io->in.desired_access		= SEC_RIGHTS_FILE_ALL;
	io->in.file_attributes		= FILE_ATTRIBUTE_NORMAL;
	io->in.share_access		= NTCREATEX_SHARE_ACCESS_READ |
					  NTCREATEX_SHARE_ACCESS_WRITE |
					  NTCREATEX_SHARE_ACCESS_DELETE;
	io->in.create_disposition	= NTCREATEX_DISP_OPEN_IF;
	io->in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	io->in.fname			= name;

	if (dir) {
		io->in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		io->in.share_access &= ~NTCREATEX_SHARE_ACCESS_DELETE;
		io->in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
		io->in.create_disposition = NTCREATEX_DISP_CREATE;
	}

	ZERO_STRUCT(*ls);
	ls->lease_key[0] = leasekey;
	ls->lease_key[1] = ~leasekey;
	ls->lease_state = leasestate;
	io->in.lease_request = ls;
}

#define CHECK_CREATED(__io, __created, __attribute)			\
	do {								\
		if (__created) {					\
			CHECK_VAL((__io)->out.create_action, NTCREATEX_ACTION_CREATED);	\
		} else {						\
			CHECK_VAL((__io)->out.create_action, NTCREATEX_ACTION_EXISTED);	\
		}							\
		CHECK_VAL((__io)->out.alloc_size, 0);			\
		CHECK_VAL((__io)->out.size, 0);				\
		CHECK_VAL((__io)->out.file_attr, (__attribute));	\
		CHECK_VAL((__io)->out.reserved2, 0);			\
	} while(0)

#define CHECK_LEASE(__io, __state, __oplevel, __key)			\
	do {								\
		if (__oplevel) {					\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE); \
			CHECK_VAL((__io)->out.lease_response.lease_key[0], (__key)); \
			CHECK_VAL((__io)->out.lease_response.lease_key[1], ~(__key)); \
			CHECK_VAL((__io)->out.lease_response.lease_state, (__state)); \
		} else {						\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_NONE); \
			CHECK_VAL((__io)->out.lease_response.lease_key[0], 0); \
			CHECK_VAL((__io)->out.lease_response.lease_key[1], 0); \
			CHECK_VAL((__io)->out.lease_response.lease_state, 0); \
		}							\
									\
		CHECK_VAL((__io)->out.lease_response.lease_flags, 0);	\
		CHECK_VAL((__io)->out.lease_response.lease_duration, 0); \
	} while(0)							\

static const uint64_t LEASE1 = 0xBADC0FFEE0DDF00Dull;
static const uint64_t LEASE2 = 0xDEADBEEFFEEDBEADull;
static const uint64_t LEASE3 = 0xDAD0FFEDD00DF00Dull;

#define NRESULTS 8
static const int request_results[NRESULTS][2] = {
	{ SMB2_LEASE_NONE, SMB2_LEASE_NONE },
	{ SMB2_LEASE_READ, SMB2_LEASE_READ },
	{ SMB2_LEASE_HANDLE, SMB2_LEASE_NONE, },
	{ SMB2_LEASE_WRITE, SMB2_LEASE_NONE },
	{ SMB2_LEASE_READ|SMB2_LEASE_HANDLE,
	  SMB2_LEASE_READ|SMB2_LEASE_HANDLE },
	{ SMB2_LEASE_READ|SMB2_LEASE_WRITE,
	  SMB2_LEASE_READ|SMB2_LEASE_WRITE },
	{ SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE, SMB2_LEASE_NONE },
	{ SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE,
	  SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE },
};

static bool test_lease_request(struct torture_context *tctx,
	                       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1, h2;
	NTSTATUS status;
	const char *fname = "lease.dat";
	const char *fname2 = "lease2.dat";
	const char *sname = "lease.dat:stream";
	const char *dname = "lease.dir";
	bool ret = true;
	int i;

	smb2_util_unlink(tree, fname);
	smb2_util_unlink(tree, fname2);
	smb2_util_rmdir(tree, dname);

	/* Win7 is happy to grant RHW leases on files. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, true, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE,
	    true, LEASE1);

	/* But will reject leases on directories. */
	smb2_lease_create(&io, &ls, true, dname, LEASE2,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, true, FILE_ATTRIBUTE_DIRECTORY);
	CHECK_LEASE(&io, SMB2_LEASE_NONE, false, 0);
	smb2_util_close(tree, io.out.file.handle);

	/* Also rejects multiple files leased under the same key. */
	smb2_lease_create(&io, &ls, true, fname2, LEASE1,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	/* And grants leases on streams (with separate leasekey). */
	smb2_lease_create(&io, &ls, false, sname, LEASE2,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);
	status = smb2_create(tree, mem_ctx, &io);
	h2 = io.out.file.handle;
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, true, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE,
	    true, LEASE2);
	smb2_util_close(tree, h2);

	smb2_util_close(tree, h1);

	/* Now see what combos are actually granted. */
	for (i = 0; i < NRESULTS; i++) {
		torture_comment(tctx, "Testing lease type %x, expecting %x\n",
		    request_results[i][0], request_results[i][1]);
		smb2_lease_create(&io, &ls, false, fname, LEASE1,
		    request_results[i][0]);
		status = smb2_create(tree, mem_ctx, &io);
		h2 = io.out.file.handle;
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_CREATED(&io, false, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, request_results[i][1], true, LEASE1);
		smb2_util_close(tree, io.out.file.handle);
	}

 done:
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);

	smb2_util_unlink(tree, fname);
	smb2_util_unlink(tree, fname2);
	smb2_util_rmdir(tree, dname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_upgrade(struct torture_context *tctx,
                               struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h, hnew;
	NTSTATUS status;
	const char *fname = "lease.dat";
	bool ret = true;

	smb2_util_unlink(tree, fname);

	/* Grab a RH lease. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, true, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE, true, LEASE1);
	h = io.out.file.handle;

	/* Upgrades (sidegrades?) to RW leave us with an RH. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1,
	    SMB2_LEASE_READ|SMB2_LEASE_WRITE);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, false, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE, true, LEASE1);
	hnew = io.out.file.handle;

	smb2_util_close(tree, hnew);

	/* Upgrade to RHW lease. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, false, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE,
	    true, LEASE1);
	hnew = io.out.file.handle;

	smb2_util_close(tree, h);
	h = hnew;

	/* Attempt to downgrade - original lease state is maintained. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, false, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE,
	    true, LEASE1);
	hnew = io.out.file.handle;

	smb2_util_close(tree, hnew);

 done:
	smb2_util_close(tree, h);
	smb2_util_close(tree, hnew);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}

struct torture_suite *torture_smb2_lease_init(void)
{
	struct torture_suite *suite =
	    torture_suite_create(talloc_autofree_context(), "LEASE");

	torture_suite_add_1smb2_test(suite, "REQUEST", test_lease_request);
	torture_suite_add_1smb2_test(suite, "UPGRADE", test_lease_upgrade);

	suite->description = talloc_strdup(suite, "SMB2-LEASE tests");

	return suite;
}
