/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 version two of durable opens

   Copyright (C) Michael Adam 2012

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
#include "../libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "librpc/ndr/libndr.h"

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

#define CHECK_CREATED(__io, __created, __attribute)			\
	do {								\
		CHECK_VAL((__io)->out.create_action, NTCREATEX_ACTION_ ## __created); \
		CHECK_VAL((__io)->out.alloc_size, 0);			\
		CHECK_VAL((__io)->out.size, 0);				\
		CHECK_VAL((__io)->out.file_attr, (__attribute));	\
		CHECK_VAL((__io)->out.reserved2, 0);			\
	} while(0)

/**
 * basic durable_open test.
 * durable state should only be granted when requested
 * along with a batch oplock or a handle lease.
 *
 * This test tests durable open with all possible oplock types.
 */

struct durable_open_vs_oplock {
	const char *level;
	const char *share_mode;
	bool durable;
	bool persistent;
};

#define NUM_OPLOCK_TYPES 4
#define NUM_SHARE_MODES 8
#define NUM_OPLOCK_OPEN_TESTS ( NUM_OPLOCK_TYPES * NUM_SHARE_MODES )
static struct durable_open_vs_oplock durable_open_vs_oplock_table[NUM_OPLOCK_OPEN_TESTS] =
{
	{ "", "", false, false },
	{ "", "R", false, false },
	{ "", "W", false, false },
	{ "", "D", false, false },
	{ "", "RD", false, false },
	{ "", "RW", false, false },
	{ "", "WD", false, false },
	{ "", "RWD", false, false },

	{ "s", "", false, false },
	{ "s", "R", false, false },
	{ "s", "W", false, false },
	{ "s", "D", false, false },
	{ "s", "RD", false, false },
	{ "s", "RW", false, false },
	{ "s", "WD", false, false },
	{ "s", "RWD", false, false },

	{ "x", "", false, false },
	{ "x", "R", false, false },
	{ "x", "W", false, false },
	{ "x", "D", false, false },
	{ "x", "RD", false, false },
	{ "x", "RW", false, false },
	{ "x", "WD", false, false },
	{ "x", "RWD", false, false },

	{ "b", "", true, false },
	{ "b", "R", true, false },
	{ "b", "W", true, false },
	{ "b", "D", true, false },
	{ "b", "RD", true, false },
	{ "b", "RW", true, false },
	{ "b", "WD", true, false },
	{ "b", "RWD", true, false },
};

static bool test_one_durable_v2_open_oplock(struct torture_context *tctx,
					    struct smb2_tree *tree,
					    const char *fname,
					    bool request_persistent,
					    struct durable_open_vs_oplock test)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	bool ret = true;
	struct smb2_create io;

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(test.share_mode),
				 smb2_util_oplock_level(test.level));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = request_persistent;
	io.in.create_guid = GUID_random();

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, test.durable);
	CHECK_VAL(io.out.persistent_open, test.persistent);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level(test.level));

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);

	return ret;
}

static bool test_durable_v2_open_oplock_table(struct torture_context *tctx,
					      struct smb2_tree *tree,
					      const char *fname,
					      bool request_persistent,
					      struct durable_open_vs_oplock *table,
					      uint8_t num_tests)
{
	bool ret = true;
	uint8_t i;

	smb2_util_unlink(tree, fname);

	for (i = 0; i < num_tests; i++) {
		ret = test_one_durable_v2_open_oplock(tctx,
						      tree,
						      fname,
						      request_persistent,
						      table[i]);
		if (ret == false) {
			goto done;
		}
	}

done:
	smb2_util_unlink(tree, fname);

	return ret;
}

bool test_durable_v2_open_oplock(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	bool ret;
	char fname[256];

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_oplock_%s.dat",
		 generate_random_str(tctx, 8));

	ret = test_durable_v2_open_oplock_table(tctx, tree, fname,
						false, /* request_persistent */
						durable_open_vs_oplock_table,
						NUM_OPLOCK_OPEN_TESTS);

	talloc_free(tree);

	return ret;
}

/**
 * basic durable handle open test.
 * persistent state should only be granted when requested
 * along with a batch oplock or a handle lease.
 *
 * This test tests persistent open with all valid lease types.
 */

struct durable_open_vs_lease {
	const char *type;
	const char *share_mode;
	bool durable;
	bool persistent;
};

#define NUM_LEASE_TYPES 5
#define NUM_LEASE_OPEN_TESTS ( NUM_LEASE_TYPES * NUM_SHARE_MODES )
static struct durable_open_vs_lease durable_open_vs_lease_table[NUM_LEASE_OPEN_TESTS] =
{
	{ "", "", false, false },
	{ "", "R", false, false },
	{ "", "W", false, false },
	{ "", "D", false, false },
	{ "", "RW", false, false },
	{ "", "RD", false, false },
	{ "", "WD", false, false },
	{ "", "RWD", false, false },

	{ "R", "", false, false },
	{ "R", "R", false, false },
	{ "R", "W", false, false },
	{ "R", "D", false, false },
	{ "R", "RW", false, false },
	{ "R", "RD", false, false },
	{ "R", "DW", false, false },
	{ "R", "RWD", false, false },

	{ "RW", "", false, false },
	{ "RW", "R", false, false },
	{ "RW", "W", false, false },
	{ "RW", "D", false, false },
	{ "RW", "RW", false, false },
	{ "RW", "RD", false, false },
	{ "RW", "WD", false, false },
	{ "RW", "RWD", false, false },

	{ "RH", "", true, false },
	{ "RH", "R", true, false },
	{ "RH", "W", true, false },
	{ "RH", "D", true, false },
	{ "RH", "RW", true, false },
	{ "RH", "RD", true, false },
	{ "RH", "WD", true, false },
	{ "RH", "RWD", true, false },

	{ "RHW", "", true, false },
	{ "RHW", "R", true, false },
	{ "RHW", "W", true, false },
	{ "RHW", "D", true, false },
	{ "RHW", "RW", true, false },
	{ "RHW", "RD", true, false },
	{ "RHW", "WD", true, false },
	{ "RHW", "RWD", true, false },
};

static bool test_one_durable_v2_open_lease(struct torture_context *tctx,
					   struct smb2_tree *tree,
					   const char *fname,
					   bool request_persistent,
					   struct durable_open_vs_lease test)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	bool ret = true;
	struct smb2_create io;
	struct smb2_lease ls;
	uint64_t lease;

	smb2_util_unlink(tree, fname);

	lease = random();

	smb2_lease_create_share(&io, &ls, false /* dir */, fname,
				smb2_util_share_access(test.share_mode),
				lease,
				smb2_util_lease_state(test.type));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = request_persistent;
	io.in.create_guid = GUID_random();

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, test.durable);
	CHECK_VAL(io.out.persistent_open, test.persistent);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response.lease_key.data[0], lease);
	CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease);
	CHECK_VAL(io.out.lease_response.lease_state,
		  smb2_util_lease_state(test.type));
done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);

	return ret;
}

static bool test_durable_v2_open_lease_table(struct torture_context *tctx,
					     struct smb2_tree *tree,
					     const char *fname,
					     bool request_persistent,
					     struct durable_open_vs_lease *table,
					     uint8_t num_tests)
{
	bool ret = true;
	uint8_t i;

	smb2_util_unlink(tree, fname);

	for (i = 0; i < num_tests; i++) {
		ret = test_one_durable_v2_open_lease(tctx,
						     tree,
						     fname,
						     request_persistent,
						     table[i]);
		if (ret == false) {
			goto done;
		}
	}

done:
	smb2_util_unlink(tree, fname);

	return ret;
}

bool test_durable_v2_open_lease(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	char fname[256];
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_lease_%s.dat", generate_random_str(tctx, 8));

	ret = test_durable_v2_open_lease_table(tctx, tree, fname,
					       false, /* request_persistent */
					       durable_open_vs_lease_table,
					       NUM_LEASE_OPEN_TESTS);

	talloc_free(tree);
	return ret;
}

/**
 * basic test for doing a durable open
 * and do a durable reopen on the same connection
 * while the first open is still active (fails)
 */
bool test_durable_v2_open_reopen1(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	bool ret = true;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_v2_open_reopen1_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, io.in.timeout);

	/* try a durable reconnect while the file is still open */
	ZERO_STRUCT(io);
	io.in.fname = "";
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic test for doing a durable open
 * tcp disconnect, reconnect, do a durable reopen (succeeds)
 */
bool test_durable_v2_open_reopen2(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	bool ret = true;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_v2_open_reopen2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, io.in.timeout);

	/* disconnect, reconnect and then do durable reopen */
	talloc_free(tree);
	tree = NULL;

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = "";
	io.in.durable_handle_v2 = h;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ZERO_STRUCT(io);
	io.in.fname = "__non_existing_fname__";
	io.in.durable_handle_v2 = h;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle_v2 = h;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ZERO_STRUCT(io);
	/*
	 * These are completely ignored by the server
	 */
	io.in.security_flags = 0x78;
	io.in.oplock_level = 0x78;
	io.in.impersonation_level = 0x12345678;
	io.in.create_flags = 0x12345678;
	io.in.reserved = 0x12345678;
	io.in.desired_access = 0x12345678;
	io.in.file_attributes = 0x12345678;
	io.in.share_access = 0x12345678;
	io.in.create_disposition = 0x12345678;
	io.in.create_options = 0x12345678;
	io.in.fname = "__non_existing_fname__";

	/*
	 * only io.in.durable_handle_v2 and
	 * io.in.create_guid are checked
	 */
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic persistent open test.
 *
 * This test tests durable open with all possible oplock types.
 */

struct durable_open_vs_oplock persistent_open_oplock_ca_table[NUM_OPLOCK_OPEN_TESTS] =
{
	{ "", "", true, true },
	{ "", "R", true, true },
	{ "", "W", true, true },
	{ "", "D", true, true },
	{ "", "RD", true, true },
	{ "", "RW", true, true },
	{ "", "WD", true, true },
	{ "", "RWD", true, true },

	{ "s", "", true, true },
	{ "s", "R", true, true },
	{ "s", "W", true, true },
	{ "s", "D", true, true },
	{ "s", "RD", true, true },
	{ "s", "RW", true, true },
	{ "s", "WD", true, true },
	{ "s", "RWD", true, true },

	{ "x", "", true, true },
	{ "x", "R", true, true },
	{ "x", "W", true, true },
	{ "x", "D", true, true },
	{ "x", "RD", true, true },
	{ "x", "RW", true, true },
	{ "x", "WD", true, true },
	{ "x", "RWD", true, true },

	{ "b", "", true, true },
	{ "b", "R", true, true },
	{ "b", "W", true, true },
	{ "b", "D", true, true },
	{ "b", "RD", true, true },
	{ "b", "RW", true, true },
	{ "b", "WD", true, true },
	{ "b", "RWD", true, true },
};

bool test_persistent_open_oplock(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	char fname[256];
	bool ret = true;
	uint32_t share_capabilities;
	bool share_is_ca = false;
	struct durable_open_vs_oplock *table;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "persistent_open_oplock_%s.dat", generate_random_str(tctx, 8));

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_ca = share_capabilities & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;

	if (share_is_ca) {
		table = persistent_open_oplock_ca_table;
	} else {
		table = durable_open_vs_oplock_table;
	}

	ret = test_durable_v2_open_oplock_table(tctx, tree, fname,
						true, /* request_persistent */
						table,
						NUM_OPLOCK_OPEN_TESTS);

	talloc_free(tree);

	return ret;
}

/**
 * basic persistent handle open test.
 * persistent state should only be granted when requested
 * along with a batch oplock or a handle lease.
 *
 * This test tests persistent open with all valid lease types.
 */

struct durable_open_vs_lease persistent_open_lease_ca_table[NUM_LEASE_OPEN_TESTS] =
{
	{ "", "", true, true },
	{ "", "R", true, true },
	{ "", "W", true, true },
	{ "", "D", true, true },
	{ "", "RW", true, true },
	{ "", "RD", true, true },
	{ "", "WD", true, true },
	{ "", "RWD", true, true },

	{ "R", "", true, true },
	{ "R", "R", true, true },
	{ "R", "W", true, true },
	{ "R", "D", true, true },
	{ "R", "RW", true, true },
	{ "R", "RD", true, true },
	{ "R", "DW", true, true },
	{ "R", "RWD", true, true },

	{ "RW", "", true, true },
	{ "RW", "R", true, true },
	{ "RW", "W", true, true },
	{ "RW", "D", true, true },
	{ "RW", "RW", true, true },
	{ "RW", "RD", true, true },
	{ "RW", "WD", true, true },
	{ "RW", "RWD", true, true },

	{ "RH", "", true, true },
	{ "RH", "R", true, true },
	{ "RH", "W", true, true },
	{ "RH", "D", true, true },
	{ "RH", "RW", true, true },
	{ "RH", "RD", true, true },
	{ "RH", "WD", true, true },
	{ "RH", "RWD", true, true },

	{ "RHW", "", true, true },
	{ "RHW", "R", true, true },
	{ "RHW", "W", true, true },
	{ "RHW", "D", true, true },
	{ "RHW", "RW", true, true },
	{ "RHW", "RD", true, true },
	{ "RHW", "WD", true, true },
	{ "RHW", "RWD", true, true },
};

bool test_persistent_open_lease(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	char fname[256];
	bool ret = true;
	uint32_t caps;
	uint32_t share_capabilities;
	bool share_is_ca;
	struct durable_open_vs_lease *table;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "persistent_open_lease_%s.dat", generate_random_str(tctx, 8));

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_ca = share_capabilities & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;

	if (share_is_ca) {
		table = persistent_open_lease_ca_table;
	} else {
		table = durable_open_vs_lease_table;
	}

	ret = test_durable_v2_open_lease_table(tctx, tree, fname,
					       true, /* request_persistent */
					       table,
					       NUM_LEASE_OPEN_TESTS);

	talloc_free(tree);

	return ret;
}

struct torture_suite *torture_smb2_durable_v2_open_init(void)
{
	struct torture_suite *suite =
	    torture_suite_create(talloc_autofree_context(), "durable-v2-open");

	torture_suite_add_1smb2_test(suite, "open-oplock", test_durable_v2_open_oplock);
	torture_suite_add_1smb2_test(suite, "open-lease", test_durable_v2_open_lease);
	torture_suite_add_1smb2_test(suite, "reopen1", test_durable_v2_open_reopen1);
	torture_suite_add_1smb2_test(suite, "reopen2", test_durable_v2_open_reopen2);
	torture_suite_add_1smb2_test(suite, "persistent-open-oplock", test_persistent_open_oplock);
	torture_suite_add_1smb2_test(suite, "persistent-open-lease", test_persistent_open_lease);

	suite->description = talloc_strdup(suite, "SMB2-DURABLE-V2-OPEN tests");

	return suite;
}
