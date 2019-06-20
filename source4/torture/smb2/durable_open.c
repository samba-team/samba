/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 durable opens

   Copyright (C) Stefan Metzmacher 2008
   Copyright (C) Michael Adam 2011-2012

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
#include "../libcli/smb/smbXcli_base.h"

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s got 0x%llx - should be 0x%llx\n", \
				__location__, #v, (unsigned long long)v, (unsigned long long)correct); \
		ret = false; \
	}} while (0)

#define CHECK_NOT_VAL(v, incorrect) do { \
	if ((v) == (incorrect)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s got 0x%llx - should not be 0x%llx\n", \
				__location__, #v, (unsigned long long)v, (unsigned long long)incorrect); \
		ret = false; \
	}} while (0)

#define CHECK_NOT_NULL(p) do { \
	if ((p) == NULL) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): %s is NULL but it should not be.\n", \
				__location__, #p); \
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
		CHECK_VAL((__io)->out.size, 0);				\
		CHECK_VAL((__io)->out.file_attr, (__attribute));	\
		CHECK_VAL((__io)->out.reserved2, 0);			\
	} while(0)

#define CHECK_CREATED_SIZE(__io, __created, __attribute, __alloc_size, __size)	\
	do {									\
		CHECK_VAL((__io)->out.create_action, NTCREATEX_ACTION_ ## __created); \
		CHECK_VAL((__io)->out.alloc_size, (__alloc_size));		\
		CHECK_VAL((__io)->out.size, (__size));				\
		CHECK_VAL((__io)->out.file_attr, (__attribute));		\
		CHECK_VAL((__io)->out.reserved2, 0);				\
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
	bool expected;
};

#define NUM_OPLOCK_TYPES 4
#define NUM_SHARE_MODES 8
#define NUM_OPLOCK_OPEN_TESTS ( NUM_OPLOCK_TYPES * NUM_SHARE_MODES )
static struct durable_open_vs_oplock durable_open_vs_oplock_table[NUM_OPLOCK_OPEN_TESTS] =
{
	{ "", "", false },
	{ "", "R", false },
	{ "", "W", false },
	{ "", "D", false },
	{ "", "RD", false },
	{ "", "RW", false },
	{ "", "WD", false },
	{ "", "RWD", false },

	{ "s", "", false },
	{ "s", "R", false },
	{ "s", "W", false },
	{ "s", "D", false },
	{ "s", "RD", false },
	{ "s", "RW", false },
	{ "s", "WD", false },
	{ "s", "RWD", false },

	{ "x", "", false },
	{ "x", "R", false },
	{ "x", "W", false },
	{ "x", "D", false },
	{ "x", "RD", false },
	{ "x", "RW", false },
	{ "x", "WD", false },
	{ "x", "RWD", false },

	{ "b", "", true },
	{ "b", "R", true },
	{ "b", "W", true },
	{ "b", "D", true },
	{ "b", "RD", true },
	{ "b", "RW", true },
	{ "b", "WD", true },
	{ "b", "RWD", true },
};

static bool test_one_durable_open_open_oplock(struct torture_context *tctx,
					      struct smb2_tree *tree,
					      const char *fname,
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
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, test.expected);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level(test.level));

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);

	return ret;
}

static bool test_durable_open_open_oplock(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	bool ret = true;
	int i;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_open_oplock_%s.dat", generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	/* test various oplock levels with durable open */

	for (i = 0; i < NUM_OPLOCK_OPEN_TESTS; i++) {
		ret = test_one_durable_open_open_oplock(tctx,
							tree,
							fname,
							durable_open_vs_oplock_table[i]);
		if (ret == false) {
			goto done;
		}
	}

done:
	smb2_util_unlink(tree, fname);
	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic durable_open test.
 * durable state should only be granted when requested
 * along with a batch oplock or a handle lease.
 *
 * This test tests durable open with all valid lease types.
 */

struct durable_open_vs_lease {
	const char *type;
	const char *share_mode;
	bool expected;
};

#define NUM_LEASE_TYPES 5
#define NUM_LEASE_OPEN_TESTS ( NUM_LEASE_TYPES * NUM_SHARE_MODES )
static struct durable_open_vs_lease durable_open_vs_lease_table[NUM_LEASE_OPEN_TESTS] =
{
	{ "", "", false },
	{ "", "R", false },
	{ "", "W", false },
	{ "", "D", false },
	{ "", "RW", false },
	{ "", "RD", false },
	{ "", "WD", false },
	{ "", "RWD", false },

	{ "R", "", false },
	{ "R", "R", false },
	{ "R", "W", false },
	{ "R", "D", false },
	{ "R", "RW", false },
	{ "R", "RD", false },
	{ "R", "DW", false },
	{ "R", "RWD", false },

	{ "RW", "", false },
	{ "RW", "R", false },
	{ "RW", "W", false },
	{ "RW", "D", false },
	{ "RW", "RW", false },
	{ "RW", "RD", false },
	{ "RW", "WD", false },
	{ "RW", "RWD", false },

	{ "RH", "", true },
	{ "RH", "R", true },
	{ "RH", "W", true },
	{ "RH", "D", true },
	{ "RH", "RW", true },
	{ "RH", "RD", true },
	{ "RH", "WD", true },
	{ "RH", "RWD", true },

	{ "RHW", "", true },
	{ "RHW", "R", true },
	{ "RHW", "W", true },
	{ "RHW", "D", true },
	{ "RHW", "RW", true },
	{ "RHW", "RD", true },
	{ "RHW", "WD", true },
	{ "RHW", "RWD", true },
};

static bool test_one_durable_open_open_lease(struct torture_context *tctx,
					     struct smb2_tree *tree,
					     const char *fname,
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
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	lease = random();

	smb2_lease_create_share(&io, &ls, false /* dir */, fname,
				smb2_util_share_access(test.share_mode),
				lease,
				smb2_util_lease_state(test.type));
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, test.expected);
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

static bool test_durable_open_open_lease(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_open_lease_%s.dat", generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);


	/* test various oplock levels with durable open */

	for (i = 0; i < NUM_LEASE_OPEN_TESTS; i++) {
		ret = test_one_durable_open_open_lease(tctx,
						       tree,
						       fname,
						       durable_open_vs_lease_table[i]);
		if (ret == false) {
			goto done;
		}
	}

done:
	smb2_util_unlink(tree, fname);
	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic test for doing a durable open
 * and do a durable reopen on the same connection
 * while the first open is still active (fails)
 */
static bool test_durable_open_reopen1(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io1, io2;
	bool ret = true;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_reopen1_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io1.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));

	/* try a durable reconnect while the file is still open */
	ZERO_STRUCT(io2);
	io2.in.fname = fname;
	io2.in.durable_handle = h;

	status = smb2_create(tree, mem_ctx, &io2);
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
 * Basic test for doing a durable open
 * and do a session reconnect while the first
 * session is still active and the handle is
 * still open in the client.
 * This closes the original session and  a
 * durable reconnect on the new session succeeds.
 */
static bool test_durable_open_reopen1a(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	bool ret = true;
	struct smb2_tree *tree2 = NULL;
	struct smb2_tree *tree3 = NULL;
	uint64_t previous_session_id;
	struct smbcli_options options;
	struct GUID orig_client_guid;

	options = tree->session->transport->options;
	orig_client_guid = options.client_guid;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_reopen1a_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));

	/*
	 * a session reconnect on a second tcp connection
	 */

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* for oplocks, the client guid can be different: */
	options.client_guid = GUID_random();

	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options, &tree2);
	torture_assert_goto(tctx, ret, ret, done, "could not reconnect");

	/*
	 * check that this has deleted the old session
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_USER_SESSION_DELETED);

	TALLOC_FREE(tree);

	/*
	 * but a durable reconnect on the new session succeeds:
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

	/*
	 * a session reconnect on a second tcp connection
	 */

	previous_session_id = smb2cli_session_current_id(tree2->session->smbXcli);

	/* the original client_guid works just the same */
	options.client_guid = orig_client_guid;

	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options, &tree3);
	torture_assert_goto(tctx, ret, ret, done, "could not reconnect");

	/*
	 * check that this has deleted the old session
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_USER_SESSION_DELETED);

	TALLOC_FREE(tree2);

	/*
	 * but a durable reconnect on the new session succeeds:
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;

	status = smb2_create(tree3, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

done:
	if (tree == NULL) {
		tree = tree2;
	}

	if (tree == NULL) {
		tree = tree3;
	}

	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
			h = NULL;
		}
		smb2_util_unlink(tree, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * lease variant of reopen1a
 *
 * Basic test for doing a durable open and doing a session
 * reconnect while the first session is still active and the
 * handle is still open in the client.
 * This closes the original session and  a durable reconnect on
 * the new session succeeds depending on the client guid:
 *
 * Durable reconnect on a session with a different client guid fails.
 * Durable reconnect on a session with the original client guid succeeds.
 */
bool test_durable_open_reopen1a_lease(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct smb2_lease ls;
	uint64_t lease_key;
	bool ret = true;
	struct smb2_tree *tree2 = NULL;
	struct smb2_tree *tree3 = NULL;
	uint64_t previous_session_id;
	struct smbcli_options options;
	struct GUID orig_client_guid;

	options = tree->session->transport->options;
	orig_client_guid = options.client_guid;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_v2_open_reopen1a_lease_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	lease_key = random();
	smb2_lease_create(&io, &ls, false /* dir */, fname,
			  lease_key, smb2_util_lease_state("RWH"));
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease_key);
	CHECK_VAL(io.out.lease_response.lease_state,
		  smb2_util_lease_state("RWH"));
	CHECK_VAL(io.out.lease_response.lease_flags, 0);
	CHECK_VAL(io.out.lease_response.lease_duration, 0);

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/*
	 * a session reconnect on a second tcp connection
	 * with a different client_guid does not allow
	 * the durable reconnect.
	 */

	options.client_guid = GUID_random();

	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options, &tree2);
	torture_assert_goto(tctx, ret, ret, done, "couldn't reconnect");

	/*
	 * check that this has deleted the old session
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	io.in.lease_request = &ls;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_USER_SESSION_DELETED);
	TALLOC_FREE(tree);


	/*
	 * but a durable reconnect on the new session with the wrong
	 * client guid fails
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	io.in.lease_request = &ls;
	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/*
	 * now a session reconnect on a second tcp connection
	 * with original client_guid allows the durable reconnect.
	 */

	options.client_guid = orig_client_guid;

	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options, &tree3);
	torture_assert_goto(tctx, ret, ret, done, "couldn't reconnect");

	/*
	 * check that this has deleted the old session
	 * In this case, a durable reconnect attempt with the
	 * correct client_guid yields a different error code.
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	io.in.lease_request = &ls;
	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	TALLOC_FREE(tree2);

	/*
	 * but a durable reconnect on the new session succeeds:
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	io.in.lease_request = &ls;
	status = smb2_create(tree3, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false); /* no dh response context... */
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease_key);
	CHECK_VAL(io.out.lease_response.lease_state,
		  smb2_util_lease_state("RWH"));
	CHECK_VAL(io.out.lease_response.lease_flags, 0);
	CHECK_VAL(io.out.lease_response.lease_duration, 0);
	_h = io.out.file.handle;
	h = &_h;

done:
	if (tree == NULL) {
		tree = tree2;
	}

	if (tree == NULL) {
		tree = tree3;
	}

	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
		}

		smb2_util_unlink(tree, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}


/**
 * basic test for doing a durable open
 * tcp disconnect, reconnect, do a durable reopen (succeeds)
 */
static bool test_durable_open_reopen2(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	bool ret = true;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_reopen2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));

	/* disconnect, leaving the durable in place */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	/* the path name is ignored by the server */
	io.in.fname = fname;
	io.in.durable_handle = h; /* durable v1 reconnect request */
	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

	/* disconnect again, leaving the durable in place */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/*
	 * show that the filename and many other fields
	 * are ignored. only the reconnect request blob
	 * is important.
	 */
	ZERO_STRUCT(io);
	/* the path name is ignored by the server */
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
	io.in.durable_handle = h; /* durable v1 reconnect request */
	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

	/* disconnect, leaving the durable in place */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/*
	 * show that an additionally specified durable v1 request
	 * is ignored by the server.
	 * See MS-SMB2, 3.3.5.9.7
	 * Handling the SMB2_CREATE_DURABLE_HANDLE_RECONNECT Create Context
	 */
	ZERO_STRUCT(io);
	/* the path name is ignored by the server */
	io.in.fname = fname;
	io.in.durable_handle = h;  /* durable v1 reconnect request */
	io.in.durable_open = true; /* durable v1 handle request */
	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

done:
	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
		}

		smb2_util_unlink(tree, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * lease variant of reopen2
 * basic test for doing a durable open
 * tcp disconnect, reconnect, do a durable reopen (succeeds)
 */
static bool test_durable_open_reopen2_lease(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct smb2_lease ls;
	uint64_t lease_key;
	bool ret = true;
	struct smbcli_options options;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_reopen2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	lease_key = random();
	smb2_lease_create(&io, &ls, false /* dir */, fname, lease_key,
			  smb2_util_lease_state("RWH"));
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease_key);
	CHECK_VAL(io.out.lease_response.lease_state,
		  smb2_util_lease_state("RWH"));
	CHECK_VAL(io.out.lease_response.lease_flags, 0);
	CHECK_VAL(io.out.lease_response.lease_duration, 0);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}


	/* a few failure tests: */

	/*
	 * several attempts without lease attached:
	 * all fail with NT_STATUS_OBJECT_NAME_NOT_FOUND
	 * irrespective of file name provided
	 */

	ZERO_STRUCT(io);
	io.in.fname = "";
	io.in.durable_handle = h;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ZERO_STRUCT(io);
	io.in.fname = "__non_existing_fname__";
	io.in.durable_handle = h;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/*
	 * attempt with lease provided, but
	 * with a changed lease key. => fails
	 */
	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open = false;
	io.in.durable_handle = h;
	io.in.lease_request = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;
	/* a wrong lease key lets the request fail */
	ls.lease_key.data[0]++;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/* restore the correct lease key */
	ls.lease_key.data[0]--;

	/*
	 * this last failing attempt is almost correct:
	 * only problem is: we use the wrong filename...
	 * Note that this gives INVALID_PARAMETER.
	 * This is different from oplocks!
	 */
	ZERO_STRUCT(io);
	io.in.fname = "__non_existing_fname__";
	io.in.durable_open = false;
	io.in.durable_handle = h;
	io.in.lease_request = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	/*
	 * Now for a succeeding reconnect:
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open = false;
	io.in.durable_handle = h;
	io.in.lease_request = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	/* the requested lease state is irrelevant */
	ls.lease_state = smb2_util_lease_state("");

	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease_key);
	CHECK_VAL(io.out.lease_response.lease_state,
		  smb2_util_lease_state("RWH"));
	CHECK_VAL(io.out.lease_response.lease_flags, 0);
	CHECK_VAL(io.out.lease_response.lease_duration, 0);
	_h = io.out.file.handle;
	h = &_h;

	/* disconnect one more time */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/*
	 * demonstrate that various parameters are ignored
	 * in the reconnect
	 */

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

	/*
	 * only these are checked:
	 * - io.in.fname
	 * - io.in.durable_handle,
	 * - io.in.lease_request->lease_key
	 */

	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.lease_request = &ls;

	/* the requested lease state is irrelevant */
	ls.lease_state = smb2_util_lease_state("");

	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease_key);
	CHECK_VAL(io.out.lease_response.lease_state,
		  smb2_util_lease_state("RWH"));
	CHECK_VAL(io.out.lease_response.lease_flags, 0);
	CHECK_VAL(io.out.lease_response.lease_duration, 0);

	_h = io.out.file.handle;
	h = &_h;

done:
	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
		}

		smb2_util_unlink(tree, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * lease v2 variant of reopen2
 * basic test for doing a durable open
 * tcp disconnect, reconnect, do a durable reopen (succeeds)
 */
static bool test_durable_open_reopen2_lease_v2(struct torture_context *tctx,
					       struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct smb2_lease ls;
	uint64_t lease_key;
	bool ret = true;
	struct smbcli_options options;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_reopen2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	lease_key = random();
	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease_key, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[1], ~lease_key);
	CHECK_VAL(io.out.lease_response_v2.lease_state,
		  smb2_util_lease_state("RWH"));
	CHECK_VAL(io.out.lease_response_v2.lease_flags, 0);
	CHECK_VAL(io.out.lease_response_v2.lease_duration, 0);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/* a few failure tests: */

	/*
	 * several attempts without lease attached:
	 * all fail with NT_STATUS_OBJECT_NAME_NOT_FOUND
	 * irrespective of file name provided
	 */

	ZERO_STRUCT(io);
	io.in.fname = "";
	io.in.durable_handle = h;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ZERO_STRUCT(io);
	io.in.fname = "__non_existing_fname__";
	io.in.durable_handle = h;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/*
	 * attempt with lease provided, but
	 * with a changed lease key. => fails
	 */
	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open = false;
	io.in.durable_handle = h;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;
	/* a wrong lease key lets the request fail */
	ls.lease_key.data[0]++;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/* restore the correct lease key */
	ls.lease_key.data[0]--;

	/*
	 * this last failing attempt is almost correct:
	 * only problem is: we use the wrong filename...
	 * Note that this gives INVALID_PARAMETER.
	 * This is different from oplocks!
	 */
	ZERO_STRUCT(io);
	io.in.fname = "__non_existing_fname__";
	io.in.durable_open = false;
	io.in.durable_handle = h;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	/*
	 * Now for a succeeding reconnect:
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open = false;
	io.in.durable_handle = h;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	/* the requested lease state is irrelevant */
	ls.lease_state = smb2_util_lease_state("");

	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[1], ~lease_key);
	CHECK_VAL(io.out.lease_response_v2.lease_state,
		  smb2_util_lease_state("RWH"));
	CHECK_VAL(io.out.lease_response_v2.lease_flags, 0);
	CHECK_VAL(io.out.lease_response_v2.lease_duration, 0);
	_h = io.out.file.handle;
	h = &_h;

	/* disconnect one more time */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/*
	 * demonstrate that various parameters are ignored
	 * in the reconnect
	 */

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

	/*
	 * only these are checked:
	 * - io.in.fname
	 * - io.in.durable_handle,
	 * - io.in.lease_request->lease_key
	 */

	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.lease_request_v2 = &ls;

	/* the requested lease state is irrelevant */
	ls.lease_state = smb2_util_lease_state("");

	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[1], ~lease_key);
	CHECK_VAL(io.out.lease_response_v2.lease_state,
		  smb2_util_lease_state("RWH"));
	CHECK_VAL(io.out.lease_response_v2.lease_flags, 0);
	CHECK_VAL(io.out.lease_response_v2.lease_duration, 0);

	_h = io.out.file.handle;
	h = &_h;

done:
	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
		}

		smb2_util_unlink(tree, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic test for doing a durable open
 * tcp disconnect, reconnect with a session reconnect and
 * do a durable reopen (succeeds)
 */
static bool test_durable_open_reopen2a(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io1, io2;
	uint64_t previous_session_id;
	bool ret = true;
	struct smbcli_options options;

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_reopen2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io1.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));

	/* disconnect, reconnect and then do durable reopen */
	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);
	talloc_free(tree);
	tree = NULL;

	if (!torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree))
	{
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io2);
	io2.in.fname = fname;
	io2.in.durable_handle = h;
	h = NULL;

	status = smb2_create(tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io2.out.file.handle;
	h = &_h;

done:
	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
		}

		smb2_util_unlink(tree, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}


/**
 * basic test for doing a durable open:
 * tdis, new tcon, try durable reopen (fails)
 */
static bool test_durable_open_reopen3(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io1, io2;
	bool ret = true;
	struct smb2_tree *tree2;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_reopen3_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io1.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));

	/* disconnect, reconnect and then do durable reopen */
	status = smb2_tdis(tree);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (!torture_smb2_tree_connect(tctx, tree->session, mem_ctx, &tree2)) {
		torture_warning(tctx, "couldn't reconnect to share, bailing\n");
		ret = false;
		goto done;
	}


	ZERO_STRUCT(io2);
	io2.in.fname = fname;
	io2.in.durable_handle = h;

	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

done:
	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
		}

		smb2_util_unlink(tree2, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic test for doing a durable open:
 * logoff, create a new session, do a durable reopen (succeeds)
 */
static bool test_durable_open_reopen4(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io1, io2;
	bool ret = true;
	struct smb2_transport *transport;
	struct smb2_session *session2;
	struct smb2_tree *tree2;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_reopen4_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io1.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));

	/*
	 * do a session logoff, establish a new session and tree
	 * connect on the same transport, and try a durable reopen
	 */
	transport = tree->session->transport;
	status = smb2_logoff(tree->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	if (!torture_smb2_session_setup(tctx, transport,
					0, /* previous_session_id */
					mem_ctx, &session2))
	{
		torture_warning(tctx, "session setup failed.\n");
		ret = false;
		goto done;
	}

	/*
	 * the session setup has talloc-stolen the transport,
	 * so we can safely free the old tree+session for clarity
	 */
	TALLOC_FREE(tree);

	if (!torture_smb2_tree_connect(tctx, session2, mem_ctx, &tree2)) {
		torture_warning(tctx, "tree connect failed.\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io2);
	io2.in.fname = fname;
	io2.in.durable_handle = h;
	h = NULL;

	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);

	_h = io2.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));

done:
	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree2, *h);
		}

		smb2_util_unlink(tree2, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}

static bool test_durable_open_delete_on_close1(struct torture_context *tctx,
					       struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io1, io2;
	bool ret = true;
	uint8_t b = 0;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_delete_on_close1_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.durable_open = true;
	io1.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io1.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));

	status = smb2_util_write(tree, *h, &b, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* disconnect, leaving the durable handle in place */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "could not reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/*
	 * Open the file on the new connection again
	 * and check that it has been newly created,
	 * i.e. delete on close was effective on the disconnected handle.
	 * Also check that the file is really empty,
	 * the previously written byte gone.
	 */
	smb2_oplock_create_share(&io2, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io2.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io2.out.file.handle;
	h = &_h;
	CHECK_CREATED_SIZE(&io2, CREATED, FILE_ATTRIBUTE_ARCHIVE, 0, 0);
	CHECK_VAL(io2.out.durable_open, false);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));

done:
	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
		}

		smb2_util_unlink(tree, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}


static bool test_durable_open_delete_on_close2(struct torture_context *tctx,
					       struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	bool ret = true;
	uint8_t b = 0;
	uint64_t previous_session_id;
	uint64_t alloc_size_step;
	struct smbcli_options options;

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_delete_on_close2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = true;
	io.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));

	status = smb2_util_write(tree, *h, &b, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* disconnect, leaving the durable handle in place */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree))
	{
		torture_warning(tctx, "could not reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	alloc_size_step = io.out.alloc_size;
	CHECK_CREATED_SIZE(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE, alloc_size_step, 1);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));

	/* close the file, thereby deleting it */
	smb2_util_close(tree, *h);
	status = smb2_logoff(tree->session);
	TALLOC_FREE(tree);

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "could not reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/*
	 * Open the file on the new connection again
	 * and check that it has been newly created,
	 * i.e. delete on close was effective on the reconnected handle.
	 * Also check that the file is really empty,
	 * the previously written byte gone.
	 */
	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = true;
	io.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED_SIZE(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE, 0, 0);
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));

done:
	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
		}

		smb2_util_unlink(tree, fname);

		talloc_free(tree);
	}

	talloc_free(mem_ctx);

	return ret;
}

/*
   basic testing of SMB2 durable opens
   regarding the position information on the handle
*/
static bool test_durable_open_file_position(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle h;
	struct smb2_create io;
	NTSTATUS status;
	const char *fname = "durable_open_position.dat";
	union smb_fileinfo qfinfo;
	union smb_setfileinfo sfinfo;
	bool ret = true;
	uint64_t pos;
	uint64_t previous_session_id;
	struct smbcli_options options;

	options = tree->session->transport->options;

	smb2_util_unlink(tree, fname);

	smb2_oplock_create(&io, fname, SMB2_OPLOCK_LEVEL_BATCH);
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* TODO: check extra blob content */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0);
	pos = qfinfo.position_information.out.position;
	torture_comment(tctx, "position: %llu\n",
			(unsigned long long)pos);

	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_POSITION_INFORMATION;
	sfinfo.generic.in.file.handle = h;
	sfinfo.position_information.in.position = 0x1000;
	status = smb2_setinfo_file(tree, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0x1000);
	pos = qfinfo.position_information.out.position;
	torture_comment(tctx, "position: %llu\n",
			(unsigned long long)pos);

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* tcp disconnect */
	talloc_free(tree);
	tree = NULL;

	/* do a session reconnect */
	if (!torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree))
	{
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = &h;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);
	CHECK_VAL(io.out.reserved, 0x00);
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.alloc_size, 0);
	CHECK_VAL(io.out.size, 0);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.reserved2, 0);

	h = io.out.file.handle;

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0x1000);
	pos = qfinfo.position_information.out.position;
	torture_comment(tctx, "position: %llu\n",
			(unsigned long long)pos);

	smb2_util_close(tree, h);

	talloc_free(mem_ctx);

	smb2_util_unlink(tree, fname);

done:
	talloc_free(tree);

	return ret;
}

/*
  Open, disconnect, oplock break, reconnect.
*/
static bool test_durable_open_oplock(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1, io2;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	NTSTATUS status;
	char fname[256];
	bool ret = true;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_oplock_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree1, fname);

	/* Create with batch oplock */
	smb2_oplock_create(&io1, fname, SMB2_OPLOCK_LEVEL_BATCH);
	io1.in.durable_open = true;

	io2 = io1;
	io2.in.create_disposition = NTCREATEX_DISP_OPEN;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* Disconnect after getting the batch */
	talloc_free(tree1);
	tree1 = NULL;

	/*
	 * Windows7 (build 7000) will break a batch oplock immediately if the
	 * original client is gone. (ZML: This seems like a bug. It should give
	 * some time for the client to reconnect!)
	 */
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.durable_open, true);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* What if tree1 tries to come back and reclaim? */
	if (!torture_smb2_connection(tctx, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io1);
	io1.in.fname = fname;
	io1.in.durable_handle = &h1;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

 done:
	smb2_util_close(tree2, h2);
	smb2_util_unlink(tree2, fname);

	talloc_free(tree1);
	talloc_free(tree2);

	return ret;
}

/*
  Open, disconnect, lease break, reconnect.
*/
static bool test_durable_open_lease(struct torture_context *tctx,
				    struct smb2_tree *tree1,
				    struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1, io2;
	struct smb2_lease ls1, ls2;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	NTSTATUS status;
	char fname[256];
	bool ret = true;
	uint64_t lease1, lease2;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	/*
	 * Choose a random name and random lease in case the state is left a
	 * little funky.
	 */
	lease1 = random();
	lease2 = random();
	snprintf(fname, 256, "durable_open_lease_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree1, fname);

	/* Create with lease */
	smb2_lease_create(&io1, &ls1, false /* dir */, fname,
			  lease1, smb2_util_lease_state("RHW"));
	io1.in.durable_open = true;

	smb2_lease_create(&io2, &ls2, false /* dir */, fname,
			  lease2, smb2_util_lease_state("RHW"));
	io2.in.durable_open = true;
	io2.in.create_disposition = NTCREATEX_DISP_OPEN;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io1.out.lease_response.lease_key.data[0], lease1);
	CHECK_VAL(io1.out.lease_response.lease_key.data[1], ~lease1);
	CHECK_VAL(io1.out.lease_response.lease_state,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);

	/* Disconnect after getting the lease */
	talloc_free(tree1);
	tree1 = NULL;

	/*
	 * Windows7 (build 7000) will grant an RH lease immediate (not an RHW?)
	 * even if the original client is gone. (ZML: This seems like a bug. It
	 * should give some time for the client to reconnect! And why RH?)
	 * 
	 * obnox: Current windows 7 and w2k8r2 grant RHW instead of RH.
	 * Test is adapted accordingly.
	 */
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_VAL(io2.out.durable_open, true);
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io2.out.lease_response.lease_key.data[0], lease2);
	CHECK_VAL(io2.out.lease_response.lease_key.data[1], ~lease2);
	CHECK_VAL(io2.out.lease_response.lease_state,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);

	/* What if tree1 tries to come back and reclaim? */
	if (!torture_smb2_connection(tctx, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io1);
	io1.in.fname = fname;
	io1.in.durable_handle = &h1;
	io1.in.lease_request = &ls1;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

 done:
	smb2_util_close(tree2, h2);
	smb2_util_unlink(tree2, fname);

	talloc_free(tree1);
	talloc_free(tree2);

	return ret;
}

static bool test_durable_open_lock_oplock(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_handle h = {{0}};
	struct smb2_lock lck;
	struct smb2_lock_element el[2];
	NTSTATUS status;
	char fname[256];
	bool ret = true;

	/*
	 */
	snprintf(fname, 256, "durable_open_oplock_lock_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree, fname);

	/* Create with oplock */

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));

	ZERO_STRUCT(lck);
	ZERO_STRUCT(el);
	lck.in.locks		= el;
	lck.in.lock_count	= 0x0001;
	lck.in.lock_sequence	= 0x00000000;
	lck.in.file.handle	= h;
	el[0].offset		= 0;
	el[0].length		= 1;
	el[0].reserved		= 0x00000000;
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Disconnect/Reconnect. */
	talloc_free(tree);
	tree = NULL;

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = &h;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;

	lck.in.file.handle	= h;
	el[0].flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

 done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	talloc_free(tree);

	return ret;
}

/*
  Open, take BRL, disconnect, reconnect.
*/
static bool test_durable_open_lock_lease(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h = {{0}};
	struct smb2_lock lck;
	struct smb2_lock_element el[2];
	NTSTATUS status;
	char fname[256];
	bool ret = true;
	uint64_t lease;
	uint32_t caps;
	struct smbcli_options options;

	options = tree->session->transport->options;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	/*
	 * Choose a random name and random lease in case the state is left a
	 * little funky.
	 */
	lease = random();
	snprintf(fname, 256, "durable_open_lease_lock_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree, fname);

	/* Create with lease */

	smb2_lease_create(&io, &ls, false /* dir */, fname, lease,
			  smb2_util_lease_state("RWH"));
	io.in.durable_open 		= true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response.lease_key.data[0], lease);
	CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease);
	CHECK_VAL(io.out.lease_response.lease_state,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);

	ZERO_STRUCT(lck);
	ZERO_STRUCT(el);
	lck.in.locks		= el;
	lck.in.lock_count	= 0x0001;
	lck.in.lock_sequence	= 0x00000000;
	lck.in.file.handle	= h;
	el[0].offset		= 0;
	el[0].length		= 1;
	el[0].reserved		= 0x00000000;
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Disconnect/Reconnect. */
	talloc_free(tree);
	tree = NULL;

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = &h;
	io.in.lease_request = &ls;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;

	lck.in.file.handle	= h;
	el[0].flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

 done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	talloc_free(tree);

	return ret;
}

/**
 * Open with a RH lease, disconnect, open in another tree, reconnect.
 *
 * This test actually demonstrates a minimum level of respect for the durable
 * open in the face of another open. As long as this test shows an inability to
 * reconnect after an open, the oplock/lease tests above will certainly
 * demonstrate an error on reconnect.
 */
static bool test_durable_open_open2_lease(struct torture_context *tctx,
					  struct smb2_tree *tree1,
					  struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1, io2;
	struct smb2_lease ls;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	NTSTATUS status;
	char fname[256];
	bool ret = true;
	uint64_t lease;
	uint32_t caps;
	struct smbcli_options options;

	options = tree1->session->transport->options;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	/*
	 * Choose a random name and random lease in case the state is left a
	 * little funky.
	 */
	lease = random();
	snprintf(fname, 256, "durable_open_open2_lease_%s.dat",
		 generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree1, fname);

	/* Create with lease */
	smb2_lease_create_share(&io1, &ls, false /* dir */, fname,
				smb2_util_share_access(""),
				lease,
				smb2_util_lease_state("RH"));
	io1.in.durable_open = true;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io1.out.lease_response.lease_key.data[0], lease);
	CHECK_VAL(io1.out.lease_response.lease_key.data[1], ~lease);
	CHECK_VAL(io1.out.lease_response.lease_state,
		  smb2_util_lease_state("RH"));

	/* Disconnect */
	talloc_free(tree1);
	tree1 = NULL;

	/* Open the file in tree2 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);

	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);

	/* Reconnect */
	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io1);
	io1.in.fname = fname;
	io1.in.durable_handle = &h1;
	io1.in.lease_request = &ls;

	/*
	 * Windows7 (build 7000) will give away an open immediately if the
	 * original client is gone. (ZML: This seems like a bug. It should give
	 * some time for the client to reconnect!)
	 */
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	h1 = io1.out.file.handle;

 done:
	if (tree1 != NULL){
		smb2_util_close(tree1, h1);
		smb2_util_unlink(tree1, fname);
		talloc_free(tree1);
	}

	smb2_util_close(tree2, h2);
	smb2_util_unlink(tree2, fname);
	talloc_free(tree2);

	return ret;
}

/**
 * Open with a batch oplock, disconnect, open in another tree, reconnect.
 *
 * This test actually demonstrates a minimum level of respect for the durable
 * open in the face of another open. As long as this test shows an inability to
 * reconnect after an open, the oplock/lease tests above will certainly
 * demonstrate an error on reconnect.
 */
static bool test_durable_open_open2_oplock(struct torture_context *tctx,
					   struct smb2_tree *tree1,
					   struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1, io2;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	NTSTATUS status;
	char fname[256];
	bool ret = true;

	/*
	 * Choose a random name and random lease in case the state is left a
	 * little funky.
	 */
	snprintf(fname, 256, "durable_open_open2_oplock_%s.dat",
		 generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree1, fname);

	/* Create with batch oplock */
	smb2_oplock_create(&io1, fname, SMB2_OPLOCK_LEVEL_BATCH);
	io1.in.durable_open = true;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* Disconnect */
	talloc_free(tree1);
	tree1 = NULL;

	/* Open the file in tree2 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);

	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	/* Reconnect */
	if (!torture_smb2_connection(tctx, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io1);
	io1.in.fname = fname;
	io1.in.durable_handle = &h1;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	h1 = io1.out.file.handle;

 done:
	smb2_util_close(tree2, h2);
	smb2_util_unlink(tree2, fname);
	if (tree1 != NULL) {
		smb2_util_close(tree1, h1);
		smb2_util_unlink(tree1, fname);
	}

	talloc_free(tree1);
	talloc_free(tree2);

	return ret;
}

/**
 * test behaviour with initial allocation size
 */
static bool test_durable_open_alloc_size(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	bool ret = true;
	uint64_t previous_session_id;
	uint64_t alloc_size_step;
	uint64_t initial_alloc_size = 0x1000;
	const uint8_t *b = NULL;
	struct smbcli_options options;

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_alloc_size_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = true;
	io.in.alloc_size = initial_alloc_size;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_NOT_VAL(io.out.alloc_size, 0);
	alloc_size_step = io.out.alloc_size;
	CHECK_CREATED_SIZE(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE,
			   alloc_size_step, 0);
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));

	/* prepare buffer */
	b = talloc_zero_size(mem_ctx, alloc_size_step);
	CHECK_NOT_NULL(b);

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* disconnect, reconnect and then do durable reopen */
	talloc_free(tree);
	tree = NULL;

	if (!torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree))
	{
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED_SIZE(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE,
			   alloc_size_step, 0);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* write one byte */
	status = smb2_util_write(tree, *h, b, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* disconnect, reconnect and then do durable reopen */
	talloc_free(tree);
	tree = NULL;

	if (!torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree))
	{
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED_SIZE(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE,
			   alloc_size_step, 1);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* write more byte than initial allocation size */
	status = smb2_util_write(tree, *h, b, 1, alloc_size_step);

	/* disconnect, reconnect and then do durable reopen */
	talloc_free(tree);
	tree = NULL;

	if (!torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree))
	{
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED_SIZE(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE,
			   alloc_size_step * 2, alloc_size_step + 1);
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
 * test behaviour when a disconnect happens while creating a read-only file
 */
static bool test_durable_open_read_only(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	bool ret = true;
	uint64_t previous_session_id;
	const uint8_t b = 0;
	uint64_t alloc_size = 0;
	struct smbcli_options options;

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_initial_alloc_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = true;
	io.in.file_attributes = FILE_ATTRIBUTE_READONLY;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* write one byte */
	status = smb2_util_write(tree, *h, &b, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* disconnect, reconnect and then do durable reopen */
	talloc_free(tree);
	tree = NULL;

	if (!torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree))
	{
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;
	h = NULL;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	alloc_size = io.out.alloc_size;
	CHECK_CREATED_SIZE(&io, EXISTED,
			   FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_ARCHIVE,
			   alloc_size, 1);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

	/* write one byte */
	status = smb2_util_write(tree, *h, &b, 1, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	if (h != NULL) {
		union smb_setfileinfo sfinfo;

		ZERO_STRUCT(sfinfo);
		sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION;
		sfinfo.basic_info.in.file.handle = *h;
		sfinfo.basic_info.in.attrib = FILE_ATTRIBUTE_NORMAL;
		smb2_setinfo_file(tree, &sfinfo);

		smb2_util_close(tree, *h);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * durable open with oplock, disconnect, exit
 */
static bool test_durable_open_oplock_disconnect(struct torture_context *tctx,
						struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	NTSTATUS status;
	char fname[256];
	bool ret = true;

	snprintf(fname, 256, "durable_open_oplock_disconnect_%s.dat",
		 generate_random_str(mem_ctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create(&io, fname, SMB2_OPLOCK_LEVEL_BATCH);
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	_h = io.out.file.handle;
	h = &_h;

	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* disconnect */
	talloc_free(tree);
	tree = NULL;

done:
	if (tree != NULL) {
		if (h != NULL) {
			smb2_util_close(tree, *h);
		}
		smb2_util_unlink(tree, fname);
	}
	talloc_free(mem_ctx);
	return ret;
}


struct torture_suite *torture_smb2_durable_open_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "durable-open");

	torture_suite_add_1smb2_test(suite, "open-oplock", test_durable_open_open_oplock);
	torture_suite_add_1smb2_test(suite, "open-lease", test_durable_open_open_lease);
	torture_suite_add_1smb2_test(suite, "reopen1", test_durable_open_reopen1);
	torture_suite_add_1smb2_test(suite, "reopen1a", test_durable_open_reopen1a);
	torture_suite_add_1smb2_test(suite, "reopen1a-lease", test_durable_open_reopen1a_lease);
	torture_suite_add_1smb2_test(suite, "reopen2", test_durable_open_reopen2);
	torture_suite_add_1smb2_test(suite, "reopen2-lease", test_durable_open_reopen2_lease);
	torture_suite_add_1smb2_test(suite, "reopen2-lease-v2", test_durable_open_reopen2_lease_v2);
	torture_suite_add_1smb2_test(suite, "reopen2a", test_durable_open_reopen2a);
	torture_suite_add_1smb2_test(suite, "reopen3", test_durable_open_reopen3);
	torture_suite_add_1smb2_test(suite, "reopen4", test_durable_open_reopen4);
	torture_suite_add_1smb2_test(suite, "delete_on_close1",
				     test_durable_open_delete_on_close1);
	torture_suite_add_1smb2_test(suite, "delete_on_close2",
				     test_durable_open_delete_on_close2);
	torture_suite_add_1smb2_test(suite, "file-position",
	    test_durable_open_file_position);
	torture_suite_add_2smb2_test(suite, "oplock", test_durable_open_oplock);
	torture_suite_add_2smb2_test(suite, "lease", test_durable_open_lease);
	torture_suite_add_1smb2_test(suite, "lock-oplock", test_durable_open_lock_oplock);
	torture_suite_add_1smb2_test(suite, "lock-lease", test_durable_open_lock_lease);
	torture_suite_add_2smb2_test(suite, "open2-lease",
				     test_durable_open_open2_lease);
	torture_suite_add_2smb2_test(suite, "open2-oplock",
				     test_durable_open_open2_oplock);
	torture_suite_add_1smb2_test(suite, "alloc-size",
				     test_durable_open_alloc_size);
	torture_suite_add_1smb2_test(suite, "read-only",
				     test_durable_open_read_only);

	suite->description = talloc_strdup(suite, "SMB2-DURABLE-OPEN tests");

	return suite;
}

struct torture_suite *torture_smb2_durable_open_disconnect_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx,
				 "durable-open-disconnect");

	torture_suite_add_1smb2_test(suite, "open-oplock-disconnect",
				     test_durable_open_oplock_disconnect);

	suite->description = talloc_strdup(suite,
					"SMB2-DURABLE-OPEN-DISCONNECT tests");

	return suite;
}
