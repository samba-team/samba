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

static struct {
	int count;
	struct smb2_close cl;
} break_info;

static void torture_oplock_close_callback(struct smb2_request *req)
{
	smb2_close_recv(req, &break_info.cl);
}

/* A general oplock break notification handler.  This should be used when a
 * test expects to break from batch or exclusive to a lower level. */
static bool torture_oplock_handler(struct smb2_transport *transport,
				   const struct smb2_handle *handle,
				   uint8_t level,
				   void *private_data)
{
	struct smb2_tree *tree = private_data;
	struct smb2_request *req;

	break_info.count++;

	ZERO_STRUCT(break_info.cl);
	break_info.cl.in.file.handle = *handle;

	req = smb2_close_send(tree, &break_info.cl);
	req->async.fn = torture_oplock_close_callback;
	req->async.private_data = NULL;
	return true;
}

/**
 * testing various create blob combinations.
 */
bool test_durable_v2_open_create_blob(struct torture_context *tctx,
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
	struct smbcli_options options;

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_v2_open_create_blob_%s.dat",
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

	/* disconnect */
	TALLOC_FREE(tree);

	/* create a new session (same client_guid) */
	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/*
	 * check invalid combinations of durable handle
	 * request and reconnect blobs
	 * See MS-SMB2: 3.3.5.9.12
	 * Handling the SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 Create Context
	 */
	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle_v2 = h; /* durable v2 reconnect request */
	io.in.durable_open = true;   /* durable v1 handle request */
	io.in.create_guid = create_guid;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;     /* durable v1 reconnect request */
	io.in.durable_open_v2 = true; /* durable v2 handle request */
	io.in.create_guid = create_guid;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h;    /* durable v1 reconnect request */
	io.in.durable_handle_v2 = h; /* durable v2 reconnect request */
	io.in.create_guid = create_guid;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle_v2 = h;  /* durable v2 reconnect request */
	io.in.durable_open_v2 = true; /* durable v2 handle request */
	io.in.create_guid = create_guid;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

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
 * Basic test for doing a durable open
 * and do a session reconnect while the first
 * session is still active and the handle is
 * still open in the client.
 * This closes the original session and  a
 * durable reconnect on the new session succeeds.
 */
bool test_durable_v2_open_reopen1a(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io, io2;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	struct smb2_tree *tree2 = NULL;
	uint64_t previous_session_id;
	struct smbcli_options options;

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_v2_open_reopen1a_%s.dat",
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

	/*
	 * a session reconnect on a second tcp connection
	 */

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	if (!torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree2))
	{
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/*
	 * check that this has deleted the old session
	 */

	ZERO_STRUCT(io);
	io.in.fname = "";
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_USER_SESSION_DELETED);

	/*
	 * but a durable reconnect on the new session succeeds:
	 */

	ZERO_STRUCT(io2);
	io2.in.fname = "";
	io2.in.durable_handle_v2 = h;
	io2.in.create_guid = create_guid;
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io2.out.durable_open, false);
	CHECK_VAL(io2.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io2.out.persistent_open, false);
	CHECK_VAL(io2.out.timeout, io.in.timeout);
	_h = io2.out.file.handle;
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
	struct GUID create_guid_invalid = GUID_random();
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

	/* disconnect, leaving the durable open */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	/*
	 * first a few failure cases
	 */

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

	/* a non-zero but non-matching create_guid does not change it: */
	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid_invalid;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/*
	 * now success:
	 * The important difference is that the create_guid is provided.
	 */
	ZERO_STRUCT(io);
	io.in.fname = fname;
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

	/* disconnect one more time */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	/* These are completely ignored by the server */
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
 * durable reconnect test:
 * connect with v2, reconnect with v1
 */
bool test_durable_v2_open_reopen2b(struct torture_context *tctx,
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
	struct smbcli_options options;

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_v2_open_reopen2b_%s.dat",
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

	/* disconnect, leaving the durable open */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle_v2 = h;     /* durable v2 reconnect */
	io.in.create_guid = GUID_zero(); /* but zero create GUID */
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = h; /* durable v1 (!) reconnect */
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
 * durable reconnect test:
 * connect with v1, reconnect with v2 : fails (no create_guid...)
 */
bool test_durable_v2_open_reopen2c(struct torture_context *tctx,
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
	struct smbcli_options options;

	options = tree->session->transport->options;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_v2_open_reopen2c_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = true;
	io.in.durable_open_v2 = false;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.durable_open_v2, false);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 0);

	/* disconnect, leaving the durable open */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle_v2 = h;     /* durable v2 reconnect */
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
 * lease variant of reopen2
 * basic test for doing a durable open
 * tcp disconnect, reconnect, do a durable reopen (succeeds)
 */
bool test_durable_v2_open_reopen2_lease(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
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
	snprintf(fname, 256, "durable_v2_open_reopen2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	lease_key = random();
	smb2_lease_create(&io, &ls, false /* dir */, fname,
			  lease_key, smb2_util_lease_state("RWH"));
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
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, io.in.timeout);
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

	/*
	 * attempt with lease provided, but
	 * with a changed lease key. => fails
	 */
	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
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
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	io.in.lease_request = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	/*
	 * Now for a succeeding reconnect:
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
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
	 * - io.in.durable_handle_v2,
	 * - io.in.create_guid
	 * - io.in.lease_request->lease_key
	 */

	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
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
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * lease_v2 variant of reopen2
 * basic test for doing a durable open
 * tcp disconnect, reconnect, do a durable reopen (succeeds)
 */
bool test_durable_v2_open_reopen2_lease_v2(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
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
	snprintf(fname, 256, "durable_v2_open_reopen2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	lease_key = random();
	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease_key, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
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
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, io.in.timeout);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[1], ~lease_key);

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

	/*
	 * attempt with lease provided, but
	 * with a changed lease key. => fails
	 */
	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
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
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	/*
	 * Now for a succeeding reconnect:
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
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
	io.in.fname = "__non_existing_fname__";

	/*
	 * only these are checked:
	 * - io.in.fname
	 * - io.in.durable_handle_v2,
	 * - io.in.create_guid
	 * - io.in.lease_request_v2->lease_key
	 */

	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
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
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * Test durable request / reconnect with AppInstanceId
 */
bool test_durable_v2_open_app_instance(struct torture_context *tctx,
				       struct smb2_tree *tree1,
				       struct smb2_tree *tree2)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h1, _h2;
	struct smb2_handle *h1 = NULL, *h2 = NULL;
	struct smb2_create io1, io2;
	bool ret = true;
	struct GUID create_guid_1 = GUID_random();
	struct GUID create_guid_2 = GUID_random();
	struct GUID app_instance_id = GUID_random();

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_v2_open_app_instance_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	ZERO_STRUCT(break_info);
	tree1->session->transport->oplock.handler = torture_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.durable_open = false;
	io1.in.durable_open_v2 = true;
	io1.in.persistent_open = false;
	io1.in.create_guid = create_guid_1;
	io1.in.app_instance_id = &app_instance_id;
	io1.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io1.out.durable_open, false);
	CHECK_VAL(io1.out.durable_open_v2, true);
	CHECK_VAL(io1.out.persistent_open, false);
	CHECK_VAL(io1.out.timeout, io1.in.timeout);

	/*
	 * try to open the file as durable from a second tree with
	 * a different create guid but the same app_instance_id
	 * while the first handle is still open.
	 */

	smb2_oplock_create_share(&io2, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io2.in.durable_open = false;
	io2.in.durable_open_v2 = true;
	io2.in.persistent_open = false;
	io2.in.create_guid = create_guid_2;
	io2.in.app_instance_id = &app_instance_id;
	io2.in.timeout = UINT32_MAX;

	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io2.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io2.out.durable_open, false);
	CHECK_VAL(io2.out.durable_open_v2, true);
	CHECK_VAL(io2.out.persistent_open, false);
	CHECK_VAL(io2.out.timeout, io2.in.timeout);

	CHECK_VAL(break_info.count, 0);

	status = smb2_util_close(tree1, *h1);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);
	h1 = NULL;

done:
	if (h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	if (h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	smb2_util_unlink(tree2, fname);

	talloc_free(tree1);
	talloc_free(tree2);

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

	torture_suite_add_1smb2_test(suite, "create-blob", test_durable_v2_open_create_blob);
	torture_suite_add_1smb2_test(suite, "open-oplock", test_durable_v2_open_oplock);
	torture_suite_add_1smb2_test(suite, "open-lease", test_durable_v2_open_lease);
	torture_suite_add_1smb2_test(suite, "reopen1", test_durable_v2_open_reopen1);
	torture_suite_add_1smb2_test(suite, "reopen1a", test_durable_v2_open_reopen1a);
	torture_suite_add_1smb2_test(suite, "reopen2", test_durable_v2_open_reopen2);
	torture_suite_add_1smb2_test(suite, "reopen2b", test_durable_v2_open_reopen2b);
	torture_suite_add_1smb2_test(suite, "reopen2c", test_durable_v2_open_reopen2c);
	torture_suite_add_1smb2_test(suite, "reopen2-lease", test_durable_v2_open_reopen2_lease);
	torture_suite_add_1smb2_test(suite, "reopen2-lease-v2", test_durable_v2_open_reopen2_lease_v2);
	torture_suite_add_2smb2_test(suite, "app-instance", test_durable_v2_open_app_instance);
	torture_suite_add_1smb2_test(suite, "persistent-open-oplock", test_persistent_open_oplock);
	torture_suite_add_1smb2_test(suite, "persistent-open-lease", test_persistent_open_lease);

	suite->description = talloc_strdup(suite, "SMB2-DURABLE-V2-OPEN tests");

	return suite;
}
