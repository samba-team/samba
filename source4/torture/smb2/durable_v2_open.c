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
#include "lease_break_handler.h"

#define CHECK_VAL(v, correct) \
	torture_assert_u64_equal_goto(tctx, v, correct, ret, done, __location__)

#define CHECK_STATUS(status, correct) \
	torture_assert_ntstatus_equal_goto(tctx, status, correct, ret, done, __location__)

#define CHECK_CREATED(__io, __created, __attribute)			\
	do {								\
		CHECK_VAL((__io)->out.create_action, NTCREATEX_ACTION_ ## __created); \
		CHECK_VAL((__io)->out.size, 0);				\
		CHECK_VAL((__io)->out.file_attr, (__attribute));	\
		CHECK_VAL((__io)->out.reserved2, 0);			\
	} while(0)

#define CHECK_LEASE_V2(__io, __state, __oplevel, __key, __flags, __parent, __epoch) \
	do {								\
		CHECK_VAL((__io)->out.lease_response_v2.lease_version, 2); \
		if (__oplevel) {					\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[0], (__key)); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[1], ~(__key)); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_state, smb2_util_lease_state(__state)); \
		} else {						\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_NONE); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[0], 0); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_key.data[1], 0); \
			CHECK_VAL((__io)->out.lease_response_v2.lease_state, 0); \
		}							\
									\
		CHECK_VAL((__io)->out.lease_response_v2.lease_flags, __flags); \
		if (__flags & SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET) { \
			CHECK_VAL((__io)->out.lease_response_v2.parent_lease_key.data[0], (__parent)); \
			CHECK_VAL((__io)->out.lease_response_v2.parent_lease_key.data[1], ~(__parent)); \
		} \
		CHECK_VAL((__io)->out.lease_response_v2.lease_duration, 0); \
		CHECK_VAL((__io)->out.lease_response_v2.lease_epoch, (__epoch)); \
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
	uint32_t share_capabilities;
	bool share_is_so;
	uint8_t expected_oplock_granted;
	bool expected_dhv2_granted;
	uint32_t expected_dhv2_timeout;

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	if (share_is_so) {
		expected_oplock_granted = SMB2_OPLOCK_LEVEL_II;
		expected_dhv2_granted = false;
		expected_dhv2_timeout = 0;
	} else {
		expected_oplock_granted = SMB2_OPLOCK_LEVEL_BATCH;
		expected_dhv2_granted = true;
		expected_dhv2_timeout = 300*1000;
}

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
	CHECK_VAL(io.out.oplock_level, expected_oplock_granted);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, expected_dhv2_granted);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, expected_dhv2_timeout);

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
	uint32_t share_capabilities;
	bool share_is_so;
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	bool ret = true;
	struct smb2_create io;
	uint8_t expected_oplock_level;
	bool expected_durable;

	smb2_util_unlink(tree, fname);

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	expected_oplock_level = smb2_util_oplock_level(test.level);
	expected_durable = test.durable;

	if (share_is_so) {
		/*
		 * MS-SMB2 3.3.5.9 Receiving an SMB2 CREATE Request
		 *
		 * If Connection.Dialect belongs to the SMB 3.x dialect family,
		 * TreeConnect.Share.Type is STYPE_CLUSTER_SOFS as specified in
		 * [MS-SRVS] section 2.2.2.4, and the RequestedOplockLevel is
		 * SMB2_OPLOCK_LEVEL_BATCH, the server MUST set
		 * RequestedOplockLevel to SMB2_OPLOCK_LEVEL_II.
		 */
		if (expected_oplock_level == SMB2_OPLOCK_LEVEL_BATCH) {
			expected_oplock_level = SMB2_OPLOCK_LEVEL_II;
		}
		/*
		 * No Durable Handles on SOFS shares, only Persistent Handles.
		 */
		if (!request_persistent) {
			expected_durable = false;
		}
	}

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
	CHECK_VAL(io.out.durable_open_v2, expected_durable);
	CHECK_VAL(io.out.persistent_open, test.persistent);
	CHECK_VAL(io.out.oplock_level, expected_oplock_level);

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
					   bool share_is_so,
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
	uint8_t expected_lease_granted;
	bool expected_durable;

	smb2_util_unlink(tree, fname);

	lease = random();

	expected_lease_granted = smb2_util_lease_state(test.type);
	expected_durable = test.durable;
	if (share_is_so) {
		expected_lease_granted &= SMB2_LEASE_READ;
		if (!request_persistent) {
			expected_durable = false;
		}
	}

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
	CHECK_VAL(io.out.durable_open_v2, expected_durable);
	CHECK_VAL(io.out.persistent_open, test.persistent);
	if (smb2_util_lease_state(test.type) != 0) {
		CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
		CHECK_VAL(io.out.lease_response.lease_key.data[0], lease);
		CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease);
		CHECK_VAL(io.out.lease_response.lease_state,
			  expected_lease_granted);
	}
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
					     bool share_is_so,
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
						     share_is_so,
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
	uint32_t share_capabilities;
	bool share_is_so;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_lease_%s.dat", generate_random_str(tctx, 8));

	ret = test_durable_v2_open_lease_table(tctx, tree, fname,
					       false, /* request_persistent */
					       share_is_so,
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
	CHECK_VAL(io.out.timeout, 300*1000);

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
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	bool ret = true;
	struct smb2_tree *tree2 = NULL;
	struct smb2_tree *tree3 = NULL;
	uint64_t previous_session_id;
	struct smbcli_options options;
	struct GUID orig_client_guid;

	options = tree->session->transport->options;
	orig_client_guid = options.client_guid;

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
	CHECK_VAL(io.out.timeout, 300*1000);

	/*
	 * a session reconnect on a second tcp connection
	 */

	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* for oplocks, the client guid can be different: */
	options.client_guid = GUID_random();

	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options, &tree2);
	torture_assert_goto(tctx, ret, ret, done, "couldn't reconnect");

	/*
	 * check that this has deleted the old session
	 */

	ZERO_STRUCT(io);
	io.in.fname = "";
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_USER_SESSION_DELETED);

	TALLOC_FREE(tree);

	/*
	 * but a durable reconnect on the new session succeeds:
	 */

	ZERO_STRUCT(io);
	io.in.fname = "";
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 0);
	_h = io.out.file.handle;
	h = &_h;

	/*
	 * a session reconnect on a second tcp connection
	 */

	previous_session_id = smb2cli_session_current_id(tree2->session->smbXcli);

	/* it works the same with the original guid */
	options.client_guid = orig_client_guid;

	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options, &tree3);
	torture_assert_goto(tctx, ret, ret, done, "couldn't reconnect");

	/*
	 * check that this has deleted the old session
	 */

	ZERO_STRUCT(io);
	io.in.fname = "";
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_USER_SESSION_DELETED);
	TALLOC_FREE(tree2);

	/*
	 * but a durable reconnect on the new session succeeds:
	 */

	ZERO_STRUCT(io);
	io.in.fname = "";
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	status = smb2_create(tree3, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 0);
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
bool test_durable_v2_open_reopen1a_lease(struct torture_context *tctx,
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
	CHECK_VAL(io.out.timeout, 300*1000);
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
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
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
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	io.in.lease_request = &ls;
	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);


	/*
	 * now a session reconnect on a second tcp connection
	 * with original client_guid allows the durable reconnect.
	 */

	options.client_guid = orig_client_guid;
	//options.client_guid = GUID_random();

	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options, &tree3);
	torture_assert_goto(tctx, ret, ret, done, "couldn't reconnect");

	/*
	 * check that this has deleted the old session
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	io.in.lease_request = &ls;
	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	TALLOC_FREE(tree2);

	/*
	 * but a durable reconnect on the new session succeeds:
	 */

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle_v2 = h;
	io.in.create_guid = create_guid;
	io.in.lease_request = &ls;
	status = smb2_create(tree3, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 0);
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
	CHECK_VAL(io.out.timeout, 300*1000);

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
	CHECK_VAL(io.out.timeout, 300*1000);

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

	lease_key = generate_random_u64();
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
	CHECK_VAL(io.out.timeout, 300*1000);
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

	smb2_deltree(tree, __func__);
	status = torture_smb2_testdir(tree, __func__, &_h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree, _h);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\durable_v2_open_reopen2_%s.dat",
		 __func__, generate_random_str(tctx, 8));

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
	CHECK_VAL(io.out.timeout, 300*1000);
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
	smb2_deltree(tree, __func__);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/*
  Open(BATCH), take BRL, disconnect, reconnect.
*/
static bool test_durable_v2_open_lock_oplock(struct torture_context *tctx,
					     struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	struct smb2_handle h = {{0}};
	struct smb2_lock lck;
	struct smb2_lock_element el[2];
	NTSTATUS status;
	char fname[256];
	bool ret = true;
	struct smbcli_options options;

	options = tree->session->transport->options;

	snprintf(fname, 256, "durable_v2_open_lock_oplock_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree, fname);

	/* Create with lease */

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
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
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

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = &h;
	io.in.create_guid = create_guid;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));

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
  Open(RWH), take BRL, disconnect, reconnect.
*/
static bool test_durable_v2_open_lock_lease(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct GUID create_guid = GUID_random();
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
	snprintf(fname, 256, "durable_v2_open_lock_lease_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree, fname);

	/* Create with lease */

	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	ls.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RWH", true, lease,
		       0, 0, ls.lease_epoch);

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
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = &h;
	io.in.create_guid = create_guid;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RWH", true, lease,
		       0, 0, ls.lease_epoch);

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
  Open(RH), take BRL, disconnect, fails reconnect without W LEASE
*/
static bool test_durable_v2_open_lock_noW_lease(struct torture_context *tctx,
						struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct GUID create_guid = GUID_random();
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
	snprintf(fname, 256, "durable_v2_open_lock_noW_lease_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree, fname);

	/* Create with lease */

	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	ls.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease,
		       0, 0, ls.lease_epoch);

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
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = &h;
	io.in.create_guid = create_guid;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

 done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	talloc_free(tree);

	return ret;
}

/**
 * 1. stat open (without lease) => h1
 * 2. durable open with RWH => h2
 * 3. disconnect
 * 4. reconnect
 * 5. durable reconnect RWH => h2
 */
static bool test_durable_v2_open_stat_and_lease(struct torture_context *tctx,
						struct smb2_tree *tree1)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls;
	uint64_t lease_key;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	smb2_generic_create(&io, NULL, false /* dir */, fname,
			    FILE_OPEN_IF, 0, 0, 0);
	io.in.desired_access  = SEC_FILE_READ_ATTRIBUTE;
	io.in.desired_access |= SEC_FILE_WRITE_ATTRIBUTE;
	io.in.desired_access |= SEC_STD_SYNCHRONIZE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	lease_key = random();
	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease_key, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RWH", true, lease_key,
		       0, 0, ls.lease_epoch);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);
	h1 = NULL;

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h2;
	io.in.create_guid = create_guid2;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RWH", true, lease_key,
		       0, 0, ls.lease_epoch);

	status = smb2_util_close(tree1, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}

	if (tree1 != NULL && h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	if (tree1 != NULL && h2 != NULL) {
		smb2_util_close(tree1, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. non stat open (without a lease) => h1
 * 2. durable open with RWH => h2 => RH
 * 3. disconnect
 * 4. reconnect
 * 5. durable reconnect RH => h2
 */
static bool test_durable_v2_open_nonstat_and_lease(struct torture_context *tctx,
						   struct smb2_tree *tree1)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls;
	uint64_t lease_key;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	smb2_generic_create(&io, NULL, false /* dir */, fname,
			    FILE_OPEN_IF, 0, 0, 0);
	io.in.desired_access  = SEC_FILE_READ_ATTRIBUTE;
	io.in.desired_access |= SEC_FILE_WRITE_ATTRIBUTE;
	io.in.desired_access |= SEC_STD_SYNCHRONIZE;
	/*
	 * SEC_STD_READ_CONTROL means we no longer
	 * have a stat open that would allow a RWH lease
	 */
	io.in.desired_access |= SEC_STD_READ_CONTROL;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	lease_key = random();
	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease_key, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key,
		       0, 0, ls.lease_epoch);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);
	h1 = NULL;

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h2;
	io.in.create_guid = create_guid2;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key,
		       0, 0, ls.lease_epoch);

	status = smb2_util_close(tree1, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}

	if (tree1 != NULL && h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	if (tree1 != NULL && h2 != NULL) {
		smb2_util_close(tree1, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. stat open with RH lease => h1
 * 2. durable open with RWH => h2 => RH
 * 3. disconnect
 * 4. reconnect
 * 5. durable reconnect RH => h2
 */
static bool test_durable_v2_open_statRH_and_lease(struct torture_context *tctx,
						  struct smb2_tree *tree1)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls;
	uint64_t lease_key;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	smb2_generic_create(&io, NULL, false /* dir */, fname,
			    FILE_OPEN_IF, 0, 0, 0);
	lease_key = random();
	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease_key, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.desired_access = SEC_FILE_READ_ATTRIBUTE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	ls.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key,
		       0, 0, ls.lease_epoch);

	lease_key = random();
	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease_key, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key,
		       0, 0, ls.lease_epoch);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);
	h1 = NULL;

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h2;
	io.in.create_guid = create_guid2;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key,
		       0, 0, ls.lease_epoch);

	status = smb2_util_close(tree1, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}

	if (tree1 != NULL && h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	if (tree1 != NULL && h2 != NULL) {
		smb2_util_close(tree1, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1(RWH) => h1
 * 2. durable open with L1(RWH) => h2
 * 3. disconnect
 * 4. reconnect
 * 5. durable reconnect L1(RWH) => h1
 * 6. durable reconnect L1(RWH) => h2
 */
static bool test_durable_v2_open_two_same_lease(struct torture_context *tctx,
						struct smb2_tree *tree1)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1 = GUID_random();
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls;
	uint64_t lease_key;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key = random();
	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease_key, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RWH", true, lease_key,
		       0, 0, ls.lease_epoch);

	smb2_lease_v2_create(&io, &ls, false /* dir */, fname,
			     lease_key, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RWH", true, lease_key,
		       0, 0, ls.lease_epoch);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1;
	io.in.create_guid = create_guid1;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RWH", true, lease_key,
		       0, 0, ls.lease_epoch);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h2;
	io.in.create_guid = create_guid2;
	io.in.lease_request_v2 = &ls;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RWH", true, lease_key,
		       0, 0, ls.lease_epoch);

	status = smb2_util_close(tree1, *h1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = NULL;

	status = smb2_util_close(tree1, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}

	if (tree1 != NULL && h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	if (tree1 != NULL && h2 != NULL) {
		smb2_util_close(tree1, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1(RH) => h1
 * 2. durable open with L2(RH) => h2
 * 3. disconnect
 * 4. reconnect
 * 5. durable reconnect L1(RH) => h1
 * 6. durable reconnect L2(RH) => h2
 */
static bool test_durable_v2_open_two_different_leases(struct torture_context *tctx,
						      struct smb2_tree *tree1)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1 = GUID_random();
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls1;
	uint64_t lease_key1;
	struct smb2_lease ls2;
	uint64_t lease_key2;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key1 = random();
	smb2_lease_v2_create(&io, &ls1, false /* dir */, fname,
			     lease_key1, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1,
		       0, 0, ls1.lease_epoch);

	lease_key2 = random();
	smb2_lease_v2_create(&io, &ls2, false /* dir */, fname,
			     lease_key2, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key2,
		       0, 0, ls2.lease_epoch);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1;
	io.in.create_guid = create_guid1;
	io.in.lease_request_v2 = &ls1;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key1,
		       0, 0, ls1.lease_epoch);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h2;
	io.in.create_guid = create_guid2;
	io.in.lease_request_v2 = &ls2;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key2,
		       0, 0, ls2.lease_epoch);

	status = smb2_util_close(tree1, *h1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = NULL;

	status = smb2_util_close(tree1, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}

	if (tree1 != NULL && h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	if (tree1 != NULL && h2 != NULL) {
		smb2_util_close(tree1, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1A(RH) on tree1 => h1a
 * 1. durable open with L1B(RH) on tree1 => h1b
 * 2. disconnect tree1
 * 3. stat open on tree2 => h2
 * 4. reconnect tree1
 * 5. durable reconnect L1A(RH) => h1a
 * 6. durable reconnect L1B(RH) => h1a
 */
static bool test_durable_v2_open_keep_disconnected_rh_with_stat_open(struct torture_context *tctx,
								     struct smb2_tree *tree1,
								     struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1a;
	struct smb2_handle *h1a = NULL;
	struct smb2_handle _h1b;
	struct smb2_handle *h1b = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1a = GUID_random();
	struct GUID create_guid1b = GUID_random();
	struct smb2_lease ls1a;
	uint64_t lease_key1a;
	struct smb2_lease ls1b;
	uint64_t lease_key1b;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key1a = random();
	smb2_lease_v2_create(&io, &ls1a, false /* dir */, fname,
			     lease_key1a, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1a;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1a.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	lease_key1b = random();
	smb2_lease_v2_create(&io, &ls1b, false /* dir */, fname,
			     lease_key1b, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1b;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1b = io.out.file.handle;
	h1b = &_h1b;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1b.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1b,
		       0, 0, ls1b.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);

	CHECK_NO_BREAK(tctx);

	smb2_generic_create(&io, NULL, false /* dir */, fname,
			    FILE_OPEN_IF, 0, 0, 0);
	io.in.desired_access = SEC_FILE_READ_ATTRIBUTE;
	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false);
	CHECK_VAL(io.out.persistent_open, false);

	CHECK_NO_BREAK(tctx);

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1a;
	io.in.create_guid = create_guid1a;
	io.in.lease_request_v2 = &ls1a;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1b;
	io.in.create_guid = create_guid1b;
	io.in.lease_request_v2 = &ls1b;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1b = io.out.file.handle;
	h1b = &_h1b;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key1b,
		       0, 0, ls1b.lease_epoch);

	status = smb2_util_close(tree1, *h1a);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = NULL;

	status = smb2_util_close(tree1, *h1b);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = NULL;

	status = smb2_util_close(tree2, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

	CHECK_NO_BREAK(tctx);

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}
	if (tree2 != NULL) {
		smb2_keepalive(tree2->session->transport);
	}
	if (tree1 != NULL && h1a != NULL) {
		smb2_util_close(tree1, *h1a);
	}
	if (tree1 != NULL && h1b != NULL) {
		smb2_util_close(tree1, *h1b);
	}
	if (tree2 != NULL && h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1A(RH) on tree1 => h1a
 * 1. durable open with L1B(RH) on tree1 => h1b
 * 2. disconnect tree1
 * 3. durable open with L2(RH) on tree2 => h2
 * 4. reconnect tree1
 * 5. durable reconnect L1A(RH) => h1a
 * 6. durable reconnect L1B(RH) => h1a
 */
static bool test_durable_v2_open_keep_disconnected_rh_with_rh_open(struct torture_context *tctx,
								   struct smb2_tree *tree1,
								   struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1a;
	struct smb2_handle *h1a = NULL;
	struct smb2_handle _h1b;
	struct smb2_handle *h1b = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1a = GUID_random();
	struct GUID create_guid1b = GUID_random();
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls1a;
	uint64_t lease_key1a;
	struct smb2_lease ls1b;
	uint64_t lease_key1b;
	struct smb2_lease ls2;
	uint64_t lease_key2;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key1a = random();
	smb2_lease_v2_create(&io, &ls1a, false /* dir */, fname,
			     lease_key1a, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1a;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1a.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	lease_key1b = random();
	smb2_lease_v2_create(&io, &ls1b, false /* dir */, fname,
			     lease_key1b, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1b;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1b = io.out.file.handle;
	h1b = &_h1b;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1b.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1b,
		       0, 0, ls1b.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);

	CHECK_NO_BREAK(tctx);

	lease_key2 = random();
	smb2_lease_v2_create(&io, &ls2, false /* dir */, fname,
			     lease_key2, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key2,
		       0, 0, ls2.lease_epoch);

	CHECK_NO_BREAK(tctx);

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1a;
	io.in.create_guid = create_guid1a;
	io.in.lease_request_v2 = &ls1a;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1b;
	io.in.create_guid = create_guid1b;
	io.in.lease_request_v2 = &ls1b;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1b = io.out.file.handle;
	h1b = &_h1b;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key1b,
		       0, 0, ls1b.lease_epoch);

	status = smb2_util_close(tree1, *h1a);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = NULL;

	status = smb2_util_close(tree1, *h1b);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = NULL;

	status = smb2_util_close(tree2, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

	CHECK_NO_BREAK(tctx);

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}
	if (tree2 != NULL) {
		smb2_keepalive(tree2->session->transport);
	}
	if (tree1 != NULL && h1a != NULL) {
		smb2_util_close(tree1, *h1a);
	}
	if (tree1 != NULL && h1b != NULL) {
		smb2_util_close(tree1, *h1b);
	}
	if (tree2 != NULL && h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1A(RH) on tree1 => h1a
 * 1. durable open with L1B(RH) on tree1 => h1b
 * 2. disconnect tree1
 * 3. durable open with L2(RWH) on tree2 => h2 => RH
 * 4. reconnect tree1
 * 5. durable reconnect L1A(RH) => h1a
 * 6. durable reconnect L1B(RH) => h1a
 */
static bool test_durable_v2_open_keep_disconnected_rh_with_rwh_open(struct torture_context *tctx,
								    struct smb2_tree *tree1,
								    struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1a;
	struct smb2_handle *h1a = NULL;
	struct smb2_handle _h1b;
	struct smb2_handle *h1b = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1a = GUID_random();
	struct GUID create_guid1b = GUID_random();
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls1a;
	uint64_t lease_key1a;
	struct smb2_lease ls1b;
	uint64_t lease_key1b;
	struct smb2_lease ls2;
	uint64_t lease_key2;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key1a = random();
	smb2_lease_v2_create(&io, &ls1a, false /* dir */, fname,
			     lease_key1a, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1a;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1a.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	lease_key1b = random();
	smb2_lease_v2_create(&io, &ls1b, false /* dir */, fname,
			     lease_key1b, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1b;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1b = io.out.file.handle;
	h1b = &_h1b;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1b.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1b,
		       0, 0, ls1b.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);

	CHECK_NO_BREAK(tctx);

	lease_key2 = random();
	smb2_lease_v2_create(&io, &ls2, false /* dir */, fname,
			     lease_key2, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key2,
		       0, 0, ls2.lease_epoch);

	CHECK_NO_BREAK(tctx);

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1a;
	io.in.create_guid = create_guid1a;
	io.in.lease_request_v2 = &ls1a;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1b;
	io.in.create_guid = create_guid1b;
	io.in.lease_request_v2 = &ls1b;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1b = io.out.file.handle;
	h1b = &_h1b;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RH", true, lease_key1b,
		       0, 0, ls1b.lease_epoch);

	status = smb2_util_close(tree1, *h1a);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = NULL;

	status = smb2_util_close(tree1, *h1b);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = NULL;

	status = smb2_util_close(tree2, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

	CHECK_NO_BREAK(tctx);

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}
	if (tree2 != NULL) {
		smb2_keepalive(tree2->session->transport);
	}
	if (tree1 != NULL && h1a != NULL) {
		smb2_util_close(tree1, *h1a);
	}
	if (tree1 != NULL && h1b != NULL) {
		smb2_util_close(tree1, *h1b);
	}
	if (tree2 != NULL && h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1(RWH) on tree1 => h1
 * 2. disconnect tree1
 * 3. stat open on tree2 => h2
 * 4. reconnect tree1
 * 5. durable reconnect L1(RWH) => h1
 */
static bool test_durable_v2_open_keep_disconnected_rwh_with_stat_open(struct torture_context *tctx,
								      struct smb2_tree *tree1,
								      struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1 = GUID_random();
	struct smb2_lease ls1;
	uint64_t lease_key1;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key1 = random();
	smb2_lease_v2_create(&io, &ls1, false /* dir */, fname,
			     lease_key1, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RWH", true, lease_key1,
		       0, 0, ls1.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);

	CHECK_NO_BREAK(tctx);

	smb2_generic_create(&io, NULL, false /* dir */, fname,
			    FILE_OPEN_IF, 0, 0, 0);
	io.in.desired_access = SEC_FILE_READ_ATTRIBUTE;
	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false);
	CHECK_VAL(io.out.persistent_open, false);

	CHECK_NO_BREAK(tctx);

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1;
	io.in.create_guid = create_guid1;
	io.in.lease_request_v2 = &ls1;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);

	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false); /* no dh2q response blob */
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_LEASE_V2(&io, "RWH", true, lease_key1,
		       0, 0, ls1.lease_epoch);

	status = smb2_util_close(tree1, *h1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = NULL;

	status = smb2_util_close(tree2, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

	CHECK_NO_BREAK(tctx);

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}
	if (tree2 != NULL) {
		smb2_keepalive(tree2->session->transport);
	}
	if (tree1 != NULL && h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	if (tree2 != NULL && h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1(RWH) on tree1 => h1
 * 2. disconnect tree1
 * 3. durable open with L2(RWH) on tree2 => h2
 * 4. reconnect tree1
 * 5. durable reconnect L1(RH) => h1 => not found
 */
static bool test_durable_v2_open_purge_disconnected_rwh_with_rwh_open(struct torture_context *tctx,
								      struct smb2_tree *tree1,
								      struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1 = GUID_random();
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls1;
	uint64_t lease_key1;
	struct smb2_lease ls2;
	uint64_t lease_key2;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key1 = random();
	smb2_lease_v2_create(&io, &ls1, false /* dir */, fname,
			     lease_key1, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RWH", true, lease_key1,
		       0, 0, ls1.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);

	CHECK_NO_BREAK(tctx);

	lease_key2 = random();
	smb2_lease_v2_create(&io, &ls2, false /* dir */, fname,
			     lease_key2, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RWH", true, lease_key2,
		       0, 0, ls2.lease_epoch);

	CHECK_NO_BREAK(tctx);

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1;
	io.in.create_guid = create_guid1;
	io.in.lease_request_v2 = &ls1;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;
	ls1.lease_state = smb2_util_lease_state("RH");

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	status = smb2_util_close(tree2, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

	CHECK_NO_BREAK(tctx);

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}
	if (tree2 != NULL) {
		smb2_keepalive(tree2->session->transport);
	}
	if (tree1 != NULL && h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	if (tree2 != NULL && h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1(RWH) on tree1 => h1
 * 2. disconnect tree1
 * 3. durable open with L2(RH) on tree2 => h2
 * 4. reconnect tree1
 * 5. durable reconnect L1(RH) => h1 => not found
 */
static bool test_durable_v2_open_purge_disconnected_rwh_with_rh_open(struct torture_context *tctx,
								     struct smb2_tree *tree1,
								     struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1 = GUID_random();
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls1;
	uint64_t lease_key1;
	struct smb2_lease ls2;
	uint64_t lease_key2;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key1 = random();
	smb2_lease_v2_create(&io, &ls1, false /* dir */, fname,
			     lease_key1, 0, /* parent lease key */
			     smb2_util_lease_state("RWH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RWH", true, lease_key1,
		       0, 0, ls1.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);

	CHECK_NO_BREAK(tctx);

	lease_key2 = random();
	smb2_lease_v2_create(&io, &ls2, false /* dir */, fname,
			     lease_key2, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key2,
		       0, 0, ls2.lease_epoch);

	CHECK_NO_BREAK(tctx);

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1;
	io.in.create_guid = create_guid1;
	io.in.lease_request_v2 = &ls1;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;
	ls1.lease_state = smb2_util_lease_state("RH");

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	status = smb2_util_close(tree2, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

	CHECK_NO_BREAK(tctx);

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}
	if (tree2 != NULL) {
		smb2_keepalive(tree2->session->transport);
	}
	if (tree1 != NULL && h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	if (tree2 != NULL && h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1A(RH) on tree1 => h1a
 * 2. durable open with L1B(RH) on tree1 => h1b
 * 3. disconnect tree1
 * 4. open with SHARE_NONE on tree2 => h2
 * 5. reconnect tree1
 * 6. durable reconnect L1A(RH) => not found
 * 7. durable reconnect L1B(RH) => not found
 */
static bool test_durable_v2_open_purge_disconnected_rh_with_share_none_open(struct torture_context *tctx,
									    struct smb2_tree *tree1,
									    struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1a;
	struct smb2_handle *h1a = NULL;
	struct smb2_handle _h1b;
	struct smb2_handle *h1b = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1a = GUID_random();
	struct GUID create_guid1b = GUID_random();
	struct smb2_lease ls1a;
	uint64_t lease_key1a;
	struct smb2_lease ls1b;
	uint64_t lease_key1b;
	bool ret = true;
	struct smbcli_options options1;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options1 = tree1->session->transport->options;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key1a = random();
	smb2_lease_v2_create(&io, &ls1a, false /* dir */, fname,
			     lease_key1a, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1a;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1a.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	lease_key1b = random();
	smb2_lease_v2_create(&io, &ls1b, false /* dir */, fname,
			     lease_key1b, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1b;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1b = io.out.file.handle;
	h1b = &_h1b;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1b.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1b,
		       0, 0, ls1b.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree1);

	CHECK_NO_BREAK(tctx);

	smb2_generic_create_share(&io, &ls1a, false /* dir */, fname,
				  NTCREATEX_DISP_OPEN_IF,
				  FILE_SHARE_NONE,
				  SMB2_OPLOCK_LEVEL_NONE, 0, 0);
	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, false);
	CHECK_VAL(io.out.persistent_open, false);

	CHECK_NO_BREAK(tctx);

	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1a;
	io.in.create_guid = create_guid1a;
	io.in.lease_request_v2 = &ls1a;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	h1a = NULL;

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h1b;
	io.in.create_guid = create_guid1b;
	io.in.lease_request_v2 = &ls1b;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	h1b = NULL;

	status = smb2_util_close(tree2, *h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = NULL;

	CHECK_NO_BREAK(tctx);

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}
	if (tree2 != NULL) {
		smb2_keepalive(tree2->session->transport);
	}
	if (tree1 != NULL && h1a != NULL) {
		smb2_util_close(tree1, *h1a);
	}
	if (tree1 != NULL && h1b != NULL) {
		smb2_util_close(tree1, *h1b);
	}
	if (tree2 != NULL && h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1A(RH) on tree1 => h1a
 * 2. durable open with L1B(RH) on tree1 => h1b
 * 3. durable open with L2(RH) on tree2 => h2
 * 4. disconnect tree2
 * 5.1 write to h1a
 * 5.2 lease break to NONE for L1B (ack requested, but ignored)
 * 6. reconnect tree2
 * 7. durable reconnect L2(RH) => h2 => not found
 * 8. close h1a
 * 9. durable open with L1A(RWH) on tree1 => h1a only RH
 */
static bool test_durable_v2_open_purge_disconnected_rh_with_write(struct torture_context *tctx,
								  struct smb2_tree *tree1,
								  struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle _h1a;
	struct smb2_handle *h1a = NULL;
	struct smb2_handle _h1b;
	struct smb2_handle *h1b = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1a = GUID_random();
	struct GUID create_guid1b = GUID_random();
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls1a;
	uint64_t lease_key1a;
	struct smb2_lease ls1b;
	uint64_t lease_key1b;
	struct smb2_lease ls2;
	uint64_t lease_key2;
	struct smb2_write wrt;
	bool ret = true;
	struct smbcli_options options2;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options2 = tree2->session->transport->options;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	lease_key1a = random();
	smb2_lease_v2_create(&io, &ls1a, false /* dir */, fname,
			     lease_key1a, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1a;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1a.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	lease_key1b = random();
	smb2_lease_v2_create(&io, &ls1b, false /* dir */, fname,
			     lease_key1b, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1b;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1b = io.out.file.handle;
	h1b = &_h1b;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1b.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1b,
		       0, 0, ls1b.lease_epoch);

	lease_key2 = random();
	smb2_lease_v2_create(&io, &ls2, false /* dir */, fname,
			     lease_key2, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key2,
		       0, 0, ls2.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree2);

	CHECK_NO_BREAK(tctx);
	lease_break_info.lease_skip_ack = true;

	ZERO_STRUCT(wrt);
	wrt.in.file.handle = *h1a;
	wrt.in.offset = 0;
	wrt.in.data = data_blob_string_const("data");
	status = smb2_write(tree1, &wrt);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls1b.lease_epoch += 1;
	CHECK_BREAK_INFO_V2(tree1->session->transport,
			    "RH", "", lease_key1b, ls1b.lease_epoch);
	torture_reset_lease_break_info(tctx, &lease_break_info);
	CHECK_NO_BREAK(tctx);

	if (!torture_smb2_connection_ext(tctx, 0, &options2, &tree2)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h2;
	io.in.create_guid = create_guid2;
	io.in.lease_request_v2 = &ls2;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	h2 = NULL;

	status = smb2_util_close(tree1, *h1a);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = NULL;

	/*
	 * Now there's only lease_key2 with state NONE
	 *
	 * And that means an additional open still
	 * only gets RH...
	 */
	smb2_lease_v2_create(&io, &ls1a, false /* dir */, fname,
			     lease_key1a, 0, /* parent lease key */
			     smb2_util_lease_state("RHW"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1a;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.size, wrt.in.data.length);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1a.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	status = smb2_util_close(tree1, *h1a);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = NULL;

	status = smb2_util_close(tree1, *h1b);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = NULL;

	CHECK_NO_BREAK(tctx);

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}
	if (tree2 != NULL) {
		smb2_keepalive(tree2->session->transport);
	}
	if (tree1 != NULL && h1a != NULL) {
		smb2_util_close(tree1, *h1a);
	}
	if (tree1 != NULL && h1b != NULL) {
		smb2_util_close(tree1, *h1b);
	}
	if (tree2 != NULL && h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * 1. durable open with L1A(RH) on tree1 => h1a
 * 2. durable open with L1B(RH) on tree1 => h1b
 * 3. durable open with L2(RH) on tree2 => h2
 * 4. disconnect tree2
 * 5.1 rename h1a
 * 5.2 lease break to R for L1B (ack requested, and required)
 * 6. reconnect tree2
 * 7. durable reconnect L2(RH) => h2 => not found
 */
static bool test_durable_v2_open_purge_disconnected_rh_with_rename(struct torture_context *tctx,
								   struct smb2_tree *tree1,
								   struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	char fname[128];
	char fname_renamed[140];
	struct smb2_handle dh;
	struct smb2_handle _h1a;
	struct smb2_handle *h1a = NULL;
	struct smb2_handle _h1b;
	struct smb2_handle *h1b = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io;
	struct GUID create_guid1a = GUID_random();
	struct GUID create_guid1b = GUID_random();
	struct GUID create_guid2 = GUID_random();
	struct smb2_lease ls1a;
	uint64_t lease_key1a;
	struct smb2_lease ls1b;
	uint64_t lease_key1b;
	struct smb2_lease ls2;
	uint64_t lease_key2;
	union smb_setfileinfo sinfo;
	bool ret = true;
	struct smbcli_options options2;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	options2 = tree2->session->transport->options;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree1, __func__);
	status = torture_smb2_testdir(tree1, __func__, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree1, dh);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 128, "%s\\file_%s.dat",
		 __func__, generate_random_str(tctx, 8));
	snprintf(fname_renamed, 140, "%s.renamed", fname);

	smb2_util_unlink(tree1, fname);
	smb2_util_unlink(tree1, fname_renamed);

	lease_key1a = random();
	smb2_lease_v2_create(&io, &ls1a, false /* dir */, fname,
			     lease_key1a, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1a;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1a = io.out.file.handle;
	h1a = &_h1a;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1a.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1a,
		       0, 0, ls1a.lease_epoch);

	lease_key1b = random();
	smb2_lease_v2_create(&io, &ls1b, false /* dir */, fname,
			     lease_key1b, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid1b;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1b = io.out.file.handle;
	h1b = &_h1b;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls1b.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key1b,
		       0, 0, ls1b.lease_epoch);

	lease_key2 = random();
	smb2_lease_v2_create(&io, &ls2, false /* dir */, fname,
			     lease_key2, 0, /* parent lease key */
			     smb2_util_lease_state("RH"), 0 /* lease epoch */);
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid2;
	io.in.timeout = UINT32_MAX;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h2 = io.out.file.handle;
	h2 = &_h2;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, false);
	CHECK_VAL(io.out.durable_open_v2, true);
	CHECK_VAL(io.out.persistent_open, false);
	CHECK_VAL(io.out.timeout, 300*1000);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, lease_key2,
		       0, 0, ls2.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree2);

	CHECK_NO_BREAK(tctx);

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = *h1a;
	sinfo.rename_information.in.overwrite = 0;
	sinfo.rename_information.in.root_fid = 0;
	sinfo.rename_information.in.new_name = fname_renamed;
	status = smb2_setinfo_file(tree1, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls1b.lease_epoch += 1;
	CHECK_BREAK_INFO_V2(tree1->session->transport,
			    "RH", "R", lease_key1b, ls1b.lease_epoch);
	torture_reset_lease_break_info(tctx, &lease_break_info);
	CHECK_NO_BREAK(tctx);

	if (!torture_smb2_connection_ext(tctx, 0, &options2, &tree2)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = h2;
	io.in.create_guid = create_guid2;
	io.in.lease_request_v2 = &ls2;
	io.in.oplock_level = SMB2_OPLOCK_LEVEL_LEASE;

	status = smb2_create(tree2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	h2 = NULL;

	status = smb2_util_close(tree1, *h1a);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = NULL;

	status = smb2_util_close(tree1, *h1b);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = NULL;

	CHECK_NO_BREAK(tctx);

done:
	if (tree1 != NULL) {
		smb2_keepalive(tree1->session->transport);
	}
	if (tree2 != NULL) {
		smb2_keepalive(tree2->session->transport);
	}
	if (tree1 != NULL && h1a != NULL) {
		smb2_util_close(tree1, *h1a);
	}
	if (tree1 != NULL && h1b != NULL) {
		smb2_util_close(tree1, *h1b);
	}
	if (tree2 != NULL && h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
		smb2_util_unlink(tree1, fname_renamed);
		smb2_deltree(tree1, __func__);

		TALLOC_FREE(tree1);
	}

	TALLOC_FREE(tree2);

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
	CHECK_VAL(io1.out.timeout, 300*1000);

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
	CHECK_VAL(io2.out.timeout, 300*1000);

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
	bool share_is_so;
	struct durable_open_vs_lease *table;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "persistent_open_lease_%s.dat", generate_random_str(tctx, 8));

	share_capabilities = smb2cli_tcon_capabilities(tree->smbXcli);
	share_is_ca = share_capabilities & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;
	share_is_so = share_capabilities & SMB2_SHARE_CAP_SCALEOUT;

	if (share_is_ca) {
		table = persistent_open_lease_ca_table;
	} else {
		table = durable_open_vs_lease_table;
	}

	ret = test_durable_v2_open_lease_table(tctx, tree, fname,
					       true, /* request_persistent */
					       share_is_so,
					       table,
					       NUM_LEASE_OPEN_TESTS);

	talloc_free(tree);

	return ret;
}

/**
 * setfileinfo test for doing a durable open
 * create the file with lease and durable handle,
 * write to it (via set end-of-file), tcp disconnect,
 * reconnect, do a durable reopen - should succeed.
 *
 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=15022
 */
bool test_durable_v2_setinfo(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	union smb_setfileinfo si;
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

	smb2_deltree(tree, __func__);
	status = torture_smb2_testdir(tree, __func__, &_h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");
	smb2_util_close(tree, _h);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "%s\\durable_v2_setinfo%s.dat",
		 __func__, generate_random_str(tctx, 8));

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
	CHECK_VAL(io.out.timeout, 300*1000);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[0], lease_key);
	CHECK_VAL(io.out.lease_response_v2.lease_key.data[1], ~lease_key);

	/*
	 * Set EOF to 0x100000.
	 * Mimics an Apple client test, but most importantly
	 * causes the mtime timestamp on disk to be updated.
	 */
	ZERO_STRUCT(si);
	si.generic.level = SMB_SFILEINFO_END_OF_FILE_INFORMATION;
	si.generic.in.file.handle = io.out.file.handle;
	si.end_of_file_info.in.size = 0x100000;
	status = smb2_setinfo_file(tree, &si);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* disconnect, reconnect and then do durable reopen */
	TALLOC_FREE(tree);

	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

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

	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.size, 0x100000);				\
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
	smb2_deltree(tree, __func__);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_reconnect_twice(struct torture_context *tctx,
				 struct smb2_tree *tree,
				 struct smb2_tree *tree2)
{
       NTSTATUS status;
       TALLOC_CTX *mem_ctx = talloc_new(tctx);
       char fname[256];
       struct smb2_handle _h;
       struct smb2_handle *h = NULL;
       struct smb2_create io;
       struct GUID create_guid = GUID_random();
       struct smbcli_options options;
       uint64_t previous_session_id;
       uint8_t b = 0;
       bool ret = true;
       bool ok;

       options = tree->session->transport->options;
       previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

       /* Choose a random name in case the state is left a little funky. */
       snprintf(fname,
                sizeof(fname),
                "durable_v2_reconnect_delay_%s.dat",
                generate_random_str(tctx, 8));

       smb2_util_unlink(tree, fname);

       smb2_oplock_create_share(&io, fname,
                                smb2_util_share_access(""),
                                smb2_util_oplock_level("b"));
       io.in.durable_open = false;
       io.in.durable_open_v2 = true;
       io.in.persistent_open = false;
       io.in.create_guid = create_guid;
       io.in.timeout = 5000;

       status = smb2_create(tree, mem_ctx, &io);
       CHECK_STATUS(status, NT_STATUS_OK);

       _h = io.out.file.handle;
       h = &_h;
       CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
       CHECK_VAL(io.out.durable_open_v2, true);

       status = smb2_util_write(tree, *h, &b, 0, 1);
       CHECK_STATUS(status, NT_STATUS_OK);

       /* disconnect, leaving the durable open */
       TALLOC_FREE(tree);
       h = NULL;

       /*
	* Getting us closer to the time the Durable Handle scavenger fires: in
	* one second it will go off...
	*/
       sleep(4);

       ok = torture_smb2_connection_ext(tctx, previous_session_id,
                                        &options, &tree);
       torture_assert_goto(tctx, ok, ret, done, "couldn't reconnect, bailing\n");

       ZERO_STRUCT(io);
       io.in.fname = fname;
       io.in.durable_open_v2 = false;
       io.in.durable_handle_v2 = &_h;
       io.in.create_guid = create_guid;

       status = smb2_create(tree, mem_ctx, &io);
       CHECK_STATUS(status, NT_STATUS_OK);
       CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
       _h = io.out.file.handle;
       h = &_h;

       /* Second disconnect, leaving the durable open */
       TALLOC_FREE(tree);
       h = NULL;

       /*
	* Sleep longer then remaining first timeout and check if the
	* scavenger time started by the first disconnect wipes the handle.
	*/
       sleep(2);

       ok = torture_smb2_connection_ext(tctx, previous_session_id,
                                        &options, &tree);
       torture_assert_goto(tctx, ok, ret, done, "couldn't reconnect, bailing\n");

       ZERO_STRUCT(io);
       io.in.fname = fname;
       io.in.durable_open_v2 = false;
       io.in.durable_handle_v2 = &_h;
       io.in.create_guid = create_guid;

       status = smb2_create(tree, mem_ctx, &io);
       CHECK_STATUS(status, NT_STATUS_OK);
       CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
       _h = io.out.file.handle;
       h = &_h;

done:
       if (h != NULL) {
               smb2_util_close(tree, *h);
       }
       smb2_util_unlink(tree2, fname);
       talloc_free(mem_ctx);
       return ret;
}

struct torture_suite *torture_smb2_durable_v2_open_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "durable-v2-open");

	torture_suite_add_1smb2_test(suite, "create-blob", test_durable_v2_open_create_blob);
	torture_suite_add_1smb2_test(suite, "open-oplock", test_durable_v2_open_oplock);
	torture_suite_add_1smb2_test(suite, "open-lease", test_durable_v2_open_lease);
	torture_suite_add_1smb2_test(suite, "reopen1", test_durable_v2_open_reopen1);
	torture_suite_add_1smb2_test(suite, "reopen1a", test_durable_v2_open_reopen1a);
	torture_suite_add_1smb2_test(suite, "reopen1a-lease", test_durable_v2_open_reopen1a_lease);
	torture_suite_add_1smb2_test(suite, "reopen2", test_durable_v2_open_reopen2);
	torture_suite_add_1smb2_test(suite, "reopen2b", test_durable_v2_open_reopen2b);
	torture_suite_add_1smb2_test(suite, "reopen2c", test_durable_v2_open_reopen2c);
	torture_suite_add_1smb2_test(suite, "reopen2-lease", test_durable_v2_open_reopen2_lease);
	torture_suite_add_1smb2_test(suite, "reopen2-lease-v2", test_durable_v2_open_reopen2_lease_v2);
	torture_suite_add_1smb2_test(suite, "durable-v2-setinfo", test_durable_v2_setinfo);
	torture_suite_add_1smb2_test(suite, "lock-oplock", test_durable_v2_open_lock_oplock);
	torture_suite_add_1smb2_test(suite, "lock-lease", test_durable_v2_open_lock_lease);
	torture_suite_add_1smb2_test(suite, "lock-noW-lease", test_durable_v2_open_lock_noW_lease);
	torture_suite_add_1smb2_test(suite, "stat-and-lease", test_durable_v2_open_stat_and_lease);
	torture_suite_add_1smb2_test(suite, "nonstat-and-lease", test_durable_v2_open_nonstat_and_lease);
	torture_suite_add_1smb2_test(suite, "statRH-and-lease", test_durable_v2_open_statRH_and_lease);
	torture_suite_add_1smb2_test(suite, "two-same-lease", test_durable_v2_open_two_same_lease);
	torture_suite_add_1smb2_test(suite, "two-different-lease", test_durable_v2_open_two_different_leases);
	torture_suite_add_2smb2_test(suite, "keep-disconnected-rh-with-stat-open", test_durable_v2_open_keep_disconnected_rh_with_stat_open);
	torture_suite_add_2smb2_test(suite, "keep-disconnected-rh-with-rh-open", test_durable_v2_open_keep_disconnected_rh_with_rh_open);
	torture_suite_add_2smb2_test(suite, "keep-disconnected-rh-with-rwh-open", test_durable_v2_open_keep_disconnected_rh_with_rwh_open);
	torture_suite_add_2smb2_test(suite, "keep-disconnected-rwh-with-stat-open", test_durable_v2_open_keep_disconnected_rwh_with_stat_open);
	torture_suite_add_2smb2_test(suite, "purge-disconnected-rwh-with-rwh-open", test_durable_v2_open_purge_disconnected_rwh_with_rwh_open);
	torture_suite_add_2smb2_test(suite, "purge-disconnected-rwh-with-rh-open", test_durable_v2_open_purge_disconnected_rwh_with_rh_open);
	torture_suite_add_2smb2_test(suite, "purge-disconnected-rh-with-share-none-open", test_durable_v2_open_purge_disconnected_rh_with_share_none_open);
	torture_suite_add_2smb2_test(suite, "purge-disconnected-rh-with-write", test_durable_v2_open_purge_disconnected_rh_with_write);
	torture_suite_add_2smb2_test(suite, "purge-disconnected-rh-with-rename", test_durable_v2_open_purge_disconnected_rh_with_rename);
	torture_suite_add_2smb2_test(suite, "app-instance", test_durable_v2_open_app_instance);
	torture_suite_add_1smb2_test(suite, "persistent-open-oplock", test_persistent_open_oplock);
	torture_suite_add_1smb2_test(suite, "persistent-open-lease", test_persistent_open_lease);
	torture_suite_add_2smb2_test(suite, "reconnect-twice", test_reconnect_twice);

	suite->description = talloc_strdup(suite, "SMB2-DURABLE-V2-OPEN tests");

	return suite;
}

/**
 * basic test for doing a durable open
 * tcp disconnect, reconnect, do a durable reopen (succeeds)
 */
static bool test_durable_v2_reconnect_delay(struct torture_context *tctx,
					    struct smb2_tree *tree,
					    struct smb2_tree *tree2)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	struct smbcli_options options;
	uint64_t previous_session_id;
	uint8_t b = 0;
	bool ret = true;
	bool ok;

	options = tree->session->transport->options;
	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname,
		 sizeof(fname),
		 "durable_v2_reconnect_delay_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = 0;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	_h = io.out.file.handle;
	h = &_h;
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open_v2, true);

	status = smb2_util_write(tree, *h, &b, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* disconnect, leaving the durable open */
	TALLOC_FREE(tree);
	h = NULL;

	ok = torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree);
	torture_assert_goto(tctx, ok, ret, done, "couldn't reconnect, bailing\n");

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = &_h;
	io.in.create_guid = create_guid;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	_h = io.out.file.handle;
	h = &_h;

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	TALLOC_FREE(tree);

	smb2_util_unlink(tree2, fname);

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic test for doing a durable open with 1msec cleanup time
 * tcp disconnect, wait a bit, reconnect, do a durable reopen (fails)
 */
static bool test_durable_v2_reconnect_delay_msec(struct torture_context *tctx,
						 struct smb2_tree *tree,
						 struct smb2_tree *tree2)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct smb2_lease ls;
	struct GUID create_guid = GUID_random();
	struct smbcli_options options;
	uint64_t previous_session_id;
	uint8_t b = 0;
	bool ret = true;
	bool ok;

	options = tree->session->transport->options;
	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname,
		 sizeof(fname),
		 "durable_v2_reconnect_delay_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_lease_create(
		&io,
		&ls,
		false /* dir */,
		fname,
		generate_random_u64(),
		smb2_util_lease_state("RWH"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = 1;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	_h = io.out.file.handle;
	h = &_h;
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.durable_open_v2, true);

	status = smb2_util_write(tree, *h, &b, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* disconnect, leaving the durable open */
	TALLOC_FREE(tree);
	h = NULL;

	ok = torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree);
	torture_assert_goto(tctx, ok, ret, done, "couldn't reconnect, bailing\n");

	sleep(10);

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = &_h;
	io.in.create_guid = create_guid;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	_h = io.out.file.handle;
	h = &_h;

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	TALLOC_FREE(tree);

	smb2_util_unlink(tree2, fname);

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic test for doing a durable open
 * tcp disconnect, reconnect, do a durable reopen (succeeds)
 */
static bool test_durable_v2_reconnect_bug15624(struct torture_context *tctx,
					       struct smb2_tree *tree,
					       struct smb2_tree *tree2)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	struct smb2_create io;
	struct GUID create_guid = GUID_random();
	struct smbcli_options options;
	uint64_t previous_session_id;
	uint8_t b = 0;
	bool ret = true;
	bool ok;

	if (!torture_setting_bool(tctx, "bug15624", false)) {
		torture_comment(tctx,
				"share requires:\n"
				"'vfs objects = error_inject'\n"
				"'error_inject:durable_reconnect=st_ex_nlink'\n"
				"test requires:\n"
				"'--option=torture:bug15624=yes'\n");
		torture_skip(tctx, "'--option=torture:bug15624=yes' missing");
	}

	options = tree->session->transport->options;
	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname,
		 sizeof(fname),
		 "durable_v2_reconnect_bug15624_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io.in.durable_open = false;
	io.in.durable_open_v2 = true;
	io.in.persistent_open = false;
	io.in.create_guid = create_guid;
	io.in.timeout = 0;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	_h = io.out.file.handle;
	h = &_h;
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("b"));
	CHECK_VAL(io.out.durable_open_v2, true);

	status = smb2_util_write(tree, *h, &b, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* disconnect, leaving the durable open */
	TALLOC_FREE(tree);
	h = NULL;

	ok = torture_smb2_connection_ext(tctx, previous_session_id,
					 &options, &tree);
	torture_assert_goto(tctx, ok, ret, done, "couldn't reconnect, bailing\n");

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_open_v2 = false;
	io.in.durable_handle_v2 = &_h;
	io.in.create_guid = create_guid;

	/*
	 * This assumes 'error_inject:durable_reconnect = st_ex_nlink'
	 * will cause the durable reconnect to fail...
	 * in order to have a regression test for the dead lock.
	 */
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/*
	 * With the regression this will fail with
	 * a timeout...
	 */
	status = smb2_util_unlink(tree2, fname);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	TALLOC_FREE(tree);

	smb2_util_unlink(tree2, fname);

	TALLOC_FREE(tree2);

	talloc_free(mem_ctx);

	return ret;
}

struct torture_suite *torture_smb2_durable_v2_delay_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "durable-v2-delay");

	torture_suite_add_2smb2_test(suite,
				     "durable_v2_reconnect_delay",
				     test_durable_v2_reconnect_delay);
	torture_suite_add_2smb2_test(suite,
				     "durable_v2_reconnect_delay_msec",
				     test_durable_v2_reconnect_delay_msec);

	return suite;
}

struct torture_suite *torture_smb2_durable_v2_regressions_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "durable-v2-regressions");

	torture_suite_add_2smb2_test(suite,
				     "durable_v2_reconnect_bug15624",
				     test_durable_v2_reconnect_bug15624);

	return suite;
}
