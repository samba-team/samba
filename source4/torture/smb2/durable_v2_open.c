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

static struct {
	const char *req_lease;
	const char *exp_granted_fo_win;
	const char *exp_granted_so_win;
	const char *exp_granted_fo_samba;
	const char *exp_granted_fo_max_rwh_samba;
	const char *exp_granted_so_samba;
} ph_lease_tests[] = {
	/*      Windows         Samba             */
	/* Req  FO      SO      FO(R)   FO(RWH) SO */
	{"",    "",     "",     "",     "",     "",},
	{"R",   "R",    "R",    "R",    "R",    "R"},
	{"RW",  "RW",   "R",    "R",    "RW",   "R"},
	{"RH",  "RH",   "R",    "R",    "RH",   "R"},
	{"RWH", "RWH",  "R",    "R",    "RWH",  "R"},
};

/*
 * Basic testing of reconnecting persistent opens with various lease levels
 *
 * This demonstrates that you don't need a lease for a persistent open.
 *
 * Windows only grants R leases on SO-shares. On non-SO shares (FO), Windows
 * grants RWH, Samba defaults to only grant R, as true active/passive failover
 * is currently not tested in our CI, where the lease state is lost and in
 * theory recreated when reconnecting. We have the option "smb3 ca:max lease
 * mask" to allow changing this, which is what this test uses to check both
 * behaviours.
 */
static bool test_persistent_leaselevels_share(struct torture_context *tctx,
					      struct smb2_tree *_tree,
					      const char *share)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_tree *tree = NULL;
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1 = {};
	uint32_t tcon_caps;
	int i;
	bool share_is_so;
	NTSTATUS status;
	bool ret = true;

	for (i = 0; i < ARRAY_SIZE(ph_lease_tests); i++) {
		char *fname = NULL;
		const char *lease = ph_lease_tests[i].req_lease;
		uint64_t previous_session_id;
		struct smbcli_options options =
			_tree->session->transport->options;
		uint64_t lease1 = random();
		struct GUID create_guid = GUID_random();
		struct smb2_lease *_ls = NULL;
		uint16_t expected_granted;
		const char *exp_granted_str = NULL;

		fname = talloc_asprintf(tctx, "lease_break-%ld.dat", random());
		torture_assert_not_null_goto(tctx, fname, ret, done,
					     "talloc_asprintf failed\n");

		options.client_guid = GUID_random();

		ret = torture_smb2_connection_share_ext(
			tctx, share, 0, &options, &tree);
		torture_assert_goto(tctx, ret, ret, done,
				    "torture_smb2_connection_ext failed\n");
		previous_session_id = smb2cli_session_current_id(
			tree->session->smbXcli);

		tcon_caps = smb2cli_tcon_capabilities(tree->smbXcli);
		if (!(tcon_caps & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)) {
			torture_fail(tctx, "Expect CA\n");
		}
		share_is_so = (tcon_caps & SMB2_SHARE_CAP_SCALEOUT);
		if (share_is_so) {
			torture_comment(tctx, "SMB2_SHARE_CAP_SCALEOUT\n");
		}

		if (TARGET_IS_SAMBA3(tctx)) {
			if (share_is_so) {
				exp_granted_str = ph_lease_tests[i].
					exp_granted_so_samba;
			} else {
				if (strequal(share, "ca_fo_max_rwh")) {
					exp_granted_str = ph_lease_tests[i].
						exp_granted_fo_max_rwh_samba;
				} else {
					exp_granted_str = ph_lease_tests[i].
						exp_granted_fo_samba;
				}
			}
		} else {
			if (share_is_so) {
				exp_granted_str = ph_lease_tests[i].
					exp_granted_so_win;
			} else {
				exp_granted_str = ph_lease_tests[i].
					exp_granted_fo_win;
			}
		}

		expected_granted = smb2_util_lease_state(exp_granted_str);

		torture_comment(tctx, "%2d: Request PH with [%-4s] lease, "
				"granted lease level [%-4s]\n",
				i+1, lease, exp_granted_str);

		/*
		 * Grab durable open
		 */
		if (lease[0] != '\0') {
			_ls = &ls;
		}

		ZERO_STRUCT(io);
		smb2_lease_create_share(&io, _ls, false, fname,
					smb2_util_share_access("RWD"), lease1,
					smb2_util_lease_state(lease));
		io.in.durable_open_v2 = true;
		io.in.persistent_open = true;
		io.in.create_guid = create_guid;
		status = smb2_create(tree, mem_ctx, &io);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		h1 = io.out.file.handle;

		if (_ls != NULL) {
			torture_assert_int_equal_goto(
				tctx, io.out.oplock_level,
				SMB2_OPLOCK_LEVEL_LEASE,
				ret, done, "Bad lease level\n");
			torture_assert_int_equal_goto(
				tctx, io.out.lease_response.lease_state,
				expected_granted,
				ret, done, "Bad lease level\n");
		}

		/*
		 * Now disconnect
		 */
		TALLOC_FREE(tree);
		sleep(1);

		/*
		 * Now reconnect the session and the persistent handle
		 */
		ret = torture_smb2_connection_share_ext(tctx,
							share,
							previous_session_id,
							&options,
							&tree);
		torture_assert_goto(tctx, ret, ret, done,
				    "torture_smb2_connection_ext failed\n");
		tree->session->transport->lease.handler	= torture_lease_handler;
		tree->session->transport->lease.private_data = tree;

		ZERO_STRUCT(io);
		smb2_lease_create(&io, _ls, false, fname, lease1,
				  smb2_util_lease_state(lease));
		h1.data[1] = 0;
		io.in.durable_handle_v2 = &h1;
		io.in.create_guid = create_guid;
		io.in.persistent_open = true;
		status = smb2_create(tree, mem_ctx, &io);

		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"reconnect failed\n");
		h1 = io.out.file.handle;

		if (_ls != NULL) {
			torture_assert_goto(
				tctx,
				io.out.oplock_level == SMB2_OPLOCK_LEVEL_LEASE,
				ret, done, "Bad oplock level\n");
			torture_assert_int_equal_goto(
				tctx,
				io.out.lease_response.lease_state,
				expected_granted,
				ret, done, "Bad lease level\n");
		}
		smb2_util_close(tree, h1);
		ZERO_STRUCT(h1);

		status = smb2_util_unlink(_tree, fname);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"unlink failed\n");
		TALLOC_FREE(tree);
		TALLOC_FREE(fname);
	}

 done:
	if (!smb2_util_handle_empty(h1) && tree != NULL) {
		smb2_util_close(tree, h1);
	}

	talloc_free(mem_ctx);

	return ret;
}

static bool test_persistent_leaselevels(struct torture_context *tctx,
					struct smb2_tree *_tree)
{
	const char *share = torture_setting_string(tctx, "share", NULL);

	return test_persistent_leaselevels_share(tctx, _tree, share);
}

static bool test_persistent_leaselevels_fo(struct torture_context *tctx,
					   struct smb2_tree *_tree)
{
	uint32_t tcon_caps;
	bool ret;

	tcon_caps = smb2cli_tcon_capabilities(_tree->smbXcli);
	if (tcon_caps & SMB2_SHARE_CAP_SCALEOUT) {
		torture_skip(tctx, "Runs against standalone, "
			     "skip against SO\n");
	}

	ret = test_persistent_leaselevels_share(tctx, _tree, "ca_fo");
	return ret;
}

static bool test_persistent_leaselevels_fo_max_rwh(struct torture_context *tctx,
						   struct smb2_tree *_tree)
{
	uint32_t tcon_caps;
	bool ret;

	tcon_caps = smb2cli_tcon_capabilities(_tree->smbXcli);
	if (tcon_caps & SMB2_SHARE_CAP_SCALEOUT) {
		torture_skip(tctx, "Runs against standalone, "
			     "skip against SO\n");
	}

	ret = test_persistent_leaselevels_share(tctx, _tree, "ca_fo_max_rwh");
	return ret;
}

static bool test_persistent_leaselevels_so(struct torture_context *tctx,
					   struct smb2_tree *_tree)
{
	uint32_t tcon_caps;
	bool ret;

	tcon_caps = smb2cli_tcon_capabilities(_tree->smbXcli);
	if (!(tcon_caps & SMB2_SHARE_CAP_SCALEOUT)) {
		torture_skip(tctx, "Runs against SO, "
			     "skip against standalone\n");
	}

	ret = test_persistent_leaselevels_share(tctx, _tree, "ca_so");
	return ret;
}

struct persistent_reconnect_contend_results {
	/* Parameters for the first client's persistent open */
	const char *held_lease;
	const char *share_mode;
	bool do_brlck;
	const char *reconnect_lease;
	const char *broken_to_lease;

	/* Parameters for the second client's contending open */
	uint32_t desired_access;
	bool overwrite;
	NTSTATUS status;
	bool async;
	const char *new_lease;
	const char *new_granted;
};

#define RO (SEC_RIGHTS_FILE_READ)
#define RW (SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_WRITE)
#define RWD (SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_WRITE|SEC_STD_DELETE)

static struct persistent_reconnect_contend_results contend_results_fo[] = {
	/* L,	SM,	brlck,	RL,	BL,	DA,	DO,	status,				async,	NL,	NG */
	{"",	"",	false,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	false,	"RH",	"R",	RO,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"",	false,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	false,	"RWH",	"RW",	RO,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	false,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	false,	"RH",	"RH",	RO,	false,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"R",	false,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	false,	"RWH",	"RH",	RO,	false,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RW",	false,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	false,	"RH",	"RH",	RO,	false,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RW",	false,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	false,	"RWH",	"RH",	RO,	false,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RWD",	false,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"RH",	RO,	false,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"RH",	RO,	false,	NT_STATUS_OK,			true,	"RWH",	"RH"},

	{"",	"",	false,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	false,	"RH",	"R",	RO,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"",	false,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	false,	"RWH",	"RW",	RO,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	false,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"R",	false,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	false,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	false,	"RH",	"",	RO,	true,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RW",	false,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	false,	"RWH",	"",	RO,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RWD",	false,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"",	RO,	true,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"",	RO,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},

	{"",	"",	false,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	false,	"RH",	"R",	RW,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"",	false,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	false,	"RWH",	"RW",	RW,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	false,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	false,	"RH",	"R",	RW,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"R",	false,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	false,	"RWH",	"RW",	RW,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RW",	false,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	false,	"RH",	"RH",	RW,	false,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RW",	false,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	false,	"RWH",	"RH",	RW,	false,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RWD",	false,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"RH",	RW,	false,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"RH",	RW,	false,	NT_STATUS_OK,			true,	"RWH",	"RH"},

	{"",	"",	false,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	false,	"RH",	"R",	RW,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"",	false,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	false,	"RWH",	"RW",	RW,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	false,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	false,	"RH",	"R",	RW,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"R",	false,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	false,	"RWH",	"RW",	RW,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RW",	false,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	false,	"RH",	"",	RW,	true,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RW",	false,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	false,	"RWH",	"",	RW,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RWD",	false,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"",	RW,	true,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"",	RW,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},

	{"",	"",	false,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	false,	"RH",	"R",	RWD,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"",	false,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	false,	"RWH",	"RW",	RWD,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	false,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	false,	"RH",	"R",	RWD,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"R",	false,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	false,	"RWH",	"RW",	RWD,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RW",	false,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	false,	"RH",	"R",	RWD,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"RW",	false,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	false,	"RWH",	"RW",	RWD,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"RH",	RWD,	false,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"RH",	RWD,	false,	NT_STATUS_OK,			true,	"RWH",	"RH"},

	{"",	"",	false,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	false,	"RH",	"R",	RWD,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"",	false,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	false,	"RWH",	"RW",	RWD,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	false,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	false,	"RH",	"R",	RWD,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"R",	false,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	false,	"RWH",	"RW",	RWD,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RW",	false,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	false,	"RH",	"R",	RWD,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"RW",	"RW",	false,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	false,	"RWH",	"RW",	RWD,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"",	RWD,	true,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"",	RWD,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},

	{"",	"",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"",	true,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	true,	"RWH",	"RW",	RO,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"R",	true,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	true,	"RWH",	"RH",	RO,	false,	NT_STATUS_OK,			true,	"RWH",	""},
	{"",	"RW",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RW",	true,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	true,	"RWH",	"RH",	RO,	false,	NT_STATUS_OK,			true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"RH",	RO,	false,	NT_STATUS_OK,			true,	"RWH",	""},
	{"",	"",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"",	true,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	true,	"RWH",	"RW",	RO,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"R",	true,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	/*
	 * The next one has two bugs in Windows: return
	 * STATUS_OBJECT_NAME_NOT_FOUND and breaks to RH instead of RW.
	{"RWH",	"R",	true,	"RWH",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},
	 */
	{"",	"RW",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RW",	true,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	true,	"RWH",	"",	RO,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RWD",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"",	RO,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"",	true,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	true,	"RWH",	"RW",	RW,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"R",	true,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	true,	"RWH",	"RW",	RW,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RW",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RW",	true,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	true,	"RWH",	"RH",	RW,	false,	NT_STATUS_OK,			true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"RH",	RW,	false,	NT_STATUS_OK,			true,	"RWH",	""},
	{"",	"",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"",	true,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	true,	"RWH",	"RW",	RW,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"R",	true,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	true,	"RWH",	"RW",	RW,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RW",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RW",	true,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	true,	"RWH",	"",	RW,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RWD",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"",	RW,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"",	true,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	true,	"RWH",	"RW",	RWD,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"R",	true,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	true,	"RWH",	"RW",	RWD,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RW",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RW",	true,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	true,	"RWH",	"RW",	RWD,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"RH",	RWD,	false,	NT_STATUS_OK,			true,	"RWH",	""},
	{"",	"",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"",	true,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"",	true,	"RWH",	"RW",	RWD,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"R",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"R",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"R",	true,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"R",	true,	"RWH",	"RW",	RWD,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RW",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RW",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RW",	true,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RW",	true,	"RWH",	"RW",	RWD,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"",	RWD,	true,	NT_STATUS_OK,			true,	"RWH",	"RH"},

	{NULL,	NULL,	false,	NULL,	NULL,	0,	false,	NT_STATUS_INTERNAL_ERROR,	false,	 NULL,	NULL}
};

static struct persistent_reconnect_contend_results contend_results_fo_win_broken[] = {
	/*
	 * The next one has a bug in Windows: it returns
	 * STATUS_OBJECT_NAME_NOT_FOUND.
	 */
	{"RH",	"R",	false,	"RH",	"R",	RO,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	/*
	 * The next one has two bugs in Windows: return
	 * STATUS_OBJECT_NAME_NOT_FOUND and breaks to RH instead of NONE.
	 */
	{"RWH",	"R",	false,	"RWH",	"RW",	RO,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"RWH",	""},
	{NULL,	NULL,	false,	NULL,	NULL,	0,	false,	NT_STATUS_INTERNAL_ERROR,	false,	 NULL,	NULL}
};


/*
 * On a share with SMB2_SHARE_CAP_SCALEOUT the server doesn't grant W or H
 * leases.
 */
static struct persistent_reconnect_contend_results contend_results_so[] = {
	{"",	"",	false,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	false,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	false,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	false,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	false,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	false,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	false,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	false,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	false,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	false,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	false,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	false,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	false,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	false,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	false,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	false,	"",	"",     RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	false,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	false,	"",	"",     RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	false,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	false,	"",	"",     RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	false,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},

	{"",	"",	true,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	true,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	true,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	true,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	true,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	true,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	true,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	true,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	true,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	true,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	true,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	true,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	true,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	true,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	true,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"",	true,	"",	"",     RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"",	true,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"R",	true,	"",	"",     RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"R",	true,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RW",	true,	"",	"",     RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RW",	true,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},

	{NULL,	NULL,	false,	NULL,	NULL,   0,	false,	NT_STATUS_INTERNAL_ERROR,	false,	 NULL,	NULL}
};

#undef RO
#undef RW
#undef RWD

/*
 * This tests trying to open a file with a disconnected persistent handle
 * with various different lease levels, sharemodes and create disposition
 * combinations.
 *
 * The client then disconnects and we try to open (contend) the now disconnected
 * Persistent Handle from the first client. This will either fail with
 * NT_STATUS_FILE_NOT_AVAILABLE or trigger a lease break which gets dispatched
 * once the first client reconnects.
 *
 * The client must always be able to reconnect the disconnected open and the
 * server guarantees that any operations which break W or H leases are blocked.
 *
 * The bottom line is:
 *
 * - incompatible opens without H-lease are blocked with
 *   NT_STATUS_FILE_NOT_AVAILABLE
 *
 * - incompatible opens with a H lease trigger a lease break and are deferred
 *   until the first client reconnects the handle
 *
 * - in addition to that, if the file has byterange locks the lease must include
 *   W, otherwise contending opens are also blocked with
 *   NT_STATUS_FILE_NOT_AVAILABLE
 * */
static bool test_persistent_reconnect_contended_do_one(
		struct torture_context *tctx,
		struct smb2_tree *_tree,
		struct persistent_reconnect_contend_results *table,
		int testnum)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smbcli_options options1 = _tree->session->transport->options;
	struct smbcli_options options2 = _tree->session->transport->options;
	struct smb2_tree *tree1 = NULL;
	struct smb2_tree *tree2 = NULL;
	struct smb2_request *req = NULL;
	struct smb2_create io;
	struct smb2_create io2;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_lease *ls = NULL;
	struct smb2_handle h1 = {};
	struct smb2_handle rh = {};
	struct smb2_handle h2 = {};
	struct smb2_lock lck = {};
	struct smb2_lock_element el[1];
	uint64_t previous_session_id;
	uint64_t lease1 = 1;
	uint64_t lease2 = 2;
	struct GUID create_guid = GUID_random();
	char *fname = NULL;
	int rc;
	bool expect_break = false;
	bool expect_acquire = false;
	bool expect_block = false;
	NTSTATUS status;
	bool ret = true;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	fname = talloc_asprintf(mem_ctx, "lease_break-%ld.dat", random());
	torture_assert_not_null_goto(tctx, fname, ret, done,
				     "talloc_asprintf failed\n");

	status = torture_setup_simple_file(tctx, _tree, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_setup_simple_file failed\n");

	torture_comment(tctx,
			"%2d: "
			"Lease [%-3s] "
			"Sharemode [%-3s] "
			"Brl [%s]. "
			"Contend access [0x%0"PRIX32"] "
			"Overwrite [%s] "
			"Result [%18s]. "
			"Reconnect [%-3s] "
			"Break [%-3s]\n",
			testnum,
			table->held_lease,
			table->share_mode,
			table->do_brlck ? "yes" : "no ",
			table->desired_access,
			table->overwrite ? "yes" : "no ",
			nt_errstr(table->status) + 10,
			table->reconnect_lease,
			table->broken_to_lease);

	options1.client_guid = GUID_random();
	options2.client_guid = GUID_random();

	ret = torture_smb2_connection_ext(tctx, 0, &options1, &tree1);
	torture_assert_goto(tctx, ret, ret, done,
			    "torture_smb2_connection_ext failed\n");

	previous_session_id = smb2cli_session_current_id(
		tree1->session->smbXcli);
	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	if (smb2_util_lease_state(table->held_lease) == SMB2_LEASE_READ &&
	    smb2_util_lease_state(table->reconnect_lease) == SMB2_LEASE_READ)
	{
		expect_acquire = true;
	}

	if (smb2_util_lease_state(table->reconnect_lease) !=
	    smb2_util_lease_state(table->broken_to_lease))
	{
		expect_break = true;
	}

	if (NT_STATUS_EQUAL(table->status, NT_STATUS_FILE_NOT_AVAILABLE)) {
		expect_block = true;
	}

	/*
	 * Get persistent open
	 */
	if (table->held_lease[0] != '\0') {
		ls = &ls1;
	} else {
		ls = NULL;
	}
	smb2_lease_v2_create_share(&io,
				   ls,
				   false,
				   fname,
				   smb2_util_share_access(table->share_mode),
				   lease1,
				   NULL,
				   smb2_util_lease_state(table->held_lease),
				   0);
	io.in.durable_open_v2 = true;
	io.in.persistent_open = true;
	io.in.create_guid = create_guid;
	status = smb2_create(tree1, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = io.out.file.handle;
	rh = h1;

	torture_assert_goto(
		tctx, io.out.persistent_open == true,
		ret, done, "Persistent open not granted\n");

	if (io.in.lease_request_v2 != NULL) {
		torture_assert_int_equal_goto(
			tctx,
			io.out.oplock_level,
			SMB2_OPLOCK_LEVEL_LEASE,
			ret, done,
			"Bad lease level\n");
		torture_assert_int_equal_goto(
			tctx,
			io.out.lease_response_v2.lease_state,
			smb2_util_lease_state(table->held_lease),
			ret, done,
			"Bad lease level\n");
	}

	if (table->do_brlck) {
		ZERO_ARRAY(el);
		ZERO_STRUCT(lck);
		el[0].offset = 0;
		el[0].length = 1;
		el[0].flags = SMB2_LOCK_FLAG_EXCLUSIVE |
			SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
		lck.in.locks = el;
		lck.in.lock_count = 1;
		lck.in.file.handle = h1;

		status = smb2_lock(tree1, &lck);
		torture_assert_ntstatus_equal_goto(
			tctx, status, NT_STATUS_OK,
			ret, done, "smb2_lock failed\n");
	}

	/*
	 * Now disconnect
	 */
	TALLOC_FREE(tree1);
	ZERO_STRUCT(h1);
	smb_msleep(1000);

	/*
	 * Contend durable open with second open from second client
	 */

	ret = torture_smb2_connection_ext(tctx, 0, &options2, &tree2);
	torture_assert_goto(tctx, ret, ret, done,
			    "torture_smb2_connection_ext failed\n");

	smb2_lease_v2_create(&io2, &ls2, false, fname,
			     lease2, NULL,
			     smb2_util_lease_state(table->new_lease), 0);
	io2.in.desired_access = table->desired_access;
	if (table->overwrite) {
		io2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	}

	req = smb2_create_send(tree2, &io2);
	torture_assert_not_null_goto(tctx, req, ret, done,
				     "smb2_create_send failed\n");

	while (!req->cancel.can_cancel &&
	       (req->state < SMB2_REQUEST_DONE))
	{
		rc = tevent_loop_once(req->transport->ev);
		torture_assert_goto(tctx, rc == 0, ret, done,
				    "tevent_loop_once failed\n");
	}

	if (table->async) {
		torture_assert_goto(tctx, req->state < SMB2_REQUEST_DONE,
				    ret, done,
				    "Expected async interim response\n");
	} else {
		torture_assert_goto(tctx, req->state == SMB2_REQUEST_DONE,
				    ret, done,
				    "Expected response\n");
	}

	/*
	 * Now reconnect first client and the persistent handle
	 */
	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options1, &tree1);
	torture_assert_goto(tctx, ret, ret, done,
			    "torture_smb2_connection_ext failed\n");
	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	if (table->held_lease[0] != '\0') {
		ls = &ls1;
	} else {
		ls = NULL;
	}
	smb2_lease_v2_create_share(&io,
				   ls,
				   false,
				   fname,
				   smb2_util_share_access(table->share_mode),
				   lease1,
				   NULL,
				   smb2_util_lease_state(table->held_lease),
				   128);
	io.in.durable_handle_v2 = &rh;
	io.in.create_guid = create_guid;
	io.in.persistent_open = true;
	status = smb2_create(tree1, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = io.out.file.handle;

	if (io.in.lease_request_v2 != NULL) {
		int expect_epoch;

		torture_assert_int_equal_goto(
			tctx,
			io.out.oplock_level,
			SMB2_OPLOCK_LEVEL_LEASE,
			ret, done,
			"Bad lease level\n");
		torture_assert_int_equal_goto(
			tctx,
			io.out.lease_response_v2.lease_state,
			smb2_util_lease_state(table->reconnect_lease),
			ret, done,
			"Bad lease level\n");

		if (expect_break) {
			expect_epoch = 1;
		} else if (expect_acquire) {
			expect_epoch = 129;
		} else if (expect_block) {
			expect_epoch = 128;
		} else {
			expect_epoch = 1;
		}

		torture_assert_int_equal_goto(
			tctx,
			io.out.lease_response_v2.lease_epoch,
			expect_epoch,
			ret,
			done,
			"Bad lease epoch\n");

		if (expect_break) {
			CHECK_BREAK_INFO_V2(tree1->session->transport,
					    table->held_lease,
					    table->broken_to_lease,
					    lease1,
					    2);
		} else {
			CHECK_NO_BREAK(tctx);
		}
	}

	status = smb2_create_recv(req, tctx, &io2);
	if (!NT_STATUS_IS_OK(table->status)) {
		torture_assert_ntstatus_equal_goto(
			tctx, status, table->status,
			ret, done, "smb2_create failed\n");
	} else {
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		h2 = io2.out.file.handle;

		if (io2.in.lease_request_v2 != NULL) {
			torture_assert_int_equal_goto(
				tctx,
				io2.out.oplock_level,
				SMB2_OPLOCK_LEVEL_LEASE,
				ret, done,
				"Bad lease level\n");
			torture_assert_int_equal_goto(
				tctx,
				io2.out.lease_response_v2.lease_state,
				smb2_util_lease_state(table->new_granted),
				ret, done,
				"Bad lease level\n");
		}

		status = smb2_util_close(tree2, h2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_close failed\n");
		ZERO_STRUCT(h2);
	}

	if ((smb2_util_share_access(table->share_mode) &
	    NTCREATEX_SHARE_ACCESS_READ) &&
	    table->do_brlck)
	{
		status = torture_smb2_testfile_access(
			tree2, fname, &h2,
			SEC_RIGHTS_FILE_READ);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");

		ZERO_ARRAY(el);
		ZERO_STRUCT(lck);
		el[0].offset = 0;
		el[0].length = 1;
		el[0].flags = SMB2_LOCK_FLAG_SHARED |
			SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
		lck.in.locks = el;
		lck.in.lock_count = 1;
		lck.in.file.handle = h2;

		status = smb2_lock(tree2, &lck);
		torture_assert_ntstatus_equal_goto(
			tctx, status, NT_STATUS_LOCK_NOT_GRANTED,
			ret, done, "smb2_lock failed\n");

		status = smb2_util_close(tree2, h2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_close failed\n");
		ZERO_STRUCT(h2);
	}

	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_close failed\n");
	ZERO_STRUCT(h1);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}
	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
	} else if (tree2 != NULL) {
		smb2_util_unlink(tree2, fname);
	}
	TALLOC_FREE(tree1);
	TALLOC_FREE(tree2);
	TALLOC_FREE(mem_ctx);
	return ret;
}

static bool test_persistent_reconnect_contended_do_table(
		struct torture_context *tctx,
		struct smb2_tree *_tree,
		struct persistent_reconnect_contend_results *table)
{
	int i;
	bool single;
	bool ok;

	i = torture_setting_int(tctx, "subtest", 0);
	single = torture_setting_bool(tctx, "single", false);

	for (; table[i].held_lease != NULL; i++) {
		ok = test_persistent_reconnect_contended_do_one(
			tctx, _tree, &table[i], i);
		if (!ok) {
			return false;
		}
		if (single) {
			return true;
		}
	}
	return true;
}

static bool test_persistent_reconnect_contended(struct torture_context *tctx,
						struct smb2_tree *_tree)
{
	struct persistent_reconnect_contend_results *table = NULL;
	uint32_t caps;
	uint32_t tcon_caps;

	caps = smb2cli_conn_server_capabilities(_tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	tcon_caps = smb2cli_tcon_capabilities(_tree->smbXcli);
	if (!(tcon_caps & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)) {
		torture_skip(tctx, "PH are not supported\n");
	}

	if (tcon_caps & SMB2_SHARE_CAP_SCALEOUT) {
		table = contend_results_so;
	} else {
		table = contend_results_fo;
	}

	return test_persistent_reconnect_contended_do_table(tctx, _tree, table);
}

static bool test_persistent_reconnect_contended_win_broken(
	struct torture_context *tctx,
	struct smb2_tree *_tree)
{
	uint32_t caps;
	uint32_t tcon_caps;

	caps = smb2cli_conn_server_capabilities(_tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	tcon_caps = smb2cli_tcon_capabilities(_tree->smbXcli);
	if (!(tcon_caps & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)) {
		torture_skip(tctx, "PH are not supported\n");
	}

	if (tcon_caps & SMB2_SHARE_CAP_SCALEOUT) {
		torture_skip(tctx, "SMB2_SHARE_CAP_SCALEOUT\n");
	}

	if (!TARGET_IS_SAMBA3(tctx)) {
		torture_skip(tctx, "Broken on Windows\n");
	}

	return test_persistent_reconnect_contended_do_table(
		tctx, _tree, contend_results_fo_win_broken);
}

#define RO (SEC_RIGHTS_FILE_READ)
#define RW (SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_WRITE)
#define RWD (SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_WRITE|SEC_STD_DELETE)

static struct persistent_reconnect_contend_results contend_results_two_fo[] = {
	/* L,	SM,	brlck,	RL,	BL,	DA,	DO,	status,				async,	NL,	NG */
	{"",	"RWD",	false,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"RH",	RO,	false,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"RH",	RO,	false,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RWD",	false,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"",	RO,	true,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"RH",	RW,	false,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"RH",	RW,	false,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RWD",	false,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"",	RW,	true,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"RH",	RWD,	false,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"RH",	RWD,	false,	NT_STATUS_OK,			true,	"RWH",	"RH"},
	{"",	"RWD",	false,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	false,	"RH",	"",	RWD,	true,	NT_STATUS_OK,			false,	"RWH",	"RH"},
	{"RW",	"RWD",	false,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	false,	"RWH",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"RH",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"",	RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"RH",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"RH",	RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RH",	"RWD",	true,	"",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RW",	"RWD",	true,	"RW",	"RW",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"RWH",	"RWD",	true,	"RWH",	"",	RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	true,	"RWH",	""},

	{NULL,	NULL,	false,	NULL,	NULL,	0,	false,	NT_STATUS_INTERNAL_ERROR,	false,	 NULL,	NULL}
};

/*
 * On a share with SMB2_SHARE_CAP_SCALEOUT the server doesn't grant W or H
 * leases.
 */
static struct persistent_reconnect_contend_results contend_results_two_so[] = {
	{"",	"RWD",	false,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	false,	"",	"",     RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	false,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RO,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"",	"RWD",	true,	"",	"",     RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RWD,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},
	{"R",	"RWD",	true,	"R",	"R",    RWD,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"RWH",	""},

	{NULL,	NULL,	false,	NULL,	NULL,   0,	false,	NT_STATUS_INTERNAL_ERROR,	false,	 NULL,	NULL}
};

#undef RO
#undef RW
#undef RWD

static bool test_persistent_reconnect_contended_do_two(
		struct torture_context *tctx,
		struct smb2_tree *_tree,
		struct persistent_reconnect_contend_results *table,
		int testnum)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smbcli_options options1 = _tree->session->transport->options;
	struct smbcli_options options2 = _tree->session->transport->options;
	struct smb2_tree *tree1 = NULL;
	struct smb2_tree *tree2 = NULL;
	struct smb2_request *req = NULL;
	struct smb2_create io;
	struct smb2_create io2;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_lease *ls = NULL;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_handle rh = {};
	struct smb2_handle rh2 = {};
	struct smb2_lock lck = {0};
	struct smb2_lock_element el[1];
	uint64_t previous_session_id;
	uint64_t lease1 = 1;
	uint64_t lease2 = 2;
	struct GUID create_guid1 = GUID_random();
	struct GUID create_guid2 = GUID_random();
	char *fname = NULL;
	int rc;
	bool expect_break = false;
	bool expect_acquire = false;
	bool expect_block = false;
	int expect_epoch = 0;
	NTSTATUS status;
	bool ret = true;

	torture_reset_lease_break_info(tctx, &lease_break_info);

	fname = talloc_asprintf(mem_ctx, "lease_break-%ld.dat", random());
	torture_assert_not_null_goto(tctx, fname, ret, done,
				     "talloc_asprintf failed\n");

	torture_comment(tctx,
			"%2d: "
			"Lease [%-3s] "
			"Sharemode [%-3s] "
			"Brl [%s]. "
			"Contend access [0x%0"PRIX32"] "
			"Overwrite [%s] "
			"Result [%18s]. "
			"Reconnect [%-3s] "
			"Break [%-3s]\n",
			testnum,
			table->held_lease,
			table->share_mode,
			table->do_brlck ? "yes" : "no ",
			table->desired_access,
			table->overwrite ? "yes" : "no ",
			nt_errstr(table->status) + 10,
			table->reconnect_lease,
			table->broken_to_lease);

	options1.client_guid = GUID_random();
	options2.client_guid = GUID_random();

	ret = torture_smb2_connection_ext(tctx, 0, &options1, &tree1);
	torture_assert_goto(tctx, ret, ret, done, "torture_smb2_connection_ext failed\n");
	previous_session_id = smb2cli_session_current_id(tree1->session->smbXcli);
	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	if (smb2_util_lease_state(table->held_lease) == SMB2_LEASE_READ &&
	    smb2_util_lease_state(table->reconnect_lease) == SMB2_LEASE_READ)
	{
		expect_acquire = true;
	}

	if (smb2_util_lease_state(table->reconnect_lease) !=
	    smb2_util_lease_state(table->broken_to_lease))
	{
		expect_break = true;
	}

	if (NT_STATUS_EQUAL(table->status, NT_STATUS_FILE_NOT_AVAILABLE)) {
		expect_block = true;
	}

	status = torture_setup_simple_file(tctx, tree1, fname);
	torture_assert_ntstatus_ok(tctx, status, "setup file failed\n");

	/*
	 * Get persistent open
	 */
	if (table->held_lease[0] != '\0') {
		ls = &ls1;
	} else {
		ls = NULL;
	}
	smb2_lease_v2_create_share(&io,
				   ls,
				   false,
				   fname,
				   smb2_util_share_access(table->share_mode),
				   lease1,
				   NULL,
				   smb2_util_lease_state(table->held_lease),
				   0);
	io.in.durable_open_v2 = true;
	io.in.persistent_open = true;
	io.in.create_guid = create_guid1;
	status = smb2_create(tree1, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = io.out.file.handle;
	rh = h1;

	torture_assert_goto(
		tctx, io.out.persistent_open == true,
		ret, done, "Persistent open not granted\n");

	if (io.in.lease_request_v2 != NULL) {
		torture_assert_int_equal_goto(
			tctx,
			io.out.oplock_level,
			SMB2_OPLOCK_LEVEL_LEASE,
			ret, done,
			"Bad lease level\n");
		torture_assert_int_equal_goto(
			tctx,
			io.out.lease_response_v2.lease_state,
			smb2_util_lease_state(table->held_lease),
			ret, done,
			"Bad lease level\n");
	}

	/*
	 * Get a second persistent open
	 */
	io.in.create_guid = create_guid2;

	status = smb2_create(tree1, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = io.out.file.handle;
	rh2 = h2;

	torture_assert_goto(
		tctx, io.out.persistent_open == true,
		ret, done, "Persistent open not granted\n");

	if (io.in.lease_request_v2 != NULL) {
		torture_assert_int_equal_goto(
			tctx,
			io.out.oplock_level,
			SMB2_OPLOCK_LEVEL_LEASE,
			ret, done,
			"Bad lease level\n");
		torture_assert_int_equal_goto(
			tctx,
			io.out.lease_response_v2.lease_state,
			smb2_util_lease_state(table->held_lease),
			ret, done,
			"Bad lease level\n");
	}

	if (table->do_brlck) {
		ZERO_ARRAY(el);
		ZERO_STRUCT(lck);
		el[0].offset = 0;
		el[0].length = 1;
		el[0].flags = SMB2_LOCK_FLAG_EXCLUSIVE|SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
		lck.in.locks = el;
		lck.in.lock_count = 1;
		lck.in.file.handle = h1;

		status = smb2_lock(tree1, &lck);
		torture_assert_ntstatus_equal_goto(
			tctx, status, NT_STATUS_OK,
			ret, done, "smb2_lock failed\n");
	}

	/*
	 * Now disconnect
	 */
	TALLOC_FREE(tree1);
	ZERO_STRUCT(h1);
	ZERO_STRUCT(h2);
	smb_msleep(100);

	/*
	 * Contend durable open with second open from second client
	 */

	ret = torture_smb2_connection_ext(tctx, 0, &options2, &tree2);
	torture_assert_goto(tctx, ret, ret, done,
			    "torture_smb2_connection_ext failed\n");

	smb2_lease_v2_create(&io2, &ls2, false, fname,
			     lease2, NULL,
			     smb2_util_lease_state(table->new_lease), 0);
	io2.in.desired_access = table->desired_access;
	if (table->overwrite) {
		io2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	}

	req = smb2_create_send(tree2, &io2);
	torture_assert_not_null_goto(tctx, req, ret, done,
				     "smb2_create_send failed\n");

	while (!req->cancel.can_cancel &&
	       (req->state < SMB2_REQUEST_DONE))
	{
		rc = tevent_loop_once(req->transport->ev);
		torture_assert_goto(tctx, rc == 0, ret, done,
				    "tevent_loop_once failed\n");
	}

	if (table->async) {
		torture_assert_goto(tctx, req->state < SMB2_REQUEST_DONE,
				    ret, done,
				    "Expected async interim response\n");
	} else {
		torture_assert_goto(tctx, req->state == SMB2_REQUEST_DONE,
				    ret, done,
				    "Expected response\n");
	}

	/*
	 * Now reconnect first client and the persistent handle
	 */
	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options1, &tree1);
	torture_assert_goto(tctx, ret, ret, done,
			    "torture_smb2_connection_ext failed\n");
	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	if (table->held_lease[0] != '\0') {
		ls = &ls1;
	} else {
		ls = NULL;
	}
	smb2_lease_v2_create_share(&io,
				   ls,
				   false,
				   fname,
				   smb2_util_share_access(table->share_mode),
				   lease1,
				   NULL,
				   smb2_util_lease_state(table->held_lease),
				   128);
	io.in.durable_handle_v2 = &rh;
	io.in.create_guid = create_guid1;
	io.in.persistent_open = true;
	status = smb2_create(tree1, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = io.out.file.handle;

	if (io.in.lease_request_v2 != NULL) {
		torture_assert_int_equal_goto(
			tctx,
			io.out.oplock_level,
			SMB2_OPLOCK_LEVEL_LEASE,
			ret, done,
			"Bad lease level\n");
		torture_assert_int_equal_goto(
			tctx,
			io.out.lease_response_v2.lease_state,
			smb2_util_lease_state(table->reconnect_lease),
			ret, done,
			"Bad lease level\n");

		if (expect_break) {
			expect_epoch = 1;
		} else if (expect_acquire) {
			expect_epoch = 129;
		} else if (expect_block) {
			expect_epoch = 128;
		} else {
			expect_epoch = 1;
		}

		torture_assert_int_equal_goto(
			tctx,
			io.out.lease_response_v2.lease_epoch,
			expect_epoch,
			ret,
			done,
			"Bad lease epoch\n");

		if (expect_break) {
			CHECK_BREAK_INFO_V2(tree1->session->transport,
					    table->held_lease,
					    table->broken_to_lease,
					    lease1,
					    2);
		} else {
			CHECK_NO_BREAK(tctx);
		}
	}

	torture_reset_lease_break_info(tctx, &lease_break_info);

	io.in.durable_handle_v2 = &rh2;
	io.in.create_guid = create_guid2;
	ls1.lease_epoch = expect_epoch + 1;
	ls1.lease_state = lease_break_info.lease_break.new_lease_state;

	status = smb2_create(tree1, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = io.out.file.handle;

	if (io.in.lease_request_v2 != NULL) {
		torture_assert_int_equal_goto(
			tctx,
			io.out.oplock_level,
			SMB2_OPLOCK_LEVEL_LEASE,
			ret, done,
			"Bad lease level\n");
		torture_assert_int_equal_goto(
			tctx,
			io.out.lease_response_v2.lease_state,
			smb2_util_lease_state(table->broken_to_lease),
			ret, done,
			"Bad lease level\n");

		if (expect_break) {
			expect_epoch = 2;
		} else if (expect_acquire) {
			expect_epoch = 129;
		} else if (expect_block) {
			expect_epoch = 128;
		} else {
			expect_epoch = 1;
		}

		torture_assert_int_equal_goto(
			tctx,
			io.out.lease_response_v2.lease_epoch,
			expect_epoch,
			ret,
			done,
			"Bad lease epoch\n");
	}
	CHECK_NO_BREAK(tctx);

	status = smb2_create_recv(req, tctx, &io2);
	if (!NT_STATUS_IS_OK(table->status)) {
		torture_assert_ntstatus_equal_goto(
			tctx, status, table->status,
			ret, done, "smb2_create failed\n");
	} else {
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		h3 = io2.out.file.handle;

		if (io2.in.lease_request_v2 != NULL) {
			torture_assert_int_equal_goto(
				tctx,
				io2.out.oplock_level,
				SMB2_OPLOCK_LEVEL_LEASE,
				ret, done,
				"Bad lease level\n");
			torture_assert_int_equal_goto(
				tctx,
				io2.out.lease_response_v2.lease_state,
				smb2_util_lease_state(table->new_granted),
				ret, done,
				"Bad lease level\n");
		}

		status = smb2_util_close(tree2, h3);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_close failed\n");
		ZERO_STRUCT(h3);
	}

	if ((smb2_util_share_access(table->share_mode) &
	     NTCREATEX_SHARE_ACCESS_READ) &&
	    table->do_brlck)
	{
		status = torture_smb2_testfile_access(
			tree2, fname, &h3,
			SEC_RIGHTS_FILE_READ);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");

		ZERO_ARRAY(el);
		ZERO_STRUCT(lck);
		el[0].offset = 0;
		el[0].length = 1;
		el[0].flags = SMB2_LOCK_FLAG_SHARED |
			SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
		lck.in.locks = el;
		lck.in.lock_count = 1;
		lck.in.file.handle = h3;

		status = smb2_lock(tree2, &lck);
		torture_assert_ntstatus_equal_goto(
			tctx, status, NT_STATUS_LOCK_NOT_GRANTED,
			ret, done, "smb2_lock failed\n");

		status = smb2_util_close(tree2, h3);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_close failed\n");
		ZERO_STRUCT(h3);
	}

	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_close failed\n");
	ZERO_STRUCT(h1);

	status = smb2_util_close(tree1, h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_close failed\n");
	ZERO_STRUCT(h2);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree1, h2);
	}
	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
	} else if (tree2 != NULL) {
		smb2_util_unlink(tree2, fname);
	}
	TALLOC_FREE(tree1);
	TALLOC_FREE(tree2);
	TALLOC_FREE(mem_ctx);
	return ret;
}

static bool test_persistent_reconnect_contended_two_do_table(
		struct torture_context *tctx,
		struct smb2_tree *_tree,
		struct persistent_reconnect_contend_results *table)
{
	int i;
	bool single;
	bool ok;

	i = torture_setting_int(tctx, "subtest", 0);
	single = torture_setting_bool(tctx, "single", false);

	for (; table[i].held_lease != NULL; i++) {
		ok = test_persistent_reconnect_contended_do_two(
			tctx, _tree, &table[i], i);
		if (!ok) {
			return false;
		}
		if (single) {
			return true;
		}
	}
	return true;
}

static bool test_persistent_reconnect_contended_two(
	struct torture_context *tctx,
	struct smb2_tree *_tree)
{
	struct persistent_reconnect_contend_results *table = NULL;
	uint32_t caps;
	uint32_t tcon_caps;

	caps = smb2cli_conn_server_capabilities(_tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	tcon_caps = smb2cli_tcon_capabilities(_tree->smbXcli);
	if (!(tcon_caps & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)) {
		torture_skip(tctx, "PH are not supported\n");
	}

	if (tcon_caps & SMB2_SHARE_CAP_SCALEOUT) {
		table = contend_results_two_so;
	} else {
		table = contend_results_two_fo;
	}

	return test_persistent_reconnect_contended_two_do_table(
		tctx, _tree, table);
}

struct oplock_persistent_reconnect_contend_results {
	/* Parameters for the first client's persistent open */
	const char *oplock;
	const char *share_mode;
	const char *reconnect_oplock;
	const char *broken_to_oplock;

	/* Parameters for the second client's contending open */
	uint32_t desired_access;
	bool overwrite;
	NTSTATUS status;
	bool async;
	const char *new_oplock;
	const char *new_granted_oplock;
};

#define RO (SEC_RIGHTS_FILE_READ)
#define RW (SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_WRITE)
#define RWD (SEC_RIGHTS_FILE_READ|SEC_RIGHTS_FILE_WRITE|SEC_STD_DELETE)

static struct oplock_persistent_reconnect_contend_results oplock_contend_results_fo[] = {
	{"",	"",	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"",	"x",	"x",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"",	"b",	"s",	RO,	false,	NT_STATUS_SHARING_VIOLATION,	true,	"b",	""},
	{"",	"R",	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"R",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"R",	"x",	"x",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"R",	"b",	"s",	RO,	false,	NT_STATUS_OK,			true,	"b",	"s"},
	{"",	"RW",	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"RW",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"RW",	"x",	"x",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"RW",	"b",	"s",	RO,	false,	NT_STATUS_OK,			true,	"b",	"s"},
	{"",	"RWD",	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"RWD",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"RWD",	"x",	"x",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"RWD",	"b",	"s",	RO,	false,	NT_STATUS_OK,			true,	"b",	"s"},
	{"",	"",	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"",	"s",	"s",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"",	"x",	"x",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"",	"b",	"s",	RW,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"b",	""},
	{"",	"R",	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"R",	"s",	"s",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"R",	"x",	"x",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"R",	"b",	"s",	RW,	true,	NT_STATUS_SHARING_VIOLATION,	true,	"b",	""},
	{"",	"RW",	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"RW",	"s",	"s",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"RW",	"x",	"x",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"RW",	"b",	"",	RW,	true,	NT_STATUS_OK,			true,	"b",	"s"},
	{"",	"RWD",	"",	"",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"RWD",	"s",	"s",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"RWD",	"x",	"x",	RW,	true,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"RWD",	"b",	"",	RW,	true,	NT_STATUS_OK,			true,	"b",	"s"},

	{NULL,	NULL,	NULL,	NULL,	0,	false,	NT_STATUS_INTERNAL_ERROR,	false,	 NULL,	NULL}
};

/*
 * On a share with SMB2_SHARE_CAP_SCALEOUT the server doesn't grant exclusive or
 * batch oplocks.
 */
static struct oplock_persistent_reconnect_contend_results oplock_contend_results_so[] = {
	{"",	"",	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"",	"R",	"",	"",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"R",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"R",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"R",	"s",	"s",	RO,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"",	"",	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"",	"s",	"s",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"",	"s",	"s",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"",	"s",	"s",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"",	"RW",	"",	"",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"s",	"RW",	"s",	"s",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"x",	"RW",	"s",	"s",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},
	{"b",	"RW",	"s",	"s",	RW,	false,	NT_STATUS_FILE_NOT_AVAILABLE,	false,	"b",	""},

	{NULL,	NULL,	NULL,	NULL,	0,	false,	NT_STATUS_INTERNAL_ERROR,	false,	 NULL,	NULL}
};

#undef RO
#undef RW
#undef RWD

static void ph_oplock_break_callback(struct smb2_request *req)
{
	NTSTATUS status;
	struct smb2_break br;

	ZERO_STRUCT(br);
	status = smb2_break_recv(req, &br);
	if (!NT_STATUS_IS_OK(status))
		lease_break_info.oplock_failures++;

	return;
}

/* a oplock break request handler */
static bool ph_oplock_handler(struct smb2_transport *transport,
			      const struct smb2_handle *handle,
			      uint8_t level, void *private_data)
{
	struct smb2_tree *tree = private_data;
	struct smb2_request *req;
	struct smb2_break br;

	lease_break_info.oplock_handle = *handle;
	lease_break_info.oplock_level	= level;
	lease_break_info.oplock_count++;

	ZERO_STRUCT(br);
	br.in.file.handle = *handle;
	br.in.oplock_level = level;

	if (lease_break_info.held_oplock_level > SMB2_OPLOCK_LEVEL_NONE) {
		req = smb2_break_send(tree, &br);
		req->async.fn = ph_oplock_break_callback;
		req->async.private_data = NULL;
	}
	lease_break_info.held_oplock_level = level;

	return true;
}

static bool test_persistent_reconnect_contended_oplock_do_one(
		struct torture_context *tctx,
		struct smb2_tree *_tree,
		struct oplock_persistent_reconnect_contend_results *table,
		int testnum)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	uint32_t tcon_caps;
	struct smbcli_options options1 = _tree->session->transport->options;
	struct smbcli_options options2 = _tree->session->transport->options;
	struct smb2_tree *tree1 = NULL;
	struct smb2_tree *tree2 = NULL;
	struct smb2_request *req = NULL;
	struct smb2_create io;
	struct smb2_create io2;
	struct smb2_handle h1 = {{0}};
	struct smb2_handle h2 = {{0}};
	uint64_t previous_session_id;
	struct GUID create_guid = GUID_random();
	char *fname = NULL;
	int rc;
	NTSTATUS status;
	bool ret = true;

	tcon_caps = smb2cli_tcon_capabilities(_tree->smbXcli);
	if (!(tcon_caps & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)) {
		torture_skip(tctx, "PH are not supported\n");
	}

	torture_reset_lease_break_info(tctx, &lease_break_info);

	fname = talloc_asprintf(mem_ctx, "%s-%ld.dat", __FUNCTION__, random());
	torture_assert_not_null_goto(tctx, fname, ret, done,
				     "talloc_asprintf failed\n");

	torture_comment(tctx,
			"%2d: Hold [%s] "
			"Sharemode [%-3s] "
			"Reconnect [%s] "
			"Break [%s]. "
			"Contend [%0"PRIX32"] "
			"Overwrite [%s] "
			"Result [%18s]\n",
			testnum,
			table->oplock,
			table->share_mode,
			table->reconnect_oplock,
			table->broken_to_oplock,
			table->desired_access,
			table->overwrite ? "yes" : "no ",
			nt_errstr(table->status) + 10);

	options1.client_guid = GUID_random();
	options2.client_guid = GUID_random();

	ret = torture_smb2_connection_ext(tctx, 0, &options1, &tree1);
	torture_assert_goto(tctx, ret, ret, done,
			    "torture_smb2_connection_ext failed\n");
	previous_session_id = smb2cli_session_current_id(
		tree1->session->smbXcli);

	/*
	 * Get persistent open
	 */

	status = torture_setup_simple_file(tctx, tree1, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	smb2_oplock_create_share(&io,
				 fname,
				 smb2_util_share_access(table->share_mode),
				 smb2_util_oplock_level(table->oplock));
	io.in.durable_open_v2 = true;
	io.in.persistent_open = true;
	io.in.create_guid = create_guid;
	status = smb2_create(tree1, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	torture_assert_goto(
		tctx, io.out.persistent_open == true,
		ret, done, "Persistent open not granted\n");

	if (tcon_caps & SMB2_SHARE_CAP_SCALEOUT) {
		if (smb2_util_oplock_level(table->oplock) >
		    SMB2_OPLOCK_LEVEL_II)
		{
			torture_assert_int_equal_goto(
				tctx,
				io.out.oplock_level,
				SMB2_OPLOCK_LEVEL_II,
				ret, done, "Bad oplock level\n");
		} else {
			torture_assert_int_equal_goto(
				tctx,
				io.out.oplock_level,
				smb2_util_oplock_level(table->oplock),
				ret, done, "Bad oplock level\n");
		}
	} else {
		torture_assert_int_equal_goto(
			tctx,
			io.out.oplock_level,
			smb2_util_oplock_level(table->oplock),
			ret, done, "Bad oplock level\n");
	}

	/*
	 * Now disconnect
	 */
	TALLOC_FREE(tree1);
	sleep(1);

	/*
	 * Contend durable open with second open from second client
	 */

	ret = torture_smb2_connection_ext(tctx, 0, &options2, &tree2);
	torture_assert_goto(tctx, ret, ret, done,
			    "torture_smb2_connection_ext failed\n");

	smb2_oplock_create(&io2,
			   fname,
			   smb2_util_oplock_level(table->new_oplock));
	io2.in.desired_access = table->desired_access;
	if (table->overwrite) {
		io2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	}

	req = smb2_create_send(tree2, &io2);
	torture_assert_not_null_goto(tctx, req, ret, done,
				     "smb2_create_send failed\n");

	while (!req->cancel.can_cancel &&
	       (req->state < SMB2_REQUEST_DONE))
	{
		rc = tevent_loop_once(req->transport->ev);
		torture_assert_goto(tctx, rc == 0, ret, done,
				    "tevent_loop_once failed\n");
	}

	if (table->async) {
		torture_assert_goto(tctx, req->state < SMB2_REQUEST_DONE,
				    ret, done,
				    "Expected async interim response\n");
	} else {
		torture_assert_goto(tctx, req->state == SMB2_REQUEST_DONE,
				    ret, done,
				    "Expected response\n");
	}

	/*
	 * Now reconnect first client and the persistent handle
	 */
	ret = torture_smb2_connection_ext(tctx, previous_session_id,
					  &options1, &tree1);
	torture_assert_goto(tctx, ret, ret, done,
			    "torture_smb2_connection_ext failed\n");

	torture_reset_lease_break_info(tctx, &lease_break_info);
	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	tree1->session->transport->oplock.handler = ph_oplock_handler;
	tree1->session->transport->oplock.private_data = tree1;

	smb2_oplock_create_share(&io,
				 fname,
				 smb2_util_share_access(table->share_mode),
				 smb2_util_oplock_level(table->oplock));
	io.in.durable_handle_v2 = &h1;
	io.in.create_guid = create_guid;
	io.in.persistent_open = true;
	status = smb2_create(tree1, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = io.out.file.handle;
	lease_break_info.held_oplock_level = io.out.oplock_level;

	if (io.in.oplock_level != SMB2_OPLOCK_LEVEL_NONE) {
		torture_assert_goto(
			tctx,
			io.out.oplock_level == smb2_util_oplock_level(
				table->reconnect_oplock),
			ret, done,
			"Bad oplock level\n");

		if (smb2_util_oplock_level(table->reconnect_oplock) !=
		    smb2_util_oplock_level(table->broken_to_oplock))
		{
			CHECK_OPLOCK_BREAK(table->broken_to_oplock);
		} else {
			CHECK_NO_BREAK(tctx);
		}
	}

	status = smb2_create_recv(req, tctx, &io2);
	if (!NT_STATUS_IS_OK(table->status)) {
		torture_assert_ntstatus_equal_goto(
			tctx, status, table->status,
			ret, done, "smb2_create failed\n");
	} else {
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		h2 = io2.out.file.handle;

		if (io2.in.oplock_level != SMB2_OPLOCK_LEVEL_NONE) {
			torture_assert_goto(
				tctx,
				io2.out.oplock_level == smb2_util_oplock_level(
					table->new_granted_oplock),
				ret, done,
				"Bad lease state\n");
		}

		status = smb2_util_close(tree2, h2);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_close failed\n");
		ZERO_STRUCT(h2);
	}

	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_close failed\n");
	ZERO_STRUCT(h1);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}
	if (tree1 != NULL) {
		smb2_util_unlink(tree1, fname);
	}
	TALLOC_FREE(tree1);
	TALLOC_FREE(tree2);
	TALLOC_FREE(mem_ctx);
	return ret;
}

static bool test_persistent_reconnect_contended_oplock_do_table(
		struct torture_context *tctx,
		struct smb2_tree *_tree,
		struct oplock_persistent_reconnect_contend_results *table)
{
	int i;
	bool single;
	bool ok;

	i = torture_setting_int(tctx, "subtest", 0);
	single = torture_setting_bool(tctx, "single", false);

	for (; table[i].oplock != NULL; i++) {
		ok = test_persistent_reconnect_contended_oplock_do_one(
			tctx, _tree, &table[i], i);
		if (!ok) {
			return false;
		}
		if (single) {
			return true;
		}
	}
	return true;
}

static bool test_persistent_reconnect_contended_oplock(
	struct torture_context *tctx,
	struct smb2_tree *_tree)
{
	struct oplock_persistent_reconnect_contend_results *table = NULL;
	uint32_t tcon_caps;

	/*
	 * Persistent Handles together with oplocks are broken on Windows:
	 * oplocks are "silently" downgraded from B to S when reconnecting a PH,
	 * instead of sending an oplock break with the downgraded oplock level
	 * (eg --option=torture:subtest=7).
	 *
	 * Samba doesn't grant Persistent Handles with oplocks at all, only with
	 * leases or without an oplock or lease.
	 *
	 * Skip these tests altogether, they're merely kept for historical
	 * reference and in case this subject needs furthter exploration in the
	 * future.
	 */

	torture_skip(tctx, "Broken on Windows\n");

	tcon_caps = smb2cli_tcon_capabilities(_tree->smbXcli);
	if (!(tcon_caps & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)) {
		torture_skip(tctx, "PH are not supported\n");
	}

	if (tcon_caps & SMB2_SHARE_CAP_SCALEOUT) {
		table = oplock_contend_results_so;
	} else {
		table = oplock_contend_results_fo;
	}

	return test_persistent_reconnect_contended_oplock_do_table(
		tctx, _tree, table);
}

struct torture_suite *torture_smb2_persistent_open_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "persistent-open");

	suite->description = talloc_strdup(suite, "SMB2-PERSISTENT-OPEN tests");

	torture_suite_add_1smb2_test(suite, "leaselevels", test_persistent_leaselevels);
	torture_suite_add_1smb2_test(suite, "leaselevels_fo", test_persistent_leaselevels_fo);
	torture_suite_add_1smb2_test(suite, "leaselevels_fo_max_rwh", test_persistent_leaselevels_fo_max_rwh);
	torture_suite_add_1smb2_test(suite, "leaselevels_so", test_persistent_leaselevels_so);
	torture_suite_add_1smb2_test(suite, "reconnect-contended", test_persistent_reconnect_contended);
	torture_suite_add_1smb2_test(suite, "reconnect-contended-win-broken", test_persistent_reconnect_contended_win_broken);
	torture_suite_add_1smb2_test(suite, "reconnect-contended-two", test_persistent_reconnect_contended_two);
	torture_suite_add_1smb2_test(suite, "reconnect-contended-oplock", test_persistent_reconnect_contended_oplock);

	return suite;
}
