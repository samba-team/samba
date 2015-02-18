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
#include <tevent.h>
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "torture/util.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/security/security.h"
#include "lib/param/param.h"

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s got 0x%x - should be 0x%x\n", \
				__location__, #v, (int)(v), (int)(correct)); \
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

#define CHECK_LEASE(__io, __state, __oplevel, __key, __flags)		\
	do {								\
		CHECK_VAL((__io)->out.lease_response.lease_version, 1); \
		if (__oplevel) {					\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[0], (__key)); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[1], ~(__key)); \
			CHECK_VAL((__io)->out.lease_response.lease_state, smb2_util_lease_state(__state)); \
		} else {						\
			CHECK_VAL((__io)->out.oplock_level, SMB2_OPLOCK_LEVEL_NONE); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[0], 0); \
			CHECK_VAL((__io)->out.lease_response.lease_key.data[1], 0); \
			CHECK_VAL((__io)->out.lease_response.lease_state, 0); \
		}							\
									\
		CHECK_VAL((__io)->out.lease_response.lease_flags, (__flags));	\
		CHECK_VAL((__io)->out.lease_response.lease_duration, 0); \
		CHECK_VAL((__io)->out.lease_response.lease_epoch, 0); \
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

static const uint64_t LEASE1 = 0xBADC0FFEE0DDF00Dull;
static const uint64_t LEASE2 = 0xDEADBEEFFEEDBEADull;
static const uint64_t LEASE3 = 0xDAD0FFEDD00DF00Dull;
static const uint64_t LEASE4 = 0xBAD0FFEDD00DF00Dull;

#define NREQUEST_RESULTS 8
static const char *request_results[NREQUEST_RESULTS][2] = {
	{ "", "" },
	{ "R", "R" },
	{ "H", "" },
	{ "W", "" },
	{ "RH", "RH" },
	{ "RW", "RW" },
	{ "HW", "" },
	{ "RHW", "RHW" },
};

static bool test_lease_request(struct torture_context *tctx,
	                       struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1, h2;
	NTSTATUS status;
	const char *fname = "lease_request.dat";
	const char *fname2 = "lease_request.2.dat";
	const char *sname = "lease_request.dat:stream";
	const char *dname = "lease_request.dir";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);
	smb2_util_unlink(tree, fname2);
	smb2_util_rmdir(tree, dname);

	/* Win7 is happy to grant RHW leases on files. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state("RHW"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RHW", true, LEASE1, 0);

	/* But will reject leases on directories. */
	if (!(caps & SMB2_CAP_DIRECTORY_LEASING)) {
		smb2_lease_create(&io, &ls, true, dname, LEASE2, smb2_util_lease_state("RHW"));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_DIRECTORY);
		CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);
		smb2_util_close(tree, io.out.file.handle);
	}

	/* Also rejects multiple files leased under the same key. */
	smb2_lease_create(&io, &ls, true, fname2, LEASE1, smb2_util_lease_state("RHW"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	/* And grants leases on streams (with separate leasekey). */
	smb2_lease_create(&io, &ls, false, sname, LEASE2, smb2_util_lease_state("RHW"));
	status = smb2_create(tree, mem_ctx, &io);
	h2 = io.out.file.handle;
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RHW", true, LEASE2, 0);
	smb2_util_close(tree, h2);

	smb2_util_close(tree, h1);

	/* Now see what combos are actually granted. */
	for (i = 0; i < NREQUEST_RESULTS; i++) {
		torture_comment(tctx, "Requesting lease type %s(%x),"
		    " expecting %s(%x)\n",
		    request_results[i][0], smb2_util_lease_state(request_results[i][0]),
		    request_results[i][1], smb2_util_lease_state(request_results[i][1]));
		smb2_lease_create(&io, &ls, false, fname, LEASE1,
		    smb2_util_lease_state(request_results[i][0]));
		status = smb2_create(tree, mem_ctx, &io);
		h2 = io.out.file.handle;
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, request_results[i][1], true, LEASE1, 0);
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
	const char *fname = "lease_upgrade.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	/* Grab a RH lease. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state("RH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RH", true, LEASE1, 0);
	h = io.out.file.handle;

	/* Upgrades (sidegrades?) to RW leave us with an RH. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state("RW"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RH", true, LEASE1, 0);
	hnew = io.out.file.handle;

	smb2_util_close(tree, hnew);

	/* Upgrade to RHW lease. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state("RHW"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RHW", true, LEASE1, 0);
	hnew = io.out.file.handle;

	smb2_util_close(tree, h);
	h = hnew;

	/* Attempt to downgrade - original lease state is maintained. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state("RH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RHW", true, LEASE1, 0);
	hnew = io.out.file.handle;

	smb2_util_close(tree, hnew);

 done:
	smb2_util_close(tree, h);
	smb2_util_close(tree, hnew);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * upgrade2 test.
 * full matrix of lease upgrade combinations
 * (non-contended case)
 *
 * The summary of the behaviour is this:
 * -------------------------------------
 * An uncontended lease upgrade results in a change
 * if and only if the requested lease state is
 * - valid, and
 * - strictly a superset of the lease state already held.
 *
 * In that case the resulting lease state is the one
 * requested in the upgrade.
 */
struct lease_upgrade2_test {
	const char *initial;
	const char *upgrade_to;
	const char *expected;
};

#define NUM_LEASE_TYPES 5
#define NUM_UPGRADE_TESTS ( NUM_LEASE_TYPES * NUM_LEASE_TYPES )
struct lease_upgrade2_test lease_upgrade2_tests[NUM_UPGRADE_TESTS] = {
	{ "", "", "" },
	{ "", "R", "R" },
	{ "", "RH", "RH" },
	{ "", "RW", "RW" },
	{ "", "RWH", "RWH" },

	{ "R", "", "R" },
	{ "R", "R", "R" },
	{ "R", "RH", "RH" },
	{ "R", "RW", "RW" },
	{ "R", "RWH", "RWH" },

	{ "RH", "", "RH" },
	{ "RH", "R", "RH" },
	{ "RH", "RH", "RH" },
	{ "RH", "RW", "RH" },
	{ "RH", "RWH", "RWH" },

	{ "RW", "", "RW" },
	{ "RW", "R", "RW" },
	{ "RW", "RH", "RW" },
	{ "RW", "RW", "RW" },
	{ "RW", "RWH", "RWH" },

	{ "RWH", "", "RWH" },
	{ "RWH", "R", "RWH" },
	{ "RWH", "RH", "RWH" },
	{ "RWH", "RW", "RWH" },
	{ "RWH", "RWH", "RWH" },
};

static bool test_lease_upgrade2(struct torture_context *tctx,
                                struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle h, hnew;
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_lease ls;
	const char *fname = "lease_upgrade2.dat";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	for (i = 0; i < NUM_UPGRADE_TESTS; i++) {
		struct lease_upgrade2_test t = lease_upgrade2_tests[i];

		smb2_util_unlink(tree, fname);

		/* Grab a lease. */
		smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state(t.initial));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, t.initial, true, LEASE1, 0);
		h = io.out.file.handle;

		/* Upgrade. */
		smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state(t.upgrade_to));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, t.expected, true, LEASE1, 0);
		hnew = io.out.file.handle;

		smb2_util_close(tree, hnew);
		smb2_util_close(tree, h);
	}

 done:
	smb2_util_close(tree, h);
	smb2_util_close(tree, hnew);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}


#define CHECK_LEASE_BREAK(__lb, __oldstate, __state, __key)		\
	do {								\
		uint16_t __new = smb2_util_lease_state(__state); \
		uint16_t __old = smb2_util_lease_state(__oldstate); \
		CHECK_VAL((__lb)->new_lease_state, __new);	\
		CHECK_VAL((__lb)->current_lease.lease_state, __old); \
		CHECK_VAL((__lb)->current_lease.lease_key.data[0], (__key)); \
		CHECK_VAL((__lb)->current_lease.lease_key.data[1], ~(__key)); \
		if (__old & (SMB2_LEASE_WRITE | SMB2_LEASE_HANDLE)) { \
			CHECK_VAL((__lb)->break_flags, \
				  SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED);	\
		} else { \
			CHECK_VAL((__lb)->break_flags, 0); \
		} \
	} while(0)

#define CHECK_LEASE_BREAK_ACK(__lba, __state, __key)			\
	do {								\
		CHECK_VAL((__lba)->out.reserved, 0);			\
		CHECK_VAL((__lba)->out.lease.lease_key.data[0], (__key)); \
		CHECK_VAL((__lba)->out.lease.lease_key.data[1], ~(__key)); \
		CHECK_VAL((__lba)->out.lease.lease_state, smb2_util_lease_state(__state)); \
		CHECK_VAL((__lba)->out.lease.lease_flags, 0);		\
		CHECK_VAL((__lba)->out.lease.lease_duration, 0);	\
	} while(0)

static struct torture_lease_break {
	struct smb2_lease_break lease_break;
	struct smb2_transport *lease_transport;
	bool lease_skip_ack;
	struct smb2_lease_break_ack lease_break_ack;
	int count;
	int failures;

	struct smb2_handle oplock_handle;
	uint8_t held_oplock_level;
	uint8_t oplock_level;
	int oplock_count;
	int oplock_failures;
} break_info;

#define CHECK_NO_BREAK(tctx)	\
	do {								\
		torture_wait_for_lease_break(tctx);			\
		CHECK_VAL(break_info.failures, 0);			\
		CHECK_VAL(break_info.count, 0);				\
		CHECK_VAL(break_info.oplock_failures, 0);		\
		CHECK_VAL(break_info.oplock_count, 0);			\
	} while(0)

#define CHECK_OPLOCK_BREAK(__brokento)	\
	do {								\
		torture_wait_for_lease_break(tctx);			\
		CHECK_VAL(break_info.oplock_count, 1);			\
		CHECK_VAL(break_info.oplock_failures, 0);		\
		CHECK_VAL(break_info.oplock_level,			\
			  smb2_util_oplock_level(__brokento)); \
		break_info.held_oplock_level = break_info.oplock_level; \
	} while(0)

#define _CHECK_BREAK_INFO(__oldstate, __state, __key)			\
	do {								\
		torture_wait_for_lease_break(tctx);			\
		CHECK_VAL(break_info.failures, 0);			\
		CHECK_VAL(break_info.count, 1);				\
		CHECK_LEASE_BREAK(&break_info.lease_break, (__oldstate), \
		    (__state), (__key));				\
		if (!break_info.lease_skip_ack && \
		    (break_info.lease_break.break_flags &		\
		     SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED))	\
		{	\
			torture_wait_for_lease_break(tctx);		\
			CHECK_LEASE_BREAK_ACK(&break_info.lease_break_ack, \
				              (__state), (__key));	\
		}							\
	} while(0)

#define CHECK_BREAK_INFO(__oldstate, __state, __key)			\
	do {								\
		_CHECK_BREAK_INFO(__oldstate, __state, __key);		\
		CHECK_VAL(break_info.lease_break.new_epoch, 0);		\
	} while(0)

#define CHECK_BREAK_INFO_V2(__transport, __oldstate, __state, __key, __epoch) \
	do {								\
		_CHECK_BREAK_INFO(__oldstate, __state, __key);		\
		CHECK_VAL(break_info.lease_break.new_epoch, __epoch);	\
		if (!TARGET_IS_SAMBA3(tctx)) {				\
			CHECK_VAL((uintptr_t)break_info.lease_transport, \
				  (uintptr_t)__transport);		\
		} \
	} while(0)

static void torture_lease_break_callback(struct smb2_request *req)
{
	NTSTATUS status;

	status = smb2_lease_break_ack_recv(req, &break_info.lease_break_ack);
	if (!NT_STATUS_IS_OK(status))
		break_info.failures++;

	return;
}

/* a lease break request handler */
static bool torture_lease_handler(struct smb2_transport *transport,
				  const struct smb2_lease_break *lb,
				  void *private_data)
{
	struct smb2_tree *tree = private_data;
	struct smb2_lease_break_ack io;
	struct smb2_request *req;

	break_info.lease_transport = transport;
	break_info.lease_break = *lb;
	break_info.count++;

	if (break_info.lease_skip_ack) {
		return true;
	}

	if (lb->break_flags & SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED) {
		ZERO_STRUCT(io);
		io.in.lease.lease_key = lb->current_lease.lease_key;
		io.in.lease.lease_state = lb->new_lease_state;

		req = smb2_lease_break_ack_send(tree, &io);
		req->async.fn = torture_lease_break_callback;
		req->async.private_data = NULL;
	}

	return true;
}

/**
 * upgrade3:
 * full matrix of lease upgrade combinations
 * (contended case)
 *
 * We start with 2 leases, and check how one can
 * be upgraded
 *
 * The summary of the behaviour is this:
 * -------------------------------------
 *
 * If we have two leases (lease1 and lease2) on the same file,
 * then attempt to upgrade lease1 results in a change if and only
 * if the requested lease state:
 * - is valid,
 * - is strictly a superset of lease1, and
 * - can held together with lease2.
 *
 * In that case, the resuling lease state of the upgraded lease1
 * is the state requested in the upgrade. lease2 is not broken
 * and remains unchanged.
 *
 * Note that this contrasts the case of directly opening with
 * an initial requested lease state, in which case you get that
 * portion of the requested state that can be shared with the
 * already existing leases (or the states that they get broken to).
 */
struct lease_upgrade3_test {
	const char *held1;
	const char *held2;
	const char *upgrade_to;
	const char *upgraded_to;
};

#define NUM_UPGRADE3_TESTS ( 20 )
struct lease_upgrade3_test lease_upgrade3_tests[NUM_UPGRADE3_TESTS] = {
	{"R", "R", "", "R" },
	{"R", "R", "R", "R" },
	{"R", "R", "RW", "R" },
	{"R", "R", "RH", "RH" },
	{"R", "R", "RHW", "R" },

	{"R", "RH", "", "R" },
	{"R", "RH", "R", "R" },
	{"R", "RH", "RW", "R" },
	{"R", "RH", "RH", "RH" },
	{"R", "RH", "RHW", "R" },

	{"RH", "R", "", "RH" },
	{"RH", "R", "R", "RH" },
	{"RH", "R", "RW", "RH" },
	{"RH", "R", "RH", "RH" },
	{"RH", "R", "RHW", "RH" },

	{"RH", "RH", "", "RH" },
	{"RH", "RH", "R", "RH" },
	{"RH", "RH", "RW", "RH" },
	{"RH", "RH", "RH", "RH" },
	{"RH", "RH", "RHW", "RH" },
};

static bool test_lease_upgrade3(struct torture_context *tctx,
                                struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle h, h2, hnew;
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_lease ls;
	const char *fname = "lease_upgrade3.dat";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;

	smb2_util_unlink(tree, fname);

	for (i = 0; i < NUM_UPGRADE3_TESTS; i++) {
		struct lease_upgrade3_test t = lease_upgrade3_tests[i];

		smb2_util_unlink(tree, fname);

		ZERO_STRUCT(break_info);

		/* grab first lease */
		smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state(t.held1));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, t.held1, true, LEASE1, 0);
		h = io.out.file.handle;

		/* grab second lease */
		smb2_lease_create(&io, &ls, false, fname, LEASE2, smb2_util_lease_state(t.held2));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, t.held2, true, LEASE2, 0);
		h2 = io.out.file.handle;

		/* no break has happened */
		CHECK_VAL(break_info.count, 0);
		CHECK_VAL(break_info.failures, 0);

		/* try to upgrade lease1 */
		smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state(t.upgrade_to));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, t.upgraded_to, true, LEASE1, 0);
		hnew = io.out.file.handle;

		/* no break has happened */
		CHECK_VAL(break_info.count, 0);
		CHECK_VAL(break_info.failures, 0);

		smb2_util_close(tree, hnew);
		smb2_util_close(tree, h);
		smb2_util_close(tree, h2);
	}

 done:
	smb2_util_close(tree, h);
	smb2_util_close(tree, hnew);
	smb2_util_close(tree, h2);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}



/*
   Timer handler function notifies the registering function that time is up
*/
static void timeout_cb(struct tevent_context *ev,
		       struct tevent_timer *te,
		       struct timeval current_time,
		       void *private_data)
{
	bool *timesup = (bool *)private_data;
	*timesup = true;
	return;
}

/*
   Wait a short period of time to receive a single oplock break request
*/
static void torture_wait_for_lease_break(struct torture_context *tctx)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct tevent_timer *te = NULL;
	struct timeval ne;
	bool timesup = false;
	int old_count = break_info.count;

	/* Wait .1 seconds for an lease break */
	ne = tevent_timeval_current_ofs(0, 100000);

	te = tevent_add_timer(tctx->ev, tmp_ctx, ne, timeout_cb, &timesup);
	if (te == NULL) {
		torture_comment(tctx, "Failed to wait for an oplock break. "
				      "test results may not be accurate.");
		goto done;
	}

	while (!timesup && break_info.count < old_count + 1) {
		if (tevent_loop_once(tctx->ev) != 0) {
			torture_comment(tctx, "Failed to wait for an oplock "
					      "break. test results may not be "
					      "accurate.");
			goto done;
		}
	}

done:
	/* We don't know if the timed event fired and was freed, we received
	 * our oplock break, or some other event triggered the loop.  Thus,
	 * we create a tmp_ctx to be able to safely free/remove the timed
	 * event in all 3 cases. */
	talloc_free(tmp_ctx);

	return;
}

/*
  break_results should be read as "held lease, new lease, hold broken to, new
  grant", i.e. { "RH", "RW", "RH", "R" } means that if key1 holds RH and key2
  tries for RW, key1 will be broken to RH (in this case, not broken at all)
  and key2 will be granted R.

  Note: break_results only includes things that Win7 will actually grant (see
  request_results above).
 */
#define NBREAK_RESULTS 16
static const char *break_results[NBREAK_RESULTS][4] = {
	{"R",	"R",	"R",	"R"},
	{"R",	"RH",	"R",	"RH"},
	{"R",	"RW",	"R",	"R"},
	{"R",	"RHW",	"R",	"RH"},

	{"RH",	"R",	"RH",	"R"},
	{"RH",	"RH",	"RH",	"RH"},
	{"RH",	"RW",	"RH",	"R"},
	{"RH",	"RHW",	"RH",	"RH"},

	{"RW",	"R",	"R",	"R"},
	{"RW",	"RH",	"R",	"RH"},
	{"RW",	"RW",	"R",	"R"},
	{"RW",	"RHW",	"R",	"RH"},

	{"RHW",	"R",	"RH",	"R"},
	{"RHW",	"RH",	"RH",	"RH"},
	{"RHW",	"RW",	"RH",	"R"},
	{"RHW", "RHW",	"RH",	"RH"},
};

static bool test_lease_break(struct torture_context *tctx,
                               struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h, h2, h3;
	NTSTATUS status;
	const char *fname = "lease_break.dat";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;

	smb2_util_unlink(tree, fname);

	for (i = 0; i < NBREAK_RESULTS; i++) {
		const char *held = break_results[i][0];
		const char *contend = break_results[i][1];
		const char *brokento = break_results[i][2];
		const char *granted = break_results[i][3];
		torture_comment(tctx, "Hold %s(%x), requesting %s(%x), "
		    "expecting break to %s(%x) and grant of %s(%x)\n",
		    held, smb2_util_lease_state(held), contend, smb2_util_lease_state(contend),
		    brokento, smb2_util_lease_state(brokento), granted, smb2_util_lease_state(granted));

		ZERO_STRUCT(break_info);

		/* Grab lease. */
		smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state(held));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		h = io.out.file.handle;
		CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, held, true, LEASE1, 0);

		/* Possibly contend lease. */
		smb2_lease_create(&io, &ls, false, fname, LEASE2, smb2_util_lease_state(contend));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		h2 = io.out.file.handle;
		CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, granted, true, LEASE2, 0);

		if (smb2_util_lease_state(held) != smb2_util_lease_state(brokento)) {
			CHECK_BREAK_INFO(held, brokento, LEASE1);
		} else {
			CHECK_NO_BREAK(tctx);
		}

		ZERO_STRUCT(break_info);

		/*
		  Now verify that an attempt to upgrade LEASE1 results in no
		  break and no change in LEASE1.
		 */
		smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state("RHW"));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		h3 = io.out.file.handle;
		CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, brokento, true, LEASE1, 0);
		CHECK_VAL(break_info.count, 0);
		CHECK_VAL(break_info.failures, 0);

		smb2_util_close(tree, h);
		smb2_util_close(tree, h2);
		smb2_util_close(tree, h3);

		status = smb2_util_unlink(tree, fname);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

 done:
	smb2_util_close(tree, h);
	smb2_util_close(tree, h2);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_nobreakself(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1, h2;
	NTSTATUS status;
	const char *fname = "lease_nobreakself.dat";
	bool ret = true;
	uint32_t caps;
	char c = 0;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	/* Win7 is happy to grant RHW leases on files. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1,
			  smb2_util_lease_state("R"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "R", true, LEASE1, 0);

	smb2_lease_create(&io, &ls, false, fname, LEASE2,
			  smb2_util_lease_state("R"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_LEASE(&io, "R", true, LEASE2, 0);

	ZERO_STRUCT(break_info);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;

	/* Make sure we don't break ourselves on write */

	status = smb2_util_write(tree, h1, &c, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_BREAK_INFO("R", "", LEASE2);

	/* Try the other way round. First, upgrade LEASE2 to R again */

	smb2_lease_create(&io, &ls, false, fname, LEASE2,
			  smb2_util_lease_state("R"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE(&io, "R", true, LEASE2, 0);
	smb2_util_close(tree, io.out.file.handle);

	/* Now break LEASE1 via h2 */

	ZERO_STRUCT(break_info);
	status = smb2_util_write(tree, h2, &c, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_BREAK_INFO("R", "", LEASE1);

	/* .. and break LEASE2 via h1 */

	ZERO_STRUCT(break_info);
	status = smb2_util_write(tree, h1, &c, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_BREAK_INFO("R", "", LEASE2);

done:
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_statopen(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1, h2;
	NTSTATUS status;
	const char *fname = "lease_statopen.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	/* Create file. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1,
			  smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);
	smb2_util_close(tree, h1);

	/* Stat open file with RWH lease. */
	smb2_lease_create_share(&io, &ls, false, fname, 0, LEASE1,
			  smb2_util_lease_state("RWH"));
	io.in.desired_access = FILE_READ_ATTRIBUTES;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

	ZERO_STRUCT(break_info);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;

	/* Ensure non-stat open doesn't break and gets same lease
	   state as existing stat open. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1,
			  smb2_util_lease_state(""));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

	CHECK_NO_BREAK(tctx);
	smb2_util_close(tree, h1);

	/* Open with conflicting lease. stat open should break down to RH */
	smb2_lease_create(&io, &ls, false, fname, LEASE2,
			  smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RH", true, LEASE2, 0);

	CHECK_BREAK_INFO("RWH", "RH", LEASE1);

done:
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}


static void torture_oplock_break_callback(struct smb2_request *req)
{
	NTSTATUS status;
	struct smb2_break br;

	ZERO_STRUCT(br);
	status = smb2_break_recv(req, &br);
	if (!NT_STATUS_IS_OK(status))
		break_info.oplock_failures++;

	return;
}

/* a oplock break request handler */
static bool torture_oplock_handler(struct smb2_transport *transport,
				   const struct smb2_handle *handle,
				   uint8_t level, void *private_data)
{
	struct smb2_tree *tree = private_data;
	struct smb2_request *req;
	struct smb2_break br;

	break_info.oplock_handle = *handle;
	break_info.oplock_level	= level;
	break_info.oplock_count++;

	ZERO_STRUCT(br);
	br.in.file.handle = *handle;
	br.in.oplock_level = level;

	if (break_info.held_oplock_level > SMB2_OPLOCK_LEVEL_II) {
		req = smb2_break_send(tree, &br);
		req->async.fn = torture_oplock_break_callback;
		req->async.private_data = NULL;
	}
	break_info.held_oplock_level = level;

	return true;
}

#define NOPLOCK_RESULTS 12
static const char *oplock_results[NOPLOCK_RESULTS][4] = {
	{"R",	"s",	"R",	"s"},
	{"R",	"x",	"R",	"s"},
	{"R",	"b",	"R",	"s"},

	{"RH",	"s",	"RH",	""},
	{"RH",	"x",	"RH",	""},
	{"RH",	"b",	"RH",	""},

	{"RW",	"s",	"R",	"s"},
	{"RW",	"x",	"R",	"s"},
	{"RW",	"b",	"R",	"s"},

	{"RHW",	"s",	"RH",	""},
	{"RHW",	"x",	"RH",	""},
	{"RHW",	"b",	"RH",	""},
};

static const char *oplock_results_2[NOPLOCK_RESULTS][4] = {
	{"s",	"R",	"s",	"R"},
	{"s",	"RH",	"s",	"R"},
	{"s",	"RW",	"s",	"R"},
	{"s",	"RHW",	"s",	"R"},

	{"x",	"R",	"s",	"R"},
	{"x",	"RH",	"s",	"R"},
	{"x",	"RW",	"s",	"R"},
	{"x",	"RHW",	"s",	"R"},

	{"b",	"R",	"s",	"R"},
	{"b",	"RH",	"s",	"R"},
	{"b",	"RW",	"s",	"R"},
	{"b",	"RHW",	"s",	"R"},
};

static bool test_lease_oplock(struct torture_context *tctx,
                              struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h, h2;
	NTSTATUS status;
	const char *fname = "lease_oplock.dat";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	smb2_util_unlink(tree, fname);

	for (i = 0; i < NOPLOCK_RESULTS; i++) {
		const char *held = oplock_results[i][0];
		const char *contend = oplock_results[i][1];
		const char *brokento = oplock_results[i][2];
		const char *granted = oplock_results[i][3];
		torture_comment(tctx, "Hold %s(%x), requesting %s(%x), "
		    "expecting break to %s(%x) and grant of %s(%x)\n",
		    held, smb2_util_lease_state(held), contend, smb2_util_oplock_level(contend),
		    brokento, smb2_util_lease_state(brokento), granted, smb2_util_oplock_level(granted));

		ZERO_STRUCT(break_info);

		/* Grab lease. */
		smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state(held));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		h = io.out.file.handle;
		CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, held, true, LEASE1, 0);

		/* Does an oplock contend the lease? */
		smb2_oplock_create(&io, fname, smb2_util_oplock_level(contend));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		h2 = io.out.file.handle;
		CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level(granted));
		break_info.held_oplock_level = io.out.oplock_level;

		if (smb2_util_lease_state(held) != smb2_util_lease_state(brokento)) {
			CHECK_BREAK_INFO(held, brokento, LEASE1);
		} else {
			CHECK_NO_BREAK(tctx);
		}

		smb2_util_close(tree, h);
		smb2_util_close(tree, h2);

		status = smb2_util_unlink(tree, fname);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	for (i = 0; i < NOPLOCK_RESULTS; i++) {
		const char *held = oplock_results_2[i][0];
		const char *contend = oplock_results_2[i][1];
		const char *brokento = oplock_results_2[i][2];
		const char *granted = oplock_results_2[i][3];
		torture_comment(tctx, "Hold %s(%x), requesting %s(%x), "
		    "expecting break to %s(%x) and grant of %s(%x)\n",
		    held, smb2_util_oplock_level(held), contend, smb2_util_lease_state(contend),
		    brokento, smb2_util_oplock_level(brokento), granted, smb2_util_lease_state(granted));

		ZERO_STRUCT(break_info);

		/* Grab an oplock. */
		smb2_oplock_create(&io, fname, smb2_util_oplock_level(held));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		h = io.out.file.handle;
		CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level(held));
		break_info.held_oplock_level = io.out.oplock_level;

		/* Grab lease. */
		smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state(contend));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		h2 = io.out.file.handle;
		CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, granted, true, LEASE1, 0);

		if (smb2_util_oplock_level(held) != smb2_util_oplock_level(brokento)) {
			CHECK_OPLOCK_BREAK(brokento);
		} else {
			CHECK_NO_BREAK(tctx);
		}

		smb2_util_close(tree, h);
		smb2_util_close(tree, h2);

		status = smb2_util_unlink(tree, fname);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

 done:
	smb2_util_close(tree, h);
	smb2_util_close(tree, h2);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_multibreak(struct torture_context *tctx,
                                  struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h, h2, h3;
	struct smb2_write w;
	NTSTATUS status;
	const char *fname = "lease_multibreak.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(break_info);

	/* Grab lease, upgrade to RHW .. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state("RH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RH", true, LEASE1, 0);

	smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state("RHW"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RHW", true, LEASE1, 0);

	/* Contend with LEASE2. */
	smb2_lease_create(&io, &ls, false, fname, LEASE2, smb2_util_lease_state("RHW"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RH", true, LEASE2, 0);

	/* Verify that we were only sent one break. */
	CHECK_BREAK_INFO("RHW", "RH", LEASE1);

	/* Drop LEASE1 / LEASE2 */
	status = smb2_util_close(tree, h);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, h2);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, h3);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(break_info);

	/* Grab an R lease. */
	smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state("R"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "R", true, LEASE1, 0);

	/* Grab a level-II oplock. */
	smb2_oplock_create(&io, fname, smb2_util_oplock_level("s"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level("s"));
	break_info.held_oplock_level = io.out.oplock_level;

	/* Verify no breaks. */
	CHECK_NO_BREAK(tctx);

	/* Open for truncate, force a break. */
	smb2_generic_create(&io, NULL, false, fname,
	    NTCREATEX_DISP_OVERWRITE_IF, smb2_util_oplock_level(""), 0, 0);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io.out.file.handle;
	CHECK_CREATED(&io, TRUNCATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level(""));
	break_info.held_oplock_level = io.out.oplock_level;

	/* Sleep, use a write to clear the recv queue. */
	smb_msleep(250);
	ZERO_STRUCT(w);
	w.in.file.handle = h3;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Verify one oplock break, one lease break. */
	CHECK_OPLOCK_BREAK("");
	CHECK_BREAK_INFO("R", "", LEASE1);

 done:
	smb2_util_close(tree, h);
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h3);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_v2_request_parent(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1;
	uint64_t parent = LEASE2;
	NTSTATUS status;
	const char *fname = "lease_v2_request_parent.dat";
	bool ret = true;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}
	if (!(caps & SMB2_CAP_DIRECTORY_LEASING)) {
		torture_skip(tctx, "directory leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, &parent,
				   smb2_util_lease_state("RHW"),
				   0x11);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RHW", true, LEASE1,
		       SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET, LEASE2,
		       ls.lease_epoch + 1);

 done:
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_break_twice(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_handle h1;
	NTSTATUS status;
	const char *fname = "lease_break_twice.dat";
	bool ret = true;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(break_info);
	ZERO_STRUCT(io);

	smb2_lease_v2_create_share(
		&io, &ls1, false, fname, smb2_util_share_access("RWD"),
		LEASE1, NULL, smb2_util_lease_state("RWH"), 0x11);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RHW", true, LEASE1, 0, 0, ls1.lease_epoch + 1);

	tree->session->transport->lease.handler = torture_lease_handler;
	tree->session->transport->lease.private_data = tree;

	ZERO_STRUCT(break_info);

	smb2_lease_v2_create_share(
		&io, &ls2, false, fname, smb2_util_share_access("R"),
		LEASE2, NULL, smb2_util_lease_state("RWH"), 0x22);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RWH", "RW", LEASE1, ls1.lease_epoch + 2);

	smb2_lease_v2_create_share(
		&io, &ls2, false, fname, smb2_util_share_access("RWD"),
		LEASE2, NULL, smb2_util_lease_state("RWH"), 0x22);

	ZERO_STRUCT(break_info);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_V2(&io, "RH", true, LEASE2, 0, 0, ls2.lease_epoch + 1);
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RW", "R", LEASE1, ls1.lease_epoch + 3);

done:
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_v2_request(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1, ls2, ls2t, ls3, ls4;
	struct smb2_handle h1, h2, h3, h4, h5;
	struct smb2_write w;
	NTSTATUS status;
	const char *fname = "lease_v2_request.dat";
	const char *dname = "lease_v2_request.dir";
	const char *dnamefname = "lease_v2_request.dir\\lease.dat";
	const char *dnamefname2 = "lease_v2_request.dir\\lease2.dat";
	bool ret = true;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}
	if (!(caps & SMB2_CAP_DIRECTORY_LEASING)) {
		torture_skip(tctx, "directory leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, dname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls1, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"),
				   0x11);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RHW", true, LEASE1, 0, 0, ls1.lease_epoch + 1);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls2, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE2, NULL,
				   smb2_util_lease_state("RHW"),
				   0x22);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_DIRECTORY);
	CHECK_LEASE_V2(&io, "RH", true, LEASE2, 0, 0, ls2.lease_epoch + 1);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls3, false, dnamefname,
				   smb2_util_share_access("RWD"),
				   LEASE3, &LEASE2,
				   smb2_util_lease_state("RHW"),
				   0x33);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RHW", true, LEASE3,
		       SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET, LEASE2,
		       ls3.lease_epoch + 1);

	CHECK_NO_BREAK(tctx);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls4, false, dnamefname2,
				   smb2_util_share_access("RWD"),
				   LEASE4, NULL,
				   smb2_util_lease_state("RHW"),
				   0x44);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h4 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RHW", true, LEASE4, 0, 0, ls4.lease_epoch + 1);

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", LEASE2, ls2.lease_epoch + 2);

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls2t, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE2, NULL,
				   smb2_util_lease_state("RHW"),
				   0x222);
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h5 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_DIRECTORY);
	CHECK_LEASE_V2(&io, "RH", true, LEASE2, 0, 0, ls2.lease_epoch+3);
	smb2_util_close(tree, h5);

	ZERO_STRUCT(w);
	w.in.file.handle = h4;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * Wait 4 seconds in order to check if the write time
	 * was updated (after 2 seconds).
	 */
	smb_msleep(4000);
	CHECK_NO_BREAK(tctx);

	/*
	 * only the close on the modified file break the
	 * directory lease.
	 */
	smb2_util_close(tree, h4);

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", LEASE2, ls2.lease_epoch+4);

 done:
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h3);
	smb2_util_close(tree, h4);
	smb2_util_close(tree, h5);

	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, dname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_v2_epoch1(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h;
	const char *fname = "lease_v2_epoch1.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"),
				   0x4711);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RHW", true, LEASE1, 0, 0, ls.lease_epoch + 1);
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);

	smb2_lease_v2_create_share(&io, &ls, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"),
				   0x11);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RWH", true, LEASE1, 0, 0, ls.lease_epoch + 1);
	smb2_util_close(tree, h);

done:
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_v2_epoch2(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1v2, ls1v2t, ls1v1;
	struct smb2_handle hv2 = {}, hv1 = {};
	const char *fname = "lease_v2_epoch2.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls1v2, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("R"),
				   0x4711);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv2 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "R", true, LEASE1, 0, 0, ls1v2.lease_epoch + 1);

	ZERO_STRUCT(io);
	smb2_lease_create_share(&io, &ls1v1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv1 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RH", true, LEASE1, 0, 0, ls1v2.lease_epoch + 2);

	smb2_util_close(tree, hv2);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls1v2t, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"),
				   0x11);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv2 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RHW", true, LEASE1, 0, 0, ls1v2.lease_epoch + 3);

	smb2_util_close(tree, hv2);

	smb2_oplock_create(&io, fname, SMB2_OPLOCK_LEVEL_NONE);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv2 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RWH", "RH", LEASE1, ls1v2.lease_epoch + 4);

	smb2_util_close(tree, hv2);
	smb2_util_close(tree, hv1);

	ZERO_STRUCT(io);
	smb2_lease_create_share(&io, &ls1v1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RHW"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv1 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RHW", true, LEASE1, 0);

	smb2_util_close(tree, hv1);

done:
	smb2_util_close(tree, hv2);
	smb2_util_close(tree, hv1);
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_v2_epoch3(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1v1 = {}, ls1v1t = {},ls1v2 = {};
	struct smb2_handle hv1 = {}, hv2 = {};
	const char *fname = "lease_v2_epoch3.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(io);
	smb2_lease_create_share(&io, &ls1v1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("R"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "R", true, LEASE1, 0);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls1v2, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RW"),
				   0x4711);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv2 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RW", true, LEASE1, 0);

	smb2_util_close(tree, hv1);

	ZERO_STRUCT(io);
	smb2_lease_create_share(&io, &ls1v1t, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv1 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

	smb2_util_close(tree, hv1);

	smb2_oplock_create(&io, fname, SMB2_OPLOCK_LEVEL_NONE);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv1 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	CHECK_BREAK_INFO("RWH", "RH", LEASE1);

	smb2_util_close(tree, hv1);
	smb2_util_close(tree, hv2);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls1v2, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RWH"),
				   0x4711);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	hv2 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RHW", true, LEASE1, 0, 0, ls1v2.lease_epoch + 1);
	smb2_util_close(tree, hv2);

done:
	smb2_util_close(tree, hv2);
	smb2_util_close(tree, hv1);
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_breaking1(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_handle h1a = {};
	struct smb2_handle h1b = {};
	struct smb2_handle h2 = {};
	struct smb2_request *req2 = NULL;
	struct smb2_lease_break_ack ack = {};
	const char *fname = "lease_breaking1.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, 0);

	/*
	 * a conflicting open is blocked until we ack the
	 * lease break
	 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);
	req2 = smb2_create_send(tree, &io2);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");

	/*
	 * we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RWH", "RH", LEASE1);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		break_info.lease_break.new_lease_state;
	ZERO_STRUCT(break_info);

	/*
	 * a open using the same lease key is still works,
	 * but reports SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
	 */
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS);
	smb2_util_close(tree, h1b);

	CHECK_NO_BREAK(tctx);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	/*
	 * We ack the lease break.
	 */
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "RH", LEASE1);

	torture_assert(tctx, req2->cancel.can_cancel,
		       "req2 can_cancel");

	status = smb2_create_recv(req2, tctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	CHECK_NO_BREAK(tctx);
done:
	smb2_util_close(tree, h1a);
	smb2_util_close(tree, h1b);
	smb2_util_close(tree, h2);
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_breaking2(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_handle h1a = {};
	struct smb2_handle h1b = {};
	struct smb2_handle h2 = {};
	struct smb2_request *req2 = NULL;
	struct smb2_lease_break_ack ack = {};
	const char *fname = "lease_breaking2.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, 0);

	/*
	 * a conflicting open is blocked until we ack the
	 * lease break
	 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);
	io2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	req2 = smb2_create_send(tree, &io2);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");

	/*
	 * we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RWH", "", LEASE1);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ZERO_STRUCT(break_info);

	/*
	 * a open using the same lease key is still works,
	 * but reports SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
	 */
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS);
	smb2_util_close(tree, h1b);

	CHECK_NO_BREAK(tctx);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	/*
	 * We ack the lease break.
	 */
	ack.in.lease.lease_state =
		SMB2_LEASE_READ | SMB2_LEASE_WRITE | SMB2_LEASE_HANDLE;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_REQUEST_NOT_ACCEPTED);

	ack.in.lease.lease_state =
		SMB2_LEASE_READ | SMB2_LEASE_WRITE;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_REQUEST_NOT_ACCEPTED);

	ack.in.lease.lease_state =
		SMB2_LEASE_WRITE | SMB2_LEASE_HANDLE;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_REQUEST_NOT_ACCEPTED);

	ack.in.lease.lease_state =
		SMB2_LEASE_READ | SMB2_LEASE_HANDLE;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_REQUEST_NOT_ACCEPTED);

	ack.in.lease.lease_state = SMB2_LEASE_WRITE;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_REQUEST_NOT_ACCEPTED);

	ack.in.lease.lease_state = SMB2_LEASE_HANDLE;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_REQUEST_NOT_ACCEPTED);

	ack.in.lease.lease_state = SMB2_LEASE_READ;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_REQUEST_NOT_ACCEPTED);

	/* Try again with the correct state this time. */
	ack.in.lease.lease_state = SMB2_LEASE_NONE;;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "", LEASE1);

	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_UNSUCCESSFUL);

	torture_assert(tctx, req2->cancel.can_cancel,
		       "req2 can_cancel");

	status = smb2_create_recv(req2, tctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, TRUNCATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	CHECK_NO_BREAK(tctx);

	/* Get state of the original handle. */
	smb2_lease_create(&io1, &ls1, false, fname, LEASE1, smb2_util_lease_state(""));
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE(&io1, "", true, LEASE1, 0);
	smb2_util_close(tree, io1.out.file.handle);

done:
	smb2_util_close(tree, h1a);
	smb2_util_close(tree, h1b);
	smb2_util_close(tree, h2);
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_breaking3(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_create io3 = {};
	struct smb2_lease ls1 = {};
	struct smb2_handle h1a = {};
	struct smb2_handle h1b = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_request *req2 = NULL;
	struct smb2_request *req3 = NULL;
	struct torture_lease_break break_info_tmp = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname = "lease_breaking3.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, 0);

	/*
	 * a conflicting open is blocked until we ack the
	 * lease break
	 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);
	req2 = smb2_create_send(tree, &io2);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");

	/*
	 * we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RWH", "RH", LEASE1);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	/*
	 * a open using the same lease key is still works,
	 * but reports SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
	 */
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS);
	smb2_util_close(tree, h1b);

	/*
	 * a conflicting open with NTCREATEX_DISP_OVERWRITE
	 * doesn't trigger an immediate lease break to none.
	 */
	break_info_tmp = break_info;
	ZERO_STRUCT(break_info);
	smb2_oplock_create(&io3, fname, SMB2_OPLOCK_LEVEL_NONE);
	io3.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	req3 = smb2_create_send(tree, &io3);
	torture_assert(tctx, req3 != NULL, "smb2_create_send");
	CHECK_NO_BREAK(tctx);
	break_info = break_info_tmp;

	torture_assert(tctx, req3->state == SMB2_REQUEST_RECV, "req3 pending");

	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		break_info.lease_break.new_lease_state;
	ZERO_STRUCT(break_info);

	/*
	 * a open using the same lease key is still works,
	 * but reports SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
	 */
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS);
	smb2_util_close(tree, h1b);

	CHECK_NO_BREAK(tctx);

	/*
	 * We ack the lease break, but defer acking the next break (to "R")
	 */
	break_info.lease_skip_ack = true;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "RH", LEASE1);

	/*
	 * We got an additional break downgrading to just "R"
	 * while we defer the ack.
	 */
	CHECK_BREAK_INFO("RH", "R", LEASE1);

	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		break_info.lease_break.new_lease_state;
	ZERO_STRUCT(break_info);

	/*
	 * a open using the same lease key is still works,
	 * but reports SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
	 */
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RH", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS);
	smb2_util_close(tree, h1b);

	CHECK_NO_BREAK(tctx);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");
	torture_assert(tctx, req3->state == SMB2_REQUEST_RECV, "req3 pending");

	/*
	 * We ack the downgrade to "R" and get an immediate break to none
	 */
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "R", LEASE1);

	/*
	 * We get the downgrade to none.
	 */
	CHECK_BREAK_INFO("R", "", LEASE1);

	torture_assert(tctx, req2->cancel.can_cancel,
		       "req2 can_cancel");
	torture_assert(tctx, req3->cancel.can_cancel,
		       "req3 can_cancel");

	ZERO_STRUCT(break_info);

	status = smb2_create_recv(req2, tctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	status = smb2_create_recv(req3, tctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io3.out.file.handle;
	CHECK_CREATED(&io3, TRUNCATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io3.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	CHECK_NO_BREAK(tctx);
done:
	smb2_util_close(tree, h1a);
	smb2_util_close(tree, h1b);
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h3);

	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_v2_breaking3(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_create io3 = {};
	struct smb2_lease ls1 = {};
	struct smb2_handle h1a = {};
	struct smb2_handle h1b = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_request *req2 = NULL;
	struct smb2_request *req3 = NULL;
	struct torture_lease_break break_info_tmp = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname = "v2_lease_breaking3.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	smb2_lease_v2_create_share(&io1, &ls1, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"),
				   0x11);
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	/* Epoch increases on open. */
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io1, "RHW", true, LEASE1, 0, 0, ls1.lease_epoch);

	/*
	 * a conflicting open is blocked until we ack the
	 * lease break
	 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);
	req2 = smb2_create_send(tree, &io2);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");

	/*
	 * we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RWH", "RH", LEASE1, ls1.lease_epoch + 1);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	/* On receiving a lease break, we must sync the new epoch. */
	ls1.lease_epoch = break_info.lease_break.new_epoch;

	/*
	 * a open using the same lease key is still works,
	 * but reports SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
	 */
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io1, "RHW", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS, 0, ls1.lease_epoch);
	smb2_util_close(tree, h1b);

	/*
	 * a conflicting open with NTCREATEX_DISP_OVERWRITE
	 * doesn't trigger an immediate lease break to none.
	 */
	break_info_tmp = break_info;
	ZERO_STRUCT(break_info);
	smb2_oplock_create(&io3, fname, SMB2_OPLOCK_LEVEL_NONE);
	io3.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	req3 = smb2_create_send(tree, &io3);
	torture_assert(tctx, req3 != NULL, "smb2_create_send");
	CHECK_NO_BREAK(tctx);
	break_info = break_info_tmp;

	torture_assert(tctx, req3->state == SMB2_REQUEST_RECV, "req3 pending");

	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		break_info.lease_break.new_lease_state;
	ZERO_STRUCT(break_info);

	/*
	 * a open using the same lease key is still works,
	 * but reports SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
	 */
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io1, "RHW", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS, 0, ls1.lease_epoch);
	smb2_util_close(tree, h1b);

	CHECK_NO_BREAK(tctx);

	/*
	 * We ack the lease break, but defer acking the next break (to "R")
	 */
	break_info.lease_skip_ack = true;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "RH", LEASE1);

	/*
	 * We got an additional break downgrading to just "R"
	 * while we defer the ack.
	 */
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "R", LEASE1, ls1.lease_epoch);
	/* On receiving a lease break, we must sync the new epoch. */
	ls1.lease_epoch = break_info.lease_break.new_epoch;

	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		break_info.lease_break.new_lease_state;
	ZERO_STRUCT(break_info);

	/*
	 * a open using the same lease key is still works,
	 * but reports SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
	 */
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io1, "RH", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS, 0, ls1.lease_epoch);
	smb2_util_close(tree, h1b);

	CHECK_NO_BREAK(tctx);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");
	torture_assert(tctx, req3->state == SMB2_REQUEST_RECV, "req3 pending");

	/*
	 * We ack the downgrade to "R" and get an immediate break to none
	 */
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "R", LEASE1);

	/*
	 * We get the downgrade to none.
	 */
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "R", "", LEASE1, ls1.lease_epoch);

	torture_assert(tctx, req2->cancel.can_cancel,
		       "req2 can_cancel");
	torture_assert(tctx, req3->cancel.can_cancel,
		       "req3 can_cancel");

	ZERO_STRUCT(break_info);

	status = smb2_create_recv(req2, tctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	status = smb2_create_recv(req3, tctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io3.out.file.handle;
	CHECK_CREATED(&io3, TRUNCATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io3.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	CHECK_NO_BREAK(tctx);
done:
	smb2_util_close(tree, h1a);
	smb2_util_close(tree, h1b);
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h3);

	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}


static bool test_lease_breaking4(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_create io3 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls1t = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_request *req2 = NULL;
	struct torture_lease_break break_info_tmp = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname = "lease_breaking4.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RH"));
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RH", true, LEASE1, 0);

	CHECK_NO_BREAK(tctx);

	/*
	 * a conflicting open is *not* blocked until we ack the
	 * lease break
	 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);
	io2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	req2 = smb2_create_send(tree, &io2);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");

	/*
	 * We got a break from RH to NONE, we're supported to ack
	 * this downgrade
	 */
	CHECK_BREAK_INFO("RH", "", LEASE1);

	break_info_tmp = break_info;
	ZERO_STRUCT(break_info);
	CHECK_NO_BREAK(tctx);

	torture_assert(tctx, req2->state == SMB2_REQUEST_DONE, "req2 done");

	status = smb2_create_recv(req2, tctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, TRUNCATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);
	smb2_util_close(tree, h2);

	CHECK_NO_BREAK(tctx);

	/*
	 * a conflicting open is *not* blocked until we ack the
	 * lease break, even if the lease is in breaking state.
	 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);
	io2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	req2 = smb2_create_send(tree, &io2);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");

	CHECK_NO_BREAK(tctx);

	torture_assert(tctx, req2->state == SMB2_REQUEST_DONE, "req2 done");

	status = smb2_create_recv(req2, tctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, TRUNCATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);
	smb2_util_close(tree, h2);

	CHECK_NO_BREAK(tctx);

	/*
	 * We now ask the server about the current lease state
	 * which should still be "RH", but with
	 * SMB2_LEASE_FLAG_BREAK_IN_PROGRESS.
	 */
	smb2_lease_create_share(&io3, &ls1t, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state(""));
	status = smb2_create(tree, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io3.out.file.handle;
	CHECK_CREATED(&io3, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io3, "RH", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS);

	/*
	 * We finally ack the lease break...
	 */
	CHECK_NO_BREAK(tctx);
	break_info = break_info_tmp;
	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		break_info.lease_break.new_lease_state;
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "", LEASE1);

	CHECK_NO_BREAK(tctx);

done:
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h3);

	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_breaking5(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_create io3 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls1t = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_request *req2 = NULL;
	struct torture_lease_break break_info_tmp = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname = "lease_breaking5.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("R"));
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "R", true, LEASE1, 0);

	CHECK_NO_BREAK(tctx);

	/*
	 * a conflicting open is *not* blocked until we ack the
	 * lease break
	 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);
	io2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	req2 = smb2_create_send(tree, &io2);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");

	/*
	 * We got a break from RH to NONE, we're supported to ack
	 * this downgrade
	 */
	CHECK_BREAK_INFO("R", "", LEASE1);

	break_info_tmp = break_info;
	ZERO_STRUCT(break_info);
	CHECK_NO_BREAK(tctx);

	torture_assert(tctx, req2->state == SMB2_REQUEST_DONE, "req2 done");

	status = smb2_create_recv(req2, tctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, TRUNCATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	CHECK_NO_BREAK(tctx);

	/*
	 * We now ask the server about the current lease state
	 * which should still be "RH", but with
	 * SMB2_LEASE_FLAG_BREAK_IN_PROGRESS.
	 */
	smb2_lease_create_share(&io3, &ls1t, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state(""));
	status = smb2_create(tree, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io3.out.file.handle;
	CHECK_CREATED(&io3, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io3, "", true, LEASE1, 0);

	/*
	 * We send an ack without without being asked.
	 */
	CHECK_NO_BREAK(tctx);
	break_info = break_info_tmp;
	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		break_info.lease_break.new_lease_state;
	ZERO_STRUCT(break_info);
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_UNSUCCESSFUL);

	CHECK_NO_BREAK(tctx);

done:
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h3);

	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_breaking6(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_handle h1a = {};
	struct smb2_handle h1b = {};
	struct smb2_handle h2 = {};
	struct smb2_request *req2 = NULL;
	struct smb2_lease_break_ack ack = {};
	const char *fname = "lease_breaking6.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1a = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, 0);

	/*
	 * a conflicting open is blocked until we ack the
	 * lease break
	 */
	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);
	req2 = smb2_create_send(tree, &io2);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");

	/*
	 * we got the lease break, but defer the ack.
	 */
	CHECK_BREAK_INFO("RWH", "RH", LEASE1);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ZERO_STRUCT(break_info);

	/*
	 * a open using the same lease key is still works,
	 * but reports SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
	 */
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1b = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, SMB2_LEASE_FLAG_BREAK_IN_PROGRESS);
	smb2_util_close(tree, h1b);

	CHECK_NO_BREAK(tctx);

	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	/*
	 * We are asked to break to "RH", but we are allowed to
	 * break to any of "RH", "R" or NONE.
	 */
	ack.in.lease.lease_state = SMB2_LEASE_NONE;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "", LEASE1);

	torture_assert(tctx, req2->cancel.can_cancel,
		       "req2 can_cancel");

	status = smb2_create_recv(req2, tctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_NONE);

	CHECK_NO_BREAK(tctx);
done:
	smb2_util_close(tree, h1a);
	smb2_util_close(tree, h1b);
	smb2_util_close(tree, h2);
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_lock1(struct torture_context *tctx,
			     struct smb2_tree *tree1a,
			     struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_create io3 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls2 = {};
	struct smb2_lease ls3 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_lock lck;
	struct smb2_lock_element el[1];
	const char *fname = "locktest.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	struct smbcli_options options1;
	struct smb2_tree *tree1b = NULL;

	options1 = tree1a->session->transport->options;

	caps = smb2cli_conn_server_capabilities(tree1a->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	/* Set up handlers. */
	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;
	tree2->session->transport->oplock.handler = torture_oplock_handler;
	tree2->session->transport->oplock.private_data = tree2;

	tree1a->session->transport->lease.handler = torture_lease_handler;
	tree1a->session->transport->lease.private_data = tree1a;
	tree1a->session->transport->oplock.handler = torture_oplock_handler;
	tree1a->session->transport->oplock.private_data = tree1a;

	/* create a new connection (same client_guid) */
	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1b)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	tree1b->session->transport->lease.handler = torture_lease_handler;
	tree1b->session->transport->lease.private_data = tree1b;
	tree1b->session->transport->oplock.handler = torture_oplock_handler;
	tree1b->session->transport->oplock.private_data = tree1b;

	smb2_util_unlink(tree1a, fname);

	ZERO_STRUCT(break_info);
	ZERO_STRUCT(lck);

	/* Open a handle on tree1a. */
	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree1a, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, 0);

	/* Open a second handle on tree1b. */
	smb2_lease_create_share(&io2, &ls2, false, fname,
				smb2_util_share_access("RWD"),
				LEASE2,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree1b, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "RH", true, LEASE2, 0);
	/* And LEASE1 got broken to RH. */
	CHECK_BREAK_INFO("RWH", "RH", LEASE1);
	ZERO_STRUCT(break_info);

	/* Now open a lease on a different client guid. */
	smb2_lease_create_share(&io3, &ls3, false, fname,
				smb2_util_share_access("RWD"),
				LEASE3,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree2, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io3.out.file.handle;
	CHECK_CREATED(&io3, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io3, "RH", true, LEASE3, 0);
	/* Doesn't break. */
	CHECK_NO_BREAK(tctx);

	lck.in.locks		= el;
	/*
	 * Try and get get an exclusive byte
	 * range lock on H1 (LEASE1).
	 */

	lck.in.lock_count	= 1;
	lck.in.lock_sequence	= 1;
	lck.in.file.handle	= h1;
	el[0].offset		= 0;
	el[0].length		= 1;
	el[0].reserved		= 0;
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE;
	status = smb2_lock(tree1a, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* LEASE2 and LEASE3 should get broken to NONE. */
	torture_wait_for_lease_break(tctx);
	torture_wait_for_lease_break(tctx);
	torture_wait_for_lease_break(tctx);
	torture_wait_for_lease_break(tctx);

	CHECK_VAL(break_info.failures, 0);                      \
	CHECK_VAL(break_info.count, 2);                         \

	/* Get state of the H1 (LEASE1) */
	smb2_lease_create(&io1, &ls1, false, fname, LEASE1, smb2_util_lease_state(""));
	status = smb2_create(tree1a, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	/* Should still be RH. */
	CHECK_LEASE(&io1, "RH", true, LEASE1, 0);
	smb2_util_close(tree1a, io1.out.file.handle);

	/* Get state of the H2 (LEASE2) */
	smb2_lease_create(&io2, &ls2, false, fname, LEASE2, smb2_util_lease_state(""));
	status = smb2_create(tree1b, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE(&io2, "", true, LEASE2, 0);
	smb2_util_close(tree1b, io2.out.file.handle);

	/* Get state of the H3 (LEASE3) */
	smb2_lease_create(&io3, &ls3, false, fname, LEASE3, smb2_util_lease_state(""));
	status = smb2_create(tree2, mem_ctx, &io3);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE(&io3, "", true, LEASE3, 0);
	smb2_util_close(tree2, io3.out.file.handle);

	ZERO_STRUCT(break_info);

	/*
	 * Try and get get an exclusive byte
	 * range lock on H3 (LEASE3).
	 */
	lck.in.lock_count	= 1;
	lck.in.lock_sequence	= 2;
	lck.in.file.handle	= h3;
	el[0].offset		= 100;
	el[0].length		= 1;
	el[0].reserved		= 0;
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE;
	status = smb2_lock(tree2, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);
	/* LEASE1 got broken to NONE. */
	CHECK_BREAK_INFO("RH", "", LEASE1);
	ZERO_STRUCT(break_info);

done:
	smb2_util_close(tree1a, h1);
	smb2_util_close(tree1b, h2);
	smb2_util_close(tree2, h3);

	smb2_util_unlink(tree1a, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_complex1(struct torture_context *tctx,
				struct smb2_tree *tree1a)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1;
	struct smb2_create io2;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_handle h, h2, h3;
	struct smb2_write w;
	NTSTATUS status;
	const char *fname = "lease_complex1.dat";
	bool ret = true;
	uint32_t caps;
	struct smb2_tree *tree1b = NULL;
	struct smbcli_options options1;

	options1 = tree1a->session->transport->options;

	caps = smb2cli_conn_server_capabilities(tree1a->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	tree1a->session->transport->lease.handler = torture_lease_handler;
	tree1a->session->transport->lease.private_data = tree1a;
	tree1a->session->transport->oplock.handler = torture_oplock_handler;
	tree1a->session->transport->oplock.private_data = tree1a;

	/* create a new connection (same client_guid) */
	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1b)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	tree1b->session->transport->lease.handler = torture_lease_handler;
	tree1b->session->transport->lease.private_data = tree1b;
	tree1b->session->transport->oplock.handler = torture_oplock_handler;
	tree1b->session->transport->oplock.private_data = tree1b;

	smb2_util_unlink(tree1a, fname);

	ZERO_STRUCT(break_info);

	/* Grab R lease over connection 1a */
	smb2_lease_create(&io1, &ls1, false, fname, LEASE1, smb2_util_lease_state("R"));
	status = smb2_create(tree1a, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "R", true, LEASE1, 0);

	/* Upgrade to RWH over connection 1b */
	ls1.lease_state = smb2_util_lease_state("RWH");
	status = smb2_create(tree1b, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RHW", true, LEASE1, 0);

	/* close over connection 1b */
	status = smb2_util_close(tree1b, h2);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Contend with LEASE2. */
	smb2_lease_create(&io2, &ls2, false, fname, LEASE2, smb2_util_lease_state("R"));
	status = smb2_create(tree1b, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "R", true, LEASE2, 0);

	/* Verify that we were only sent one break. */
	CHECK_BREAK_INFO("RHW", "RH", LEASE1);

	/* again RH over connection 1b doesn't change the epoch */
	ls1.lease_state = smb2_util_lease_state("RH");
	status = smb2_create(tree1b, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RH", true, LEASE1, 0);

	/* close over connection 1b */
	status = smb2_util_close(tree1b, h2);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(w);
	w.in.file.handle = h;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree1a, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls2.lease_epoch += 1;
	CHECK_BREAK_INFO("R", "", LEASE2);

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(w);
	w.in.file.handle = h3;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree1b, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls1.lease_epoch += 1;
	CHECK_BREAK_INFO("RH", "", LEASE1);

 done:
	smb2_util_close(tree1a, h);
	smb2_util_close(tree1b, h2);
	smb2_util_close(tree1b, h3);

	smb2_util_unlink(tree1a, fname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_v2_complex1(struct torture_context *tctx,
				   struct smb2_tree *tree1a)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1;
	struct smb2_create io2;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_handle h, h2, h3;
	struct smb2_write w;
	NTSTATUS status;
	const char *fname = "lease_v2_complex1.dat";
	bool ret = true;
	uint32_t caps;
	enum protocol_types protocol;
	struct smb2_tree *tree1b = NULL;
	struct smbcli_options options1;

	options1 = tree1a->session->transport->options;

	caps = smb2cli_conn_server_capabilities(tree1a->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree1a->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	tree1a->session->transport->lease.handler = torture_lease_handler;
	tree1a->session->transport->lease.private_data = tree1a;
	tree1a->session->transport->oplock.handler = torture_oplock_handler;
	tree1a->session->transport->oplock.private_data = tree1a;

	/* create a new connection (same client_guid) */
	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1b)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	tree1b->session->transport->lease.handler = torture_lease_handler;
	tree1b->session->transport->lease.private_data = tree1b;
	tree1b->session->transport->oplock.handler = torture_oplock_handler;
	tree1b->session->transport->oplock.private_data = tree1b;

	smb2_util_unlink(tree1a, fname);

	ZERO_STRUCT(break_info);

	/* Grab R lease over connection 1a */
	smb2_lease_v2_create(&io1, &ls1, false, fname, LEASE1, NULL,
			     smb2_util_lease_state("R"), 0x4711);
	status = smb2_create(tree1a, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io1, "R", true, LEASE1,
		       0, 0, ls1.lease_epoch);

	/* Upgrade to RWH over connection 1b */
	ls1.lease_state = smb2_util_lease_state("RWH");
	status = smb2_create(tree1b, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io1, "RHW", true, LEASE1,
		       0, 0, ls1.lease_epoch);

	/* close over connection 1b */
	status = smb2_util_close(tree1b, h2);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Contend with LEASE2. */
	smb2_lease_v2_create(&io2, &ls2, false, fname, LEASE2, NULL,
			     smb2_util_lease_state("R"), 0x11);
	status = smb2_create(tree1b, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io2, "R", true, LEASE2,
		       0, 0, ls2.lease_epoch);

	/* Verify that we were only sent one break. */
	ls1.lease_epoch += 1;
	CHECK_BREAK_INFO_V2(tree1a->session->transport,
			    "RHW", "RH", LEASE1, ls1.lease_epoch);

	/* again RH over connection 1b doesn't change the epoch */
	ls1.lease_state = smb2_util_lease_state("RH");
	status = smb2_create(tree1b, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io1.out.file.handle;
	CHECK_CREATED(&io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io1, "RH", true, LEASE1,
		       0, 0, ls1.lease_epoch);

	/* close over connection 1b */
	status = smb2_util_close(tree1b, h2);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(w);
	w.in.file.handle = h;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree1a, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls2.lease_epoch += 1;
	CHECK_BREAK_INFO_V2(tree1a->session->transport,
			    "R", "", LEASE2, ls2.lease_epoch);

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(w);
	w.in.file.handle = h3;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree1b, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls1.lease_epoch += 1;
	CHECK_BREAK_INFO_V2(tree1a->session->transport,
			    "RH", "", LEASE1, ls1.lease_epoch);

 done:
	smb2_util_close(tree1a, h);
	smb2_util_close(tree1b, h2);
	smb2_util_close(tree1b, h3);

	smb2_util_unlink(tree1a, fname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_v2_complex2(struct torture_context *tctx,
				   struct smb2_tree *tree1a)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1;
	struct smb2_create io2;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_handle h, h2;
	struct smb2_request *req2 = NULL;
	struct smb2_lease_break_ack ack = {};
	NTSTATUS status;
	const char *fname = "lease_v2_complex2.dat";
	bool ret = true;
	uint32_t caps;
	enum protocol_types protocol;
	struct smb2_tree *tree1b = NULL;
	struct smbcli_options options1;

	options1 = tree1a->session->transport->options;

	caps = smb2cli_conn_server_capabilities(tree1a->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree1a->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	tree1a->session->transport->lease.handler = torture_lease_handler;
	tree1a->session->transport->lease.private_data = tree1a;
	tree1a->session->transport->oplock.handler = torture_oplock_handler;
	tree1a->session->transport->oplock.private_data = tree1a;

	/* create a new connection (same client_guid) */
	if (!torture_smb2_connection_ext(tctx, 0, &options1, &tree1b)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	tree1b->session->transport->lease.handler = torture_lease_handler;
	tree1b->session->transport->lease.private_data = tree1b;
	tree1b->session->transport->oplock.handler = torture_oplock_handler;
	tree1b->session->transport->oplock.private_data = tree1b;

	smb2_util_unlink(tree1a, fname);

	ZERO_STRUCT(break_info);

	/* Grab RWH lease over connection 1a */
	smb2_lease_v2_create(&io1, &ls1, false, fname, LEASE1, NULL,
			     smb2_util_lease_state("RWH"), 0x4711);
	status = smb2_create(tree1a, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io1, "RWH", true, LEASE1,
		       0, 0, ls1.lease_epoch);

	/*
	 * we defer acking the lease break.
	 */
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	/* Ask for RWH on connection 1b, different lease. */
	smb2_lease_v2_create(&io2, &ls2, false, fname, LEASE2, NULL,
			     smb2_util_lease_state("RWH"), 0x11);
	req2 = smb2_create_send(tree1b, &io2);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");

	ls1.lease_epoch += 1;

	CHECK_BREAK_INFO_V2(tree1a->session->transport,
			    "RWH", "RH", LEASE1, ls1.lease_epoch);

	/* Send the break ACK on tree1b. */
	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state = SMB2_LEASE_HANDLE|SMB2_LEASE_READ;

	status = smb2_lease_break_ack(tree1b, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "RH", LEASE1);

	ZERO_STRUCT(break_info);

	status = smb2_create_recv(req2, tctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io2, "RH", true, LEASE2,
		       0, 0, ls2.lease_epoch+1);
	h2 = io2.out.file.handle;

 done:
	smb2_util_close(tree1a, h);
	smb2_util_close(tree1b, h2);

	smb2_util_unlink(tree1a, fname);

	talloc_free(mem_ctx);

	return ret;
}


static bool test_lease_timeout(struct torture_context *tctx,
                               struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_handle h, hnew, h1b;
	NTSTATUS status;
	const char *fname = "lease_timeout.dat";
	bool ret = true;
	struct smb2_lease_break_ack ack = {};
	struct smb2_request *req2 = NULL;
	struct smb2_write w;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	/* Grab a RWH lease. */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);
	h = io.out.file.handle;

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * Just don't ack the lease break.
	 */
	ZERO_STRUCT(break_info);
	break_info.lease_skip_ack = true;

	/* Break with a RWH request. */
	smb2_lease_create(&io, &ls2, false, fname, LEASE2, smb2_util_lease_state("RWH"));
	req2 = smb2_create_send(tree, &io);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");
	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	CHECK_BREAK_INFO("RWH", "RH", LEASE1);

	/* Copy the break request. */
	ack.in.lease.lease_key =
		break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		break_info.lease_break.new_lease_state;

	/* Now wait for the timeout and get the reply. */
	status = smb2_create_recv(req2, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RH", true, LEASE2, 0);
	hnew = io.out.file.handle;

	/* Ack the break after the timeout... */
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_UNSUCCESSFUL);

	/* Get state of the original handle. */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state(""));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE(&io, "", true, LEASE1, 0);
	smb2_util_close(tree, io.out.file.handle);

	/* Write on the original handle and make sure it's still valid. */
	ZERO_STRUCT(break_info);
	ZERO_STRUCT(w);
	w.in.file.handle = h;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, '1', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Causes new handle to break to NONE. */
	CHECK_BREAK_INFO("RH", "", LEASE2);

	/* Write on the new handle. */
	ZERO_STRUCT(break_info);
	ZERO_STRUCT(w);
	w.in.file.handle = hnew;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 1024);
	memset(w.in.data.data, '2', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);
	/* No break - original handle was already NONE. */
	CHECK_NO_BREAK(tctx);
	smb2_util_close(tree, hnew);

	/* Upgrade to R on LEASE1. */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("R"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE(&io, "R", true, LEASE1, 0);
	h1b = io.out.file.handle;
	smb2_util_close(tree, h1b);

	/* Upgrade to RWH on LEASE1. */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);
	h1b = io.out.file.handle;
	smb2_util_close(tree, h1b);

 done:
	smb2_util_close(tree, h);
	smb2_util_close(tree, hnew);
	smb2_util_close(tree, h1b);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_v2_rename(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_handle h, h1, h2;
	union smb_setfileinfo sinfo;
	const char *fname = "lease_v2_rename_src.dat";
	const char *fname_dst = "lease_v2_rename_dst.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);
	smb2_util_unlink(tree, fname_dst);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	ZERO_STRUCT(break_info);

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls1, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"),
				   0x4711);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RHW", true, LEASE1, 0, 0, ls1.lease_epoch);

	/* Now rename - what happens ? */
        ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h;
	sinfo.rename_information.in.overwrite = true;
	sinfo.rename_information.in.new_name = fname_dst;
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* No lease break. */
	CHECK_NO_BREAK(tctx);

	/* Check we can open another handle on the new name. */
	smb2_lease_v2_create_share(&io, &ls1, false, fname_dst,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state(""),
				   ls1.lease_epoch);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RHW", true, LEASE1, 0, 0, ls1.lease_epoch);
	smb2_util_close(tree, h1);

	/* Try another lease key. */
	smb2_lease_v2_create_share(&io, &ls2, false, fname_dst,
				   smb2_util_share_access("RWD"),
				   LEASE2, NULL,
				   smb2_util_lease_state("RWH"),
				   0x44);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io, "RH", true, LEASE2, 0, 0, ls2.lease_epoch );
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RWH", "RH", LEASE1, ls1.lease_epoch + 1);
	ls1.lease_epoch += 1;
	ZERO_STRUCT(break_info);

	/* Now rename back. */
	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h;
	sinfo.rename_information.in.overwrite = true;
	sinfo.rename_information.in.new_name = fname;
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Breaks to R on LEASE2. */
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "R", LEASE2, ls2.lease_epoch + 1);
	ls2.lease_epoch += 1;

	/* Check we can open another handle on the current name. */
	smb2_lease_v2_create_share(&io, &ls1, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state(""),
				   ls1.lease_epoch);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&io, "RH", true, LEASE1, 0, 0, ls1.lease_epoch);
	smb2_util_close(tree, h1);

done:

	smb2_util_close(tree, h);
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);

	smb2_util_unlink(tree, fname);
	smb2_util_unlink(tree, fname_dst);

	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}


static bool test_lease_dynamic_share(struct torture_context *tctx,
				   struct smb2_tree *tree1a)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1;
	struct smb2_handle h, h1, h2;
	struct smb2_write w;
	NTSTATUS status;
	const char *fname = "dynamic_path.dat";
	bool ret = true;
	uint32_t caps;
	struct smb2_tree *tree_2_1 = NULL;
	struct smb2_tree *tree_3_0 = NULL;
	struct smbcli_options options2_1;
	struct smbcli_options options3_0;
	const char *orig_share = NULL;

	if (!TARGET_IS_SAMBA3(tctx)) {
		torture_skip(tctx, "dynamic shares are not supported");
		return true;
	}

	options2_1 = tree1a->session->transport->options;
	options3_0 = tree1a->session->transport->options;

	caps = smb2cli_conn_server_capabilities(tree1a->session->transport->conn);
	if (!(caps & SMB2_CAP_LEASING)) {
		torture_skip(tctx, "leases are not supported");
	}

	/*
	 * Save off original share name and change it to dynamic_share.
	 * This must have been pre-created with a dynamic path containing
	 * %R.
	 */

	orig_share = lpcfg_parm_string(tctx->lp_ctx, NULL, "torture", "share");
	orig_share = talloc_strdup(tctx->lp_ctx, orig_share);
	if (orig_share == NULL) {
		torture_result(tctx, TORTURE_FAIL, __location__ "no memory\n");
                ret = false;
                goto done;
	}
	lpcfg_set_cmdline(tctx->lp_ctx, "torture:share", "dynamic_share");

	/* Set max protocol to SMB2.1 */
	options2_1.max_protocol = PROTOCOL_SMB2_10;
	/* create a new connection (same client_guid) */
	if (!torture_smb2_connection_ext(tctx, 0, &options2_1, &tree_2_1)) {
		torture_warning(tctx, "couldn't reconnect max protocol 2.1, bailing\n");
		ret = false;
		goto done;
	}

	tree_2_1->session->transport->lease.handler = torture_lease_handler;
	tree_2_1->session->transport->lease.private_data = tree_2_1;
	tree_2_1->session->transport->oplock.handler = torture_oplock_handler;
	tree_2_1->session->transport->oplock.private_data = tree_2_1;

	smb2_util_unlink(tree_2_1, fname);

	/* Set max protocol to SMB3.0 */
	options3_0.max_protocol = PROTOCOL_SMB3_00;
	/* create a new connection (same client_guid) */
	if (!torture_smb2_connection_ext(tctx, 0, &options3_0, &tree_3_0)) {
		torture_warning(tctx, "couldn't reconnect max protocol 3.0, bailing\n");
		ret = false;
		goto done;
	}

	tree_3_0->session->transport->lease.handler = torture_lease_handler;
	tree_3_0->session->transport->lease.private_data = tree_3_0;
	tree_3_0->session->transport->oplock.handler = torture_oplock_handler;
	tree_3_0->session->transport->oplock.private_data = tree_3_0;

	smb2_util_unlink(tree_3_0, fname);

	ZERO_STRUCT(break_info);

	/* Get RWH lease over connection 2_1 */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_2_1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);
	h = io.out.file.handle;

	/* Write some data into it. */
	w.in.file.handle = h;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, '1', w.in.data.length);
	status = smb2_write(tree_2_1, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Open the same name over connection 3_0. */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_3_0, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	/* h1 should have replied with NONE. */
	CHECK_LEASE(&io, "", true, LEASE1, 0);

	/* We should have broken h to NONE. */
	CHECK_BREAK_INFO("RWH", "", LEASE1);

	/* Try to upgrade to RWH over connection 2_1 */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_2_1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.size, 4096);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	/* Should have been denied. */
	CHECK_LEASE(&io, "", true, LEASE1, 0);
	smb2_util_close(tree_2_1, h2);

	/* Try to upgrade to RWH over connection 3_0 */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_3_0, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.size, 0);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	/* Should have been denied. */
	CHECK_LEASE(&io, "", true, LEASE1, 0);
	smb2_util_close(tree_3_0, h2);

	/* Write some data into it. */
	w.in.file.handle = h1;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 1024);
	memset(w.in.data.data, '2', w.in.data.length);
	status = smb2_write(tree_3_0, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Close everything.. */
	smb2_util_close(tree_2_1, h);
	smb2_util_close(tree_3_0, h1);

	/* And ensure we can get a lease ! */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_2_1, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);
	h = io.out.file.handle;
	/* And the file is the right size. */
	CHECK_VAL(io.out.size, 4096);				\
	/* Close it. */
	smb2_util_close(tree_2_1, h);

	/* And ensure we can get a lease ! */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_3_0, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);
	h = io.out.file.handle;
	/* And the file is the right size. */
	CHECK_VAL(io.out.size, 1024);				\
	/* Close it. */
	smb2_util_close(tree_3_0, h);

 done:

	smb2_util_close(tree_2_1, h);
	smb2_util_close(tree_3_0, h1);
	smb2_util_close(tree_3_0, h2);

	smb2_util_unlink(tree_2_1, fname);
	smb2_util_unlink(tree_3_0, fname);

	/* Set sharename back. */
	lpcfg_set_cmdline(tctx->lp_ctx, "torture:share", orig_share);

	talloc_free(mem_ctx);

	return ret;
}

struct torture_suite *torture_smb2_lease_init(void)
{
	struct torture_suite *suite =
	    torture_suite_create(talloc_autofree_context(), "lease");

	torture_suite_add_1smb2_test(suite, "request", test_lease_request);
	torture_suite_add_1smb2_test(suite, "break_twice",
				     test_lease_break_twice);
	torture_suite_add_1smb2_test(suite, "nobreakself",
				     test_lease_nobreakself);
	torture_suite_add_1smb2_test(suite, "statopen", test_lease_statopen);
	torture_suite_add_1smb2_test(suite, "upgrade", test_lease_upgrade);
	torture_suite_add_1smb2_test(suite, "upgrade2", test_lease_upgrade2);
	torture_suite_add_1smb2_test(suite, "upgrade3", test_lease_upgrade3);
	torture_suite_add_1smb2_test(suite, "break", test_lease_break);
	torture_suite_add_1smb2_test(suite, "oplock", test_lease_oplock);
	torture_suite_add_1smb2_test(suite, "multibreak", test_lease_multibreak);
	torture_suite_add_1smb2_test(suite, "breaking1", test_lease_breaking1);
	torture_suite_add_1smb2_test(suite, "breaking2", test_lease_breaking2);
	torture_suite_add_1smb2_test(suite, "breaking3", test_lease_breaking3);
	torture_suite_add_1smb2_test(suite, "v2_breaking3", test_lease_v2_breaking3);
	torture_suite_add_1smb2_test(suite, "breaking4", test_lease_breaking4);
	torture_suite_add_1smb2_test(suite, "breaking5", test_lease_breaking5);
	torture_suite_add_1smb2_test(suite, "breaking6", test_lease_breaking6);
	torture_suite_add_2smb2_test(suite, "lock1", test_lease_lock1);
	torture_suite_add_1smb2_test(suite, "complex1", test_lease_complex1);
	torture_suite_add_1smb2_test(suite, "v2_request_parent",
				     test_lease_v2_request_parent);
	torture_suite_add_1smb2_test(suite, "v2_request", test_lease_v2_request);
	torture_suite_add_1smb2_test(suite, "v2_epoch1", test_lease_v2_epoch1);
	torture_suite_add_1smb2_test(suite, "v2_epoch2", test_lease_v2_epoch2);
	torture_suite_add_1smb2_test(suite, "v2_epoch3", test_lease_v2_epoch3);
	torture_suite_add_1smb2_test(suite, "v2_complex1", test_lease_v2_complex1);
	torture_suite_add_1smb2_test(suite, "v2_complex2", test_lease_v2_complex2);
	torture_suite_add_1smb2_test(suite, "v2_rename", test_lease_v2_rename);
	torture_suite_add_1smb2_test(suite, "dynamic_share", test_lease_dynamic_share);
	torture_suite_add_1smb2_test(suite, "timeout", test_lease_timeout);

	suite->description = talloc_strdup(suite, "SMB2-LEASE tests");

	return suite;
}
