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
#include "lease_break_handler.h"

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
		} else { \
			CHECK_VAL((__io)->out.lease_response_v2.parent_lease_key.data[0], 0); \
			CHECK_VAL((__io)->out.lease_response_v2.parent_lease_key.data[1], 0); \
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
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	NTSTATUS status;
	const char *fname = "lease_request.dat";
	const char *fname2 = "lease_request.2.dat";
	const char *sname = "lease_request.dat:stream";
	const char *dname = "lease_request.dir";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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
	struct smb2_handle h = {};
	struct smb2_handle hnew = {};
	NTSTATUS status;
	const char *fname = "lease_upgrade.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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
	struct smb2_handle h = {};
	struct smb2_handle hnew = {};
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_lease ls;
	const char *fname = "lease_upgrade2.dat";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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
 * In that case, the resulting lease state of the upgraded lease1
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
	struct smb2_handle h = {};
	struct smb2_handle h2 = {};
	struct smb2_handle hnew = {};
	NTSTATUS status;
	struct smb2_create io;
	struct smb2_lease ls;
	const char *fname = "lease_upgrade3.dat";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;

	smb2_util_unlink(tree, fname);

	for (i = 0; i < NUM_UPGRADE3_TESTS; i++) {
		struct lease_upgrade3_test t = lease_upgrade3_tests[i];

		smb2_util_unlink(tree, fname);

		torture_reset_lease_break_info(tctx, &lease_break_info);

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
		CHECK_VAL(lease_break_info.count, 0);
		CHECK_VAL(lease_break_info.failures, 0);

		/* try to upgrade lease1 */
		smb2_lease_create(&io, &ls, false, fname, LEASE1, smb2_util_lease_state(t.upgrade_to));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_LEASE(&io, t.upgraded_to, true, LEASE1, 0);
		hnew = io.out.file.handle;

		/* no break has happened */
		CHECK_VAL(lease_break_info.count, 0);
		CHECK_VAL(lease_break_info.failures, 0);

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
	struct smb2_handle h = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	NTSTATUS status;
	const char *fname = "lease_break.dat";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

		torture_reset_lease_break_info(tctx, &lease_break_info);

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

		torture_reset_lease_break_info(tctx, &lease_break_info);

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
		CHECK_VAL(lease_break_info.count, 0);
		CHECK_VAL(lease_break_info.failures, 0);

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
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	NTSTATUS status;
	const char *fname = "lease_nobreakself.dat";
	bool ret = true;
	uint32_t caps;
	char c = 0;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	torture_reset_lease_break_info(tctx, &lease_break_info);
	status = smb2_util_write(tree, h2, &c, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_BREAK_INFO("R", "", LEASE1);

	/* .. and break LEASE2 via h1 */

	torture_reset_lease_break_info(tctx, &lease_break_info);
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
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	NTSTATUS status;
	const char *fname = "lease_statopen.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

static bool test_lease_statopen2(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	NTSTATUS status;
	const char *fname = "lease_statopen2.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname);
	torture_reset_lease_break_info(tctx, &lease_break_info);
	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;

	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* Open file with RWH lease. */
	smb2_lease_create_share(&io, &ls, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = io.out.file.handle;
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

	/* Stat open */
	ZERO_STRUCT(io);
	io.in.desired_access = FILE_READ_ATTRIBUTES;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname = fname;
	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = io.out.file.handle;

	/* Open file with RWH lease. */
	smb2_lease_create_share(&io, &ls, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h3 = io.out.file.handle;
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

done:
	if (!smb2_util_handle_empty(h3)) {
		smb2_util_close(tree, h3);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_statopen3(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	NTSTATUS status;
	const char *fname = "lease_statopen3.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname);
	torture_reset_lease_break_info(tctx, &lease_break_info);
	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;

	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* Stat open */
	ZERO_STRUCT(io);
	io.in.desired_access = FILE_READ_ATTRIBUTES;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname = fname;
	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = io.out.file.handle;

	/* Open file with RWH lease. */
	smb2_lease_create_share(&io, &ls, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = io.out.file.handle;
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_statopen4_do(struct torture_context *tctx,
				    struct smb2_tree *tree,
				    uint32_t access_mask,
				    bool expect_stat_open)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	NTSTATUS status;
	const char *fname = "lease_statopen2.dat";
	bool ret = true;

	/* Open file with RWH lease. */
	smb2_lease_create_share(&io, &ls, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	io.in.desired_access = SEC_FILE_ALL;
	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = io.out.file.handle;
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

	/* Stat open */
	ZERO_STRUCT(io);
	io.in.desired_access = access_mask;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.fname = fname;
	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = io.out.file.handle;

	if (expect_stat_open) {
		CHECK_NO_BREAK(tctx);
		if (!ret) {
			goto done;
		}
	} else {
		CHECK_VAL(lease_break_info.count, 1);
		if (!ret) {
			goto done;
		}
		/*
		 * Don't bother checking the lease state of an additional open
		 * below...
		 */
		goto done;
	}

	/* Open file with RWH lease. */
	smb2_lease_create_share(&io, &ls, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h3 = io.out.file.handle;
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

done:
	if (!smb2_util_handle_empty(h3)) {
		smb2_util_close(tree, h3);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_statopen4(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	const char *fname = "lease_statopen4.dat";
	struct smb2_handle h1 = {};
	uint32_t caps;
	size_t i;
	NTSTATUS status;
	bool ret = true;
	struct {
		uint32_t access_mask;
		bool expect_stat_open;
	} tests[] = {
		{
			.access_mask = FILE_READ_DATA,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_WRITE_DATA,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_READ_EA,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_WRITE_EA,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_EXECUTE,
			.expect_stat_open = false,
		},
		{
			.access_mask = FILE_READ_ATTRIBUTES,
			.expect_stat_open = true,
		},
		{
			.access_mask = FILE_WRITE_ATTRIBUTES,
			.expect_stat_open = true,
		},
		{
			.access_mask = DELETE_ACCESS,
			.expect_stat_open = false,
		},
		{
			.access_mask = READ_CONTROL_ACCESS,
			.expect_stat_open = true,
		},
		{
			.access_mask = WRITE_DAC_ACCESS,
			.expect_stat_open = false,
		},
		{
			.access_mask = WRITE_OWNER_ACCESS,
			.expect_stat_open = false,
		},
		{
			.access_mask = SYNCHRONIZE_ACCESS,
			.expect_stat_open = true,
		},
	};

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname);
	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;

	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		torture_reset_lease_break_info(tctx, &lease_break_info);

		ret = test_lease_statopen4_do(tctx,
					      tree,
					      tests[i].access_mask,
					      tests[i].expect_stat_open);
		if (ret == true) {
			continue;
		}
		torture_result(tctx, TORTURE_FAIL,
			       "test %zu: access_mask: %s, "
			       "expect_stat_open: %s\n",
			       i,
			       get_sec_mask_str(tree, tests[i].access_mask),
			       tests[i].expect_stat_open ? "yes" : "no");
		goto done;
	}

done:
	smb2_util_unlink(tree, fname);
	return ret;
}

static void torture_oplock_break_callback(struct smb2_request *req)
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
static bool torture_oplock_handler(struct smb2_transport *transport,
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

	if (lease_break_info.held_oplock_level > SMB2_OPLOCK_LEVEL_II) {
		req = smb2_break_send(tree, &br);
		req->async.fn = torture_oplock_break_callback;
		req->async.private_data = NULL;
	}
	lease_break_info.held_oplock_level = level;

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
	struct smb2_handle h = {};
	struct smb2_handle h2 = {};
	NTSTATUS status;
	const char *fname = "lease_oplock.dat";
	bool ret = true;
	int i;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

		torture_reset_lease_break_info(tctx, &lease_break_info);

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
		lease_break_info.held_oplock_level = io.out.oplock_level;

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

		torture_reset_lease_break_info(tctx, &lease_break_info);

		/* Grab an oplock. */
		smb2_oplock_create(&io, fname, smb2_util_oplock_level(held));
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OK);
		h = io.out.file.handle;
		CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
		CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level(held));
		lease_break_info.held_oplock_level = io.out.oplock_level;

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
	struct smb2_handle h = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_write w;
	NTSTATUS status;
	const char *fname = "lease_multibreak.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	smb2_util_unlink(tree, fname);

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	lease_break_info.held_oplock_level = io.out.oplock_level;

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
	lease_break_info.held_oplock_level = io.out.oplock_level;

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
	struct smb2_handle h1 = {};
	uint64_t parent = LEASE2;
	NTSTATUS status;
	const char *fname = "lease_v2_request_parent.dat";
	bool ret = true;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");
	torture_assert_goto(tctx, caps & SMB2_CAP_DIRECTORY_LEASING, ret, done,
		"SMB3 Directory Leases are not supported\n");

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

static bool test_dirlease_oplocks(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	const char *dname = "test_dirlease_leases_dir";
	struct smb2_create c;
	struct smb2_handle h = {};
	uint16_t levels[] = {
		SMB2_OPLOCK_LEVEL_NONE,
		SMB2_OPLOCK_LEVEL_II,
		SMB2_OPLOCK_LEVEL_EXCLUSIVE,
		SMB2_OPLOCK_LEVEL_BATCH
	};
	uint32_t caps;
	int i;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");
	torture_assert_goto(tctx, caps & SMB2_CAP_DIRECTORY_LEASING, ret, done,
		"SMB3 Directory Leases are not supported\n");

	smb2_deltree(tree, dname);

	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		c = (struct smb2_create) {
			.in.oplock_level = levels[i],
			.in.desired_access = SEC_RIGHTS_DIR_READ,
			.in.create_options = NTCREATEX_OPTIONS_DIRECTORY,
			.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
			.in.fname = dname,
		};

		status = smb2_create(tree, tree, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		h = c.out.file.handle;
		status = smb2_util_close(tree, h);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_util_close failed\n");

		torture_assert_int_equal_goto(
			tctx,
			c.out.oplock_level,
			SMB2_OPLOCK_LEVEL_NONE,
			ret, done, "bad level");
	}

done:
	smb2_util_close(tree, h);
	smb2_deltree(tree, dname);

	return ret;
}

/*
 * Checks server accepts "RWH", "RH" and "R" lease request and grants at most
 * (lease_request & "RH"), so no "W", but "R" without "H" if requested.
 */
static bool test_dirlease_leases(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1 = {};
	NTSTATUS status;
	const char *dname = "test_dirlease_leases_dir";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");
	torture_assert_goto(tctx, caps & SMB2_CAP_DIRECTORY_LEASING, ret, done,
		"SMB3 Directory Leases are not supported\n");

	smb2_deltree(tree, dname);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Request "RWH" -> grant "RH" */

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RWH"),
				   0x11);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_LEASE_V2(&io, "RH", true, LEASE1,
		       0, 0, ++ls.lease_epoch);
	smb2_util_close(tree, h1);

	/* Request "RW" -> grant "R" */

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RW"),
				   0x11);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_LEASE_V2(&io, "R", true, LEASE1,
		       0, 0, ++ls.lease_epoch);
	smb2_util_close(tree, h1);

	/* Request "RH" -> grant "RH" */

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RH"),
				   0x11);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_LEASE_V2(&io, "RH", true, LEASE1,
		       0, 0, ++ls.lease_epoch);
	smb2_util_close(tree, h1);

	/* Request "R" -> grant "R" */

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &ls, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("R"),
				   0x11);

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_LEASE_V2(&io, "R", true, LEASE1,
		       0, 0, ++ls.lease_epoch);
	smb2_util_close(tree, h1);

done:
	smb2_util_close(tree, h1);
	smb2_deltree(tree, dname);

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
	struct smb2_handle h1 = {};
	NTSTATUS status;
	const char *fname = "lease_break_twice.dat";
	bool ret = true;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	torture_reset_lease_break_info(tctx, &lease_break_info);
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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

static bool test_rearm_dirlease(TALLOC_CTX *mem_ctx,
				struct torture_context *tctx,
				struct smb2_tree *tree,
				const char *dname,
				uint64_t lease_key,
				uint16_t *lease_epoch)
{
	struct smb2_create io;
	struct smb2_lease ls;
	NTSTATUS status;
	bool ret = true;

	smb2_lease_v2_create_share(&io,
				   &ls,
				   true,
				   dname,
				   smb2_util_share_access("RWD"),
				   lease_key,
				   NULL,
				   smb2_util_lease_state("RH"),
				   *lease_epoch);

	io.in.create_disposition = NTCREATEX_DISP_OPEN;

	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "rearm failed\n");

	smb2_util_close(tree, io.out.file.handle);

	(*lease_epoch)++;
	CHECK_LEASE_V2(&io, "RH", true, lease_key, 0, 0, *lease_epoch);

done:
	return ret;
}

static bool test_lease_v2_request(struct torture_context *tctx,
				  struct smb2_tree *tree,
				  struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1, ls3, ls4, dirlease;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_handle h4 = {};
	struct smb2_handle h5 = {};
	struct smb2_write w;
	struct smb2_lease tr2_ls1;
	struct smb2_request *req = NULL;
	NTSTATUS status;
	const char *fname = "lease_v2_request.dat";
	const char *dname = "lease_v2_request.dir";
	const char *dnamefname = "lease_v2_request.dir\\lease.dat";
	const char *dnamefname2 = "lease_v2_request.dir\\lease2.dat";
	bool ret = true;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");
	torture_assert_goto(tctx, caps & SMB2_CAP_DIRECTORY_LEASING, ret, done,
		"SMB3 Directory Leases are not supported\n");

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	smb2_lease_v2_create_share(&io, &dirlease, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE2, NULL,
				   smb2_util_lease_state("RHW"),
				   0x22);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_DIRECTORY);
	CHECK_LEASE_V2(&io, "RH", true, LEASE2, 0, 0, ++dirlease.lease_epoch);

	/*
	 * TEST: second client opens the same directory as first client,
	 * triggering a sharing violation
	 */
	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &tr2_ls1, true, dname,
				   smb2_util_share_access(""),
				   LEASE3, NULL,
				   smb2_util_lease_state("RHW"),
				   0x22);
	status = smb2_create(tree2, mem_ctx, &io);
	torture_assert_ntstatus_equal_goto(
		tctx, status, NT_STATUS_SHARING_VIOLATION, ret, done,
		"CREATE didn't fail with NT_STATUS_SHARING_VIOLATION\n");

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "R", LEASE2, ++dirlease.lease_epoch);

	torture_reset_lease_break_info(tctx, &lease_break_info);
	ret = test_rearm_dirlease(mem_ctx, tctx, tree, dname, LEASE2, &dirlease.lease_epoch);
	torture_assert_goto(tctx, ret == true, ret, done, "Rearm dirlease failed\n");

	/*
	 * TEST: second client opens the same directory as first client,
	 * triggering a sharing violation, first client closes his handle, open
	 * should pass.
	 */
	lease_break_info.lease_skip_ack = true;

	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &tr2_ls1, true, dname,
				   smb2_util_share_access(""),
				   LEASE3, NULL,
				   smb2_util_lease_state("RHW"),
				   0x22);
	req = smb2_create_send(tree2, &io);
	torture_assert(tctx, req != NULL, "smb2_create_send");

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "R", LEASE2, ++dirlease.lease_epoch);

	status = smb2_util_close(tree, h2);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_create_recv(req, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;

	status = smb2_util_close(tree2, h2);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Reopen directory for subsequent tests */
	ZERO_STRUCT(io);
	smb2_lease_v2_create_share(&io, &dirlease, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE2, NULL,
				   smb2_util_lease_state("RHW"),
				   0x22);
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_LEASE_V2(&io, "RH", true, LEASE2, 0, 0, ++dirlease.lease_epoch);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/*
	 * TEST: create file in a directory with dirlease with valid parent key
	 * -> no break
	 */

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

	/*
	 * TEST: create file in a directory with dirlease with invalid parent
	 * key -> break
	 */

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
			    "RH", "", LEASE2, ++dirlease.lease_epoch);

	/*
	 * TEST: Write on handle without valid parent key -> break
	 */

	torture_reset_lease_break_info(tctx, &lease_break_info);
	ret = test_rearm_dirlease(mem_ctx, tctx, tree, dname, LEASE2, &dirlease.lease_epoch);
	torture_assert_goto(tctx, ret == true, ret, done, "Rearm dirlease failed\n");

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
	ZERO_STRUCT(h4);

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", LEASE2, ++dirlease.lease_epoch);

	/*
	 * TEST: Write on handle with valid parent key -> no break
	 */

	torture_reset_lease_break_info(tctx, &lease_break_info);
	ret = test_rearm_dirlease(mem_ctx, tctx, tree, dname, LEASE2, &dirlease.lease_epoch);
	torture_assert_goto(tctx, ret == true, ret, done, "Rearm dirlease failed\n");

	ZERO_STRUCT(w);
	w.in.file.handle = h3;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb_msleep(4000);
	CHECK_NO_BREAK(tctx);
	smb2_util_close(tree, h3);
	ZERO_STRUCT(h3);
	CHECK_NO_BREAK(tctx);

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

static bool test_lease_v2_flags_breaking(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	struct smb2_create c = {};
	struct smb2_lease ls = {};
	struct smb2_handle h = {};
	const char *fname = "lease_v2_epoch1.dat";
	enum protocol_types protocol;
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	smb2_lease_v2_create_share(&c, &ls, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"),
				   0x4711);
	ls.lease_flags |= SMB2_LEASE_FLAG_BREAK_IN_PROGRESS;

	status = smb2_create(tree, tree, &c);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = c.out.file.handle;

	CHECK_CREATED(&c, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&c, "RHW", true, LEASE1, 0, 0, ls.lease_epoch + 1);

done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	return ret;
}

/*
 * Verify server ignores the parent leasekey if
 * SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET is not set in the request.
 */
static bool test_lease_v2_flags_parentkey(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	struct smb2_create c = {};
	struct smb2_lease ls = {};
	struct smb2_handle h = {};
	const char *fname = "lease_v2_epoch1.dat";
	enum protocol_types protocol;
	uint32_t caps;
	NTSTATUS status;
	bool ret = true;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	smb2_lease_v2_create_share(&c, &ls, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1, &LEASE1,
				   smb2_util_lease_state("RHW"),
				   0x4711);
	ls.lease_flags = 0;

	status = smb2_create(tree, tree, &c);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = c.out.file.handle;

	CHECK_CREATED(&c, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE_V2(&c, "RHW", true, LEASE1, 0, 0, ls.lease_epoch + 1);

done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	return ret;
}

static bool test_lease_v2_epoch1(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h = {};
	const char *fname = "lease_v2_epoch1.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

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
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

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
		lease_break_info.lease_break.current_lease.lease_key;
	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	struct lease_break_info lease_break_info_tmp = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname = "lease_breaking3.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

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
	lease_break_info_tmp = lease_break_info;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	smb2_oplock_create(&io3, fname, SMB2_OPLOCK_LEVEL_NONE);
	io3.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	req3 = smb2_create_send(tree, &io3);
	torture_assert(tctx, req3 != NULL, "smb2_create_send");
	CHECK_NO_BREAK(tctx);
	lease_break_info = lease_break_info_tmp;

	torture_assert(tctx, req3->state == SMB2_REQUEST_RECV, "req3 pending");

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	lease_break_info.lease_skip_ack = true;
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "RH", LEASE1);

	/*
	 * We got an additional break downgrading to just "R"
	 * while we defer the ack.
	 */
	CHECK_BREAK_INFO("RH", "R", LEASE1);

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	struct lease_break_info lease_break_info_tmp = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname = "v2_lease_breaking3.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

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
	ls1.lease_epoch = lease_break_info.lease_break.new_epoch;

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
	lease_break_info_tmp = lease_break_info;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	smb2_oplock_create(&io3, fname, SMB2_OPLOCK_LEVEL_NONE);
	io3.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	req3 = smb2_create_send(tree, &io3);
	torture_assert(tctx, req3 != NULL, "smb2_create_send");
	CHECK_NO_BREAK(tctx);
	lease_break_info = lease_break_info_tmp;

	torture_assert(tctx, req3->state == SMB2_REQUEST_RECV, "req3 pending");

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	lease_break_info.lease_skip_ack = true;
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
	ls1.lease_epoch = lease_break_info.lease_break.new_epoch;

	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	struct lease_break_info lease_break_info_tmp = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname = "lease_breaking4.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

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

	lease_break_info_tmp = lease_break_info;
	torture_reset_lease_break_info(tctx, &lease_break_info);
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
	lease_break_info = lease_break_info_tmp;
	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

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
	struct lease_break_info lease_break_info_tmp = {};
	struct smb2_lease_break_ack ack = {};
	const char *fname = "lease_breaking5.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

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

	lease_break_info_tmp = lease_break_info;
	torture_reset_lease_break_info(tctx, &lease_break_info);
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
	lease_break_info = lease_break_info_tmp;
	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;
	torture_reset_lease_break_info(tctx, &lease_break_info);
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
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	/*
	 * we defer acking the lease break.
	 */
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

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
		lease_break_info.lease_break.current_lease.lease_key;
	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

	torture_reset_lease_break_info(tctx, &lease_break_info);
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
	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	CHECK_VAL(lease_break_info.failures, 0);                      \
	CHECK_VAL(lease_break_info.count, 2);                         \

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	torture_reset_lease_break_info(tctx, &lease_break_info);

done:
	smb2_util_close(tree1a, h1);
	smb2_util_close(tree1b, h2);
	smb2_util_close(tree2, h3);

	smb2_util_unlink(tree1a, fname);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Verifies byterange locks only affect lease state if the lock is actually
 * "backed" by the file. Eg, if a file has size 0, byterange locks will never
 * affect lease state.
 *
 * Client 1: create file with lease=RWH
 * Client 1: set brl off=0, size=1
 * Client 2: open file, expect pending
 * Server: expect lease break to RH
 * Client 2: expect open success with lease=RH
 */
static bool test_lease_lock2(struct torture_context *tctx,
			     struct smb2_tree *tree1,
			     struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_lock lck = {};
	struct smb2_lock_element el = {};
	const char *fname = __FUNCTION__;
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	/* Set up handlers. */
	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	smb2_util_unlink(tree1, fname);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Open a handle on tree1. */
	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, 0);

	/*
	 * Try and get get an exclusive byte
	 * range lock on H1 (LEASE1).
	 */
	lck.in.locks		= &el;
	lck.in.lock_count	= 1;
	lck.in.lock_sequence	= 1;
	lck.in.file.handle	= h1;
	el.offset		= 0;
	el.length		= 1;
	el.reserved		= 0;
	el.flags		= SMB2_LOCK_FLAG_EXCLUSIVE;
	status = smb2_lock(tree1, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Open a second handle on tree2. */
	smb2_lease_create_share(&io2, &ls2, false, fname,
				smb2_util_share_access("RWD"),
				LEASE2,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "RH", true, LEASE2, 0);
	/* And LEASE1 got broken to RH. */
	CHECK_BREAK_INFO("RWH", "RH", LEASE1);
	torture_reset_lease_break_info(tctx, &lease_break_info);

done:
	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);

	smb2_util_unlink(tree1, fname);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Verifies a create with overwrite disposition on a file with a byterange lock
 * can get an RH lease.
 *
 * Client 1: create file with lease=RWH
 * Client 1: write 1 byte to the file
 * Client 1: set brl off=0, size=1
 * Client 2: open file with overwrite disposition, expect status pending
 * Server -> Client 1: Break lease break to none
 * Client 2: expect open success with lease=RH
 */
static bool test_lease_lock3(struct torture_context *tctx,
			     struct smb2_tree *tree1,
			     struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_lock lck = {};
	struct smb2_lock_element el = {};
	const char *fname = __FUNCTION__;
	char c = 'x';
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	/* Set up handlers. */
	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	smb2_util_unlink(tree1, fname);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Open a handle on tree1. */
	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access("RWD"),
				LEASE1,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, 0);

	status = smb2_util_write(tree1, h1, &c, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * Try and get an exclusive byte
	 * range lock on H1 (LEASE1).
	 */
	lck.in.locks		= &el;
	lck.in.lock_count	= 1;
	lck.in.lock_sequence	= 1;
	lck.in.file.handle	= h1;
	el.offset		= 0;
	el.length		= 1;
	el.reserved		= 0;
	el.flags		= SMB2_LOCK_FLAG_EXCLUSIVE;
	status = smb2_lock(tree1, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Open a second handle on tree2. */
	smb2_lease_create_share(&io2, &ls2, false, fname,
				smb2_util_share_access("RWD"),
				LEASE2,
				smb2_util_lease_state("RWH"));
	io2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_LEASE(&io2, "RH", true, LEASE2, 0);
	/* And LEASE1 got broken to NONE. */
	CHECK_BREAK_INFO("RWH", "", LEASE1);
	torture_reset_lease_break_info(tctx, &lease_break_info);

done:
	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);

	smb2_util_unlink(tree1, fname);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * Verifies an existing RWH lease on a file is only broken to RW when a
 * contending create fails with STATUS_SHARING_VIOLATION.
 *
 * Client 1: open file with lease=RWH sharemode=none
 * Client 2: open file, expect STATUS_PENDING
 * Server: send lease break to RW to client 1
 * Client 2: expect open to fail with STATUS_SHARING_VIOLATION.
 */
static bool test_lease_sharing_violation(struct torture_context *tctx,
					 struct smb2_tree *tree1,
					 struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1 = {};
	struct smb2_create io2 = {};
	struct smb2_lease ls1 = {};
	struct smb2_lease ls2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	const char *fname = __FUNCTION__;
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree1->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	/* Set up handlers. */
	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;

	smb2_util_unlink(tree1, fname);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Open a handle on tree1. */
	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access(""),
				LEASE1,
				smb2_util_lease_state("RWH"));
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RWH", true, LEASE1, 0);

	/* Open a second handle on tree2. */
	smb2_lease_create_share(&io2, &ls2, false, fname,
				smb2_util_share_access("RWD"),
				LEASE2,
				smb2_util_lease_state("RWH"));
	io2.in.create_disposition = NTCREATEX_DISP_OVERWRITE;
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_SHARING_VIOLATION);
	/* And LEASE1 got broken to RW. */
	CHECK_BREAK_INFO("RWH", "RW", LEASE1);

done:
	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);

	smb2_util_unlink(tree1, fname);
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
	struct smb2_handle h = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_write w;
	NTSTATUS status;
	const char *fname = "lease_complex1.dat";
	bool ret = true;
	uint32_t caps;
	struct smb2_tree *tree1b = NULL;
	struct smbcli_options options1;

	options1 = tree1a->session->transport->options;

	caps = smb2cli_conn_server_capabilities(tree1a->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

	ZERO_STRUCT(w);
	w.in.file.handle = h;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree1a, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls2.lease_epoch += 1;
	CHECK_BREAK_INFO("R", "", LEASE2);

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	struct smb2_handle h = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
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
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	struct smb2_handle h = {};
	struct smb2_handle h2 = {};
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
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

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
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state = SMB2_LEASE_HANDLE|SMB2_LEASE_READ;

	status = smb2_lease_break_ack(tree1b, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_LEASE_BREAK_ACK(&ack, "RH", LEASE1);

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	struct smb2_handle h = {};
	struct smb2_handle hnew = {};
	struct smb2_handle h1b = {};
	NTSTATUS status;
	const char *fname = "lease_timeout.dat";
	bool ret = true;
	struct smb2_lease_break_ack ack = {};
	struct smb2_request *req2 = NULL;
	struct smb2_write w;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	/* Break with a RWH request. */
	smb2_lease_create(&io, &ls2, false, fname, LEASE2, smb2_util_lease_state("RWH"));
	req2 = smb2_create_send(tree, &io);
	torture_assert(tctx, req2 != NULL, "smb2_create_send");
	torture_assert(tctx, req2->state == SMB2_REQUEST_RECV, "req2 pending");

	CHECK_BREAK_INFO("RWH", "RH", LEASE1);

	/* Copy the break request. */
	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;

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
	torture_reset_lease_break_info(tctx, &lease_break_info);
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
	torture_reset_lease_break_info(tctx, &lease_break_info);
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

static bool test_lease_rename_wait(struct torture_context *tctx,
                               struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_lease ls3;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	union smb_setfileinfo sinfo;
	NTSTATUS status;
	const char *fname_src = "lease_rename_src.dat";
	const char *fname_dst = "lease_rename_dst.dat";
	bool ret = true;
	struct smb2_lease_break_ack ack = {};
	struct smb2_request *rename_req = NULL;
	uint32_t caps;
	unsigned int i;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree, fname_src);
	smb2_util_unlink(tree, fname_dst);

	/* Short timeout for fails. */
	tree->session->transport->options.request_timeout = 15;

	/* Grab a RH lease. */
	smb2_lease_create(&io,
			&ls1,
			false,
			fname_src,
			LEASE1,
			smb2_util_lease_state("RH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RH", true, LEASE1, 0);
	h1 = io.out.file.handle;

	/* Second open with a RH lease. */
	smb2_lease_create(&io,
			&ls2,
			false,
			fname_src,
			LEASE2,
			smb2_util_lease_state("RH"));
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.desired_access = GENERIC_READ_ACCESS;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RH", true, LEASE2, 0);
	h2 = io.out.file.handle;

	/*
	 * Don't ack a lease break.
	 */
	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	/* Break with a rename. */
	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h1;
	sinfo.rename_information.in.overwrite = true;
	sinfo.rename_information.in.new_name = fname_dst;
	rename_req = smb2_setinfo_file_send(tree, &sinfo);

	torture_assert(tctx,
			rename_req != NULL,
			"smb2_setinfo_file_send");
	torture_assert(tctx,
			rename_req->state == SMB2_REQUEST_RECV,
			"rename pending");

	/* Try and open the destination with a RH lease. */
	smb2_lease_create(&io,
			&ls3,
			false,
			fname_dst,
			LEASE3,
			smb2_util_lease_state("RH"));
	/* We want to open, not create. */
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.desired_access = GENERIC_READ_ACCESS;
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

	/*
	 * The smb2_create() I/O should have picked up the break request
	 * caused by the pending rename.
	 */

	/* Copy the break request. */
	ack.in.lease.lease_key =
		lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state =
		lease_break_info.lease_break.new_lease_state;

	/*
	 * Give the server 3 more chances to have renamed
	 * the file. Better than doing a sleep.
	 */
	for (i = 0; i < 3; i++) {
		status = smb2_create(tree, mem_ctx, &io);
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	/* Ack the break. The server is now free to rename. */
	status = smb2_lease_break_ack(tree, &ack);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Get the rename reply. */
	status = smb2_setinfo_recv(rename_req);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* The target should now exist. */
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h3 = io.out.file.handle;

 done:
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h3);

	smb2_util_unlink(tree, fname_src);
	smb2_util_unlink(tree, fname_dst);

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
	struct smb2_handle h = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	union smb_setfileinfo sinfo;
	const char *fname = "lease_v2_rename_src.dat";
	const char *fname_dst = "lease_v2_rename_dst.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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
	torture_reset_lease_break_info(tctx, &lease_break_info);

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

/*
 * Try doing a rename overwrite where the target file is open
 * with a RWH lease.
 */

static bool test_lease_v2_rename_target_overwrite(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_create io_dst;
	struct smb2_lease ls1;
	struct smb2_lease ls_dst;
	struct smb2_handle h = {};
	struct smb2_handle h_dst = {};
	union smb_setfileinfo sinfo;
	const char *fname = "lease_v2_rename_overwrite_src.dat";
	const char *fname_dst = "lease_v2_rename_overwrite_dst.dat";
	bool ret = true;
	NTSTATUS status;
	uint32_t caps;
	enum protocol_types protocol;
	struct smb2_request *rename_req = NULL;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

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

	torture_reset_lease_break_info(tctx, &lease_break_info);

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

	/* Create the target file with a lease and leave open. */
	ZERO_STRUCT(io_dst);
	smb2_lease_v2_create_share(&io_dst, &ls_dst, false, fname_dst,
				   smb2_util_share_access("RWD"),
				   LEASE2, NULL,
				   smb2_util_lease_state("RHW"),
				   0x4711);
	status = smb2_create(tree, mem_ctx, &io_dst);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_dst = io_dst.out.file.handle;
	CHECK_CREATED(&io_dst, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	ls_dst.lease_epoch += 1;
	CHECK_LEASE_V2(&io_dst, "RHW", true, LEASE2, 0, 0, ls_dst.lease_epoch);

	/*
	 * Now rename - should break the target lease then return
	 * ACCESS_DENIED.
	 * */
	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h;
	sinfo.rename_information.in.overwrite = true;
	sinfo.rename_information.in.new_name = fname_dst;
	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RWH", "RW", LEASE2, ls_dst.lease_epoch + 1);

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	/*
	 * Do the rename again, this time there's no h-lease on the dst anymore,
	 * so we should get no break and the rename should still fail.
	 */

	torture_reset_lease_break_info(tctx, &lease_break_info);

	status = smb2_setinfo_file(tree, &sinfo);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	CHECK_NO_BREAK(tctx);

	/*
	 * Do the rename again, but this time close the handle on the
	 * destination when receiving the h-lease break.
	 */

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	status = smb2_util_close(tree, h_dst);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h_dst);

	status = smb2_create(tree, mem_ctx, &io_dst);
	CHECK_STATUS(status, NT_STATUS_OK);
	h_dst = io_dst.out.file.handle;
	ls_dst.lease_epoch += 1;

	ZERO_STRUCT(sinfo);
	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = h;
	sinfo.rename_information.in.overwrite = true;
	sinfo.rename_information.in.new_name = fname_dst;
	rename_req = smb2_setinfo_file_send(tree, &sinfo);

	torture_assert(tctx,
			rename_req != NULL,
			"smb2_setinfo_file_send");
	torture_assert(tctx,
			rename_req->state == SMB2_REQUEST_RECV,
			"rename pending");

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RWH", "RW", LEASE2, ls_dst.lease_epoch + 1);

	status = smb2_util_close(tree, h_dst);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h_dst);

	/* Get the rename reply. */
	status = smb2_setinfo_recv(rename_req);
	CHECK_STATUS(status, NT_STATUS_OK);

done:

	smb2_util_close(tree, h);
	smb2_util_close(tree, h_dst);

	smb2_util_unlink(tree, fname);
	smb2_util_unlink(tree, fname_dst);

	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_dynamic_share(struct torture_context *tctx,
				   struct smb2_tree *tree1a)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls1;
	struct smb2_handle h = {}, h1 = {}, h2 = {};
	struct smb2_write w = {};
	NTSTATUS status;
	const char *fname = "dynamic_path.dat";
	bool ret = true;
	uint32_t caps;
	struct smb2_tree *tree_2 = NULL;
	struct smb2_tree *tree_3 = NULL;
	struct smbcli_options options;
	const char *orig_share = NULL;

	if (!TARGET_IS_SAMBA3(tctx)) {
		torture_skip(tctx, "dynamic shares are not supported");
		return true;
	}

	options = tree1a->session->transport->options;
	options.client_guid = GUID_random();

	caps = smb2cli_conn_server_capabilities(tree1a->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	/*
	 * Save off original share name and change it to dynamic_share.
	 * This must have been pre-created with a dynamic path containing
	 * %t. It means we'll sleep between the connects in order to
	 * get a different timestamp for the share path.
	 */

	orig_share = lpcfg_parm_string(tctx->lp_ctx, NULL, "torture", "share");
	orig_share = talloc_strdup(tctx->lp_ctx, orig_share);
	if (orig_share == NULL) {
		torture_result(tctx, TORTURE_FAIL, __location__ "no memory\n");
                ret = false;
                goto done;
	}
	lpcfg_set_cmdline(tctx->lp_ctx, "torture:share", "dynamic_share");

	/* create a new connection (same client_guid) */
	sleep(2);
	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree_2)) {
		torture_result(tctx,  TORTURE_FAIL,
			__location__ "couldn't reconnect "
			"max protocol 2.1, bailing\n");
		ret = false;
		goto done;
	}

	tree_2->session->transport->lease.handler = torture_lease_handler;
	tree_2->session->transport->lease.private_data = tree_2;
	tree_2->session->transport->oplock.handler = torture_oplock_handler;
	tree_2->session->transport->oplock.private_data = tree_2;

	smb2_util_unlink(tree_2, fname);

	/* create a new connection (same client_guid) */
	sleep(2);
	if (!torture_smb2_connection_ext(tctx, 0, &options, &tree_3)) {
		torture_result(tctx,  TORTURE_FAIL,
			__location__ "couldn't reconnect "
			"max protocol 3.0, bailing\n");
		ret = false;
		goto done;
	}

	tree_3->session->transport->lease.handler = torture_lease_handler;
	tree_3->session->transport->lease.private_data = tree_3;
	tree_3->session->transport->oplock.handler = torture_oplock_handler;
	tree_3->session->transport->oplock.private_data = tree_3;

	smb2_util_unlink(tree_3, fname);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Get RWH lease over connection 2 */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);
	h = io.out.file.handle;

	/* Write some data into it. */
	w.in.file.handle = h;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, '1', w.in.data.length);
	status = smb2_write(tree_2, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Open the same name over connection 3. */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_3, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	/* h1 should have replied with NONE. */
	CHECK_LEASE(&io, "", true, LEASE1, 0);

	/* We should have broken h to NONE. */
	CHECK_BREAK_INFO("RWH", "", LEASE1);

	/* Try to upgrade to RWH over connection 2 */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.size, 4096);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	/* Should have been denied. */
	CHECK_LEASE(&io, "", true, LEASE1, 0);
	smb2_util_close(tree_2, h2);

	/* Try to upgrade to RWH over connection 3 */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_3, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.size, 0);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	/* Should have been denied. */
	CHECK_LEASE(&io, "", true, LEASE1, 0);
	smb2_util_close(tree_3, h2);

	/* Write some data into it. */
	w.in.file.handle = h1;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 1024);
	memset(w.in.data.data, '2', w.in.data.length);
	status = smb2_write(tree_3, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Close everything.. */
	smb2_util_close(tree_2, h);
	smb2_util_close(tree_3, h1);

	/* And ensure we can get a lease ! */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_2, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);
	h = io.out.file.handle;
	/* And the file is the right size. */
	CHECK_VAL(io.out.size, 4096);				\
	/* Close it. */
	smb2_util_close(tree_2, h);

	/* And ensure we can get a lease ! */
	smb2_lease_create(&io, &ls1, false, fname, LEASE1, smb2_util_lease_state("RWH"));
	status = smb2_create(tree_3, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(io.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);
	h = io.out.file.handle;
	/* And the file is the right size. */
	CHECK_VAL(io.out.size, 1024);				\
	/* Close it. */
	smb2_util_close(tree_3, h);

 done:

	if (tree_2 != NULL) {
		smb2_util_close(tree_2, h);
		smb2_util_unlink(tree_2, fname);
	}
	if (tree_3 != NULL) {
		smb2_util_close(tree_3, h1);
		smb2_util_close(tree_3, h2);

		smb2_util_unlink(tree_3, fname);
	}

	/* Set sharename back. */
	lpcfg_set_cmdline(tctx->lp_ctx, "torture:share", orig_share);

	talloc_free(mem_ctx);

	return ret;
}

/*
 * Test identifies a bug where the Samba server will not trigger a lease break
 * for a handle caching lease held by a client when the underlying file is
 * deleted.
 * Test:
 * 	Connect session2.
 * 	open file in session1
 * 		session1 should have RWH lease.
 * 	open file in session2
 * 		lease break sent to session1 to downgrade lease to RH
 * 	close file in session 2
 * 	unlink file in session 2
 * 		lease break sent to session1 to downgrade lease to R
 * 	Cleanup
 */
static bool test_lease_unlink(struct torture_context *tctx,
			      struct smb2_tree *tree1)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	bool ret = true;
	struct smbcli_options transport2_options;
	struct smb2_tree *tree2 = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smb2_transport *transport2;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	const char *fname = "lease_unlink.dat";
	uint32_t caps;
	struct smb2_create io1;
	struct smb2_create io2;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	union smb_setfileinfo sfinfo = {};

	caps = smb2cli_conn_server_capabilities(
			tree1->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	/* Connect 2nd connection */
	transport2_options = transport1->options;
	transport2_options.client_guid = GUID_random();
	if (!torture_smb2_connection_ext(tctx, 0, &transport2_options, &tree2)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		return false;
	}
	transport2 = tree2->session->transport;

	/* Set lease handlers */
	transport1->lease.handler = torture_lease_handler;
	transport1->lease.private_data = tree1;
	transport2->lease.handler = torture_lease_handler;
	transport2->lease.private_data = tree2;


	smb2_lease_create(&io1, &ls1, false, fname, LEASE1,
				smb2_util_lease_state("RHW"));
	smb2_lease_create(&io2, &ls2, false, fname, LEASE2,
				smb2_util_lease_state("RHW"));

	smb2_util_unlink(tree1, fname);

	torture_comment(tctx, "Client opens fname with session 1\n");
	torture_reset_lease_break_info(tctx, &lease_break_info);
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RHW", true, LEASE1, 0);
	CHECK_VAL(lease_break_info.count, 0);

	torture_comment(tctx, "Client opens fname with session 2\n");
	torture_reset_lease_break_info(tctx, &lease_break_info);
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "RH", true, LEASE2, 0);
	CHECK_VAL(lease_break_info.count, 1);
	CHECK_BREAK_INFO("RHW", "RH", LEASE1);

	torture_comment(tctx,
		"Client closes and then unlinks fname with session 2\n");
	torture_reset_lease_break_info(tctx, &lease_break_info);
	smb2_util_close(tree2, h2);
	smb2_util_unlink(tree2, fname);
	CHECK_VAL(lease_break_info.count, 1);
	CHECK_BREAK_INFO("RH", "R", LEASE1);

	smb2_util_close(tree1, h1);

	torture_comment(tctx, "Client 1 recreates file with RH lease\n");

	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_lease_create(&io1, &ls1, false, fname, LEASE1,
				smb2_util_lease_state("RH"));

	status = smb2_create(tree1, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RH", true, LEASE1, 0);
	CHECK_VAL(lease_break_info.count, 0);

	torture_comment(tctx, "Client 2 opens with RH lease\n");

	smb2_lease_create(&io2, &ls2, false, fname, LEASE2,
				smb2_util_lease_state("RH"));
	status = smb2_create(tree2, mem_ctx, &io2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create failed\n");

	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "RH", true, LEASE2, 0);
	CHECK_VAL(lease_break_info.count, 0);

	torture_comment(tctx, "Client 2 sets delete on close, "
			"triggering lease break\n");

	sfinfo.disposition_info.in.delete_on_close = 1;
	sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.generic.in.file.handle = h2;

	status = smb2_setinfo_file(tree2, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
				      "Set DELETE_ON_CLOSE disposition "
				      "returned un expected status.\n");

	CHECK_LEASE(&io1, "RH", true, LEASE1, 0);
	CHECK_VAL(lease_break_info.count, 1);

	status = smb2_util_close(tree2, h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h2);

done:
	smb2_util_close(tree1, h1);
	smb2_util_close(tree2, h2);
	smb2_util_unlink(tree1, fname);

	return ret;
}

static bool test_lease_timeout_disconnect(struct torture_context *tctx,
					  struct smb2_tree *tree1)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	NTSTATUS status;
	bool ret = true;
	struct smbcli_options transport2_options;
	struct smbcli_options transport3_options;
	struct smb2_tree *tree2 = NULL;
	struct smb2_tree *tree3 = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smb2_transport *transport2;
	struct smb2_transport *transport3;
	const char *fname = "lease_timeout_logoff.dat" ;
	uint32_t caps;
	struct smb2_create io1;
	struct smb2_create io2;
	struct smb2_request *req2 = NULL;
	struct smb2_lease ls1;

	caps = smb2cli_conn_server_capabilities(
			tree1->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	smb2_util_unlink(tree1, fname);

	/* Connect 2nd connection */
	torture_comment(tctx, "connect tree2 with the same client_guid\n");
	transport2_options = transport1->options;
	if (!torture_smb2_connection_ext(tctx, 0, &transport2_options, &tree2)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		return false;
	}
	transport2 = tree2->session->transport;

	/* Connect 3rd connection */
	torture_comment(tctx, "connect tree3 with the same client_guid\n");
	transport3_options = transport1->options;
	if (!torture_smb2_connection_ext(tctx, 0, &transport3_options, &tree3)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		return false;
	}
	transport3 = tree3->session->transport;

	/* Set lease handlers */
	transport1->lease.handler = torture_lease_handler;
	transport1->lease.private_data = tree1;
	transport2->lease.handler = torture_lease_handler;
	transport2->lease.private_data = tree2;
	transport3->lease.handler = torture_lease_handler;
	transport3->lease.private_data = tree3;

	smb2_lease_create_share(&io1, &ls1, false, fname,
				smb2_util_share_access(""),
				LEASE1,
				smb2_util_lease_state("RH"));
	io1.in.durable_open = true;
	smb2_generic_create(&io2, NULL, false, fname,
			    NTCREATEX_DISP_OPEN_IF,
			    SMB2_OPLOCK_LEVEL_NONE, 0, 0);

	torture_comment(tctx, "tree1: create file[%s] with durable RH lease (SHARE NONE)\n", fname);
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "RH", true, LEASE1, 0);
	CHECK_VAL(lease_break_info.count, 0);

	torture_comment(tctx, "tree1: skip lease acks\n");
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;
	torture_comment(tctx, "tree2: open file[%s] without lease (SHARE RWD)\n", fname);
	req2 = smb2_create_send(tree2, &io2);
	torture_assert(tctx, req2 != NULL, "req2 started");

	torture_comment(tctx, "tree1: wait for lease break\n");
	torture_wait_for_lease_break(tctx);
	CHECK_VAL(lease_break_info.count, 1);
	CHECK_BREAK_INFO("RH", "R", LEASE1);

	torture_comment(tctx, "tree1: reset lease handler\n");
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;
	CHECK_VAL(lease_break_info.count, 0);

	torture_comment(tctx, "tree2: check for SMB2_REQUEST_RECV\n");
	torture_assert_int_equal(tctx, req2->state,
				 SMB2_REQUEST_RECV,
				 "SMB2_REQUEST_RECV");

	torture_comment(tctx, "sleep 1\n");
	smb_msleep(1000);

	torture_comment(tctx, "transport1: keepalive\n");
	status = smb2_keepalive(transport1);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "transport2: keepalive\n");
	status = smb2_keepalive(transport2);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "transport3: keepalive\n");
	status = smb2_keepalive(transport3);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "tree2: check for SMB2_REQUEST_RECV\n");
	torture_assert_int_equal(tctx, req2->state,
				 SMB2_REQUEST_RECV,
				 "SMB2_REQUEST_RECV");
	torture_comment(tctx, "tree2: check for STATUS_PENDING\n");
	torture_assert(tctx, req2->cancel.can_cancel, "STATUS_PENDING");

	torture_comment(tctx, "sleep 1\n");
	smb_msleep(1000);
	torture_comment(tctx, "transport1: keepalive\n");
	status = smb2_keepalive(transport1);
	CHECK_STATUS(status, NT_STATUS_OK);
	torture_comment(tctx, "transport2: disconnect\n");
	TALLOC_FREE(tree2);

	torture_comment(tctx, "sleep 1\n");
	smb_msleep(1000);
	torture_comment(tctx, "transport1: keepalive\n");
	status = smb2_keepalive(transport1);
	CHECK_STATUS(status, NT_STATUS_OK);
	torture_comment(tctx, "transport1: disconnect\n");
	TALLOC_FREE(tree1);

	torture_comment(tctx, "sleep 1\n");
	smb_msleep(1000);
	torture_comment(tctx, "transport3: keepalive\n");
	status = smb2_keepalive(transport3);
	CHECK_STATUS(status, NT_STATUS_OK);
	torture_comment(tctx, "transport3: disconnect\n");
	TALLOC_FREE(tree3);

done:

	return ret;
}

static bool test_lease_duplicate_create(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	NTSTATUS status;
	const char *fname1 = "duplicate_create1.dat";
	const char *fname2 = "duplicate_create2.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	/* Ensure files don't exist. */
	smb2_util_unlink(tree, fname1);
	smb2_util_unlink(tree, fname2);

	/* Create file1 - LEASE1 key. */
	smb2_lease_create(&io, &ls, false, fname1, LEASE1,
			  smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

	/*
	 * Create file2 with the same LEASE1 key - this should fail with.
	 * INVALID_PARAMETER.
	 */
	smb2_lease_create(&io, &ls, false, fname2, LEASE1,
			  smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
	smb2_util_close(tree, h1);

done:
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname1);
	smb2_util_unlink(tree, fname2);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_duplicate_open(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	NTSTATUS status;
	const char *fname1 = "duplicate_open1.dat";
	const char *fname2 = "duplicate_open2.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(
		tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	/* Ensure files don't exist. */
	smb2_util_unlink(tree, fname1);
	smb2_util_unlink(tree, fname2);

	/* Create file1 - LEASE1 key. */
	smb2_lease_create(&io, &ls, false, fname1, LEASE1,
			  smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io, "RWH", true, LEASE1, 0);

	/* Leave file1 open and leased. */

	/* Create file2 - no lease. */
	smb2_lease_create(&io, NULL, false, fname2, 0,
			  smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	/* Close it. */
	smb2_util_close(tree, h2);

	/*
	 * Try and open file2 with the same LEASE1 key - this should fail with.
	 * INVALID_PARAMETER.
	 */
	smb2_lease_create(&io, &ls, false, fname2, LEASE1,
			  smb2_util_lease_state("RWH"));
	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
	/*
	 * If we did open this is an error, but save off
	 * the handle so we close below.
	 */
	h2 = io.out.file.handle;

done:
	smb2_util_close(tree, h2);
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname1);
	smb2_util_unlink(tree, fname2);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_lease_v1_bug_15148(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1;
	struct smb2_create io2;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_write w;
	NTSTATUS status;
	const char *fname = "lease_v1_bug_15148.dat";
	bool ret = true;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	tree->session->transport->lease.handler = torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	smb2_util_unlink(tree, fname);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Grab R lease over connection 1a */
	smb2_lease_create(&io1, &ls1, false, fname, LEASE1, smb2_util_lease_state("R"));
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io1, "R", true, LEASE1, 0);

	CHECK_NO_BREAK(tctx);

	/* Contend with LEASE2. */
	smb2_lease_create(&io2, &ls2, false, fname, LEASE2, smb2_util_lease_state("R"));
	status = smb2_create(tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_LEASE(&io2, "R", true, LEASE2, 0);

	CHECK_NO_BREAK(tctx);

	ZERO_STRUCT(w);
	w.in.file.handle = h1;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls2.lease_epoch += 1;
	CHECK_BREAK_INFO("R", "", LEASE2);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	ZERO_STRUCT(w);
	w.in.file.handle = h1;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'O', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_NO_BREAK(tctx);

	ZERO_STRUCT(w);
	w.in.file.handle = h2;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls1.lease_epoch += 1;
	CHECK_BREAK_INFO("R", "", LEASE1);

 done:
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_lease_v2_bug_15148(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1;
	struct smb2_create io2;
	struct smb2_lease ls1;
	struct smb2_lease ls2;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_write w;
	NTSTATUS status;
	const char *fname = "lease_v2_bug_15148.dat";
	bool ret = true;
	uint32_t caps;
	enum protocol_types protocol;

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);
	torture_assert_goto(tctx, caps & SMB2_CAP_LEASING, ret, done, "leases are not supported");

	protocol = smbXcli_conn_protocol(tree->session->transport->conn);
	if (protocol < PROTOCOL_SMB3_00) {
		torture_skip(tctx, "v2 leases are not supported");
	}

	tree->session->transport->lease.handler = torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	tree->session->transport->oplock.handler = torture_oplock_handler;
	tree->session->transport->oplock.private_data = tree;

	smb2_util_unlink(tree, fname);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Grab R lease over connection 1a */
	smb2_lease_v2_create(&io1, &ls1, false, fname, LEASE1, NULL,
			     smb2_util_lease_state("R"), 0x4711);
	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	ls1.lease_epoch += 1;
	CHECK_LEASE_V2(&io1, "R", true, LEASE1,
		       0, 0, ls1.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* Contend with LEASE2. */
	smb2_lease_v2_create(&io2, &ls2, false, fname, LEASE2, NULL,
			     smb2_util_lease_state("R"), 0x11);
	status = smb2_create(tree, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	ls2.lease_epoch += 1;
	CHECK_LEASE_V2(&io2, "R", true, LEASE2,
		       0, 0, ls2.lease_epoch);

	CHECK_NO_BREAK(tctx);

	ZERO_STRUCT(w);
	w.in.file.handle = h1;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls2.lease_epoch += 1;
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "R", "", LEASE2, ls2.lease_epoch);

	torture_reset_lease_break_info(tctx, &lease_break_info);

	ZERO_STRUCT(w);
	w.in.file.handle = h1;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'O', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	CHECK_NO_BREAK(tctx);

	ZERO_STRUCT(w);
	w.in.file.handle = h2;
	w.in.offset      = 0;
	w.in.data        = data_blob_talloc(mem_ctx, NULL, 4096);
	memset(w.in.data.data, 'o', w.in.data.length);
	status = smb2_write(tree, &w);
	CHECK_STATUS(status, NT_STATUS_OK);

	ls1.lease_epoch += 1;
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "R", "", LEASE1, ls1.lease_epoch);

 done:
	smb2_util_close(tree, h1);
	smb2_util_close(tree, h2);

	smb2_util_unlink(tree, fname);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_initial_delete_tdis(struct torture_context *tctx,
				     struct smb2_tree *tree1)
{
	struct smb2_tree *tree2 = NULL;
	struct smb2_create c = {};
	struct smb2_handle h1 = {};
	struct smb2_lease lease1 = {};
	const char *fname = "test_initial_delete_tdis.dat";
	NTSTATUS status;
	bool ret = true;

	tree1->session->transport->lease.handler	= torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	ret = torture_smb2_connection(tctx, &tree2);
	torture_assert_goto(tctx, ret, ret, done, "torture_smb2_connection failed\n");

	smb2_util_unlink(tree1, fname);

	smb2_lease_v2_create_share(&c, &lease1, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1,
				   NULL,
				   smb2_util_lease_state("RH"),
				   0);
	status = smb2_create(tree1, tree1, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	c = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_FILE_ALL ,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree2, tree2, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	status = smb2_tdis(tree2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	CHECK_BREAK_INFO_V2(tree1->session->transport,
			    "RH", "R",
			    LEASE1,
			    2);

	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	c = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_FILE_ALL ,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree1, tree1, &c);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "file still there?\n");

done:
	smb2_util_unlink(tree1, fname);
	return ret;
}

static bool test_initial_delete_logoff(struct torture_context *tctx,
				       struct smb2_tree *tree1)
{
	struct smb2_tree *tree2 = NULL;
	struct smb2_create c = {};
	struct smb2_handle h1 = {};
	struct smb2_lease lease1 = {};
	const char *fname = "test_initial_delete_logoff.dat";
	NTSTATUS status;
	bool ret = true;

	tree1->session->transport->lease.handler	= torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	ret = torture_smb2_connection(tctx, &tree2);
	torture_assert_goto(tctx, ret, ret, done, "torture_smb2_connection failed\n");

	smb2_util_unlink(tree2, fname);

	smb2_lease_v2_create_share(&c, &lease1, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1,
				   NULL,
				   smb2_util_lease_state("RH"),
				   0);
	status = smb2_create(tree1, tree1, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	c = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_FILE_ALL ,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree2, tree2, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	status = smb2_logoff(tree2->session);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	CHECK_BREAK_INFO_V2(tree1->session->transport,
			    "RH", "R",
			    LEASE1,
			    2);

	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	c = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_FILE_ALL ,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree1, tree1, &c);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "file still there?\n");

done:
	return ret;
}

static bool test_initial_delete_disconnect(struct torture_context *tctx,
					   struct smb2_tree *tree1)
{
	struct smb2_tree *tree2 = NULL;
	struct smb2_create c = {};
	struct smb2_handle h1 = {};
	struct smb2_lease lease1 = {};
	const char *fname = "test_initial_delete_disconnect.dat";
	NTSTATUS status;
	bool ret = true;

	tree1->session->transport->lease.handler	= torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	ret = torture_smb2_connection(tctx, &tree2);
	torture_assert_goto(tctx, ret, ret, done, "torture_smb2_connection failed\n");

	smb2_util_unlink(tree2, fname);

	smb2_lease_v2_create_share(&c, &lease1, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE1,
				   NULL,
				   smb2_util_lease_state("RH"),
				   0);
	status = smb2_create(tree1, tree1, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	c = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_FILE_ALL ,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree2, tree2, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	TALLOC_FREE(tree2);

	CHECK_BREAK_INFO_V2(tree1->session->transport,
			    "RH", "R",
			    LEASE1,
			    2);

	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed\n");
	ZERO_STRUCT(h1);

	c = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_FILE_ALL ,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree1, tree1, &c);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done,
					   "file still there?\n");

done:
	return ret;
}

struct rename_tcase_open {
	bool hlease;
	bool close_on_break;
};

struct rename_tcase {
	const char *name;
	bool disabled;
	struct rename_tcase_open o1;
	struct rename_tcase_open o2;
	bool do_o3;
	struct rename_tcase_open o3;
	NTSTATUS status;
};

static bool torture_rename_dir_openfile_do(struct torture_context *tctx,
					   struct smb2_tree *tree1,
					   struct smb2_tree *tree2,
					   struct rename_tcase *t)
{
	struct smb2_create c = {};
	union smb_setfileinfo sinfo = {};
	struct smb2_handle d1 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle h3 = {};
	struct smb2_handle *h = NULL;
	struct smb2_lease *please1 = NULL;
	struct smb2_lease *please2 = NULL;
	struct smb2_lease *please3 = NULL;
	struct smb2_lease lease1 = {};
	struct smb2_lease lease2 = {};
	struct smb2_lease lease3 = {};
	struct smb2_request *req = NULL;
	struct smb2_lease_break_ack ack = {};
	struct rename_tcase_open *to = NULL;
	const char *dname = "torture_rename_dir_openfile_dir";
	const char *fname1 = "torture_rename_dir_openfile_dir\\torture_rename_dir_openfile_file1";
	const char *fname2 = "torture_rename_dir_openfile_dir\\torture_rename_dir_openfile_file2";
	const char *fname3 = "torture_rename_dir_openfile_dir\\torture_rename_dir_openfile_file3";
	const char *new_dname = "torture_rename_dir_openfile_dir-renamed";
	bool expect_immediate_fail = false;
	bool ret = true;
	NTSTATUS status;

	torture_comment(tctx, "Subtest: %s\n", t->name);
	if (t->disabled) {
		torture_comment(tctx, "...skipped\n");
		return true;
	}

	tree2->session->transport->lease.handler = torture_lease_handler;
	tree2->session->transport->lease.private_data = tree2;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	smb2_deltree(tree1, dname);
	smb2_deltree(tree1, new_dname);

	torture_comment(tctx, "Creating base directory\n");

	smb2_lease_v2_create_share(&c, NULL, true, dname,
				   smb2_util_share_access("RWD"),
				   0,
				   NULL,
				   smb2_util_lease_state(""),
				   0);
	status = smb2_create(tree1, tree1, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	d1 = c.out.file.handle;

	torture_comment(tctx, "Creating test file1\n");

	if (t->o1.hlease) {
		please1 = &lease1;
	}
	smb2_lease_v2_create_share(&c, please1, false, fname1,
				   smb2_util_share_access("RWD"),
				   LEASE1,
				   NULL,
				   smb2_util_lease_state("RH"),
				   0);
	status = smb2_create(tree2, tree2, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	torture_comment(tctx, "Creating test file2\n");

	if (t->o2.hlease) {
		please2 = &lease2;
	}
	smb2_lease_v2_create_share(&c, please2, false, fname2,
				   smb2_util_share_access("RWD"),
				   LEASE2,
				   NULL,
				   smb2_util_lease_state("RH"),
				   0);
	status = smb2_create(tree2, tree2, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = c.out.file.handle;

	torture_comment(tctx, "Renaming directory\n");

	sinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sinfo.rename_information.in.file.handle = d1;
	sinfo.rename_information.in.new_name = new_dname;

	req = smb2_setinfo_file_send(tree1, &sinfo);
	torture_assert_goto(tctx, req != NULL, ret, done,
			    "smb2_setinfo_file_send");

	torture_assert(tctx, req->state == SMB2_REQUEST_RECV, "bad req state");

	if (t->o1.hlease || t->o2.hlease) {
		/* Get the first break */
		torture_wait_for_lease_break(tctx);

		if (lease_break_info.count == 0) {
			/*
			 * If one of the two opens was without a h-lease, the
			 * scan for opens might hit the open without h-lease
			 * first triggering an immediate STATUS_ACCESS_DENIED
			 * for the rename without sending out any lease break.
			 */
			torture_assert_goto(tctx, (!t->o1.hlease || !t->o2.hlease),
					    ret, done,
					    "Expected only one hlease when getting no hlease break\n");

			status = smb2_setinfo_recv(req);
			torture_assert_ntstatus_equal_goto(tctx, status, t->status, ret, done,
							   "Rename didn't work as expected\n");
			goto done;
		}

		if (lease_break_info.lease_break.current_lease.lease_key.data[0] == LEASE1 &&
		    lease_break_info.lease_break.current_lease.lease_key.data[1] == ~LEASE1)
		{
			torture_comment(tctx, "Got break for file 1\n");
			please1 = &lease1;
			h = &h1;
			to = &t->o1;
		} else {
			torture_comment(tctx, "Got break for file 2\n");
			please1 = &lease2;
			h = &h2;
			to = &t->o2;
		}
		please1->lease_epoch += 2;

		CHECK_BREAK_INFO_V2_NOWAIT(tree2->session->transport,
					   "RH", "R",
					   please1->lease_key.data[0],
					   please1->lease_epoch);

		ack.in.lease.lease_key = lease_break_info.lease_break.current_lease.lease_key;
		ack.in.lease.lease_state = lease_break_info.lease_break.new_lease_state;
		torture_reset_lease_break_info(tctx, &lease_break_info);
		lease_break_info.lease_skip_ack = true;

		if (to->close_on_break) {
			status = smb2_util_close(tree2, *h);
			torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
							"smb2_util_close failed\n");
			ZERO_STRUCTP(h);
		} else {
			status = smb2_lease_break_ack(tree2, &ack);
			torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
							"ack failed\n");
			expect_immediate_fail = true;
		}
	}

	if (t->do_o3) {
		torture_comment(tctx, "Doing additional open after first break\n");

		if (t->o3.hlease) {
			please3 = &lease3;
		}
		smb2_lease_v2_create_share(&c, please3, false, fname3,
					   smb2_util_share_access("RWD"),
					   LEASE3,
					   NULL,
					   smb2_util_lease_state("RH"),
					   0);
		status = smb2_create(tree2, tree2, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		h3 = c.out.file.handle;
	}

	if (!expect_immediate_fail && t->o1.hlease && t->o2.hlease) {
		/* Get the second break */
		torture_wait_for_lease_break(tctx);

		if (lease_break_info.lease_break.current_lease.lease_key.data[0] == LEASE1 &&
		    lease_break_info.lease_break.current_lease.lease_key.data[1] == ~LEASE1)
		{
			torture_comment(tctx, "Got break for file 1\n");
			please1 = &lease1;
			h = &h1;
			to = &t->o1;
		} else {
			torture_comment(tctx, "Got break for file 2\n");
			please1 = &lease2;
			h = &h2;
			to = &t->o2;
		}
		please1->lease_epoch += 2;

		CHECK_BREAK_INFO_V2_NOWAIT(tree2->session->transport,
					   "RH", "R",
					   please1->lease_key.data[0],
					   please1->lease_epoch);

		ack.in.lease.lease_key = lease_break_info.lease_break.current_lease.lease_key;
		ack.in.lease.lease_state = lease_break_info.lease_break.new_lease_state;
		torture_reset_lease_break_info(tctx, &lease_break_info);
		lease_break_info.lease_skip_ack = true;

		if (to->close_on_break) {
			status = smb2_util_close(tree2, *h);
			torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
							"smb2_util_close failed\n");
			ZERO_STRUCTP(h);
		} else {
			status = smb2_lease_break_ack(tree2, &ack);
			torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
							"ack failed\n");
		}
	}

	status = smb2_setinfo_recv(req);
	torture_assert_ntstatus_equal_goto(tctx, status, t->status, ret, done,
					   "Rename didn't work as expected\n");

done:
	if (!smb2_util_handle_empty(d1)) {
		smb2_util_close(tree1, d1);
	}
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree2, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}
	if (!smb2_util_handle_empty(h3)) {
		smb2_util_close(tree2, h3);
	}
	smb2_deltree(tree1, dname);
	smb2_deltree(tree1, new_dname);
	return ret;
}

static bool torture_rename_dir_openfile(struct torture_context *tctx,
					struct smb2_tree *tree1,
					struct smb2_tree *tree2)
{
	struct rename_tcase tcases[] = {
		{
			.name = "two-hleases-two-closes",
			.o1 = { .hlease = true, .close_on_break = true },
			.o2 = { .hlease = true, .close_on_break = true },
			.do_o3 = false,
			.status = NT_STATUS_OK,
		},
		{
			.name = "no-hleases",
			.o1 = { .hlease = false, },
			.o2 = { .hlease = false, },
			.do_o3 = false,
			.status = NT_STATUS_ACCESS_DENIED,
		},
		{
			.name = "two-hleases-second-hlease-close",
			.o1 = { .hlease = true, .close_on_break = false },
			.o2 = { .hlease = true, .close_on_break = true },
			.do_o3 = false,
			.status = NT_STATUS_ACCESS_DENIED,
		},
		{
			.name = "two-hleases-first-hlease-close",
			.o1 = { .hlease = true, .close_on_break = true },
			.o2 = { .hlease = true, .close_on_break = false },
			.do_o3 = false,
			.status = NT_STATUS_ACCESS_DENIED,
		},
		{
			.name = "first-hlease-close",
			.o1 = { .hlease = true, .close_on_break = true },
			.o2 = { .hlease = false, },
			.do_o3 = false,
			.status = NT_STATUS_ACCESS_DENIED,
		},
		{
			.name = "second-hlease-close",
			.o1 = { .hlease = false, },
			.o2 = { .hlease = true, .close_on_break = true },
			.do_o3 = false,
			.status = NT_STATUS_ACCESS_DENIED,
		},
		{
			.name = "two-hleases-two-closes-addopen-w-hlease",
			.o1 = { .hlease = true, .close_on_break = true },
			.o2 = { .hlease = true, .close_on_break = true },
			.do_o3 = true,
			.o3 = { .hlease = true, .close_on_break = true },
			.status = NT_STATUS_ACCESS_DENIED,
		},
		{
			.name = "two-hleases-two-closes-addopen-wo-hlease",
			.o1 = { .hlease = true, .close_on_break = true },
			.o2 = { .hlease = true, .close_on_break = true },
			.do_o3 = true,
			.o3 = { .hlease = false, },
			.status = NT_STATUS_ACCESS_DENIED,
		},
	};
	size_t i;
	bool ret;

	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree2;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	for (i = 0; i < ARRAY_SIZE(tcases); i++) {
		ret = torture_rename_dir_openfile_do(tctx, tree1, tree2, &tcases[i]);
		torture_assert_goto(tctx, ret, ret, done, "test failed\n");
	}

done:
	return ret;
}

/*
 * Verifies the lease epoch is not incremented by the server (returns what the
 * client sent in the request) if a lease was not granted ie lease_level=NONE.
 */
static bool test_lease_epoch(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	struct smb2_create c;
	struct smb2_lease ls1;
	struct smb2_handle h1 = {};
	struct smb2_write wr;
	char dat = 'x';
	DATA_BLOB data = (DATA_BLOB) {.data = (uint8_t *)&dat, .length = 1};
	struct smb2_lock lck = {0};
	struct smb2_lock_element el[1];
	uint64_t lease1 = 1;
	struct GUID create_guid = GUID_random();
	char *fname = NULL;
	NTSTATUS status;
	bool ret = true;

	fname = talloc_asprintf(tctx, "lease_break-%ld.dat", random());
	torture_assert_not_null_goto(tctx, fname, ret, done,
				     "talloc_asprintf failed\n");

	c = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	ZERO_STRUCT(wr);
	wr.in.file.handle = h1;
	wr.in.offset      = 0;
	wr.in.data        = data;
	status = smb2_write(tree, &wr);
	torture_assert_ntstatus_ok(tctx, status, "smb2_write failed\n");

	ZERO_ARRAY(el);
	ZERO_STRUCT(lck);
	el[0].offset = 0;
	el[0].length = 1;
	el[0].flags = SMB2_LOCK_FLAG_EXCLUSIVE|SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
	lck.in.locks = el;
	lck.in.lock_count = 1;
	lck.in.file.handle = h1;

	status = smb2_lock(tree, &lck);
	torture_assert_ntstatus_equal_goto(
		tctx, status, NT_STATUS_OK,
		ret, done, "smb2_lock failed\n");


	smb2_lease_v2_create_share(&c,
				   &ls1,
				   false,
				   fname,
				   smb2_util_share_access("RWD"),
				   lease1,
				   NULL,
				   smb2_util_lease_state("R"),
				   100);
	c.in.durable_open_v2 = true;
	c.in.create_guid = create_guid;
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

	torture_assert_int_equal_goto(
		tctx,
		c.out.oplock_level,
		SMB2_OPLOCK_LEVEL_LEASE,
		ret, done,
		"Bad lease level\n");
	torture_assert_int_equal_goto(
		tctx,
		c.out.lease_response_v2.lease_state,
		0,
		ret, done,
		"Bad lease level\n");
	torture_assert_int_equal_goto(
		tctx,
		c.out.lease_response_v2.lease_epoch,
		100,
		ret,
		done,
		"Bad lease epoch\n");

done:
	return ret;
}

/*
 * Verify a redispatched deferred open doesn't send a lease break to the client
 *
 * 1. Client 1: Open file with RH lease
 * 2. Client 1: Second open with RH lease, different lease key
 * 3. Client 2: Try to open file with incompatible mode, triggers sharing
 *    violation, triggers H lease breaks and gets deferred.
 * 4. Client 1: close handle 1, this will trigger a redispatch of the deferred
 *    open from 3.
 * 5. Check the client doesn't get a lease break.
 */
static bool test_two_leases(struct torture_context *tctx,
			    struct smb2_tree *_tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smbcli_options options = _tree->session->transport->options;
	struct smb2_tree *tree1 = NULL;
	struct smb2_tree *tree2 = NULL;
	struct smb2_request *req = NULL;
	struct smb2_create c;
	struct smb2_lease ls;
	uint64_t broken_ls_key;
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_handle ch1 = {};
	struct smb2_handle ch2 = {};
	char *fname = NULL;
	int rc;
	NTSTATUS status;
	bool ret = true;

	fname = talloc_asprintf(mem_ctx, "lease_break-%ld.dat", random());
	torture_assert_not_null_goto(tctx, fname, ret, done,
				     "talloc_asprintf failed\n");

	options.client_guid = GUID_random();
	ret = torture_smb2_connection_ext(tctx, 0, &options, &tree1);
	torture_assert_goto(tctx, ret, ret, done, "torture_smb2_connection_ext failed\n");

	options.client_guid = GUID_random();
	ret = torture_smb2_connection_ext(tctx, 0, &options, &tree2);
	torture_assert_goto(tctx, ret, ret, done,
			    "torture_smb2_connection_ext failed\n");

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;
	tree1->session->transport->lease.handler = torture_lease_handler;
	tree1->session->transport->lease.private_data = tree1;

	status = torture_setup_simple_file(tctx, tree1, fname);
	torture_assert_ntstatus_ok(tctx, status, "setup file failed\n");

	/*
	 * First open with RH lease
	 */
	smb2_lease_v2_create_share(&c,
				   &ls,
				   false,
				   fname,
				   smb2_util_share_access("R"),
				   1,
				   NULL,
				   smb2_util_lease_state("RH"),
				   0);
	c.in.durable_open_v2 = true;
	c.in.create_guid = GUID_random();
	c.in.desired_access = SEC_RIGHTS_FILE_READ;

	status = smb2_create(tree1, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	torture_assert_int_equal_goto(
		tctx,
		c.out.oplock_level,
		SMB2_OPLOCK_LEVEL_LEASE,
		ret, done,
		"Bad lease level\n");
	torture_assert_int_equal_goto(
		tctx,
		c.out.lease_response_v2.lease_state,
		smb2_util_lease_state("RH"),
		ret, done,
		"Bad lease level\n");

	/*
	 * Second open with RH lease
	 */
	smb2_lease_v2_create_share(&c,
				   &ls,
				   false,
				   fname,
				   smb2_util_share_access("R"),
				   2,
				   NULL,
				   smb2_util_lease_state("RH"),
				   0);
	c.in.durable_open_v2 = true;
	c.in.create_guid = GUID_random();
	c.in.desired_access = SEC_RIGHTS_FILE_READ;

	status = smb2_create(tree1, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = c.out.file.handle;

	torture_assert_int_equal_goto(
		tctx,
		c.out.oplock_level,
		SMB2_OPLOCK_LEVEL_LEASE,
		ret, done,
		"Bad lease level\n");
	torture_assert_int_equal_goto(
		tctx,
		c.out.lease_response_v2.lease_state,
		smb2_util_lease_state("RH"),
		ret, done,
		"Bad lease level\n");

	/*
	 * Third open triggering a sharing violation and two H-lease breaks
	 */

	smb2_lease_v2_create_share(&c,
				   &ls,
				   false,
				   fname,
				   smb2_util_share_access(""),
				   3,
				   NULL,
				   smb2_util_lease_state("RH"),
				   0);
	c.in.durable_open_v2 = true;
	c.in.create_guid = GUID_random();

	req = smb2_create_send(tree2, &c);
	torture_assert_not_null_goto(tctx, req, ret, done,
				     "smb2_create_send failed\n");

	while (!req->cancel.can_cancel &&
	       (req->state < SMB2_REQUEST_DONE))
	{
		rc = tevent_loop_once(req->transport->ev);
		torture_assert_goto(tctx, rc == 0, ret, done,
				    "tevent_loop_once failed\n");
	}
	torture_assert_goto(tctx, req->state < SMB2_REQUEST_DONE,
			    ret, done,
			    "Expected async interim response\n");

	/* Wait for first break */
	torture_wait_for_lease_break(tctx);

	if (lease_break_info.lease_break.current_lease.lease_key.data[0] == 1) {
		broken_ls_key = 1;
		ch1 = h1;
		ch2 = h2;
		ZERO_STRUCT(h1);
		ZERO_STRUCT(h2);
	} else {
		broken_ls_key = 2;
		ch1 = h2;
		ch2 = h1;
		ZERO_STRUCT(h1);
		ZERO_STRUCT(h2);
	}

	/* Wait for second break */
	torture_wait_for_lease_break(tctx);

	CHECK_VAL(lease_break_info.count, 2);
	lease_break_info.count = 1; /* trick CHECK_BREAK_INFO_V2_NOWAIT() */
	CHECK_BREAK_INFO_V2_NOWAIT(tree1->session->transport,
			    "RH",
			    "R",
			    broken_ls_key,
			    2);

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	status = smb2_util_close(tree1, ch1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	ZERO_STRUCT(ch1);

	CHECK_NO_BREAK(tctx);

	status = smb2_util_close(tree1, ch2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	ZERO_STRUCT(ch2);

	status = smb2_create_recv(req, tctx, &c);
	torture_assert_ntstatus_equal_goto(
		tctx, status, NT_STATUS_OK,
		ret, done, "smb2_create failed\n");

	status = smb2_util_close(tree2, c.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree1, h2);
	}
	if (!smb2_util_handle_empty(ch1)) {
		smb2_util_close(tree1, ch1);
	}
	if (!smb2_util_handle_empty(ch2)) {
		smb2_util_close(tree1, ch2);
	}
	smb2_util_unlink(_tree, fname);
	TALLOC_FREE(tree1);
	TALLOC_FREE(tree2);
	TALLOC_FREE(mem_ctx);
	return ret;
}

struct torture_suite *torture_smb2_lease_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "lease");

	torture_suite_add_1smb2_test(suite, "request", test_lease_request);
	torture_suite_add_1smb2_test(suite, "break_twice",
				     test_lease_break_twice);
	torture_suite_add_1smb2_test(suite, "nobreakself",
				     test_lease_nobreakself);
	torture_suite_add_1smb2_test(suite, "statopen", test_lease_statopen);
	torture_suite_add_1smb2_test(suite, "statopen2", test_lease_statopen2);
	torture_suite_add_1smb2_test(suite, "statopen3", test_lease_statopen3);
	torture_suite_add_1smb2_test(suite, "statopen4", test_lease_statopen4);
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
	torture_suite_add_2smb2_test(suite, "lock2", test_lease_lock2);
	torture_suite_add_2smb2_test(suite, "lock3", test_lease_lock3);
	torture_suite_add_2smb2_test(suite, "sharing_violation", test_lease_sharing_violation);
	torture_suite_add_1smb2_test(suite, "complex1", test_lease_complex1);
	torture_suite_add_1smb2_test(suite, "v2_flags_breaking", test_lease_v2_flags_breaking);
	torture_suite_add_1smb2_test(suite, "v2_flags_parentkey", test_lease_v2_flags_parentkey);
	torture_suite_add_1smb2_test(suite, "v2_epoch1", test_lease_v2_epoch1);
	torture_suite_add_1smb2_test(suite, "v2_epoch2", test_lease_v2_epoch2);
	torture_suite_add_1smb2_test(suite, "v2_epoch3", test_lease_v2_epoch3);
	torture_suite_add_1smb2_test(suite, "v2_complex1", test_lease_v2_complex1);
	torture_suite_add_1smb2_test(suite, "v2_complex2", test_lease_v2_complex2);
	torture_suite_add_1smb2_test(suite, "v2_rename", test_lease_v2_rename);
	torture_suite_add_1smb2_test(suite, "dynamic_share", test_lease_dynamic_share);
	torture_suite_add_1smb2_test(suite, "timeout", test_lease_timeout);
	torture_suite_add_1smb2_test(suite, "unlink", test_lease_unlink);
	torture_suite_add_1smb2_test(suite, "timeout-disconnect", test_lease_timeout_disconnect);
	torture_suite_add_1smb2_test(suite, "rename_wait",
				test_lease_rename_wait);
	torture_suite_add_1smb2_test(suite, "duplicate_create",
				test_lease_duplicate_create);
	torture_suite_add_1smb2_test(suite, "duplicate_open",
				test_lease_duplicate_open);
	torture_suite_add_1smb2_test(suite, "v1_bug15148",
				test_lease_v1_bug_15148);
	torture_suite_add_1smb2_test(suite, "v2_bug15148",
				test_lease_v2_bug_15148);
	torture_suite_add_1smb2_test(suite, "v2_rename_target_overwrite",
				test_lease_v2_rename_target_overwrite);
	torture_suite_add_1smb2_test(suite, "initial_delete_tdis",
				     test_initial_delete_tdis);
	torture_suite_add_1smb2_test(suite, "initial_delete_logoff",
				     test_initial_delete_logoff);
	torture_suite_add_1smb2_test(suite, "initial_delete_disconnect",
				     test_initial_delete_disconnect);
	torture_suite_add_2smb2_test(suite, "rename_dir_openfile",
				     torture_rename_dir_openfile);
	torture_suite_add_1smb2_test(suite, "lease-epoch", test_lease_epoch);
	torture_suite_add_1smb2_test(suite, "two-leases", test_two_leases);

	suite->description = talloc_strdup(suite, "SMB2-LEASE tests");

	return suite;
}

enum dirlease_test {
	DLT_SETEOF,
	DLT_SETDOS,
	DLT_BTIME,
	DLT_MTIME,
	DLT_CTIME,
	DLT_ATIME,
};

static void prepare_setinfo(enum dirlease_test t,
			    union smb_setfileinfo *s,
			    struct smb2_handle *h)
{
	s->generic.in.file.handle = *h;

	switch (t) {
	case DLT_SETEOF:
		s->end_of_file_info.in.size++;
		break;
	case DLT_SETDOS:
		s->basic_info.in.attrib ^= FILE_ATTRIBUTE_HIDDEN;
		if (s->basic_info.in.attrib == 0) {
			s->basic_info.in.attrib = FILE_ATTRIBUTE_NORMAL;
		}
		break;
	case DLT_BTIME:
		s->basic_info.in.create_time++;
		break;
	case DLT_MTIME:
		s->basic_info.in.write_time++;
		break;
	case DLT_CTIME:
		s->basic_info.in.change_time++;
		break;
	case DLT_ATIME:
		s->basic_info.in.access_time++;
		break;
	default:
		break;
	}
}

static bool test_dirlease_setinfo(struct torture_context *tctx,
				  TALLOC_CTX *mem_ctx,
				  enum dirlease_test t,
				  struct smb2_tree *tree,
				  struct smb2_tree *tree2,
				  const char *dname,
				  const char *dnamefname,
				  struct smb2_handle *dirh,
				  struct smb2_lease *dirlease,
				  union smb_setfileinfo *s)
{
	struct smb2_create c;
	struct smb2_lease ls1;
	struct smb2_handle h1 = {};
	NTSTATUS status;
	bool ret = true;

	/* 1. Same client */

	/* 1.1. Handle with correct parent lease key -> no break */
	smb2_lease_v2_create_share(&c, &ls1, false, dnamefname,
				   smb2_util_share_access("RWD"),
				   LEASE2, &LEASE1,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	prepare_setinfo(t, s, &h1);
	status = smb2_setinfo_file(tree, s);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_filefailed");
	CHECK_NO_BREAK(tctx);

	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* 1.2. Handle with bad parent lease key -> break */
	smb2_lease_v2_create_share(&c, &ls1, false, dnamefname,
				   smb2_util_share_access("RWD"),
				   LEASE2, &LEASE3,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	prepare_setinfo(t, s, &h1);
	status = smb2_setinfo_file(tree, s);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_filefailed");
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", LEASE1, ++(dirlease->lease_epoch));
	torture_reset_lease_break_info(tctx, &lease_break_info);
	ret = test_rearm_dirlease(mem_ctx, tctx, tree, dname,
				  LEASE1, &dirlease->lease_epoch);
	torture_assert_goto(tctx, ret == true, ret, done,
			    "Rearm dirlease failed\n");

	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* 1.3. Handle with no parent lease key -> break */
	smb2_lease_v2_create_share(&c, &ls1, false, dnamefname,
				   smb2_util_share_access("RWD"),
				   LEASE2, NULL,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	prepare_setinfo(t, s, &h1);
	status = smb2_setinfo_file(tree, s);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_filefailed");
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", LEASE1, ++(dirlease->lease_epoch));
	torture_reset_lease_break_info(tctx, &lease_break_info);
	ret = test_rearm_dirlease(mem_ctx, tctx, tree, dname,
				  LEASE1, &dirlease->lease_epoch);
	torture_assert_goto(tctx, ret == true, ret, done,
			    "Rearm dirlease failed\n");

	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* 2. Second client */

	/* 2.1. Handle with correct parent lease key -> no break */
	smb2_lease_v2_create_share(&c, &ls1, false, dnamefname,
				   smb2_util_share_access("RWD"),
				   LEASE2, &LEASE1,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree2, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	prepare_setinfo(t, s, &h1);
	status = smb2_setinfo_file(tree2, s);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_filefailed");
	CHECK_NO_BREAK(tctx);

	smb2_util_close(tree2, h1);
	ZERO_STRUCT(h1);

	/* 2.2. Handle with bad parent lease key -> break */
	smb2_lease_v2_create_share(&c, &ls1, false, dnamefname,
				   smb2_util_share_access("RWD"),
				   LEASE2, &LEASE3,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree2, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	prepare_setinfo(t, s, &h1);
	status = smb2_setinfo_file(tree2, s);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_filefailed");
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", LEASE1, ++(dirlease->lease_epoch));
	torture_reset_lease_break_info(tctx, &lease_break_info);
	ret = test_rearm_dirlease(mem_ctx, tctx, tree, dname,
				  LEASE1, &dirlease->lease_epoch);
	torture_assert_goto(tctx, ret == true, ret, done,
			    "Rearm dirlease failed\n");

	smb2_util_close(tree2, h1);
	ZERO_STRUCT(h1);

	/* 2.3. Handle with no parent lease key -> break */
	smb2_lease_v2_create_share(&c, &ls1, false, dnamefname,
				   smb2_util_share_access("RWD"),
				   LEASE2, NULL,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree2, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	prepare_setinfo(t, s, &h1);
	status = smb2_setinfo_file(tree2, s);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_filefailed");
	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", LEASE1, ++(dirlease->lease_epoch));
	torture_reset_lease_break_info(tctx, &lease_break_info);
	ret = test_rearm_dirlease(mem_ctx, tctx, tree, dname,
				  LEASE1, &dirlease->lease_epoch);
	torture_assert_goto(tctx, ret == true, ret, done,
			    "Rearm dirlease failed\n");

	smb2_util_close(tree2, h1);
	ZERO_STRUCT(h1);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree2, h1);
	}
	return ret;
}

static bool test_dirlease_seteof(struct torture_context *tctx,
				 struct smb2_tree *tree,
				 struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create c;
	struct smb2_lease dirlease;
	struct smb2_handle dirh = {};
	const char *dname = "test_dirlease_seteof_dir";
	const char *dnamefname = "test_dirlease_seteof_dir\\lease.dat";
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, dname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Get an RH directory lease on the test directory */

	smb2_lease_v2_create_share(&c, &dirlease, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	dirh = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, LEASE1, 0, 0, ++dirlease.lease_epoch);

	/*
	 * TEST: test setting EOF
	 *
	 * Test from same and second client, and test with correct, bad and no
	 * parent lease key.
	 */

	sfinfo.generic.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;

	ret = test_dirlease_setinfo(tctx, mem_ctx, DLT_SETEOF, tree, tree2,
				    dname, dnamefname,
				    &dirh, &dirlease, &sfinfo);
	torture_assert_goto(tctx, ret, ret, done, "seteof test failed\n");

done:
	if (!smb2_util_handle_empty(dirh)) {
		smb2_util_close(tree, dirh);
	}
	smb2_deltree(tree, dname);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_dirlease_setdos(struct torture_context *tctx,
				 struct smb2_tree *tree,
				 struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create c;
	struct smb2_lease dirlease;
	struct smb2_handle dirh = {};
	const char *dname = "test_dirlease_setdos_dir";
	const char *dnamefname = "test_dirlease_setdos_dir\\lease.dat";
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, dname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Get an RH directory lease on the test directory */

	smb2_lease_v2_create_share(&c, &dirlease, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	dirh = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, LEASE1, 0, 0, ++dirlease.lease_epoch);

	/*
	 * TEST: Test setting DOS attributes
	 *
	 * Test from same and second client, and test with correct, bad and no
	 * parent lease key.
	 */

	sfinfo.basic_info.in.attrib = FILE_ATTRIBUTE_HIDDEN;
	sfinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;

	ret = test_dirlease_setinfo(tctx, mem_ctx, DLT_SETDOS, tree, tree2,
				    dname, dnamefname,
				    &dirh, &dirlease, &sfinfo);
	torture_assert_goto(tctx, ret, ret, done, "setdos test failed\n");

done:
	if (!smb2_util_handle_empty(dirh)) {
		smb2_util_close(tree, dirh);
	}
	smb2_deltree(tree, dname);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * TEST: Test setting creation date
 */
static bool test_dirlease_setbtime(struct torture_context *tctx,
				   struct smb2_tree *tree,
				   struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create c;
	struct smb2_lease dirlease;
	struct smb2_handle dirh = {};
	const char *dname = "test_dirlease_setbtime_dir";
	const char *dnamefname = "test_dirlease_setbtime_dir\\lease.dat";
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, dname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Get an RH directory lease on the test directory */

	smb2_lease_v2_create_share(&c, &dirlease, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	dirh = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, LEASE1, 0, 0, ++dirlease.lease_epoch);

	sfinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	unix_to_nt_time(&sfinfo.basic_info.in.create_time, time(NULL) + 9*30*24*60*60);

	ret = test_dirlease_setinfo(tctx, mem_ctx, DLT_BTIME, tree, tree2,
				    dname, dnamefname,
				    &dirh, &dirlease, &sfinfo);
	torture_assert_goto(tctx, ret, ret, done, "setbtime test failed\n");

done:
	if (!smb2_util_handle_empty(dirh)) {
		smb2_util_close(tree, dirh);
	}
	smb2_deltree(tree, dname);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * TEST: Test setting modification date
 */
static bool test_dirlease_setmtime(struct torture_context *tctx,
				   struct smb2_tree *tree,
				   struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create c;
	struct smb2_lease dirlease;
	struct smb2_handle dirh = {};
	const char *dname = "test_dirlease_setmtime_dir";
	const char *dnamefname = "test_dirlease_setmtime_dir\\lease.dat";
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, dname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Get an RH directory lease on the test directory */

	smb2_lease_v2_create_share(&c, &dirlease, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	dirh = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, LEASE1, 0, 0, ++dirlease.lease_epoch);

	sfinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	unix_to_nt_time(&sfinfo.basic_info.in.create_time, time(NULL) + 9*30*24*60*60);

	ret = test_dirlease_setinfo(tctx, mem_ctx, DLT_MTIME, tree, tree2,
				    dname, dnamefname,
				    &dirh, &dirlease, &sfinfo);
	torture_assert_goto(tctx, ret, ret, done, "setmtime test failed\n");

done:
	if (!smb2_util_handle_empty(dirh)) {
		smb2_util_close(tree, dirh);
	}
	smb2_deltree(tree, dname);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * TEST: Test setting inode change date
 */
static bool test_dirlease_setctime(struct torture_context *tctx,
				   struct smb2_tree *tree,
				   struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create c;
	struct smb2_lease dirlease;
	struct smb2_handle dirh = {};
	const char *dname = "test_dirlease_setctime_dir";
	const char *dnamefname = "test_dirlease_setctime_dir\\lease.dat";
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, dname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Get an RH directory lease on the test directory */

	smb2_lease_v2_create_share(&c, &dirlease, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	dirh = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, LEASE1, 0, 0, ++dirlease.lease_epoch);

	sfinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	unix_to_nt_time(&sfinfo.basic_info.in.change_time, time(NULL) + 9*30*24*60*60);

	ret = test_dirlease_setinfo(tctx, mem_ctx, DLT_CTIME, tree, tree2,
				    dname, dnamefname,
				    &dirh, &dirlease, &sfinfo);
	torture_assert_goto(tctx, ret, ret, done, "setctime test failed\n");

done:
	if (!smb2_util_handle_empty(dirh)) {
		smb2_util_close(tree, dirh);
	}
	smb2_deltree(tree, dname);
	talloc_free(mem_ctx);
	return ret;
}

/*
 * TEST: Test setting last access date
 */
static bool test_dirlease_setatime(struct torture_context *tctx,
				   struct smb2_tree *tree,
				   struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create c;
	struct smb2_lease dirlease;
	struct smb2_handle dirh = {};
	const char *dname = "test_dirlease_setatime_dir";
	const char *dnamefname = "test_dirlease_setatime_dir\\lease.dat";
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, dname);

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	/* Get an RH directory lease on the test directory */

	smb2_lease_v2_create_share(&c, &dirlease, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RHW"), 0);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	dirh = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, LEASE1, 0, 0, ++dirlease.lease_epoch);

	sfinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	unix_to_nt_time(&sfinfo.basic_info.in.access_time, time(NULL) + 9*30*24*60*60);

	ret = test_dirlease_setinfo(tctx, mem_ctx, DLT_ATIME, tree, tree2,
				    dname, dnamefname,
				    &dirh, &dirlease, &sfinfo);
	torture_assert_goto(tctx, ret, ret, done, "setctime test failed\n");

done:
	if (!smb2_util_handle_empty(dirh)) {
		smb2_util_close(tree, dirh);
	}
	smb2_deltree(tree, dname);
	talloc_free(mem_ctx);
	return ret;
}

#define DLEASE1 0x0000000000000001ull
#define DLEASE2 0x0000000000000002ull
#define DLEASE3 0x0000000000000003ull

static struct dlt_rename {
	const char *testname;
	bool expect_srcdir_break;
	bool expect_dstdir_break;
	const char *srcdir;
	const char *dstdir;
	uint64_t srcdir_leasekey;
	uint64_t dstdir_leasekey;
	uint64_t parent_leasekey;
	const char *srcfname;
	const char *dstfname;
} dlt_renames[] = {
	{
		.testname = "samedir-correct-parent-leaskey",
		.expect_srcdir_break = false,
		.expect_dstdir_break = false,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE1,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir\\dstfile",
	}, {
		.testname = "samedir-wrong-parent-leaskey",
		.expect_srcdir_break = true,
		.expect_dstdir_break = false,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE3,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir\\dstfile",
	}, {
		.testname = "samedir-no-parent-leaskey",
		.expect_srcdir_break = true,
		.expect_dstdir_break = false,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = 0,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir\\dstfile",
	}, {
		.testname = "otherdir-correct-srcparent-leaskey",
		.expect_srcdir_break = false,
		.expect_dstdir_break = true,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir2",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE1,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir2\\dstfile",
	}, {
		.testname = "otherdir-correct-dstparent-leaskey",
		.expect_srcdir_break = true,
		.expect_dstdir_break = false,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir2",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE2,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir2\\dstfile",
	}, {
		.testname = "otherdir-wrong-parent-leaskey",
		.expect_srcdir_break = true,
		.expect_dstdir_break = true,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir2",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE3,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir2\\dstfile",
	}, {
		.testname = "otherdir-no-parent-leaskey",
		.expect_srcdir_break = true,
		.expect_dstdir_break = true,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir2",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = 0,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir2\\dstfile",
	}, {
		.testname = NULL,
	}
};

static bool test_rename_one(struct torture_context *tctx,
			    struct smb2_tree *tree,
			    struct dlt_rename *t)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create c;
	struct smb2_lease dirlease1;
	struct smb2_lease dirlease2;
	struct smb2_handle dirh1 = {};
	struct smb2_handle dirh2 = {};
	struct smb2_lease lease1;
	struct smb2_handle h1 = {};
	struct smb2_lease_break_ack ack = {};
	bool samedir = strequal(t->srcdir, t->dstdir);
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	torture_comment(tctx, "\nRename subtest: %s\n"
			"==================================\n",
			t->testname);

	smb2_deltree(tree, t->srcdir);
	smb2_deltree(tree, t->dstdir);
	torture_reset_lease_break_info(tctx, &lease_break_info);


	/* Get an RH directory lease on the src directory */
	smb2_lease_v2_create_share(&c, &dirlease1, true, t->srcdir,
				   smb2_util_share_access("RWD"),
				   t->srcdir_leasekey, NULL,
				   smb2_util_lease_state("RHW"), 0);
	c.in.desired_access &= ~DELETE_ACCESS;
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	dirh1 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, t->srcdir_leasekey, 0, 0, ++dirlease1.lease_epoch);

	if (!samedir) {
		/* Get an RH directory lease on the dst directory */
		smb2_lease_v2_create_share(&c, &dirlease2, true, t->dstdir,
					   smb2_util_share_access("RWD"),
					   t->dstdir_leasekey, NULL,
					   smb2_util_lease_state("RHW"), 0);
		c.in.desired_access &= ~DELETE_ACCESS;
		status = smb2_create(tree, mem_ctx, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		dirh2 = c.out.file.handle;
		CHECK_LEASE_V2(&c, "RH", true, t->dstdir_leasekey, 0, 0, ++dirlease2.lease_epoch);
	}

	/* Create the to be renamed file */
	smb2_lease_v2_create_share(&c, &lease1, false, t->srcfname,
				   smb2_util_share_access("RWD"),
				   LEASE4, &t->srcdir_leasekey,
				   smb2_util_lease_state("RHW"),
				   0x33);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* Open the testfile, possibly with a bad parent leasekey */
	smb2_lease_v2_create_share(&c, &lease1, false, t->srcfname,
				   smb2_util_share_access("RWD"),
				   LEASE4,
				   t->parent_leasekey != 0 ? &t->parent_leasekey : NULL,
				   smb2_util_lease_state("RHW"),
				   0x33);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	sfinfo.generic.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	sfinfo.rename_information.in.new_name = t->dstfname;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");
	if (t->expect_srcdir_break) {
		/* Delay the ack in order to be able to possibly process two breaks */
		lease_break_info.lease_skip_ack = true;
		CHECK_BREAK_INFO_V2(tree->session->transport,
				    "RH", "",
				    t->srcdir_leasekey,
				    ++dirlease1.lease_epoch);
		ack.in.lease.lease_key = lease_break_info.lease_break.current_lease.lease_key;
		ack.in.lease.lease_state = lease_break_info.lease_break.new_lease_state;
		torture_reset_lease_break_info(tctx, &lease_break_info);
		if (!t->expect_dstdir_break) {
			CHECK_NO_BREAK(tctx);
		}
	}
	if (t->expect_dstdir_break) {
		CHECK_BREAK_INFO_V2(tree->session->transport,
				    "RH", "",
				    t->dstdir_leasekey,
				    ++dirlease2.lease_epoch);
		torture_reset_lease_break_info(tctx, &lease_break_info);
		if (!t->expect_srcdir_break) {
			CHECK_NO_BREAK(tctx);
		}
	}
	if (!t->expect_srcdir_break && !t->expect_dstdir_break) {
		CHECK_NO_BREAK(tctx);
	}

	if (t->expect_srcdir_break) {
		/* ack the first lease break. */
		status = smb2_lease_break_ack(tree, &ack);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_lease_break_ack failed\n");
		CHECK_LEASE_BREAK_ACK(&ack, "", t->srcdir_leasekey);
	}


done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(dirh1)) {
		smb2_util_close(tree, dirh1);
	}
	if (!smb2_util_handle_empty(dirh2)) {
		smb2_util_close(tree, dirh2);
	}
	smb2_deltree(tree, t->srcdir);
	smb2_deltree(tree, t->dstdir);
	return ret;
}

static bool test_rename(struct torture_context *tctx,
			struct smb2_tree *tree)
{
	struct dlt_rename *t = NULL;
	bool ret = true;

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	for (t = dlt_renames; t->testname != NULL; t++) {
		ret = test_rename_one(tctx, tree, t);
		torture_assert_goto(tctx, ret, ret, done,
				    talloc_asprintf(tctx, "%s failed\n",
						    t->testname));
	}

done:
	return ret;
}

static bool test_rename_dst_parent(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *srcdir = "test_rename_dst_parent_src";
	const char *srcfile = "test_rename_dst_parent_src\\file";
	const char *dstdir = "test_rename_dst_parent_dst";
	const char *dstfile = "test_rename_dst_parent_dst\\file";
	struct smb2_create create_dp;
	struct smb2_lease lease_dp;
	struct smb2_handle h1 = {};
	struct smb2_handle handle_sf = {};
	struct smb2_handle handle_dp = {};
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	status = torture_smb2_testdir(tree, srcdir, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);

	status = torture_smb2_testdir(tree, dstdir, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);

	status = smb2_create_simple_file(tctx, tree, srcfile, &handle_sf);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create_simple_file\n");

	/* Get a RH lease on the destination parent */

	smb2_lease_v2_create_share(&create_dp, &lease_dp, true, dstdir,
				   smb2_util_share_access("RWD"),
				   0x01, NULL,
				   smb2_util_lease_state("RH"), 0);
	create_dp.in.desired_access = DELETE_ACCESS;
	status = smb2_create(tree, mem_ctx, &create_dp);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	handle_dp = create_dp.out.file.handle;
	CHECK_LEASE_V2(&create_dp, "RH", true, 0x01, 0, 0, 1);

	/*
	 * Rename, expect break on dst parent. As we'll be keeping our
	 * conflicting open, the rename should fail.
	 */

	sfinfo.generic.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfinfo.generic.in.file.handle = handle_sf;
	sfinfo.rename_information.in.new_name = dstfile;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_equal_goto(
		tctx, status, NT_STATUS_SHARING_VIOLATION, ret, done,
		"smb2_setinfo_file\n");

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "R", 0x01, 2);

	/* Upgrade lease to "RH" */

	smb2_lease_v2_create_share(&create_dp, &lease_dp, true, dstdir,
				   smb2_util_share_access("RWD"),
				   0x01, NULL,
				   smb2_util_lease_state("RH"), 0);
	create_dp.in.desired_access = DELETE_ACCESS;
	status = smb2_create(tree, mem_ctx, &create_dp);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = create_dp.out.file.handle;
	smb2_util_close(tree, h1);
	CHECK_LEASE_V2(&create_dp, "RH", true, 0x01, 0, 0, 3);

	/*
	 * Rename, expect break on dst parent. Let the break
	 * handler close the handle so the rename should pass.
	 */

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_handle = handle_dp;

	sfinfo.generic.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfinfo.generic.in.file.handle = handle_sf;
	sfinfo.rename_information.in.new_name = dstfile;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	CHECK_LEASE_BREAK(&lease_break_info.lease_break, "RH", "R", 0x01);

done:
	if (!smb2_util_handle_empty(handle_sf)) {
		smb2_util_close(tree, handle_sf);
	}
	if (!smb2_util_handle_empty(handle_dp)) {
		smb2_util_close(tree, handle_dp);
	}
	smb2_deltree(tree, srcdir);
	smb2_deltree(tree, dstdir);
	return ret;
}

static bool test_overwrite(struct torture_context *tctx,
			   struct smb2_tree *tree,
			   struct smb2_tree *tree2)
{
	struct smb2_create c = {};
	struct smb2_lease dirlease1 = {};
	struct smb2_handle dirh1 = {};
	struct smb2_lease lease1 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_request *req = NULL;
	struct smb2_lease_break_ack ack = {};
	struct smb2_lease *expected_lease1 = NULL;
	struct smb2_lease *expected_lease2 = NULL;
	uint64_t expected_leasekey1;
	uint64_t expected_leasekey2;
	const char *dname = "test_overwrite_dir";
	const char *fname = "test_overwrite_dir\\fname";
	int n;
	NTSTATUS status;
	bool ret = true;

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	n = smb2_deltree(tree, dname);
	torture_assert_goto(tctx, n != -1, ret, done, "smb2_deltree failed\n");

	/* Get an RH directory lease on the directory */
	smb2_lease_v2_create_share(&c, &dirlease1, true, dname,
				   smb2_util_share_access("RWD"),
				   LEASE1, NULL,
				   smb2_util_lease_state("RH"), 0);
	c.in.desired_access &= ~DELETE_ACCESS;
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	dirh1 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, LEASE1, 0, 0, ++dirlease1.lease_epoch);

	/* Create a file with parent leasekey set*/
	smb2_lease_v2_create_share(&c, &lease1, false, fname,
				   smb2_util_share_access("RWD"),
				   LEASE2, &LEASE1,
				   smb2_util_lease_state("RH"), 0);
	c.in.desired_access &= ~DELETE_ACCESS;
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, LEASE2,
		       SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET, LEASE1,
		       ++lease1.lease_epoch);

	CHECK_NO_BREAK(tctx);

	/* Second client opens with overwrite disposition */
	c = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OVERWRITE,
		.in.file_attributes = FILE_ATTRIBUTE_ARCHIVE,
		.in.fname = fname,
	};
	req = smb2_create_send(tree2, &c);
	torture_assert(tctx, req != NULL, "smb2_create_send failed\n");
	torture_assert(tctx, req->state == SMB2_REQUEST_RECV, "req2 pending");

	torture_wait_for_lease_break(tctx);

	/*
	 * Expect two lease breaks (dir and file) and accept the lease breaks in
	 * any order.
	 */
	ack.in.lease.lease_key = lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state = lease_break_info.lease_break.new_lease_state;
	if (ack.in.lease.lease_key.data[0] == LEASE1) {
		expected_leasekey1 = LEASE1;
		expected_lease1 = &dirlease1;
		expected_leasekey2 = LEASE2;
		expected_lease2 = &lease1;
	} else {
		expected_leasekey1 = LEASE2;
		expected_lease1 = &lease1;
		expected_leasekey2 = LEASE1;
		expected_lease2 = &dirlease1;
	}

	/* Break 1 */

	CHECK_BREAK_INFO_V2_NOWAIT(tree->session->transport,
				   "RH", "", expected_leasekey1,
				   ++(expected_lease1->lease_epoch));

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	status = smb2_lease_break_ack(tree, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "", expected_leasekey1);

	/* Break 2 */

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", expected_leasekey2,
			    ++(expected_lease2->lease_epoch));
	ack.in.lease.lease_key = lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state = lease_break_info.lease_break.new_lease_state;

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	status = smb2_lease_break_ack(tree, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "", expected_leasekey2);

	status = smb2_create_recv(req, tctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create_recv failed\n");
	h2 = c.out.file.handle;

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}
	if (!smb2_util_handle_empty(dirh1)) {
		smb2_util_close(tree, dirh1);
	}

	n = smb2_deltree(tree, dname);
	torture_assert(tctx, n != -1, "smb2_deltree failed\n");
	return ret;
}

static struct dlt_hardlink {
	const char *testname;
	bool expect_srcdir_break;
	bool expect_dstdir_break;
	const char *srcdir;
	const char *dstdir;
	uint64_t srcdir_leasekey;
	uint64_t dstdir_leasekey;
	uint64_t parent_leasekey;
	const char *srcfname;
	const char *dstfname;
} dlt_hardlinks[] = {
	{
		.testname = "samedir-correct-parent-leaskey",
		.expect_srcdir_break = false,
		.expect_dstdir_break = false,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE1,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir\\dstfile",
	}, {
		.testname = "samedir-wrong-parent-leaskey",
		.expect_srcdir_break = true,
		.expect_dstdir_break = false,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE3,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir\\dstfile",
	}, {
		.testname = "samedir-no-parent-leaskey",
		.expect_srcdir_break = true,
		.expect_dstdir_break = false,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = 0,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir\\dstfile",
	}, {
		.testname = "otherdir-correct-srcparent-leaskey",
		.expect_srcdir_break = false,
		.expect_dstdir_break = true,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir2",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE1,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir2\\dstfile",
	}, {
		.testname = "otherdir-correct-dstparent-leaskey",
		.expect_srcdir_break = false,
		.expect_dstdir_break = false,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir2",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE2,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir2\\dstfile",
	}, {
		.testname = "otherdir-wrong-parent-leaskey",
		.expect_srcdir_break = false,
		.expect_dstdir_break = true,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir2",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = DLEASE3,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir2\\dstfile",
	}, {
		.testname = "otherdir-no-parent-leaskey",
		.expect_srcdir_break = false,
		.expect_dstdir_break = true,
		.srcdir = "test_dirlease_rename_dir",
		.dstdir = "test_dirlease_rename_dir2",
		.srcdir_leasekey = DLEASE1,
		.dstdir_leasekey = DLEASE2,
		.parent_leasekey = 0,
		.srcfname = "test_dirlease_rename_dir\\srcfile",
		.dstfname = "test_dirlease_rename_dir2\\dstfile",
	}, {
		.testname = NULL,
	}
};

static bool test_hardlink_one(struct torture_context *tctx,
			    struct smb2_tree *tree,
			    struct dlt_hardlink *t)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create c;
	struct smb2_lease dirlease1;
	struct smb2_lease dirlease2;
	struct smb2_handle dirh1 = {};
	struct smb2_handle dirh2 = {};
	struct smb2_lease lease1;
	struct smb2_handle h1 = {};
	struct smb2_lease_break_ack ack = {};
	bool samedir = strequal(t->srcdir, t->dstdir);
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	torture_comment(tctx, "\nHardlink subtest: %s\n"
			"==================================\n",
			t->testname);

	smb2_deltree(tree, t->srcdir);
	smb2_deltree(tree, t->dstdir);
	torture_reset_lease_break_info(tctx, &lease_break_info);


	/* Get an RH directory lease on the src directory */
	smb2_lease_v2_create_share(&c, &dirlease1, true, t->srcdir,
				   smb2_util_share_access("RWD"),
				   t->srcdir_leasekey, NULL,
				   smb2_util_lease_state("RHW"), 0);
	c.in.desired_access &= ~DELETE_ACCESS;
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	dirh1 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, t->srcdir_leasekey, 0, 0, ++dirlease1.lease_epoch);

	if (!samedir) {
		/* Get an RH directory lease on the dst directory */
		smb2_lease_v2_create_share(&c, &dirlease2, true, t->dstdir,
					   smb2_util_share_access("RWD"),
					   t->dstdir_leasekey, NULL,
					   smb2_util_lease_state("RHW"), 0);
		c.in.desired_access &= ~DELETE_ACCESS;
		status = smb2_create(tree, mem_ctx, &c);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_create failed\n");
		dirh2 = c.out.file.handle;
		CHECK_LEASE_V2(&c, "RH", true, t->dstdir_leasekey, 0, 0, ++dirlease2.lease_epoch);
	}

	/* Create the to be hardlinkd file */
	smb2_lease_v2_create_share(&c, &lease1, false, t->srcfname,
				   smb2_util_share_access("RWD"),
				   LEASE4, &t->srcdir_leasekey,
				   smb2_util_lease_state("RHW"),
				   0x33);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;
	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	/* Open the testfile, possibly with a bad parent leasekey */
	smb2_lease_v2_create_share(&c, &lease1, false, t->srcfname,
				   smb2_util_share_access("RWD"),
				   LEASE4,
				   t->parent_leasekey != 0 ? &t->parent_leasekey : NULL,
				   smb2_util_lease_state("RHW"),
				   0x33);
	status = smb2_create(tree, mem_ctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	sfinfo.generic.level = RAW_SFILEINFO_LINK_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	sfinfo.link_information.in.new_name = t->dstfname;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");
	if (t->expect_srcdir_break) {
		/* Delay the ack in order to be able to possibly process two breaks */
		lease_break_info.lease_skip_ack = true;
		CHECK_BREAK_INFO_V2(tree->session->transport,
				    "RH", "",
				    t->srcdir_leasekey,
				    ++dirlease1.lease_epoch);
		ack.in.lease.lease_key = lease_break_info.lease_break.current_lease.lease_key;
		ack.in.lease.lease_state = lease_break_info.lease_break.new_lease_state;
		torture_reset_lease_break_info(tctx, &lease_break_info);
		if (!t->expect_dstdir_break) {
			CHECK_NO_BREAK(tctx);
		}
	}
	if (t->expect_dstdir_break) {
		CHECK_BREAK_INFO_V2(tree->session->transport,
				    "RH", "",
				    t->dstdir_leasekey,
				    ++dirlease2.lease_epoch);
		torture_reset_lease_break_info(tctx, &lease_break_info);
		if (!t->expect_srcdir_break) {
			CHECK_NO_BREAK(tctx);
		}
	}
	if (!t->expect_srcdir_break && !t->expect_dstdir_break) {
		CHECK_NO_BREAK(tctx);
	}

	if (t->expect_srcdir_break) {
		/* ack the first lease break. */
		status = smb2_lease_break_ack(tree, &ack);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_lease_break_ack failed\n");
		CHECK_LEASE_BREAK_ACK(&ack, "", t->srcdir_leasekey);
	}


done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(dirh1)) {
		smb2_util_close(tree, dirh1);
	}
	if (!smb2_util_handle_empty(dirh2)) {
		smb2_util_close(tree, dirh2);
	}
	smb2_deltree(tree, t->srcdir);
	smb2_deltree(tree, t->dstdir);
	return ret;
}

static bool test_hardlink(struct torture_context *tctx,
			struct smb2_tree *tree)
{
	struct dlt_hardlink *t = NULL;
	bool ret = true;

	tree->session->transport->lease.handler	= torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	for (t = dlt_hardlinks; t->testname != NULL; t++) {
		ret = test_hardlink_one(tctx, tree, t);
		torture_assert_goto(tctx, ret, ret, done,
				    talloc_asprintf(tctx, "%s failed\n",
						    t->testname));
	}

done:
	return ret;
}

/*
 * If the parent key of handle on which delete-on-close was set is the same as
 * the parent key of last handle closed, don't break this parent lease but all
 * others.
 */
static bool test_unlink_same_set_and_close(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	struct smb2_create c = {};
	struct smb2_handle d1 = {};
	struct smb2_handle d2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_lease dlease1 = {};
	struct smb2_lease dlease2 = {};
	const uint64_t dlk1 = DLEASE1;
	const uint64_t dlk2 = DLEASE2;
	struct smb2_lease flease1 = {};
	struct smb2_lease flease2 = {};
	const char *dname = "test_unlink";
	const char *fname = "test_unlink\\test_unlink.dat";
	union smb_setfileinfo sfinfo = {};
	NTSTATUS status;
	bool ret = true;

	tree->session->transport->lease.handler = torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);

	smb2_deltree(tree, dname);
	smb2_util_mkdir(tree, dname);
	torture_setup_simple_file(tctx, tree, fname);

	torture_comment(tctx, "First open test directory with RH-dirlease\n");

	smb2_lease_v2_create(&c, &dlease1, true, dname,
			     DLEASE1, NULL,
			     smb2_util_lease_state("RH"), 0);
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	d1 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, DLEASE1, 0, 0, ++dlease1.lease_epoch);

	torture_comment(tctx, "Second open test directory with RH-dirlease\n");

	smb2_lease_v2_create(&c, &dlease2, true, dname,
			     DLEASE2, NULL,
			     smb2_util_lease_state("RH"), 0);
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	d2 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, DLEASE2, 0, 0, ++dlease2.lease_epoch);

	torture_comment(tctx, "First open test file\n");

	smb2_lease_v2_create(&c, &flease1, false, fname,
			     LEASE1, &dlk1,
			     smb2_util_lease_state("R"), 0);

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	torture_comment(tctx, "Second open test file\n");

	smb2_lease_v2_create(&c, &flease2, false, fname,
			     LEASE2, &dlk2,
			     smb2_util_lease_state("R"), 0);

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = c.out.file.handle;

	torture_comment(tctx, "Sets delete on close on open 2\n");

	sfinfo.disposition_info.in.delete_on_close = 1;
	sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.generic.in.file.handle = h2;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	torture_comment(tctx, "Closing first handle that has not set delete-on-close, "
			"this should not trigger a break\n");

	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);
	CHECK_NO_BREAK(tctx);

	torture_comment(tctx, "Closing second and last handle will remove the file, "
			"trigger a break on first directory with different "
			"parent lease key\n");

	smb2_util_close(tree, h2);
	ZERO_STRUCT(h2);

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", DLEASE1,
			    ++dlease1.lease_epoch);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	if (!smb2_util_handle_empty(d1)) {
		smb2_util_close(tree, d1);
	}
	if (!smb2_util_handle_empty(d2)) {
		smb2_util_close(tree, d2);
	}
	return ret;
}

/*
 * When the parent key of handle on which delete-on-close was set differs from
 * the parent key of last handle closed, which actually does delete the file,
 * all directory leases must be broken.
 */
static bool test_unlink_different_set_and_close(struct torture_context *tctx,
						struct smb2_tree *tree)
{
	struct smb2_create c = {};
	struct smb2_handle d1 = {};
	struct smb2_handle d2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_lease dlease1 = {};
	struct smb2_lease dlease2 = {};
	const uint64_t dlk1 = DLEASE1;
	const uint64_t dlk2 = DLEASE2;
	struct smb2_lease flease1 = {};
	struct smb2_lease flease2 = {};
	const char *dname = "test_unlink";
	const char *fname = "test_unlink\\test_unlink.dat";
	union smb_setfileinfo sfinfo = {};
	struct smb2_lease_break_ack ack = {};
	struct smb2_lease *expected_lease1 = NULL;
	struct smb2_lease *expected_lease2 = NULL;
	uint64_t expected_leasekey1;
	uint64_t expected_leasekey2;
	NTSTATUS status;
	bool ret = true;

	tree->session->transport->lease.handler = torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	smb2_deltree(tree, dname);
	smb2_util_mkdir(tree, dname);
	torture_setup_simple_file(tctx, tree, fname);

	torture_comment(tctx, "First open test directory with RH-dirlease\n");

	smb2_lease_v2_create(&c, &dlease1, true, dname,
			     DLEASE1, NULL,
			     smb2_util_lease_state("RH"), 0);
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	d1 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, DLEASE1, 0, 0, ++dlease1.lease_epoch);

	torture_comment(tctx, "Second open test directory with RH-dirlease\n");

	smb2_lease_v2_create(&c, &dlease2, true, dname,
			     DLEASE2, NULL,
			     smb2_util_lease_state("RH"), 0);
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	d2 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, DLEASE2, 0, 0, ++dlease2.lease_epoch);

	torture_comment(tctx, "First open test file\n");

	smb2_lease_v2_create(&c, &flease1, false, fname,
			     LEASE1, &dlk1,
			     smb2_util_lease_state("R"), 0);

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	torture_comment(tctx, "Second open test file\n");

	smb2_lease_v2_create(&c, &flease2, false, fname,
			     LEASE2, &dlk2,
			     smb2_util_lease_state("R"), 0);

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = c.out.file.handle;

	torture_comment(tctx, "Client 1 sets delete on close\n");

	sfinfo.disposition_info.in.delete_on_close = 1;
	sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	sfinfo.generic.in.file.handle = h1;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	torture_comment(tctx, "Closing first handle that has set delete-on-close, "
			"will not delete the file and not trigger a break\n");

	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);
	CHECK_NO_BREAK(tctx);

	torture_comment(tctx, "Closing second and last handle will remove the file, "
			"and trigger a break as the parent lease keys don't match\n");

	smb2_util_close(tree, h2);
	ZERO_STRUCT(h2);

	torture_wait_for_lease_break(tctx);
	ack.in.lease.lease_key = lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state = lease_break_info.lease_break.new_lease_state;

	if (ack.in.lease.lease_key.data[0] == DLEASE1) {
		expected_leasekey1 = DLEASE1;
		expected_lease1 = &dlease1;
		expected_leasekey2 = DLEASE2;
		expected_lease2 = &dlease2;
	} else {
		expected_leasekey1 = DLEASE2;
		expected_lease1 = &dlease2;
		expected_leasekey2 = DLEASE1;
		expected_lease2 = &dlease1;
	}

	CHECK_BREAK_INFO_V2_NOWAIT(tree->session->transport,
				   "RH", "", expected_leasekey1,
				   ++(expected_lease1->lease_epoch));

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	status = smb2_lease_break_ack(tree, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "", expected_leasekey1);

	CHECK_BREAK_INFO_V2_NOWAIT(tree->session->transport,
				   "RH", "", expected_leasekey2,
				   ++(expected_lease2->lease_epoch));

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	if (!smb2_util_handle_empty(d1)) {
		smb2_util_close(tree, d1);
	}
	if (!smb2_util_handle_empty(d2)) {
		smb2_util_close(tree, d2);
	}
	return ret;
}

/*
 * If the parent key of handle on which initial delete-on-close was requested is
 * the same as the parent key of last handle closed, don't break that parent
 * lease but all others.
 */
static bool test_unlink_same_initial_and_close(struct torture_context *tctx,
					       struct smb2_tree *tree)
{
	struct smb2_create c = {};
	struct smb2_handle d1 = {};
	struct smb2_handle d2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_lease dlease1 = {};
	struct smb2_lease dlease2 = {};
	const uint64_t dlk1 = DLEASE1;
	const uint64_t dlk2 = DLEASE2;
	struct smb2_lease flease1 = {};
	struct smb2_lease flease2 = {};
	const char *dname = "test_unlink";
	const char *fname = "test_unlink\\test_unlink.dat";
	NTSTATUS status;
	bool ret = true;

	tree->session->transport->lease.handler = torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	smb2_deltree(tree, dname);
	smb2_util_mkdir(tree, dname);
	torture_setup_simple_file(tctx, tree, fname);

	torture_comment(tctx, "First open test directory with RH-dirlease\n");

	smb2_lease_v2_create(&c, &dlease1, true, dname,
			     DLEASE1, NULL,
			     smb2_util_lease_state("RH"), 0);
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	d1 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, DLEASE1, 0, 0, ++dlease1.lease_epoch);

	torture_comment(tctx, "Second open test directory with RH-dirlease\n");

	smb2_lease_v2_create(&c, &dlease2, true, dname,
			     DLEASE2, NULL,
			     smb2_util_lease_state("RH"), 0);
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	d2 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, DLEASE2, 0, 0, ++dlease2.lease_epoch);

	torture_comment(tctx, "First open test file with initial delete-on-close\n");

	smb2_lease_v2_create(&c, &flease1, false, fname,
			     LEASE1, &dlk1,
			     smb2_util_lease_state("R"), 0);
	c.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	torture_comment(tctx, "Second open test file\n");

	smb2_lease_v2_create(&c, &flease2, false, fname,
			     LEASE2, &dlk2,
			     smb2_util_lease_state("R"), 0);

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = c.out.file.handle;

	torture_comment(tctx, "Closing second handle should not trigger a lease break\n");

	smb2_util_close(tree, h2);
	ZERO_STRUCT(h2);

	torture_comment(tctx, "Closing first handle that had initial delete-on-close, "
			"must trigger single break on directory handle 2\n");

	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

	CHECK_BREAK_INFO_V2(tree->session->transport,
			    "RH", "", DLEASE2,
			    ++dlease2.lease_epoch);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	if (!smb2_util_handle_empty(d1)) {
		smb2_util_close(tree, d1);
	}
	if (!smb2_util_handle_empty(d2)) {
		smb2_util_close(tree, d2);
	}
	return ret;
}

/*
 * When the parent key of handle on which initial delete-on-close was set
 * differs from the parent key of last handle closed, which actually does delete
 * the file, all directory leases must be broken.
 */
static bool test_unlink_different_initial_and_close(struct torture_context *tctx,
						    struct smb2_tree *tree)
{
	struct smb2_create c = {};
	struct smb2_handle d1 = {};
	struct smb2_handle d2 = {};
	struct smb2_handle h1 = {};
	struct smb2_handle h2 = {};
	struct smb2_lease dlease1 = {};
	struct smb2_lease dlease2 = {};
	const uint64_t dlk1 = DLEASE1;
	const uint64_t dlk2 = DLEASE2;
	struct smb2_lease flease1 = {};
	struct smb2_lease flease2 = {};
	const char *dname = "test_unlink";
	const char *fname = "test_unlink\\test_unlink.dat";
	struct smb2_lease_break_ack ack = {};
	struct smb2_lease *expected_lease1 = NULL;
	struct smb2_lease *expected_lease2 = NULL;
	uint64_t expected_leasekey1;
	uint64_t expected_leasekey2;
	NTSTATUS status;
	bool ret = true;

	tree->session->transport->lease.handler = torture_lease_handler;
	tree->session->transport->lease.private_data = tree;
	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	smb2_deltree(tree, dname);
	smb2_util_mkdir(tree, dname);
	torture_setup_simple_file(tctx, tree, fname);

	torture_comment(tctx, "First open test directory with RH-dirlease\n");

	smb2_lease_v2_create(&c, &dlease1, true, dname,
			     DLEASE1, NULL,
			     smb2_util_lease_state("RH"), 0);
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	d1 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, DLEASE1, 0, 0, ++dlease1.lease_epoch);

	torture_comment(tctx, "Second open test directory with RH-dirlease\n");

	smb2_lease_v2_create(&c, &dlease2, true, dname,
			     DLEASE2, NULL,
			     smb2_util_lease_state("RH"), 0);
	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	d2 = c.out.file.handle;
	CHECK_LEASE_V2(&c, "RH", true, DLEASE2, 0, 0, ++dlease2.lease_epoch);

	torture_comment(tctx, "First open test file\n");

	smb2_lease_v2_create(&c, &flease1, false, fname,
			     LEASE1, &dlk1,
			     smb2_util_lease_state("R"), 0);
	c.in.create_options = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h1 = c.out.file.handle;

	torture_comment(tctx, "Second open test file\n");

	smb2_lease_v2_create(&c, &flease2, false, fname,
			     LEASE2, &dlk2,
			     smb2_util_lease_state("R"), 0);

	status = smb2_create(tree, tree, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h2 = c.out.file.handle;

	torture_comment(tctx, "Closing first handle that requested initial delete-on-close, "
			"will not delete the file and not trigger a break\n");

	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);
	CHECK_NO_BREAK(tctx);

	torture_comment(tctx, "Closing second and last handle will remove the file, "
			"and trigger a break as the parent lease keys don't match\n");

	smb2_util_close(tree, h2);
	ZERO_STRUCT(h2);

	torture_wait_for_lease_break(tctx);
	ack.in.lease.lease_key = lease_break_info.lease_break.current_lease.lease_key;
	ack.in.lease.lease_state = lease_break_info.lease_break.new_lease_state;

	if (ack.in.lease.lease_key.data[0] == DLEASE1) {
		expected_leasekey1 = DLEASE1;
		expected_lease1 = &dlease1;
		expected_leasekey2 = DLEASE2;
		expected_lease2 = &dlease2;
	} else {
		expected_leasekey1 = DLEASE2;
		expected_lease1 = &dlease2;
		expected_leasekey2 = DLEASE1;
		expected_lease2 = &dlease1;
	}

	CHECK_BREAK_INFO_V2_NOWAIT(tree->session->transport,
				   "RH", "", expected_leasekey1,
				   ++(expected_lease1->lease_epoch));

	torture_reset_lease_break_info(tctx, &lease_break_info);
	lease_break_info.lease_skip_ack = true;

	status = smb2_lease_break_ack(tree, &ack);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lease_break_ack failed\n");
	CHECK_LEASE_BREAK_ACK(&ack, "", expected_leasekey1);

	CHECK_BREAK_INFO_V2_NOWAIT(tree->session->transport,
				   "RH", "", expected_leasekey2,
				   ++(expected_lease2->lease_epoch));

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree, h2);
	}
	if (!smb2_util_handle_empty(d1)) {
		smb2_util_close(tree, d1);
	}
	if (!smb2_util_handle_empty(d2)) {
		smb2_util_close(tree, d2);
	}
	return ret;
}

struct torture_suite *torture_smb2_dirlease_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "dirlease");

	suite->description = talloc_strdup(suite, "SMB3 Directory Lease tests");

	torture_suite_add_1smb2_test(suite, "v2_request_parent", test_lease_v2_request_parent);
	torture_suite_add_2smb2_test(suite, "v2_request", test_lease_v2_request);
	torture_suite_add_1smb2_test(suite, "oplocks", test_dirlease_oplocks);
	torture_suite_add_1smb2_test(suite, "leases", test_dirlease_leases);
	torture_suite_add_2smb2_test(suite, "seteof", test_dirlease_seteof);
	torture_suite_add_2smb2_test(suite, "setdos", test_dirlease_setdos);
	torture_suite_add_2smb2_test(suite, "setbtime", test_dirlease_setbtime);
	torture_suite_add_2smb2_test(suite, "setmtime", test_dirlease_setmtime);
	torture_suite_add_2smb2_test(suite, "setctime", test_dirlease_setctime);
	torture_suite_add_2smb2_test(suite, "setatime", test_dirlease_setatime);
	torture_suite_add_1smb2_test(suite, "rename", test_rename);
	torture_suite_add_1smb2_test(suite, "rename_dst_parent", test_rename_dst_parent);
	torture_suite_add_2smb2_test(suite, "overwrite", test_overwrite);
	torture_suite_add_1smb2_test(suite, "hardlink", test_hardlink);
	torture_suite_add_1smb2_test(suite, "unlink_same_set_and_close", test_unlink_same_set_and_close);
	torture_suite_add_1smb2_test(suite, "unlink_different_set_and_close", test_unlink_different_set_and_close);
	torture_suite_add_1smb2_test(suite, "unlink_same_initial_and_close", test_unlink_same_initial_and_close);
	torture_suite_add_1smb2_test(suite, "unlink_different_initial_and_close", test_unlink_different_initial_and_close);
	return suite;
}
