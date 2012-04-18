/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 session setups

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
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/cmdline/popt_common.h"
#include "auth/credentials/credentials.h"


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
 * basic test for doing a session reconnect
 */
bool test_session_reconnect(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_handle _h2;
	struct smb2_handle *h2 = NULL;
	struct smb2_create io1, io2;
	uint64_t previous_session_id;
	bool ret = true;
	struct smb2_tree *tree2;
	union smb_fileinfo qfinfo;

	/* Add some random component to the file name. */
	snprintf(fname, 256, "session_reconnect_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));

	/* disconnect, reconnect and then do durable reopen */
	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	if (!torture_smb2_connection_ext(tctx, previous_session_id, &tree2)) {
		torture_warning(tctx, "session reconnect failed\n");
		ret = false;
		goto done;
	}

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_USER_SESSION_DELETED);
	h1 = NULL;

	smb2_oplock_create_share(&io2, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.oplock_level, smb2_util_oplock_level("b"));
	_h2 = io2.out.file.handle;
	h2 = &_h2;

done:
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}
	if (h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	smb2_util_unlink(tree2, fname);

	talloc_free(tree);
	talloc_free(tree2);

	talloc_free(mem_ctx);

	return ret;
}

bool test_session_reauth1(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	bool ret = true;
	union smb_fileinfo qfinfo;

	/* Add some random component to the file name. */
	snprintf(fname, 256, "session_reauth1_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));

	status = smb2_session_setup_spnego(tree->session,
					   cmdline_credentials,
					   0 /* previous_session_id */);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_session_setup_spnego(tree->session,
					   cmdline_credentials,
					   0 /* previous_session_id */);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

bool test_session_reauth2(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	bool ret = true;
	union smb_fileinfo qfinfo;
	struct cli_credentials *anon_creds = NULL;

	/* Add some random component to the file name. */
	snprintf(fname, 256, "session_reauth2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.oplock_level, smb2_util_oplock_level("b"));

	/* re-authenticate as anonymous */

	anon_creds = cli_credentials_init_anon(mem_ctx);
	torture_assert(tctx, (anon_creds != NULL), "talloc error");

	status = smb2_session_setup_spnego(tree->session,
					   anon_creds,
					   0 /* previous_session_id */);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* re-authenticate as original user again */

	status = smb2_session_setup_spnego(tree->session,
					   cmdline_credentials,
					   0 /* previous_session_id */);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}


struct torture_suite *torture_smb2_session_init(void)
{
	struct torture_suite *suite =
	    torture_suite_create(talloc_autofree_context(), "session");

	torture_suite_add_1smb2_test(suite, "reconnect", test_session_reconnect);
	torture_suite_add_1smb2_test(suite, "reauth1", test_session_reauth1);
	torture_suite_add_1smb2_test(suite, "reauth2", test_session_reauth2);

	suite->description = talloc_strdup(suite, "SMB2-SESSION tests");

	return suite;
}
