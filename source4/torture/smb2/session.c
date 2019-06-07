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
#include "auth/credentials/credentials_krb5.h"
#include "libcli/security/security.h"
#include "libcli/resolve/resolve.h"
#include "lib/param/param.h"
#include "lib/util/tevent_ntstatus.h"

#define CHECK_CREATED(tctx, __io, __created, __attribute)			\
	do {									\
		torture_assert_int_equal(tctx, (__io)->out.create_action,	\
						NTCREATEX_ACTION_ ## __created,	\
						"out.create_action incorrect");	\
		torture_assert_int_equal(tctx, (__io)->out.size, 0,		\
						"out.size incorrect");		\
		torture_assert_int_equal(tctx, (__io)->out.file_attr,		\
						(__attribute),			\
						"out.file_attr incorrect");	\
		torture_assert_int_equal(tctx, (__io)->out.reserved2, 0,	\
				"out.reserverd2 incorrect");			\
	} while(0)

/**
 * basic test for doing a session reconnect
 */
bool test_session_reconnect1(struct torture_context *tctx, struct smb2_tree *tree)
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
	struct smb2_tree *tree2 = NULL;
	union smb_fileinfo qfinfo;

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "session_reconnect_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* disconnect, reconnect and then do durable reopen */
	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	torture_assert_goto(tctx, torture_smb2_connection_ext(tctx, previous_session_id,
			    &tree->session->transport->options, &tree2),
			    ret, done,
			    "session reconnect failed\n");

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_USER_SESSION_DELETED,
					   ret, done, "smb2_getinfo_file "
					   "returned unexpected status");
	h1 = NULL;

	smb2_oplock_create_share(&io2, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree2, mem_ctx, &io2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");

	CHECK_CREATED(tctx, &io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");
	_h2 = io2.out.file.handle;
	h2 = &_h2;

done:
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}
	if (h2 != NULL) {
		smb2_util_close(tree2, *h2);
	}

	if (tree2 != NULL) {
		smb2_util_unlink(tree2, fname);
	}
	smb2_util_unlink(tree, fname);

	talloc_free(tree);
	talloc_free(tree2);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic test for doing a session reconnect on one connection
 */
bool test_session_reconnect2(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	uint64_t previous_session_id;
	bool ret = true;
	struct smb2_session *session2 = NULL;
	union smb_fileinfo qfinfo;

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "session_reconnect_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* disconnect, reconnect and then do durable reopen */
	previous_session_id = smb2cli_session_current_id(tree->session->smbXcli);

	torture_assert(tctx, torture_smb2_session_setup(tctx, tree->session->transport,
				previous_session_id, tctx, &session2),
				"session reconnect (on the same connection) failed");

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_USER_SESSION_DELETED,
					   ret, done, "smb2_getinfo_file "
					   "returned unexpected status");
	h1 = NULL;

done:
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	talloc_free(tree);
	talloc_free(session2);

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
	snprintf(fname, sizeof(fname), "session_reauth1_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	status = smb2_session_setup_spnego(tree->session,
					   popt_get_cmdline_credentials(),
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	status = smb2_session_setup_spnego(tree->session,
					   popt_get_cmdline_credentials(),
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

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
	snprintf(fname, sizeof(fname), "session_reauth2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* re-authenticate as anonymous */

	anon_creds = cli_credentials_init_anon(mem_ctx);
	torture_assert(tctx, (anon_creds != NULL), "talloc error");

	status = smb2_session_setup_spnego(tree->session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	/* re-authenticate as original user again */

	status = smb2_session_setup_spnego(tree->session,
					   popt_get_cmdline_credentials(),
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

done:
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * test getting security descriptor after reauth
 */
bool test_session_reauth3(struct torture_context *tctx, struct smb2_tree *tree)
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
	uint32_t secinfo_flags = SECINFO_OWNER
				| SECINFO_GROUP
				| SECINFO_DACL
				| SECINFO_PROTECTED_DACL
				| SECINFO_UNPROTECTED_DACL;

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "session_reauth3_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* get the security descriptor */

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _h1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	/* re-authenticate as anonymous */

	anon_creds = cli_credentials_init_anon(mem_ctx);
	torture_assert(tctx, (anon_creds != NULL), "talloc error");

	status = smb2_session_setup_spnego(tree->session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _h1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	/* re-authenticate as original user again */

	status = smb2_session_setup_spnego(tree->session,
					   popt_get_cmdline_credentials(),
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _h1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

done:
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * test setting security descriptor after reauth.
 */
bool test_session_reauth4(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	bool ret = true;
	union smb_fileinfo qfinfo;
	union smb_setfileinfo sfinfo;
	struct cli_credentials *anon_creds = NULL;
	uint32_t secinfo_flags = SECINFO_OWNER
				| SECINFO_GROUP
				| SECINFO_DACL
				| SECINFO_PROTECTED_DACL
				| SECINFO_UNPROTECTED_DACL;
	struct security_descriptor *sd1;
	struct security_ace ace;
	struct dom_sid *extra_sid;

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "session_reauth4_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* get the security descriptor */

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _h1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	sd1 = qfinfo.query_secdesc.out.sd;

	/* re-authenticate as anonymous */

	anon_creds = cli_credentials_init_anon(mem_ctx);
	torture_assert(tctx, (anon_creds != NULL), "talloc error");

	status = smb2_session_setup_spnego(tree->session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* give full access on the file to anonymous */

	extra_sid = dom_sid_parse_talloc(tctx, SID_NT_ANONYMOUS);

	ZERO_STRUCT(ace);
	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;
	ace.access_mask = SEC_STD_ALL | SEC_FILE_ALL;
	ace.trustee = *extra_sid;

	status = security_descriptor_dacl_add(sd1, &ace);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"security_descriptor_dacl_add failed");

	ZERO_STRUCT(sfinfo);
	sfinfo.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	sfinfo.set_secdesc.in.file.handle = _h1;
	sfinfo.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	sfinfo.set_secdesc.in.sd = sd1;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed");

	/* re-authenticate as original user again */

	status = smb2_session_setup_spnego(tree->session,
					   popt_get_cmdline_credentials(),
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* re-get the security descriptor */

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _h1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	ret = true;

done:
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * test renaming after reauth.
 * compare security descriptors before and after rename/reauth
 */
bool test_session_reauth5(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char dname[128];
	char fname[256];
	char fname2[256];
	struct smb2_handle _dh1;
	struct smb2_handle *dh1 = NULL;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	bool ret = true;
	bool ok;
	union smb_fileinfo qfinfo;
	union smb_setfileinfo sfinfo;
	struct cli_credentials *anon_creds = NULL;
	uint32_t secinfo_flags = SECINFO_OWNER
				| SECINFO_GROUP
				| SECINFO_DACL
				| SECINFO_PROTECTED_DACL
				| SECINFO_UNPROTECTED_DACL;
	struct security_descriptor *f_sd1;
	struct security_descriptor *d_sd1 = NULL;
	struct security_ace ace;
	struct dom_sid *extra_sid;

	/* Add some random component to the file name. */
	snprintf(dname, sizeof(dname), "session_reauth5_%s.d",
		 generate_random_str(tctx, 8));
	snprintf(fname, sizeof(fname), "%s\\file.dat", dname);

	ok = smb2_util_setup_dir(tctx, tree, dname);
	torture_assert(tctx, ok, "smb2_util_setup_dir not ok");

	status = torture_smb2_testdir(tree, dname, &_dh1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed");
	dh1 = &_dh1;

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* get the security descriptor */

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _h1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	f_sd1 = qfinfo.query_secdesc.out.sd;

	/* re-authenticate as anonymous */

	anon_creds = cli_credentials_init_anon(mem_ctx);
	torture_assert(tctx, (anon_creds != NULL), "talloc error");

	status = smb2_session_setup_spnego(tree->session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* try to rename the file: fails */

	snprintf(fname2, sizeof(fname2), "%s\\file2.dat", dname);

	status = smb2_util_unlink(tree, fname2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_unlink failed");


	ZERO_STRUCT(sfinfo);
	sfinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfinfo.rename_information.in.file.handle = _h1;
	sfinfo.rename_information.in.overwrite = true;
	sfinfo.rename_information.in.new_name = fname2;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED,
					   ret, done, "smb2_setinfo_file "
					   "returned unexpected status");

	/* re-authenticate as original user again */

	status = smb2_session_setup_spnego(tree->session,
					   popt_get_cmdline_credentials(),
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* give full access on the file to anonymous */

	extra_sid = dom_sid_parse_talloc(tctx, SID_NT_ANONYMOUS);

	ZERO_STRUCT(ace);
	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;
	ace.access_mask = SEC_RIGHTS_FILE_ALL;
	ace.trustee = *extra_sid;

	status = security_descriptor_dacl_add(f_sd1, &ace);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"security_descriptor_dacl_add failed");

	ZERO_STRUCT(sfinfo);
	sfinfo.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	sfinfo.set_secdesc.in.file.handle = _h1;
	sfinfo.set_secdesc.in.secinfo_flags = secinfo_flags;
	sfinfo.set_secdesc.in.sd = f_sd1;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed");

	/* re-get the security descriptor */

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _h1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	/* re-authenticate as anonymous - again */

	anon_creds = cli_credentials_init_anon(mem_ctx);
	torture_assert(tctx, (anon_creds != NULL), "talloc error");

	status = smb2_session_setup_spnego(tree->session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* try to rename the file: fails */

	ZERO_STRUCT(sfinfo);
	sfinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfinfo.rename_information.in.file.handle = _h1;
	sfinfo.rename_information.in.overwrite = true;
	sfinfo.rename_information.in.new_name = fname2;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_ACCESS_DENIED,
					   ret, done, "smb2_setinfo_file "
					   "returned unexpected status");

	/* give full access on the parent dir to anonymous */

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _dh1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	d_sd1 = qfinfo.query_secdesc.out.sd;

	ZERO_STRUCT(ace);
	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;
	ace.access_mask = SEC_RIGHTS_FILE_ALL;
	ace.trustee = *extra_sid;

	status = security_descriptor_dacl_add(d_sd1, &ace);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"security_descriptor_dacl_add failed");

	ZERO_STRUCT(sfinfo);
	sfinfo.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	sfinfo.set_secdesc.in.file.handle = _dh1;
	sfinfo.set_secdesc.in.secinfo_flags = secinfo_flags;
	sfinfo.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	sfinfo.set_secdesc.in.sd = d_sd1;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed");

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _dh1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	status = smb2_util_close(tree, _dh1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed");
	dh1 = NULL;

	/* try to rename the file: still fails */

	ZERO_STRUCT(sfinfo);
	sfinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfinfo.rename_information.in.file.handle = _h1;
	sfinfo.rename_information.in.overwrite = true;
	sfinfo.rename_information.in.new_name = fname2;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status,
					NT_STATUS_ACCESS_DENIED,
					ret, done, "smb2_setinfo_file "
					"returned unexpected status");

	/* re-authenticate as original user - again */

	status = smb2_session_setup_spnego(tree->session,
					   popt_get_cmdline_credentials(),
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* rename the file - for verification that it works */

	ZERO_STRUCT(sfinfo);
	sfinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	sfinfo.rename_information.in.file.handle = _h1;
	sfinfo.rename_information.in.overwrite = true;
	sfinfo.rename_information.in.new_name = fname2;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed");

	/* closs the file, check it is gone and reopen under the new name */

	status = smb2_util_close(tree, _h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed");
	ZERO_STRUCT(io1);

	smb2_generic_create_share(&io1,
				  NULL /* lease */, false /* dir */,
				  fname,
				  NTCREATEX_DISP_OPEN,
				  smb2_util_share_access(""),
				  smb2_util_oplock_level("b"),
				  0 /* leasekey */, 0 /* leasestate */);

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_equal_goto(tctx, status,
					NT_STATUS_OBJECT_NAME_NOT_FOUND,
					ret, done, "smb2_create "
					"returned unexpected status");

	ZERO_STRUCT(io1);

	smb2_generic_create_share(&io1,
				  NULL /* lease */, false /* dir */,
				  fname2,
				  NTCREATEX_DISP_OPEN,
				  smb2_util_share_access(""),
				  smb2_util_oplock_level("b"),
				  0 /* leasekey */, 0 /* leasestate */);

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* try to access the file via the old handle */

	ZERO_STRUCT(qfinfo);

	qfinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	qfinfo.query_secdesc.in.file.handle = _h1;
	qfinfo.query_secdesc.in.secinfo_flags = secinfo_flags;

	status = smb2_getinfo_file(tree, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

done:
	if (dh1 != NULL) {
		smb2_util_close(tree, *dh1);
	}
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	smb2_deltree(tree, dname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}

/**
 * do reauth with wrong credentials,
 * hence triggering the error path in reauth.
 * The invalid reauth deletes the session.
 */
bool test_session_reauth6(struct torture_context *tctx, struct smb2_tree *tree)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	bool ret = true;
	char *corrupted_password;
	struct cli_credentials *broken_creds;
	bool ok;
	bool encrypted;
	NTSTATUS expected;
	enum credentials_use_kerberos krb_state;

	krb_state = cli_credentials_get_kerberos_state(
			popt_get_cmdline_credentials());
	if (krb_state == CRED_MUST_USE_KERBEROS) {
		torture_skip(tctx,
			     "Can't test failing session setup with kerberos.");
	}

	encrypted = smb2cli_tcon_is_encryption_on(tree->smbXcli);

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "session_reauth1_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/*
	 * reauthentication with invalid credentials:
	 */

	broken_creds = cli_credentials_shallow_copy(mem_ctx,
					    popt_get_cmdline_credentials());
	torture_assert(tctx, (broken_creds != NULL), "talloc error");

	corrupted_password = talloc_asprintf(mem_ctx, "%s%s",
				cli_credentials_get_password(broken_creds),
				"corrupt");
	torture_assert(tctx, (corrupted_password != NULL), "talloc error");

	ok = cli_credentials_set_password(broken_creds, corrupted_password,
					  CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_password not ok");

	status = smb2_session_setup_spnego(tree->session,
					   broken_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_equal_goto(tctx, status,
					NT_STATUS_LOGON_FAILURE, ret, done,
					"smb2_session_setup_spnego "
					"returned unexpected status");

	torture_comment(tctx, "did failed reauth\n");
	/*
	 * now verify that the invalid session reauth has closed our session
	 */

	if (encrypted) {
		expected = NT_STATUS_CONNECTION_DISCONNECTED;
	} else {
		expected = NT_STATUS_USER_SESSION_DELETED;
	}

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree, mem_ctx, &io1);
	torture_assert_ntstatus_equal_goto(tctx, status, expected,
					ret, done, "smb2_create "
					"returned unexpected status");

done:
	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	smb2_util_unlink(tree, fname);

	talloc_free(tree);

	talloc_free(mem_ctx);

	return ret;
}


static bool test_session_expire1i(struct torture_context *tctx,
				  bool force_signing,
				  bool force_encryption)
{
	NTSTATUS status;
	bool ret = false;
	struct smbcli_options options;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	struct smb2_tree *tree = NULL;
	enum credentials_use_kerberos use_kerberos;
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	union smb_fileinfo qfinfo;
	size_t i;

	use_kerberos = cli_credentials_get_kerberos_state(credentials);
	if (use_kerberos != CRED_MUST_USE_KERBEROS) {
		torture_warning(tctx, "smb2.session.expire1 requires -k yes!");
		torture_skip(tctx, "smb2.session.expire1 requires -k yes!");
	}

	torture_assert_int_equal(tctx, use_kerberos, CRED_MUST_USE_KERBEROS,
				 "please use -k yes");

	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	lpcfg_set_option(tctx->lp_ctx, "gensec_gssapi:requested_life_time=4");

	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	if (force_signing) {
		options.signing = SMB_SIGNING_REQUIRED;
	}

	status = smb2_connect(tctx,
			      host,
			      lpcfg_smb_ports(tctx->lp_ctx),
			      share,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_connect failed");

	if (force_encryption) {
		status = smb2cli_session_encryption_on(tree->session->smbXcli);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2cli_session_encryption_on failed");
	}

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "session_expire1_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, tctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* get the security descriptor */

	ZERO_STRUCT(qfinfo);

	qfinfo.access_information.level = RAW_FILEINFO_ACCESS_INFORMATION;
	qfinfo.access_information.in.file.handle = _h1;

	for (i=0; i < 2; i++) {
		torture_comment(tctx, "query info => OK\n");

		ZERO_STRUCT(qfinfo.access_information.out);
		status = smb2_getinfo_file(tree, tctx, &qfinfo);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_getinfo_file failed");

		torture_comment(tctx, "sleep 10 seconds\n");
		smb_msleep(10*1000);

		torture_comment(tctx, "query info => EXPIRED\n");
		ZERO_STRUCT(qfinfo.access_information.out);
		status = smb2_getinfo_file(tree, tctx, &qfinfo);
		torture_assert_ntstatus_equal_goto(tctx, status,
					NT_STATUS_NETWORK_SESSION_EXPIRED,
					ret, done, "smb2_getinfo_file "
					"returned unexpected status");

		/*
		 * the krb5 library may not handle expired creds
		 * well, lets start with an empty ccache.
		 */
		cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

		if (!force_encryption) {
			smb2cli_session_require_signed_response(
				tree->session->smbXcli, true);
		}

		torture_comment(tctx, "reauth => OK\n");
		status = smb2_session_setup_spnego(tree->session,
						   credentials,
						   0 /* previous_session_id */);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

		smb2cli_session_require_signed_response(
			tree->session->smbXcli, false);
	}

	ZERO_STRUCT(qfinfo.access_information.out);
	status = smb2_getinfo_file(tree, tctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	ret = true;
done:
	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	talloc_free(tree);
	lpcfg_set_option(tctx->lp_ctx, "gensec_gssapi:requested_life_time=0");
	return ret;
}

static bool test_session_expire1n(struct torture_context *tctx)
{
	return test_session_expire1i(tctx,
				     false,   /* force_signing */
				     false); /* force_encryption */
}

static bool test_session_expire1s(struct torture_context *tctx)
{
	return test_session_expire1i(tctx,
				     true,   /* force_signing */
				     false); /* force_encryption */
}

static bool test_session_expire1e(struct torture_context *tctx)
{
	return test_session_expire1i(tctx,
				     true,   /* force_signing */
				     true); /* force_encryption */
}

static bool test_session_expire2i(struct torture_context *tctx,
				  bool force_encryption)
{
	NTSTATUS status;
	bool ret = false;
	struct smbcli_options options;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	struct smb2_tree *tree = NULL;
	const char *unc = NULL;
	struct smb2_tree *tree2 = NULL;
	struct tevent_req *subreq = NULL;
	uint32_t timeout_msec;
	enum credentials_use_kerberos use_kerberos;
	uint32_t caps;
	char fname[256];
	struct smb2_handle dh;
	struct smb2_handle dh2;
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	union smb_fileinfo qfinfo;
	union smb_setfileinfo sfinfo;
	struct smb2_flush flsh;
	struct smb2_read rd;
	const uint8_t wd = 0;
	struct smb2_lock lck;
	struct smb2_lock_element el;
	struct smb2_ioctl ctl;
	struct smb2_break oack;
	struct smb2_lease_break_ack lack;
	struct smb2_find fnd;
	union smb_search_data *d = NULL;
	unsigned int count;
	struct smb2_request *req = NULL;
	struct smb2_notify ntf1;
	struct smb2_notify ntf2;

	use_kerberos = cli_credentials_get_kerberos_state(credentials);
	if (use_kerberos != CRED_MUST_USE_KERBEROS) {
		torture_warning(tctx, "smb2.session.expire2 requires -k yes!");
		torture_skip(tctx, "smb2.session.expire2 requires -k yes!");
	}

	torture_assert_int_equal(tctx, use_kerberos, CRED_MUST_USE_KERBEROS,
				 "please use -k yes");

	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	lpcfg_set_option(tctx->lp_ctx, "gensec_gssapi:requested_life_time=4");

	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	options.signing = SMB_SIGNING_REQUIRED;

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	torture_assert(tctx, unc != NULL, "talloc_asprintf");

	status = smb2_connect(tctx,
			      host,
			      lpcfg_smb_ports(tctx->lp_ctx),
			      share,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_connect failed");

	if (force_encryption) {
		status = smb2cli_session_encryption_on(tree->session->smbXcli);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2cli_session_encryption_on failed");
	}

	caps = smb2cli_conn_server_capabilities(tree->session->transport->conn);

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "session_expire2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	status = smb2_util_roothandle(tree, &dh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_roothandle failed");

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, tctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* get the security descriptor */

	ZERO_STRUCT(qfinfo);

	qfinfo.access_information.level = RAW_FILEINFO_ACCESS_INFORMATION;
	qfinfo.access_information.in.file.handle = _h1;

	torture_comment(tctx, "query info => OK\n");

	ZERO_STRUCT(qfinfo.access_information.out);
	status = smb2_getinfo_file(tree, tctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	torture_comment(tctx, "lock => OK\n");
	ZERO_STRUCT(lck);
	lck.in.locks		= &el;
	lck.in.lock_count	= 0x0001;
	lck.in.lock_sequence	= 0x00000000;
	lck.in.file.handle	= *h1;
	ZERO_STRUCT(el);
	el.flags		= SMB2_LOCK_FLAG_EXCLUSIVE |
				  SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
	el.offset		= 0x0000000000000000;
	el.length		= 0x0000000000000001;
	status = smb2_lock(tree, &lck);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lock lock failed");

	torture_comment(tctx, "1st notify => PENDING\n");
	ZERO_STRUCT(ntf1);
	ntf1.in.file.handle	= dh;
	ntf1.in.recursive	= 0x0000;
	ntf1.in.buffer_size	= 128;
	ntf1.in.completion_filter= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	ntf1.in.unknown		= 0x00000000;
	req = smb2_notify_send(tree, &ntf1);

	while (!req->cancel.can_cancel && req->state <= SMB2_REQUEST_RECV) {
		if (tevent_loop_once(tctx->ev) != 0) {
			break;
		}
	}

	torture_assert_goto(tctx, req->state <= SMB2_REQUEST_RECV, ret, done,
			    "smb2_notify finished");

	torture_comment(tctx, "sleep 10 seconds\n");
	smb_msleep(10*1000);

	torture_comment(tctx, "query info => EXPIRED\n");
	ZERO_STRUCT(qfinfo.access_information.out);
	status = smb2_getinfo_file(tree, tctx, &qfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_getinfo_file "
				"returned unexpected status");


	torture_comment(tctx, "set info => EXPIRED\n");
	ZERO_STRUCT(sfinfo);
	sfinfo.end_of_file_info.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
	sfinfo.end_of_file_info.in.file.handle = *h1;
	sfinfo.end_of_file_info.in.size = 1;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_setinfo_file "
				"returned unexpected status");

	torture_comment(tctx, "flush => EXPIRED\n");
	ZERO_STRUCT(flsh);
	flsh.in.file.handle = *h1;
	status = smb2_flush(tree, &flsh);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_flush "
				"returned unexpected status");

	torture_comment(tctx, "read => EXPIRED\n");
	ZERO_STRUCT(rd);
	rd.in.file.handle = *h1;
	rd.in.length      = 5;
	rd.in.offset      = 0;
	status = smb2_read(tree, tctx, &rd);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_read "
				"returned unexpected status");

	torture_comment(tctx, "write => EXPIRED\n");
	status = smb2_util_write(tree, *h1, &wd, 0, 1);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_util_write "
				"returned unexpected status");

	torture_comment(tctx, "ioctl => EXPIRED\n");
	ZERO_STRUCT(ctl);
	ctl.in.file.handle = *h1;
	ctl.in.function = FSCTL_SRV_ENUM_SNAPS;
	ctl.in.max_output_response = 16;
	ctl.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	status = smb2_ioctl(tree, tctx, &ctl);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_ioctl "
				"returned unexpected status");

	torture_comment(tctx, "oplock ack => EXPIRED\n");
	ZERO_STRUCT(oack);
	oack.in.file.handle = *h1;
	status = smb2_break(tree, &oack);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_break "
				"returned unexpected status");

	if (caps & SMB2_CAP_LEASING) {
		torture_comment(tctx, "lease ack => EXPIRED\n");
		ZERO_STRUCT(lack);
		lack.in.lease.lease_version = 1;
		lack.in.lease.lease_key.data[0] = 1;
		lack.in.lease.lease_key.data[1] = 2;
		status = smb2_lease_break_ack(tree, &lack);
		torture_assert_ntstatus_equal_goto(tctx, status,
					NT_STATUS_NETWORK_SESSION_EXPIRED,
					ret, done, "smb2_break "
					"returned unexpected status");
	}

	torture_comment(tctx, "query directory => EXPIRED\n");
	ZERO_STRUCT(fnd);
	fnd.in.file.handle	= dh;
	fnd.in.pattern		= "*";
	fnd.in.continue_flags	= SMB2_CONTINUE_FLAG_SINGLE;
	fnd.in.max_response_size= 0x100;
	fnd.in.level		= SMB2_FIND_BOTH_DIRECTORY_INFO;
	status = smb2_find_level(tree, tree, &fnd, &count, &d);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_find_level "
				"returned unexpected status");

	torture_comment(tctx, "1st notify => CANCEL\n");
	smb2_cancel(req);

	torture_comment(tctx, "2nd notify => EXPIRED\n");
	ZERO_STRUCT(ntf2);
	ntf2.in.file.handle	= dh;
	ntf2.in.recursive	= 0x0000;
	ntf2.in.buffer_size	= 128;
	ntf2.in.completion_filter= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	ntf2.in.unknown		= 0x00000000;
	status = smb2_notify(tree, tctx, &ntf2);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_notify "
				"returned unexpected status");

	torture_assert_goto(tctx, req->state > SMB2_REQUEST_RECV, ret, done,
			    "smb2_notify (1st) not finished");

	status = smb2_notify_recv(req, tctx, &ntf1);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_CANCELLED,
				ret, done, "smb2_notify cancelled"
				"returned unexpected status");

	torture_comment(tctx, "tcon => EXPIRED\n");
	tree2 = smb2_tree_init(tree->session, tctx, false);
	torture_assert(tctx, tree2 != NULL, "smb2_tree_init");
	timeout_msec = tree->session->transport->options.request_timeout * 1000;
	subreq = smb2cli_tcon_send(tree2, tctx->ev,
				   tree2->session->transport->conn,
				   timeout_msec,
				   tree2->session->smbXcli,
				   tree2->smbXcli,
				   0, /* flags */
				   unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");
	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");
	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2cli_tcon"
				"returned unexpected status");

	torture_comment(tctx, "create => EXPIRED\n");
	status = smb2_util_roothandle(tree, &dh2);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_util_roothandle"
				"returned unexpected status");

	torture_comment(tctx, "tdis => EXPIRED\n");
	status = smb2_tdis(tree);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2cli_tdis"
				"returned unexpected status");

	/*
	 * (Un)Lock, Close and Logoff are still possible
	 */

	torture_comment(tctx, "1st unlock => OK\n");
	el.flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_lock unlock failed");

	torture_comment(tctx, "2nd unlock => RANGE_NOT_LOCKED\n");
	status = smb2_lock(tree, &lck);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_RANGE_NOT_LOCKED,
				ret, done, "smb2_lock 2nd unlock"
				"returned unexpected status");

	torture_comment(tctx, "lock => EXPIRED\n");
	el.flags		= SMB2_LOCK_FLAG_EXCLUSIVE |
				  SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
	status = smb2_lock(tree, &lck);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_util_roothandle"
				"returned unexpected status");

	torture_comment(tctx, "close => OK\n");
	status = smb2_util_close(tree, *h1);
	h1 = NULL;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_close failed");

	torture_comment(tctx, "echo without session => OK\n");
	status = smb2_keepalive(tree->session->transport);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_keepalive without session failed");

	torture_comment(tctx, "echo with session => OK\n");
	req = smb2_keepalive_send(tree->session->transport, tree->session);
	status = smb2_keepalive_recv(req);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_keepalive with session failed");

	torture_comment(tctx, "logoff => OK\n");
	status = smb2_logoff(tree->session);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_logoff failed");

	ret = true;
done:
	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	talloc_free(tree);
	lpcfg_set_option(tctx->lp_ctx, "gensec_gssapi:requested_life_time=0");
	return ret;
}

static bool test_session_expire2s(struct torture_context *tctx)
{
	return test_session_expire2i(tctx,
				     false); /* force_encryption */
}

static bool test_session_expire2e(struct torture_context *tctx)
{
	return test_session_expire2i(tctx,
				     true); /* force_encryption */
}

static bool test_session_expire_disconnect(struct torture_context *tctx)
{
	NTSTATUS status;
	bool ret = false;
	struct smbcli_options options;
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	struct smb2_tree *tree = NULL;
	enum credentials_use_kerberos use_kerberos;
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	union smb_fileinfo qfinfo;
	bool connected;

	use_kerberos = cli_credentials_get_kerberos_state(credentials);
	if (use_kerberos != CRED_MUST_USE_KERBEROS) {
		torture_warning(tctx, "smb2.session.expire1 requires -k yes!");
		torture_skip(tctx, "smb2.session.expire1 requires -k yes!");
	}

	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	lpcfg_set_option(tctx->lp_ctx, "gensec_gssapi:requested_life_time=4");
	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	options.signing = SMB_SIGNING_REQUIRED;

	status = smb2_connect(tctx,
			      host,
			      lpcfg_smb_ports(tctx->lp_ctx),
			      share,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_connect failed");

	smbXcli_session_set_disconnect_expired(tree->session->smbXcli);

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "session_expire1_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));
	io1.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;

	status = smb2_create(tree, tctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* get the security descriptor */

	ZERO_STRUCT(qfinfo);

	qfinfo.access_information.level = RAW_FILEINFO_ACCESS_INFORMATION;
	qfinfo.access_information.in.file.handle = _h1;

	torture_comment(tctx, "query info => OK\n");

	ZERO_STRUCT(qfinfo.access_information.out);
	status = smb2_getinfo_file(tree, tctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	torture_comment(tctx, "sleep 10 seconds\n");
	smb_msleep(10*1000);

	torture_comment(tctx, "query info => EXPIRED\n");
	ZERO_STRUCT(qfinfo.access_information.out);
	status = smb2_getinfo_file(tree, tctx, &qfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_NETWORK_SESSION_EXPIRED,
					   ret, done, "smb2_getinfo_file "
					   "returned unexpected status");

	connected = smbXcli_conn_is_connected(tree->session->transport->conn);
	torture_assert_goto(tctx, !connected, ret, done, "connected\n");

	ret = true;
done:
	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	talloc_free(tree);
	lpcfg_set_option(tctx->lp_ctx, "gensec_gssapi:requested_life_time=0");
	return ret;
}

bool test_session_bind1(struct torture_context *tctx, struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = popt_get_cmdline_credentials();
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	union smb_fileinfo qfinfo;
	bool ret = false;
	struct smb2_tree *tree2 = NULL;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smbcli_options options2;
	struct smb2_transport *transport2 = NULL;
	struct smb2_session *session1_1 = tree1->session;
	struct smb2_session *session1_2 = NULL;
	struct smb2_session *session2_1 = NULL;
	struct smb2_session *session2_2 = NULL;
	uint32_t caps;

	caps = smb2cli_conn_server_capabilities(transport1->conn);
	if (!(caps & SMB2_CAP_MULTI_CHANNEL)) {
		torture_skip(tctx, "server doesn't support SMB2_CAP_MULTI_CHANNEL\n");
	}

	/*
	 * We always want signing for this test!
	 */
	smb2cli_tcon_should_sign(tree1->smbXcli, true);
	options2 = transport1->options;
	options2.signing = SMB_SIGNING_REQUIRED;

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "session_bind1_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	status = smb2_create(tree1, mem_ctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	status = smb2_connect(tctx,
			      host,
			      lpcfg_smb_ports(tctx->lp_ctx),
			      share,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree2,
			      tctx->ev,
			      &options2,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_connect failed");
	session2_2 = tree2->session;
	transport2 = tree2->session->transport;

	/*
	 * Now bind the 2nd transport connection to the 1st session
	 */
	session1_2 = smb2_session_channel(transport2,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree2,
					  session1_1);
	torture_assert(tctx, session1_2 != NULL, "smb2_session_channel failed");

	status = smb2_session_setup_spnego(session1_2,
					   popt_get_cmdline_credentials(),
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/* use the 1st connection, 1st session */
	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	tree1->session = session1_1;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	/* use the 2nd connection, 1st session */
	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1;
	tree1->session = session1_2;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	tree1->session = session1_1;
	status = smb2_util_close(tree1, *h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed");
	h1 = NULL;

	/*
	 * Now bind the 1st transport connection to the 2nd session
	 */
	session2_1 = smb2_session_channel(transport1,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree1,
					  session2_2);
	torture_assert(tctx, session2_1 != NULL, "smb2_session_channel failed");

	status = smb2_session_setup_spnego(session2_1,
					   popt_get_cmdline_credentials(),
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	tree2->session = session2_1;
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_unlink failed");
	ret = true;
done:
	talloc_free(tree2);
	tree1->session = session1_1;

	if (h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}

	smb2_util_unlink(tree1, fname);

	talloc_free(tree1);

	talloc_free(mem_ctx);

	return ret;
}

struct torture_suite *torture_smb2_session_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "session");

	torture_suite_add_1smb2_test(suite, "reconnect1", test_session_reconnect1);
	torture_suite_add_1smb2_test(suite, "reconnect2", test_session_reconnect2);
	torture_suite_add_1smb2_test(suite, "reauth1", test_session_reauth1);
	torture_suite_add_1smb2_test(suite, "reauth2", test_session_reauth2);
	torture_suite_add_1smb2_test(suite, "reauth3", test_session_reauth3);
	torture_suite_add_1smb2_test(suite, "reauth4", test_session_reauth4);
	torture_suite_add_1smb2_test(suite, "reauth5", test_session_reauth5);
	torture_suite_add_1smb2_test(suite, "reauth6", test_session_reauth6);
	torture_suite_add_simple_test(suite, "expire1n", test_session_expire1n);
	torture_suite_add_simple_test(suite, "expire1s", test_session_expire1s);
	torture_suite_add_simple_test(suite, "expire1e", test_session_expire1e);
	torture_suite_add_simple_test(suite, "expire2s", test_session_expire2s);
	torture_suite_add_simple_test(suite, "expire2e", test_session_expire2e);
	torture_suite_add_simple_test(suite, "expire_disconnect",
				      test_session_expire_disconnect);
	torture_suite_add_1smb2_test(suite, "bind1", test_session_bind1);

	suite->description = talloc_strdup(suite, "SMB2-SESSION tests");

	return suite;
}
