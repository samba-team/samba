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
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/cmdline/cmdline.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_krb5.h"
#include "libcli/security/security.h"
#include "libcli/resolve/resolve.h"
#include "lib/param/param.h"
#include "lib/util/tevent_ntstatus.h"

/* Ticket lifetime we want to request in seconds */
#define KRB5_TICKET_LIFETIME 5
/* Allowed clock skew in seconds */
#define KRB5_CLOCKSKEW 5
/* Time till ticket fully expired in seconds */
#define KRB5_TICKET_EXPIRETIME KRB5_TICKET_LIFETIME + KRB5_CLOCKSKEW

#define texpand(x) #x
#define GENSEC_GSSAPI_REQUESTED_LIFETIME(x) \
	"gensec_gssapi:requested_life_time=" texpand(x)

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

#define WAIT_FOR_ASYNC_RESPONSE(req) \
	while (!req->cancel.can_cancel && req->state <= SMB2_REQUEST_RECV) { \
		if (tevent_loop_once(tctx->ev) != 0) { \
			break; \
		} \
	}

static void sleep_remaining(struct torture_context *tctx,
			    const struct timeval *endtime)
{
	struct timeval current = tevent_timeval_current();
	double remaining_secs = timeval_elapsed2(&current, endtime);

	remaining_secs = remaining_secs < 1.0 ? 1.0 : remaining_secs;
	torture_comment(
		tctx,
		"sleep for %2.f second(s) that the krb5 ticket expires",
		remaining_secs);
	smb_msleep((int)(remaining_secs * 1000));
}

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
					   samba_cmdline_get_creds(),
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
					   samba_cmdline_get_creds(),
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
					   samba_cmdline_get_creds(),
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
					   samba_cmdline_get_creds(),
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
					   samba_cmdline_get_creds(),
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
					   samba_cmdline_get_creds(),
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
					   samba_cmdline_get_creds(),
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
			samba_cmdline_get_creds());
	if (krb_state == CRED_USE_KERBEROS_REQUIRED) {
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
					    samba_cmdline_get_creds());
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
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	struct smb2_tree *tree = NULL;
	enum credentials_use_kerberos use_kerberos;
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	union smb_fileinfo qfinfo;
	size_t i;
	struct timeval endtime;
	bool ticket_expired = false;

	use_kerberos = cli_credentials_get_kerberos_state(credentials);
	if (use_kerberos != CRED_USE_KERBEROS_REQUIRED) {
		torture_warning(tctx,
				"smb2.session.expire1 requires "
				"--use-kerberos=required!");
		torture_skip(tctx,
			     "smb2.session.expire1 requires "
			     "--use-kerberos=required!");
	}

	torture_assert_int_equal(tctx,
				 use_kerberos,
				 CRED_USE_KERBEROS_REQUIRED,
				 "please use --use-kerberos=required");

	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	lpcfg_set_option(
		tctx->lp_ctx,
		GENSEC_GSSAPI_REQUESTED_LIFETIME(KRB5_TICKET_LIFETIME));

	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	if (force_signing) {
		options.signing = SMB_SIGNING_REQUIRED;
	}

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	/*
	 * We request a ticket lifetime of KRB5_TICKET_LIFETIME seconds.
	 * Give the server at least KRB5_TICKET_LIFETIME + KRB5_CLOCKSKEW + a
	 * few more milliseconds for this to kick in.
	 */
	endtime = timeval_current_ofs(KRB5_TICKET_EXPIRETIME, 500 * 1000);
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
		torture_comment(tctx, "%s: query info => OK\n",
				current_timestring(tctx, true));

		ZERO_STRUCT(qfinfo.access_information.out);
		status = smb2_getinfo_file(tree, tctx, &qfinfo);
		torture_comment(tctx, "%s: %s:%s: after smb2_getinfo_file() => %s\n",
			current_timestring(tctx, true),
			__location__, __func__,
			nt_errstr(status));
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"smb2_getinfo_file failed");

		sleep_remaining(tctx, &endtime);

		torture_comment(tctx, "%s: query info => EXPIRED\n",
				current_timestring(tctx, true));
		ZERO_STRUCT(qfinfo.access_information.out);
		status = smb2_getinfo_file(tree, tctx, &qfinfo);
		torture_comment(tctx, "%s: %s:%s: after smb2_getinfo_file() => %s\n",
			current_timestring(tctx, true),
			__location__, __func__,
			nt_errstr(status));
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

		torture_comment(tctx, "%s: reauth => OK\n",
				current_timestring(tctx, true));
		status = smb2_session_setup_spnego(tree->session,
						   credentials,
						   0 /* previous_session_id */);
		/*
		 * We request a ticket lifetime of KRB5_TICKET_LIFETIME seconds.
		 * Give the server at least KRB5_TICKET_LIFETIME +
		 * KRB5_CLOCKSKEW + a few more milliseconds for this to kick in.
		 */
		endtime = timeval_current_ofs(KRB5_TICKET_EXPIRETIME,
					      500 * 1000);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

		smb2cli_session_require_signed_response(
			tree->session->smbXcli, false);
	}

	ticket_expired = timeval_expired(&endtime);
	if (ticket_expired) {
		struct timeval current = timeval_current();
		double remaining_secs = timeval_elapsed2(&current, &endtime);
		remaining_secs = remaining_secs < 0.0 ? remaining_secs * -1.0
						      : remaining_secs;
		torture_warning(
			tctx,
			"The ticket already expired %.2f seconds ago. "
			"You might want to increase KRB5_TICKET_LIFETIME.",
			remaining_secs);
	}
	torture_assert(tctx,
		       ticket_expired == false,
		       "The kerberos ticket already expired");
	ZERO_STRUCT(qfinfo.access_information.out);
	torture_comment(tctx, "%s: %s:%s: before smb2_getinfo_file()\n",
			current_timestring(tctx, true),
			__location__, __func__);
	status = smb2_getinfo_file(tree, tctx, &qfinfo);
	torture_comment(tctx, "%s: %s:%s: after smb2_getinfo_file() => %s\n",
			current_timestring(tctx, true),
			__location__, __func__,
			nt_errstr(status));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	ret = true;
done:
	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	if (h1 != NULL) {
		smb2_util_close(tree, *h1);
	}

	talloc_free(tree);
	lpcfg_set_option(tctx->lp_ctx, GENSEC_GSSAPI_REQUESTED_LIFETIME(0));
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
	struct cli_credentials *credentials = samba_cmdline_get_creds();
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
	struct smb2_handle relhandle = { .data = { UINT64_MAX, UINT64_MAX } };
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
	struct smb2_create cio;
	struct smb2_find fnd;
	struct smb2_close cl;
	struct smb2_request *reqs[3] = { NULL, };
	union smb_search_data *d = NULL;
	unsigned int count;
	struct smb2_request *req = NULL;
	struct smb2_notify ntf1;
	struct smb2_notify ntf2;
	struct timeval endtime;

	use_kerberos = cli_credentials_get_kerberos_state(credentials);
	if (use_kerberos != CRED_USE_KERBEROS_REQUIRED) {
		torture_warning(tctx,
				"smb2.session.expire1 requires "
				"--use-kerberos=required!");
		torture_skip(tctx,
			     "smb2.session.expire1 requires "
			     "--use-kerberos=required!");
	}

	torture_assert_int_equal(tctx,
				 use_kerberos,
				 CRED_USE_KERBEROS_REQUIRED,
				 "please use --use-kerberos=required");

	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	lpcfg_set_option(
		tctx->lp_ctx,
		GENSEC_GSSAPI_REQUESTED_LIFETIME(KRB5_TICKET_LIFETIME));

	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	options.signing = SMB_SIGNING_REQUIRED;

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	torture_assert(tctx, unc != NULL, "talloc_asprintf");

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	/*
	 * We request a ticket lifetime of KRB5_TICKET_LIFETIME seconds.
	 * Give the server at least KRB5_TICKET_LIFETIME + KRB5_CLOCKSKEW + a
	 * few more milliseconds for this to kick in.
	 */
	endtime = timeval_current_ofs(KRB5_TICKET_EXPIRETIME, 500 * 1000);
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

	sleep_remaining(tctx, &endtime);

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

	/* Now do a compound open + query directory + close handle. */
	smb2_transport_compound_start(tree->session->transport, 3);
	torture_comment(tctx, "Compound: Open+QueryDirectory+Close => EXPIRED\n");

	ZERO_STRUCT(cio);
	cio.in.oplock_level = 0;
	cio.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_DIR_READ_ATTRIBUTE | SEC_DIR_LIST;
	cio.in.file_attributes   = 0;
	cio.in.create_disposition = NTCREATEX_DISP_OPEN;
	cio.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_DELETE;
	cio.in.create_options = NTCREATEX_OPTIONS_ASYNC_ALERT;
	cio.in.fname = "";

	reqs[0] = smb2_create_send(tree, &cio);
	torture_assert_not_null_goto(tctx, reqs[0], ret, done,
		"smb2_create_send failed\n");

	smb2_transport_compound_set_related(tree->session->transport, true);

	ZERO_STRUCT(fnd);
	fnd.in.file.handle	= relhandle;
	fnd.in.pattern		= "*";
	fnd.in.continue_flags	= SMB2_CONTINUE_FLAG_SINGLE;
	fnd.in.max_response_size= 0x100;
	fnd.in.level		= SMB2_FIND_BOTH_DIRECTORY_INFO;

	reqs[1] = smb2_find_send(tree, &fnd);
	torture_assert_not_null_goto(tctx, reqs[1], ret, done,
		"smb2_find_send failed\n");

	ZERO_STRUCT(cl);
	cl.in.file.handle = relhandle;
	reqs[2] = smb2_close_send(tree, &cl);
	torture_assert_not_null_goto(tctx, reqs[2], ret, done,
		"smb2_close_send failed\n");

	status = smb2_create_recv(reqs[0], tree, &cio);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_create "
				"returned unexpected status");
	status = smb2_find_recv(reqs[1], tree, &fnd);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_find "
				"returned unexpected status");
	status = smb2_close_recv(reqs[2], &cl);
	torture_assert_ntstatus_equal_goto(tctx, status,
				NT_STATUS_NETWORK_SESSION_EXPIRED,
				ret, done, "smb2_close "
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
	lpcfg_set_option(tctx->lp_ctx, GENSEC_GSSAPI_REQUESTED_LIFETIME(0));
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
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	struct smb2_tree *tree = NULL;
	enum credentials_use_kerberos use_kerberos;
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	union smb_fileinfo qfinfo;
	bool connected;
	struct timeval endtime;

	use_kerberos = cli_credentials_get_kerberos_state(credentials);
	if (use_kerberos != CRED_USE_KERBEROS_REQUIRED) {
		torture_warning(tctx,
				"smb2.session.expire1 requires "
				"--use-kerberos=required!");
		torture_skip(tctx,
			     "smb2.session.expire1 requires "
			     "--use-kerberos=required!");
	}

	cli_credentials_invalidate_ccache(credentials, CRED_SPECIFIED);

	lpcfg_set_option(
		tctx->lp_ctx,
		GENSEC_GSSAPI_REQUESTED_LIFETIME(KRB5_TICKET_LIFETIME));
	lpcfg_smbcli_options(tctx->lp_ctx, &options);
	options.signing = SMB_SIGNING_REQUIRED;

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	/*
	 * We request a ticket lifetime of KRB5_TICKET_LIFETIME seconds.
	 * Give the server at least KRB5_TICKET_LIFETIME + KRB5_CLOCKSKEW + a
	 * few more milliseconds for this to kick in.
	 */
	endtime = timeval_current_ofs(KRB5_TICKET_EXPIRETIME, 500 * 1000);
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

	sleep_remaining(tctx, &endtime);

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
	lpcfg_set_option(tctx->lp_ctx, GENSEC_GSSAPI_REQUESTED_LIFETIME(0));
	return ret;
}

bool test_session_bind1(struct torture_context *tctx, struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = samba_cmdline_get_creds();
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
			      share,
			      tctx->lp_ctx,
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
					   samba_cmdline_get_creds(),
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
					   samba_cmdline_get_creds(),
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

static bool test_session_bind2(struct torture_context *tctx, struct smb2_tree *tree1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname1[256];
	char fname2[256];
	struct smb2_handle _h1f1;
	struct smb2_handle *h1f1 = NULL;
	struct smb2_handle _h1f2;
	struct smb2_handle *h1f2 = NULL;
	struct smb2_handle _h2f2;
	struct smb2_handle *h2f2 = NULL;
	struct smb2_create io1f1;
	struct smb2_create io1f2;
	struct smb2_create io2f1;
	struct smb2_create io2f2;
	union smb_fileinfo qfinfo;
	bool ret = false;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smbcli_options options2;
	struct smb2_tree *tree2 = NULL;
	struct smb2_transport *transport2 = NULL;
	struct smbcli_options options3;
	struct smb2_tree *tree3 = NULL;
	struct smb2_transport *transport3 = NULL;
	struct smb2_session *session1_1 = tree1->session;
	struct smb2_session *session1_2 = NULL;
	struct smb2_session *session1_3 = NULL;
	struct smb2_session *session2_1 = NULL;
	struct smb2_session *session2_2 = NULL;
	struct smb2_session *session2_3 = NULL;
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
	snprintf(fname1, sizeof(fname1), "session_bind2_1_%s.dat",
		 generate_random_str(tctx, 8));
	snprintf(fname2, sizeof(fname2), "session_bind2_2_%s.dat",
		 generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);

	smb2_oplock_create_share(&io1f1, fname1,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level(""));
	smb2_oplock_create_share(&io1f2, fname2,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level(""));

	status = smb2_create(tree1, mem_ctx, &io1f1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1f1 = io1f1.out.file.handle;
	h1f1 = &_h1f1;
	CHECK_CREATED(tctx, &io1f1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1f1.out.oplock_level,
					smb2_util_oplock_level(""),
					"oplock_level incorrect");

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
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
	smb2cli_tcon_should_sign(tree2->smbXcli, true);

	smb2_oplock_create_share(&io2f1, fname1,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level(""));
	smb2_oplock_create_share(&io2f2, fname2,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level(""));

	status = smb2_create(tree2, mem_ctx, &io2f2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h2f2 = io2f2.out.file.handle;
	h2f2 = &_h2f2;
	CHECK_CREATED(tctx, &io2f2, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io2f2.out.oplock_level,
					smb2_util_oplock_level(""),
					"oplock_level incorrect");

	options3 = transport1->options;
	options3.signing = SMB_SIGNING_REQUIRED;
	options3.only_negprot = true;

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree3,
			      tctx->ev,
			      &options3,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_connect failed");
	transport3 = tree3->session->transport;

	/*
	 * Create a fake session for the 2nd transport connection to the 1st session
	 */
	session1_2 = smb2_session_channel(transport2,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree1,
					  session1_1);
	torture_assert(tctx, session1_2 != NULL, "smb2_session_channel failed");

	/*
	 * Now bind the 3rd transport connection to the 1st session
	 */
	session1_3 = smb2_session_channel(transport3,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree1,
					  session1_1);
	torture_assert(tctx, session1_3 != NULL, "smb2_session_channel failed");

	status = smb2_session_setup_spnego(session1_3,
					   credentials,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	/*
	 * Create a fake session for the 1st transport connection to the 2nd session
	 */
	session2_1 = smb2_session_channel(transport1,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree2,
					  session2_2);
	torture_assert(tctx, session2_1 != NULL, "smb2_session_channel failed");

	/*
	 * Now bind the 3rd transport connection to the 2nd session
	 */
	session2_3 = smb2_session_channel(transport3,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree2,
					  session2_2);
	torture_assert(tctx, session2_3 != NULL, "smb2_session_channel failed");

	status = smb2_session_setup_spnego(session2_3,
					   credentials,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h1f1;
	tree1->session = session1_1;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");
	tree1->session = session1_2;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
					"smb2_getinfo_file failed");
	tree1->session = session1_3;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = _h2f2;
	tree2->session = session2_1;
	status = smb2_getinfo_file(tree2, mem_ctx, &qfinfo);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
					"smb2_getinfo_file failed");
	tree2->session = session2_2;
	status = smb2_getinfo_file(tree2, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");
	tree2->session = session2_3;
	status = smb2_getinfo_file(tree2, mem_ctx, &qfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	tree1->session = session1_1;
	status = smb2_create(tree1, mem_ctx, &io1f2);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_SHARING_VIOLATION, ret, done,
					"smb2_create failed");
	tree1->session = session1_2;
	status = smb2_create(tree1, mem_ctx, &io1f2);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
					"smb2_create failed");
	tree1->session = session1_3;
	status = smb2_create(tree1, mem_ctx, &io1f2);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_SHARING_VIOLATION, ret, done,
					"smb2_create failed");

	tree2->session = session2_1;
	status = smb2_create(tree2, mem_ctx, &io2f1);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
					"smb2_create failed");
	tree2->session = session2_2;
	status = smb2_create(tree2, mem_ctx, &io2f1);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_SHARING_VIOLATION, ret, done,
					"smb2_create failed");
	tree2->session = session2_3;
	status = smb2_create(tree2, mem_ctx, &io2f1);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_SHARING_VIOLATION, ret, done,
					"smb2_create failed");

	smbXcli_conn_disconnect(transport3->conn, NT_STATUS_LOCAL_DISCONNECT);
	smb_msleep(500);

	tree1->session = session1_1;
	status = smb2_create(tree1, mem_ctx, &io1f2);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_SHARING_VIOLATION, ret, done,
					"smb2_create failed");
	tree1->session = session1_2;
	status = smb2_create(tree1, mem_ctx, &io1f2);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
					"smb2_create failed");

	tree2->session = session2_1;
	status = smb2_create(tree2, mem_ctx, &io2f1);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
					"smb2_create failed");
	tree2->session = session2_2;
	status = smb2_create(tree2, mem_ctx, &io2f1);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_SHARING_VIOLATION, ret, done,
					"smb2_create failed");

	smbXcli_conn_disconnect(transport2->conn, NT_STATUS_LOCAL_DISCONNECT);
	smb_msleep(500);
	h2f2 = NULL;

	tree1->session = session1_1;
	status = smb2_create(tree1, mem_ctx, &io1f2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1f2 = io1f2.out.file.handle;
	h1f2 = &_h1f2;
	CHECK_CREATED(tctx, &io1f2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1f2.out.oplock_level,
					smb2_util_oplock_level(""),
					"oplock_level incorrect");

	tree1->session = session1_1;
	status = smb2_util_close(tree1, *h1f1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_close failed");
	h1f1 = NULL;

	ret = true;
done:

	smbXcli_conn_disconnect(transport3->conn, NT_STATUS_LOCAL_DISCONNECT);
	smbXcli_conn_disconnect(transport2->conn, NT_STATUS_LOCAL_DISCONNECT);

	tree1->session = session1_1;
	tree2->session = session2_2;

	if (h1f1 != NULL) {
		smb2_util_close(tree1, *h1f1);
	}
	if (h1f2 != NULL) {
		smb2_util_close(tree1, *h1f2);
	}
	if (h2f2 != NULL) {
		smb2_util_close(tree2, *h2f2);
	}

	smb2_util_unlink(tree1, fname1);
	smb2_util_unlink(tree1, fname2);

	talloc_free(tree1);

	talloc_free(mem_ctx);

	return ret;
}

static bool test_session_bind_auth_mismatch(struct torture_context *tctx,
					    struct smb2_tree *tree1,
					    const char *testname,
					    struct cli_credentials *creds1,
					    struct cli_credentials *creds2,
					    bool creds2_require_ok)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
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
	struct smb2_session *session3_1 = NULL;
	uint32_t caps;
	bool encrypted;
	bool creds2_got_ok = false;

	encrypted = smb2cli_tcon_is_encryption_on(tree1->smbXcli);

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
	snprintf(fname, sizeof(fname), "%s_%s.dat", testname,
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
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      creds1,
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
					   creds1,
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
	 * Create a 3rd session in order to check if the invalid (creds2)
	 * are mapped to guest.
	 */
	session3_1 = smb2_session_init(transport1,
				       lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				       tctx);
	torture_assert(tctx, session3_1 != NULL, "smb2_session_channel failed");

	status = smb2_session_setup_spnego(session3_1,
					   creds2,
					   0 /* previous_session_id */);
	if (creds2_require_ok) {
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego worked");
		creds2_got_ok = true;
	} else if (NT_STATUS_IS_OK(status)) {
		bool authentiated = smbXcli_session_is_authenticated(session3_1->smbXcli);
		torture_assert(tctx, !authentiated, "Invalid credentials allowed!");
		creds2_got_ok = true;
	} else {
		torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_LOGON_FAILURE, ret, done,
					"smb2_session_setup_spnego worked");
	}

	/*
	 * Now bind the 1st transport connection to the 2nd session
	 */
	session2_1 = smb2_session_channel(transport1,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree1,
					  session2_2);
	torture_assert(tctx, session2_1 != NULL, "smb2_session_channel failed");

	tree2->session = session2_1;
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
					"smb2_util_unlink worked on invalid channel");

	status = smb2_session_setup_spnego(session2_1,
					   creds2,
					   0 /* previous_session_id */);
	if (creds2_got_ok) {
		/*
		 * attaching with a different user (guest or anonymous) results
		 * in ACCESS_DENIED.
		 */
		torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_ACCESS_DENIED, ret, done,
					"smb2_session_setup_spnego worked");
	} else {
		torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_LOGON_FAILURE, ret, done,
					"smb2_session_setup_spnego worked");
	}

	tree2->session = session2_1;
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
					"smb2_util_unlink worked on invalid channel");

	tree2->session = session2_2;
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_unlink failed");
	status = smb2_util_unlink(tree2, fname);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND, ret, done,
					"smb2_util_unlink worked");
	if (creds2_got_ok) {
		/*
		 * We got ACCESS_DENIED on the session bind
		 * with a different user, now check that
		 * the correct user can actually bind on
		 * the same connection.
		 */
		TALLOC_FREE(session2_1);
		session2_1 = smb2_session_channel(transport1,
						  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
						  tree1,
						  session2_2);
		torture_assert(tctx, session2_1 != NULL, "smb2_session_channel failed");

		status = smb2_session_setup_spnego(session2_1,
						   creds1,
						   0 /* previous_session_id */);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_session_setup_spnego failed");
		tree2->session = session2_1;
		status = smb2_util_unlink(tree2, fname);
		torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND, ret, done,
						"smb2_util_unlink worked");
		tree2->session = session2_2;
	}

	tree1->session = session1_1;
	status = smb2_util_unlink(tree1, fname);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND, ret, done,
					"smb2_util_unlink worked");

	tree1->session = session1_2;
	status = smb2_util_unlink(tree1, fname);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND, ret, done,
					"smb2_util_unlink worked");

	if (creds2_got_ok) {
		/*
		 * With valid credentials, there's no point to test a failing
		 * reauth.
		 */
		ret = true;
		goto done;
	}

	/*
	 * Do a failing reauth the 2nd channel
	 */
	status = smb2_session_setup_spnego(session1_2,
					   creds2,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_LOGON_FAILURE, ret, done,
					"smb2_session_setup_spnego worked");

	tree1->session = session1_1;
	status = smb2_util_unlink(tree1, fname);
	if (encrypted) {
		torture_assert_goto(tctx, !smbXcli_conn_is_connected(transport1->conn), ret, done,
						"smb2_util_unlink worked");
	} else {
		torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
						"smb2_util_unlink worked");
	}

	tree1->session = session1_2;
	status = smb2_util_unlink(tree1, fname);
	if (encrypted) {
		torture_assert_goto(tctx, !smbXcli_conn_is_connected(transport2->conn), ret, done,
						"smb2_util_unlink worked");
	} else {
		torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_USER_SESSION_DELETED, ret, done,
						"smb2_util_unlink worked");
	}

	status = smb2_util_unlink(tree2, fname);
	if (encrypted) {
		torture_assert_goto(tctx, !smbXcli_conn_is_connected(transport1->conn), ret, done,
						"smb2_util_unlink worked");
		torture_assert_goto(tctx, !smbXcli_conn_is_connected(transport2->conn), ret, done,
						"smb2_util_unlink worked");
	} else {
		torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_OBJECT_NAME_NOT_FOUND, ret, done,
						"smb2_util_unlink worked");
	}

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

static bool test_session_bind_invalid_auth(struct torture_context *tctx, struct smb2_tree *tree1)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	struct cli_credentials *invalid_credentials = NULL;
	bool ret = false;

	invalid_credentials = cli_credentials_init(tctx);
	torture_assert(tctx, (invalid_credentials != NULL), "talloc error");
	cli_credentials_set_username(invalid_credentials, "__none__invalid__none__", CRED_SPECIFIED);
	cli_credentials_set_domain(invalid_credentials, "__none__invalid__none__", CRED_SPECIFIED);
	cli_credentials_set_password(invalid_credentials, "__none__invalid__none__", CRED_SPECIFIED);
	cli_credentials_set_realm(invalid_credentials, NULL, CRED_SPECIFIED);
	cli_credentials_set_workstation(invalid_credentials, "", CRED_UNINITIALISED);

	ret = test_session_bind_auth_mismatch(tctx, tree1, __func__,
					      credentials,
					      invalid_credentials,
					      false);
	return ret;
}

static bool test_session_bind_different_user(struct torture_context *tctx, struct smb2_tree *tree1)
{
	struct cli_credentials *credentials1 = samba_cmdline_get_creds();
	struct cli_credentials *credentials2 = torture_user2_credentials(tctx, tctx);
	char *u1 = cli_credentials_get_unparsed_name(credentials1, tctx);
	char *u2 = cli_credentials_get_unparsed_name(credentials2, tctx);
	bool ret = false;
	bool bval;

	torture_assert(tctx, (credentials2 != NULL), "talloc error");
	bval = cli_credentials_is_anonymous(credentials2);
	if (bval) {
		torture_skip(tctx, "valid user2 credentials are required");
	}
	bval = strequal(u1, u2);
	if (bval) {
		torture_skip(tctx, "different user2 credentials are required");
	}

	ret = test_session_bind_auth_mismatch(tctx, tree1, __func__,
					      credentials1,
					      credentials2,
					      true);
	return ret;
}

static bool test_session_bind_negative_smbXtoX(struct torture_context *tctx,
					       const char *testname,
					       struct cli_credentials *credentials,
					       const struct smbcli_options *options1,
					       const struct smbcli_options *options2,
					       NTSTATUS bind_reject_status)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	NTSTATUS status;
	bool ret = false;
	struct smb2_tree *tree1 = NULL;
	struct smb2_session *session1_1 = NULL;
	char fname[256];
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	union smb_fileinfo qfinfo1;
	struct smb2_tree *tree2_0 = NULL;
	struct smb2_transport *transport2 = NULL;
	struct smb2_session *session1_2 = NULL;
	uint64_t session1_id = 0;
	uint16_t session1_flags = 0;
	NTSTATUS deleted_status = NT_STATUS_USER_SESSION_DELETED;

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree1,
			      tctx->ev,
			      options1,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_connect options1 failed");
	session1_1 = tree1->session;
	session1_id = smb2cli_session_current_id(session1_1->smbXcli);
	session1_flags = smb2cli_session_get_flags(session1_1->smbXcli);

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "%s_%s.dat",
		 testname, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	io1.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	status = smb2_create(tree1, tctx, &io1);
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
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      &tree2_0,
			      tctx->ev,
			      options2,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_connect options2 failed");
	transport2 = tree2_0->session->transport;

	/*
	 * Now bind the 2nd transport connection to the 1st session
	 */
	session1_2 = smb2_session_channel(transport2,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree2_0,
					  session1_1);
	torture_assert(tctx, session1_2 != NULL, "smb2_session_channel failed");

	status = smb2_session_setup_spnego(session1_2,
					   credentials,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_equal_goto(tctx, status, bind_reject_status, ret, done,
					   "smb2_session_setup_spnego failed");
	if (NT_STATUS_IS_OK(bind_reject_status)) {
		ZERO_STRUCT(qfinfo1);
		qfinfo1.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
		qfinfo1.generic.in.file.handle = _h1;
		tree1->session = session1_2;
		status = smb2_getinfo_file(tree1, tctx, &qfinfo1);
		tree1->session = session1_1;
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");
	}
	TALLOC_FREE(session1_2);

	/* Check the initial session is still alive */
	ZERO_STRUCT(qfinfo1);
	qfinfo1.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo1.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree1, tctx, &qfinfo1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	if (NT_STATUS_IS_OK(bind_reject_status)) {
		deleted_status = NT_STATUS_ACCESS_DENIED;
		bind_reject_status = NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * I guess this is not part of MultipleChannel_Negative_SMB2002,
	 * but we should also check the status without
	 * SMB2_SESSION_FLAG_BINDING.
	 */
	session1_2 = smb2_session_channel(transport2,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree2_0,
					  session1_1);
	torture_assert(tctx, session1_2 != NULL, "smb2_session_channel failed");
	session1_2->needs_bind = false;

	status = smb2_session_setup_spnego(session1_2,
					   credentials,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_equal_goto(tctx, status, deleted_status, ret, done,
					   "smb2_session_setup_spnego failed");
	TALLOC_FREE(session1_2);

	/*
	 * ... and we should also check the status without any existing
	 * session keys.
	 */
	session1_2 = smb2_session_init(transport2,
				       lpcfg_gensec_settings(tctx, tctx->lp_ctx),
				       tree2_0);
	torture_assert(tctx, session1_2 != NULL, "smb2_session_channel failed");
	talloc_steal(tree2_0->session, transport2);
	smb2cli_session_set_id_and_flags(session1_2->smbXcli,
					 session1_id, session1_flags);

	status = smb2_session_setup_spnego(session1_2,
					   credentials,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_equal_goto(tctx, status, deleted_status, ret, done,
					   "smb2_session_setup_spnego failed");
	TALLOC_FREE(session1_2);

	/* Check the initial session is still alive */
	ZERO_STRUCT(qfinfo1);
	qfinfo1.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo1.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree1, tctx, &qfinfo1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	/*
	 * Now bind the 2nd transport connection to the 1st session (again)
	 */
	session1_2 = smb2_session_channel(transport2,
					  lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					  tree2_0,
					  session1_1);
	torture_assert(tctx, session1_2 != NULL, "smb2_session_channel failed");

	status = smb2_session_setup_spnego(session1_2,
					   credentials,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_equal_goto(tctx, status, bind_reject_status, ret, done,
					   "smb2_session_setup_spnego failed");
	TALLOC_FREE(session1_2);

	/* Check the initial session is still alive */
	ZERO_STRUCT(qfinfo1);
	qfinfo1.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo1.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree1, tctx, &qfinfo1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	ret = true;
done:
	talloc_free(tree2_0);
	if (h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	talloc_free(tree1);

	return ret;
}

/*
 * This is similar to the MultipleChannel_Negative_SMB2002 test
 * from the Windows Protocol Test Suite.
 *
 * It demonstrates that the server needs to do lookup
 * in the global session table in order to get the signing
 * and error code of invalid session setups correct.
 *
 * See: https://bugzilla.samba.org/show_bug.cgi?id=14512
 *
 * Note you can ignore tree0...
 */
static bool test_session_bind_negative_smb202(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.02 if encryption is required");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_zero();
	options1.max_protocol = PROTOCOL_SMB2_02;

	options2 = options1;
	options2.only_negprot = true;

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_NOT_ACCEPTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb210s(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.max_protocol = PROTOCOL_SMB2_10;

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_NOT_ACCEPTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb210d(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.max_protocol = PROTOCOL_SMB2_10;

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_NOT_ACCEPTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb2to3s(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx,
			     "Can't test without SMB3 support");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB2_02;
	options1.max_protocol = PROTOCOL_SMB2_10;

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_00;
	options2.max_protocol = PROTOCOL_SMB3_11;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_INVALID_PARAMETER);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb2to3d(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx,
			     "Can't test without SMB3 support");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB2_02;
	options1.max_protocol = PROTOCOL_SMB2_10;

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_00;
	options2.max_protocol = PROTOCOL_SMB3_11;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_INVALID_PARAMETER);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3to2s(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx,
			     "Can't test without SMB3 support");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_00;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB2_02;
	options2.max_protocol = PROTOCOL_SMB2_10;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_NOT_ACCEPTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3to2d(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx,
			     "Can't test without SMB3 support");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_00;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB2_02;
	options2.max_protocol = PROTOCOL_SMB2_10;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_NOT_ACCEPTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3to3s(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_02;
	options1.max_protocol = PROTOCOL_SMB3_02;

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_11;
	options2.max_protocol = PROTOCOL_SMB3_11;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_INVALID_PARAMETER);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3to3d(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_02;
	options1.max_protocol = PROTOCOL_SMB3_02;

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_11;
	options2.max_protocol = PROTOCOL_SMB3_11;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_INVALID_PARAMETER);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3encGtoCs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_INVALID_PARAMETER);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3encGtoCd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_INVALID_PARAMETER);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signCtoHs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_OK);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signCtoHd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_OK);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signHtoCs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_OK);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signHtoCd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_OK);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signHtoGs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signHtoGd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signCtoGs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signCtoGd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signGtoCs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signGtoCd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signGtoHs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signGtoHd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3sneGtoCs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3sneGtoCd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3sneGtoHs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3sneGtoHd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3sneCtoGs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3sneCtoGd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3sneHtoGs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3sneHtoGd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};
	options2.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signC30toGs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_00;
	options1.max_protocol = PROTOCOL_SMB3_02;
	options1.signing = SMB_SIGNING_REQUIRED;

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_11;
	options2.max_protocol = PROTOCOL_SMB3_11;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signC30toGd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_00;
	options1.max_protocol = PROTOCOL_SMB3_02;
	options1.signing = SMB_SIGNING_REQUIRED;

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_11;
	options2.max_protocol = PROTOCOL_SMB3_11;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signH2XtoGs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_OFF,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB2_02;
	options1.max_protocol = PROTOCOL_SMB2_10;
	options1.signing = SMB_SIGNING_REQUIRED;

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_11;
	options2.max_protocol = PROTOCOL_SMB3_11;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signH2XtoGd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_OFF,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB2_02;
	options1.max_protocol = PROTOCOL_SMB2_10;
	options1.signing = SMB_SIGNING_REQUIRED;

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_11;
	options2.max_protocol = PROTOCOL_SMB3_11;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_NOT_SUPPORTED);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signGtoC30s(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_00;
	options2.max_protocol = PROTOCOL_SMB3_02;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signGtoC30d(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB3_00;
	options2.max_protocol = PROTOCOL_SMB3_02;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signGtoH2Xs(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	/* same client guid */
	options2 = options1;
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB2_02;
	options2.max_protocol = PROTOCOL_SMB2_10;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_bind_negative_smb3signGtoH2Xd(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	struct smbcli_options options2;
	bool ok;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test SMB 2.10 if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	/* different client guid */
	options2 = options1;
	options2.client_guid = GUID_random();
	options2.only_negprot = true;
	options2.min_protocol = PROTOCOL_SMB2_02;
	options2.max_protocol = PROTOCOL_SMB2_10;
	options2.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	ret = test_session_bind_negative_smbXtoX(tctx, __func__,
						 credentials,
						 &options1, &options2,
						 NT_STATUS_REQUEST_OUT_OF_SEQUENCE);
	talloc_free(tree0);
	return ret;
}

static bool test_session_two_logoff(struct torture_context *tctx,
				    struct smb2_tree *tree1)
{
	NTSTATUS status;
	bool ret = true;
	struct smbcli_options transport2_options;
	struct smb2_tree *tree2 = NULL;
	struct smb2_session *session2 = NULL;
	struct smb2_session *session1 = tree1->session;
	struct smb2_transport *transport1 = tree1->session->transport;
	struct smb2_transport *transport2;
	bool ok;

	/* Connect 2nd connection */
	torture_comment(tctx, "connect tree2 with the same client_guid\n");
	transport2_options = transport1->options;
	ok = torture_smb2_connection_ext(tctx, 0, &transport2_options, &tree2);
	torture_assert(tctx, ok, "couldn't connect tree2\n");
	transport2 = tree2->session->transport;
	session2 = tree2->session;

	torture_comment(tctx, "session2: logoff\n");
	status = smb2_logoff(session2);
	torture_assert_ntstatus_ok(tctx, status, "session2: logoff");
	torture_comment(tctx, "transport2: keepalive\n");
	status = smb2_keepalive(transport2);
	torture_assert_ntstatus_ok(tctx, status, "transport2: keepalive");
	torture_comment(tctx, "transport2: disconnect\n");
	TALLOC_FREE(tree2);

	torture_comment(tctx, "session1: logoff\n");
	status = smb2_logoff(session1);
	torture_assert_ntstatus_ok(tctx, status, "session1: logoff");
	torture_comment(tctx, "transport1: keepalive\n");
	status = smb2_keepalive(transport1);
	torture_assert_ntstatus_ok(tctx, status, "transport1: keepalive");
	torture_comment(tctx, "transport1: disconnect\n");
	TALLOC_FREE(tree1);

	return ret;
}

static bool test_session_sign_enc(struct torture_context *tctx,
				  const char *testname,
				  struct cli_credentials *credentials1,
				  const struct smbcli_options *options1)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	NTSTATUS status;
	bool ret = false;
	struct smb2_tree *tree1 = NULL;
	char fname[256];
	struct smb2_handle rh = {{0}};
	struct smb2_handle _h1;
	struct smb2_handle *h1 = NULL;
	struct smb2_create io1;
	union smb_fileinfo qfinfo1;
	union smb_notify notify;
	struct smb2_request *req = NULL;

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials1,
			      &tree1,
			      tctx->ev,
			      options1,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_connect options1 failed");

	status = smb2_util_roothandle(tree1, &rh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_roothandle failed");

	/* Add some random component to the file name. */
	snprintf(fname, sizeof(fname), "%s_%s.dat",
		 testname, generate_random_str(tctx, 8));

	smb2_util_unlink(tree1, fname);

	smb2_oplock_create_share(&io1, fname,
				 smb2_util_share_access(""),
				 smb2_util_oplock_level("b"));

	io1.in.create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	status = smb2_create(tree1, tctx, &io1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed");
	_h1 = io1.out.file.handle;
	h1 = &_h1;
	CHECK_CREATED(tctx, &io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	torture_assert_int_equal(tctx, io1.out.oplock_level,
					smb2_util_oplock_level("b"),
					"oplock_level incorrect");

	/* Check the initial session is still alive */
	ZERO_STRUCT(qfinfo1);
	qfinfo1.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo1.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree1, tctx, &qfinfo1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	/* ask for a change notify,
	   on file or directory name changes */
	ZERO_STRUCT(notify);
	notify.smb2.level = RAW_NOTIFY_SMB2;
	notify.smb2.in.buffer_size = 1000;
	notify.smb2.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.smb2.in.file.handle = rh;
	notify.smb2.in.recursive = true;

	req = smb2_notify_send(tree1, &(notify.smb2));
	WAIT_FOR_ASYNC_RESPONSE(req);

	status = smb2_cancel(req);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_cancel failed");

	status = smb2_notify_recv(req, tctx, &(notify.smb2));
	torture_assert_ntstatus_equal_goto(tctx, status, NT_STATUS_CANCELLED,
					   ret, done,
					   "smb2_notify_recv failed");

	/* Check the initial session is still alive */
	ZERO_STRUCT(qfinfo1);
	qfinfo1.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo1.generic.in.file.handle = _h1;
	status = smb2_getinfo_file(tree1, tctx, &qfinfo1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed");

	ret = true;
done:
	if (h1 != NULL) {
		smb2_util_close(tree1, *h1);
	}
	TALLOC_FREE(tree1);

	return ret;
}

static bool test_session_signing_hmac_sha_256(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test signing only if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_HMAC_SHA256,
		},
	};

	ret = test_session_sign_enc(tctx,
				    __func__,
				    credentials,
				    &options1);
	TALLOC_FREE(tree0);
	return ret;
}

static bool test_session_signing_aes_128_cmac(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test signing only if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_CMAC,
		},
	};

	ret = test_session_sign_enc(tctx,
				    __func__,
				    credentials,
				    &options1);
	TALLOC_FREE(tree0);
	return ret;
}

static bool test_session_signing_aes_128_gmac(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials = samba_cmdline_get_creds();
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	bool encrypted;

	encrypted = smb2cli_tcon_is_encryption_on(tree0->smbXcli);
	if (encrypted) {
		torture_skip(tctx,
			     "Can't test signing only if encryption is required");
	}

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.signing = (struct smb3_signing_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_SIGNING_AES128_GMAC,
		},
	};

	ret = test_session_sign_enc(tctx,
				    __func__,
				    credentials,
				    &options1);
	TALLOC_FREE(tree0);
	return ret;
}

static bool test_session_encryption_aes_128_ccm(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_CCM,
		},
	};

	ret = test_session_sign_enc(tctx,
				    __func__,
				    credentials,
				    &options1);
	TALLOC_FREE(tree0);
	return ret;
}

static bool test_session_encryption_aes_128_gcm(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES128_GCM,
		},
	};

	ret = test_session_sign_enc(tctx,
				    __func__,
				    credentials,
				    &options1);
	TALLOC_FREE(tree0);
	return ret;
}

static bool test_session_encryption_aes_256_ccm(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES256_CCM,
		},
	};

	ret = test_session_sign_enc(tctx,
				    __func__,
				    credentials,
				    &options1);
	TALLOC_FREE(tree0);
	return ret;
}

static bool test_session_encryption_aes_256_gcm(struct torture_context *tctx, struct smb2_tree *tree0)
{
	struct cli_credentials *credentials0 = samba_cmdline_get_creds();
	struct cli_credentials *credentials = NULL;
	bool ret = false;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct smbcli_options options1;
	bool ok;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_11) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 support");
	}

	if (smb2cli_conn_server_signing_algo(transport0->conn) < SMB2_SIGNING_AES128_GMAC) {
		torture_skip(tctx,
			     "Can't test without SMB 3.1.1 signing negotiation support");
	}

	credentials = cli_credentials_shallow_copy(tctx, credentials0);
	torture_assert(tctx, credentials != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(credentials,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options1 = transport0->options;
	options1.client_guid = GUID_random();
	options1.min_protocol = PROTOCOL_SMB3_11;
	options1.max_protocol = PROTOCOL_SMB3_11;
	options1.signing = SMB_SIGNING_REQUIRED;
	options1.smb3_capabilities.encryption = (struct smb3_encryption_capabilities) {
		.num_algos = 1,
		.algos = {
			SMB2_ENCRYPTION_AES256_GCM,
		},
	};

	ret = test_session_sign_enc(tctx,
				    __func__,
				    credentials,
				    &options1);
	TALLOC_FREE(tree0);
	return ret;
}

static bool test_session_ntlmssp_bug14932(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct cli_credentials *ntlm_creds =
		cli_credentials_shallow_copy(tctx, samba_cmdline_get_creds());
	NTSTATUS status;
	bool ret = true;
	/*
	 * This is a NTLMv2_RESPONSE with the strange
	 * NTLMv2_CLIENT_CHALLENGE used by the net diag
	 * tool.
	 *
	 * As we expect an error anyway we fill the
	 * Response part with 0xab...
	 */
	static const char *netapp_magic =
		"\xab\xab\xab\xab\xab\xab\xab\xab"
		"\xab\xab\xab\xab\xab\xab\xab\xab"
		"\x01\x01\x00\x00\x00\x00\x00\x00"
		"\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f"
		"\xb8\x82\x3a\xf1\xb3\xdd\x08\x15"
		"\x00\x00\x00\x00\x11\xa2\x08\x81"
		"\x50\x38\x22\x78\x2b\x94\x47\xfe"
		"\x54\x94\x7b\xff\x17\x27\x5a\xb4"
		"\xf4\x18\xba\xdc\x2c\x38\xfd\x5b"
		"\xfb\x0e\xc1\x85\x1e\xcc\x92\xbb"
		"\x9b\xb1\xc4\xd5\x53\x14\xff\x8c"
		"\x76\x49\xf5\x45\x90\x19\xa2";
	DATA_BLOB lm_response = data_blob_talloc_zero(tctx, 24);
	DATA_BLOB lm_session_key = data_blob_talloc_zero(tctx, 16);
	DATA_BLOB nt_response = data_blob_const(netapp_magic, 95);
	DATA_BLOB nt_session_key = data_blob_talloc_zero(tctx, 16);

	cli_credentials_set_kerberos_state(ntlm_creds,
					   CRED_USE_KERBEROS_DISABLED,
					   CRED_SPECIFIED);
	cli_credentials_set_ntlm_response(ntlm_creds,
					  &lm_response,
					  &lm_session_key,
					  &nt_response,
					  &nt_session_key,
					  CRED_SPECIFIED);
	status = smb2_session_setup_spnego(tree->session,
					   ntlm_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_INVALID_PARAMETER,
				      "smb2_session_setup_spnego failed");

	return ret;
}

static bool test_session_anon_encryption1(struct torture_context *tctx,
					  struct smb2_tree *tree0)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = "IPC$";
	char *unc = NULL;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct cli_credentials *anon_creds = NULL;
	struct smbcli_options options;
	struct smb2_transport *transport = NULL;
	struct smb2_session *anon_session = NULL;
	struct smb2_tree *anon_tree = NULL;
	NTSTATUS status;
	bool ok = true;
	struct tevent_req *subreq = NULL;
	uint32_t timeout_msec;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx,
			     "Can't test without SMB3 support");
	}

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	torture_assert(tctx, unc != NULL, "talloc_asprintf");

	anon_creds = cli_credentials_init_anon(tctx);
	torture_assert(tctx, anon_creds != NULL, "cli_credentials_init_anon");
	ok = cli_credentials_set_smb_encryption(anon_creds,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options = transport0->options;
	options.client_guid = GUID_random();
	options.only_negprot = true;

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      anon_creds,
			      &anon_tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "smb2_connect failed");
	anon_session = anon_tree->session;
	transport = anon_session->transport;

	anon_session->anonymous_session_key = true;
	smb2cli_session_torture_anonymous_encryption(anon_session->smbXcli, true);

	status = smb2_session_setup_spnego(anon_session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok(tctx, status,
				   "smb2_session_setup_spnego failed");

	ok = smbXcli_session_is_authenticated(anon_session->smbXcli);
	torture_assert(tctx, !ok, "smbXcli_session_is_authenticated(anon) wrong");

	/*
	 * The connection is still in ConstrainedConnection state...
	 *
	 * This will use encryption and causes a connection reset
	 */
	timeout_msec = transport->options.request_timeout * 1000;
	subreq = smb2cli_tcon_send(tctx,
				   tctx->ev,
				   transport->conn,
				   timeout_msec,
				   anon_session->smbXcli,
				   anon_tree->smbXcli,
				   0, /* flags */
				   unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");

	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");

	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_DISCONNECTED)) {
		status = NT_STATUS_CONNECTION_RESET;
	}
	torture_assert_ntstatus_equal(tctx, status,
				      NT_STATUS_CONNECTION_RESET,
				      "smb2cli_tcon_recv");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, !ok, "smbXcli_conn_is_connected still connected");

	return true;
}

static bool test_session_anon_encryption2(struct torture_context *tctx,
					  struct smb2_tree *tree0)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = "IPC$";
	char *unc = NULL;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct cli_credentials *_creds = samba_cmdline_get_creds();
	struct cli_credentials *user_creds = NULL;
	struct cli_credentials *anon_creds = NULL;
	struct smbcli_options options;
	struct smb2_transport *transport = NULL;
	struct smb2_session *user_session = NULL;
	struct smb2_tree *user_tree = NULL;
	struct smb2_session *anon_session = NULL;
	struct smb2_tree *anon_tree = NULL;
	struct smb2_ioctl ioctl = {
		.level = RAW_IOCTL_SMB2,
		.in = {
			.file = {
				.handle = {
					.data = {
						[0] = UINT64_MAX,
						[1] = UINT64_MAX,
					},
				},
			},
			.function = FSCTL_QUERY_NETWORK_INTERFACE_INFO,
			/* Windows client sets this to 64KiB */
			.max_output_response = 0x10000,
			.flags = SMB2_IOCTL_FLAG_IS_FSCTL,
		},
	};
	NTSTATUS status;
	bool ok = true;
	struct tevent_req *subreq = NULL;
	uint32_t timeout_msec;
	uint32_t caps = smb2cli_conn_server_capabilities(transport0->conn);
	NTSTATUS expected_mc_status;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx,
			     "Can't test without SMB3 support");
	}

	if (caps & SMB2_CAP_MULTI_CHANNEL) {
		expected_mc_status = NT_STATUS_OK;
	} else {
		expected_mc_status = NT_STATUS_FS_DRIVER_REQUIRED;
	}

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	torture_assert(tctx, unc != NULL, "talloc_asprintf");

	user_creds = cli_credentials_shallow_copy(tctx, _creds);
	torture_assert(tctx, user_creds != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(user_creds,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	anon_creds = cli_credentials_init_anon(tctx);
	torture_assert(tctx, anon_creds != NULL, "cli_credentials_init_anon");
	ok = cli_credentials_set_smb_encryption(anon_creds,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options = transport0->options;
	options.client_guid = GUID_random();

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      user_creds,
			      &user_tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "smb2_connect failed");
	user_session = user_tree->session;
	transport = user_session->transport;
	ok = smb2cli_tcon_is_encryption_on(user_tree->smbXcli);
	torture_assert(tctx, ok, "smb2cli_tcon_is_encryption_on(user)");
	ok = smbXcli_session_is_authenticated(user_session->smbXcli);
	torture_assert(tctx, ok, "smbXcli_session_is_authenticated(user)");

	anon_session = smb2_session_init(transport,
					 lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					 tctx);
	torture_assert(tctx, anon_session != NULL, "smb2_session_init(anon)");

	anon_session->anonymous_session_key = true;
	smb2cli_session_torture_anonymous_encryption(anon_session->smbXcli, true);

	status = smb2_session_setup_spnego(anon_session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok(tctx, status,
				   "smb2_session_setup_spnego failed");

	ok = smb2cli_tcon_is_encryption_on(user_tree->smbXcli);
	torture_assert(tctx, ok, "smb2cli_tcon_is_encryption_on(anon)");
	ok = smbXcli_session_is_authenticated(anon_session->smbXcli);
	torture_assert(tctx, !ok, "smbXcli_session_is_authenticated(anon) wrong");

	anon_tree = smb2_tree_init(anon_session, tctx, false);
	torture_assert(tctx, anon_tree != NULL, "smb2_tree_init");

	timeout_msec = transport->options.request_timeout * 1000;
	subreq = smb2cli_tcon_send(tctx,
				   tctx->ev,
				   transport->conn,
				   timeout_msec,
				   anon_session->smbXcli,
				   anon_tree->smbXcli,
				   0, /* flags */
				   unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");

	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");

	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_ok(tctx, status,
				   "smb2cli_tcon_recv(anon)");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, ok, "smbXcli_conn_is_connected");

	ok = smb2cli_tcon_is_encryption_on(anon_tree->smbXcli);
	torture_assert(tctx, ok, "smb2cli_tcon_is_encryption_on(anon)");
	ok = smbXcli_session_is_authenticated(anon_session->smbXcli);
	torture_assert(tctx, !ok, "smbXcli_session_is_authenticated(anon) wrong");

	status = smb2_ioctl(user_tree, tctx, &ioctl);
	torture_assert_ntstatus_equal(tctx, status, expected_mc_status,
				      "FSCTL_QUERY_NETWORK_INTERFACE_INFO user");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, ok, "smbXcli_conn_is_connected");

	status = smb2_ioctl(anon_tree, tctx, &ioctl);
	torture_assert_ntstatus_equal(tctx, status, expected_mc_status,
				      "FSCTL_QUERY_NETWORK_INTERFACE_INFO anonymous");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, ok, "smbXcli_conn_is_connected");

	status = smb2_ioctl(user_tree, tctx, &ioctl);
	torture_assert_ntstatus_equal(tctx, status, expected_mc_status,
				      "FSCTL_QUERY_NETWORK_INTERFACE_INFO user");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, ok, "smbXcli_conn_is_connected");

	status = smb2_ioctl(anon_tree, tctx, &ioctl);
	torture_assert_ntstatus_equal(tctx, status, expected_mc_status,
				      "FSCTL_QUERY_NETWORK_INTERFACE_INFO anonymous");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, ok, "smbXcli_conn_is_connected");

	return true;
}

static bool test_session_anon_encryption3(struct torture_context *tctx,
					  struct smb2_tree *tree0)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = "IPC$";
	char *unc = NULL;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct cli_credentials *_creds = samba_cmdline_get_creds();
	struct cli_credentials *user_creds = NULL;
	struct cli_credentials *anon_creds = NULL;
	struct smbcli_options options;
	struct smb2_transport *transport = NULL;
	struct smb2_session *user_session = NULL;
	struct smb2_tree *user_tree = NULL;
	struct smb2_session *anon_session = NULL;
	struct smb2_tree *anon_tree = NULL;
	NTSTATUS status;
	bool ok = true;
	struct tevent_req *subreq = NULL;
	uint32_t timeout_msec;
	uint8_t wrong_session_key[16] = { 0x1f, 0x2f, 0x3f, };

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx,
			     "Can't test without SMB3 support");
	}

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	torture_assert(tctx, unc != NULL, "talloc_asprintf");

	user_creds = cli_credentials_shallow_copy(tctx, _creds);
	torture_assert(tctx, user_creds != NULL, "cli_credentials_shallow_copy");
	ok = cli_credentials_set_smb_encryption(user_creds,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	anon_creds = cli_credentials_init_anon(tctx);
	torture_assert(tctx, anon_creds != NULL, "cli_credentials_init_anon");
	ok = cli_credentials_set_smb_encryption(anon_creds,
						SMB_ENCRYPTION_REQUIRED,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options = transport0->options;
	options.client_guid = GUID_random();

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      user_creds,
			      &user_tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "smb2_connect failed");
	user_session = user_tree->session;
	transport = user_session->transport;
	ok = smb2cli_tcon_is_encryption_on(user_tree->smbXcli);
	torture_assert(tctx, ok, "smb2cli_tcon_is_encryption_on(user)");
	ok = smbXcli_session_is_authenticated(user_session->smbXcli);
	torture_assert(tctx, ok, "smbXcli_session_is_authenticated(user)");

	anon_session = smb2_session_init(transport,
					 lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					 tctx);
	torture_assert(tctx, anon_session != NULL, "smb2_session_init(anon)");

	anon_session->anonymous_session_key = true;
	anon_session->forced_session_key = data_blob_const(wrong_session_key,
						ARRAY_SIZE(wrong_session_key));
	smb2cli_session_torture_anonymous_encryption(anon_session->smbXcli, true);

	status = smb2_session_setup_spnego(anon_session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok(tctx, status,
				   "smb2_session_setup_spnego failed");

	ok = smb2cli_tcon_is_encryption_on(user_tree->smbXcli);
	torture_assert(tctx, ok, "smb2cli_tcon_is_encryption_on(anon)");
	ok = smbXcli_session_is_authenticated(anon_session->smbXcli);
	torture_assert(tctx, !ok, "smbXcli_session_is_authenticated(anon) wrong");

	anon_tree = smb2_tree_init(anon_session, tctx, false);
	torture_assert(tctx, anon_tree != NULL, "smb2_tree_init");

	timeout_msec = transport->options.request_timeout * 1000;
	subreq = smb2cli_tcon_send(tctx,
				   tctx->ev,
				   transport->conn,
				   timeout_msec,
				   anon_session->smbXcli,
				   anon_tree->smbXcli,
				   0, /* flags */
				   unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");

	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");

	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_DISCONNECTED)) {
		status = NT_STATUS_CONNECTION_RESET;
	}
	torture_assert_ntstatus_equal(tctx, status,
				      NT_STATUS_CONNECTION_RESET,
				      "smb2cli_tcon_recv");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, !ok, "smbXcli_conn_is_connected still connected");

	return true;
}

static bool test_session_anon_signing1(struct torture_context *tctx,
				       struct smb2_tree *tree0)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = "IPC$";
	char *unc = NULL;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct cli_credentials *anon_creds = NULL;
	struct smbcli_options options;
	struct smb2_transport *transport = NULL;
	struct smb2_session *anon_session = NULL;
	struct smb2_tree *anon_tree = NULL;
	NTSTATUS status;
	bool ok = true;
	struct tevent_req *subreq = NULL;
	uint32_t timeout_msec;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx,
			     "Can't test without SMB3 support");
	}

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	torture_assert(tctx, unc != NULL, "talloc_asprintf");

	anon_creds = cli_credentials_init_anon(tctx);
	torture_assert(tctx, anon_creds != NULL, "cli_credentials_init_anon");
	ok = cli_credentials_set_smb_signing(anon_creds,
					     SMB_SIGNING_REQUIRED,
					     CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_signing");
	ok = cli_credentials_set_smb_ipc_signing(anon_creds,
						 SMB_SIGNING_REQUIRED,
						 CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_ipc_signing");
	ok = cli_credentials_set_smb_encryption(anon_creds,
						SMB_ENCRYPTION_OFF,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options = transport0->options;
	options.client_guid = GUID_random();
	options.only_negprot = true;
	options.signing = SMB_SIGNING_REQUIRED;

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      anon_creds,
			      &anon_tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "smb2_connect failed");
	anon_session = anon_tree->session;
	transport = anon_session->transport;

	anon_session->anonymous_session_key = true;
	smb2cli_session_torture_anonymous_signing(anon_session->smbXcli, true);

	status = smb2_session_setup_spnego(anon_session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok(tctx, status,
				   "smb2_session_setup_spnego failed");

	ok = smbXcli_session_is_authenticated(anon_session->smbXcli);
	torture_assert(tctx, !ok, "smbXcli_session_is_authenticated(anon) wrong");

	timeout_msec = transport->options.request_timeout * 1000;
	subreq = smb2cli_tcon_send(tctx,
				   tctx->ev,
				   transport->conn,
				   timeout_msec,
				   anon_session->smbXcli,
				   anon_tree->smbXcli,
				   0, /* flags */
				   unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");

	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");

	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_ok(tctx, status, "smb2cli_tcon_recv");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, ok, "smbXcli_conn_is_connected");

	return true;
}

static bool test_session_anon_signing2(struct torture_context *tctx,
				       struct smb2_tree *tree0)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = "IPC$";
	char *unc = NULL;
	struct smb2_transport *transport0 = tree0->session->transport;
	struct cli_credentials *anon_creds = NULL;
	struct smbcli_options options;
	struct smb2_transport *transport = NULL;
	struct smb2_session *anon_session = NULL;
	struct smb2_session *anon_session_nosign = NULL;
	struct smb2_tree *anon_tree = NULL;
	NTSTATUS status;
	bool ok = true;
	struct tevent_req *subreq = NULL;
	uint32_t timeout_msec;
	uint8_t wrong_session_key[16] = { 0x1f, 0x2f, 0x3f, };
	uint64_t session_id;

	if (smbXcli_conn_protocol(transport0->conn) < PROTOCOL_SMB3_00) {
		torture_skip(tctx,
			     "Can't test without SMB3 support");
	}

	unc = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	torture_assert(tctx, unc != NULL, "talloc_asprintf");

	anon_creds = cli_credentials_init_anon(tctx);
	torture_assert(tctx, anon_creds != NULL, "cli_credentials_init_anon");
	ok = cli_credentials_set_smb_signing(anon_creds,
					     SMB_SIGNING_REQUIRED,
					     CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_signing");
	ok = cli_credentials_set_smb_ipc_signing(anon_creds,
						 SMB_SIGNING_REQUIRED,
						 CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_ipc_signing");
	ok = cli_credentials_set_smb_encryption(anon_creds,
						SMB_ENCRYPTION_OFF,
						CRED_SPECIFIED);
	torture_assert(tctx, ok, "cli_credentials_set_smb_encryption");

	options = transport0->options;
	options.client_guid = GUID_random();
	options.only_negprot = true;
	options.signing = SMB_SIGNING_REQUIRED;

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      anon_creds,
			      &anon_tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "smb2_connect failed");
	anon_session = anon_tree->session;
	transport = anon_session->transport;

	anon_session->anonymous_session_key = true;
	anon_session->forced_session_key = data_blob_const(wrong_session_key,
						ARRAY_SIZE(wrong_session_key));
	smb2cli_session_torture_anonymous_signing(anon_session->smbXcli, true);
	smb2cli_session_torture_no_signing_disconnect(anon_session->smbXcli);

	status = smb2_session_setup_spnego(anon_session,
					   anon_creds,
					   0 /* previous_session_id */);
	torture_assert_ntstatus_ok(tctx, status,
				   "smb2_session_setup_spnego failed");

	ok = smbXcli_session_is_authenticated(anon_session->smbXcli);
	torture_assert(tctx, !ok, "smbXcli_session_is_authenticated(anon) wrong");

	/*
	 * create a new structure for the same session id,
	 * but without smb2.should_sign set.
	 */
	session_id = smb2cli_session_current_id(anon_session->smbXcli);
	anon_session_nosign = smb2_session_init(transport,
					        lpcfg_gensec_settings(tctx, tctx->lp_ctx),
					        tctx);
	torture_assert(tctx, anon_session_nosign != NULL, "smb2_session_init(anon_nosign)");
	smb2cli_session_set_id_and_flags(anon_session_nosign->smbXcli, session_id, 0);
	smb2cli_session_torture_no_signing_disconnect(anon_session_nosign->smbXcli);

	timeout_msec = transport->options.request_timeout * 1000;
	subreq = smb2cli_tcon_send(tctx,
				   tctx->ev,
				   transport->conn,
				   timeout_msec,
				   anon_session->smbXcli,
				   anon_tree->smbXcli,
				   0, /* flags */
				   unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");

	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");

	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_equal(tctx, status,
				      NT_STATUS_ACCESS_DENIED,
				      "smb2cli_tcon_recv");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, ok, "smbXcli_conn_is_connected");

	subreq = smb2cli_tcon_send(tctx,
				   tctx->ev,
				   transport->conn,
				   timeout_msec,
				   anon_session_nosign->smbXcli,
				   anon_tree->smbXcli,
				   0, /* flags */
				   unc);
	torture_assert(tctx, subreq != NULL, "smb2cli_tcon_send");

	torture_assert(tctx,
		       tevent_req_poll_ntstatus(subreq, tctx->ev, &status),
		       "tevent_req_poll_ntstatus");

	status = smb2cli_tcon_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_ok(tctx, status, "smb2cli_tcon_recv");

	ok = smbXcli_conn_is_connected(transport->conn);
	torture_assert(tctx, ok, "smbXcli_conn_is_connected");

	return true;
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
	torture_suite_add_1smb2_test(suite, "bind2", test_session_bind2);
	torture_suite_add_1smb2_test(suite, "bind_invalid_auth", test_session_bind_invalid_auth);
	torture_suite_add_1smb2_test(suite, "bind_different_user", test_session_bind_different_user);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb202", test_session_bind_negative_smb202);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb210s", test_session_bind_negative_smb210s);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb210d", test_session_bind_negative_smb210d);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb2to3s", test_session_bind_negative_smb2to3s);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb2to3d", test_session_bind_negative_smb2to3d);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3to2s", test_session_bind_negative_smb3to2s);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3to2d", test_session_bind_negative_smb3to2d);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3to3s", test_session_bind_negative_smb3to3s);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3to3d", test_session_bind_negative_smb3to3d);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3encGtoCs", test_session_bind_negative_smb3encGtoCs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3encGtoCd", test_session_bind_negative_smb3encGtoCd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signCtoHs", test_session_bind_negative_smb3signCtoHs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signCtoHd", test_session_bind_negative_smb3signCtoHd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signCtoGs", test_session_bind_negative_smb3signCtoGs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signCtoGd", test_session_bind_negative_smb3signCtoGd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signHtoCs", test_session_bind_negative_smb3signHtoCs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signHtoCd", test_session_bind_negative_smb3signHtoCd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signHtoGs", test_session_bind_negative_smb3signHtoGs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signHtoGd", test_session_bind_negative_smb3signHtoGd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signGtoCs", test_session_bind_negative_smb3signGtoCs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signGtoCd", test_session_bind_negative_smb3signGtoCd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signGtoHs", test_session_bind_negative_smb3signGtoHs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signGtoHd", test_session_bind_negative_smb3signGtoHd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3sneGtoCs", test_session_bind_negative_smb3sneGtoCs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3sneGtoCd", test_session_bind_negative_smb3sneGtoCd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3sneGtoHs", test_session_bind_negative_smb3sneGtoHs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3sneGtoHd", test_session_bind_negative_smb3sneGtoHd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3sneCtoGs", test_session_bind_negative_smb3sneCtoGs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3sneCtoGd", test_session_bind_negative_smb3sneCtoGd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3sneHtoGs", test_session_bind_negative_smb3sneHtoGs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3sneHtoGd", test_session_bind_negative_smb3sneHtoGd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signC30toGs", test_session_bind_negative_smb3signC30toGs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signC30toGd", test_session_bind_negative_smb3signC30toGd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signH2XtoGs", test_session_bind_negative_smb3signH2XtoGs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signH2XtoGd", test_session_bind_negative_smb3signH2XtoGd);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signGtoC30s", test_session_bind_negative_smb3signGtoC30s);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signGtoC30d", test_session_bind_negative_smb3signGtoC30d);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signGtoH2Xs", test_session_bind_negative_smb3signGtoH2Xs);
	torture_suite_add_1smb2_test(suite, "bind_negative_smb3signGtoH2Xd", test_session_bind_negative_smb3signGtoH2Xd);
	torture_suite_add_1smb2_test(suite, "two_logoff", test_session_two_logoff);
	torture_suite_add_1smb2_test(suite, "signing-hmac-sha-256", test_session_signing_hmac_sha_256);
	torture_suite_add_1smb2_test(suite, "signing-aes-128-cmac", test_session_signing_aes_128_cmac);
	torture_suite_add_1smb2_test(suite, "signing-aes-128-gmac", test_session_signing_aes_128_gmac);
	torture_suite_add_1smb2_test(suite, "encryption-aes-128-ccm", test_session_encryption_aes_128_ccm);
	torture_suite_add_1smb2_test(suite, "encryption-aes-128-gcm", test_session_encryption_aes_128_gcm);
	torture_suite_add_1smb2_test(suite, "encryption-aes-256-ccm", test_session_encryption_aes_256_ccm);
	torture_suite_add_1smb2_test(suite, "encryption-aes-256-gcm", test_session_encryption_aes_256_gcm);
	torture_suite_add_1smb2_test(suite, "ntlmssp_bug14932", test_session_ntlmssp_bug14932);
	torture_suite_add_1smb2_test(suite, "anon-encryption1", test_session_anon_encryption1);
	torture_suite_add_1smb2_test(suite, "anon-encryption2", test_session_anon_encryption2);
	torture_suite_add_1smb2_test(suite, "anon-encryption3", test_session_anon_encryption3);
	torture_suite_add_1smb2_test(suite, "anon-signing1", test_session_anon_signing1);
	torture_suite_add_1smb2_test(suite, "anon-signing2", test_session_anon_signing2);

	suite->description = talloc_strdup(suite, "SMB2-SESSION tests");

	return suite;
}

static bool test_session_require_sign_bug15397(struct torture_context *tctx,
					       struct smb2_tree *_tree)
{
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *share = torture_setting_string(tctx, "share", NULL);
	struct cli_credentials *_creds = samba_cmdline_get_creds();
	struct cli_credentials *creds = NULL;
	struct smbcli_options options;
	struct smb2_tree *tree = NULL;
	uint8_t security_mode;
	NTSTATUS status;
	bool ok = true;

	/*
	 * Setup our own connection so we can control the signing flags
	 */

	creds = cli_credentials_shallow_copy(tctx, _creds);
	torture_assert(tctx, creds != NULL, "cli_credentials_shallow_copy");

	options = _tree->session->transport->options;
	options.client_guid = GUID_random();
	options.signing = SMB_SIGNING_IF_REQUIRED;

	status = smb2_connect(tctx,
			      host,
			      share,
			      tctx->lp_ctx,
			      lpcfg_resolve_context(tctx->lp_ctx),
			      creds,
			      &tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done,
					"smb2_connect failed");

	security_mode = smb2cli_session_security_mode(tree->session->smbXcli);

	torture_assert_int_equal_goto(
		tctx,
		security_mode,
		SMB2_NEGOTIATE_SIGNING_REQUIRED | SMB2_NEGOTIATE_SIGNING_ENABLED,
		ok,
		done,
		"Signing not required");

done:
	return ok;
}

struct torture_suite *torture_smb2_session_req_sign_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite =
	    torture_suite_create(ctx, "session-require-signing");

	torture_suite_add_1smb2_test(suite, "bug15397",
				     test_session_require_sign_bug15397);

	suite->description = talloc_strdup(suite, "SMB2-SESSION require signing tests");
	return suite;
}
