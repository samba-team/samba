/*
   Unix SMB/CIFS implementation.

   Copyright (C) Ralph Boehme 2016

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
#include "lib/cmdline/popt_common.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/vfs/proto.h"
#include "libcli/resolve/resolve.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/param/param.h"

#define BASEDIR "smb2-testsd"

#define CHECK_SECURITY_DESCRIPTOR(_sd1, _sd2) do { \
	if (!security_descriptor_equal(_sd1, _sd2)) { \
		torture_warning(tctx, "security descriptors don't match!\n"); \
		torture_warning(tctx, "got:\n"); \
		NDR_PRINT_DEBUG(security_descriptor, _sd1); \
		torture_warning(tctx, "expected:\n"); \
		NDR_PRINT_DEBUG(security_descriptor, _sd2); \
		torture_result(tctx, TORTURE_FAIL, \
			       "%s: security descriptors don't match!\n", \
			       __location__); \
		ret = false; \
	} \
} while (0)

/**
 * SMB2 connect with explicit share
 **/
static bool torture_smb2_con_share(struct torture_context *tctx,
                           const char *share,
                           struct smb2_tree **tree)
{
        struct smbcli_options options;
        NTSTATUS status;
        const char *host = torture_setting_string(tctx, "host", NULL);

        lpcfg_smbcli_options(tctx->lp_ctx, &options);

        status = smb2_connect_ext(tctx,
                                  host,
                                  lpcfg_smb_ports(tctx->lp_ctx),
                                  share,
                                  lpcfg_resolve_context(tctx->lp_ctx),
                                  popt_get_cmdline_credentials(),
                                  0,
                                  tree,
                                  tctx->ev,
                                  &options,
                                  lpcfg_socket_options(tctx->lp_ctx),
                                  lpcfg_gensec_settings(tctx, tctx->lp_ctx)
                                  );
        if (!NT_STATUS_IS_OK(status)) {
                printf("Failed to connect to SMB2 share \\\\%s\\%s - %s\n",
                       host, share, nt_errstr(status));
                return false;
        }
        return true;
}

static bool test_default_acl_posix(struct torture_context *tctx,
				   struct smb2_tree *tree_unused)
{
	struct smb2_tree *tree = NULL;
	NTSTATUS status;
	bool ok;
	bool ret = true;
	const char *dname = BASEDIR "\\testdir";
	const char *fname = BASEDIR "\\testdir\\testfile";
	struct smb2_handle fhandle = {{0}};
	struct smb2_handle dhandle = {{0}};
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd = NULL;
	struct security_descriptor *exp_sd = NULL;
	char *owner_sid = NULL;
	char *group_sid = NULL;

	ok = torture_smb2_con_share(tctx, "acl_xattr_ign_sysacl_posix", &tree);
	torture_assert_goto(tctx, ok == true, ret, done,
			    "Unable to connect to 'acl_xattr_ign_sysacl_posix'\n");

	ok = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ok == true, ret, done, "Unable to setup testdir\n");

	ZERO_STRUCT(dhandle);
	status = torture_smb2_testdir(tree, dname, &dhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir\n");

	torture_comment(tctx, "Get the original sd\n");

	ZERO_STRUCT(q);
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = dhandle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER | SECINFO_GROUP;
	status = smb2_getinfo_file(tree, tctx, &q);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_getinfo_file\n");

	sd = q.query_secdesc.out.sd;
	owner_sid = dom_sid_string(tctx, sd->owner_sid);
	group_sid = dom_sid_string(tctx, sd->group_sid);
	torture_comment(tctx, "owner [%s] group [%s]\n", owner_sid, group_sid);

	torture_comment(tctx, "Set ACL with no inheritable ACE\n");

	sd = security_descriptor_dacl_create(tctx,
					     0, NULL, NULL,
					     owner_sid,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     SEC_RIGHTS_DIR_ALL,
					     0,
					     NULL);

	ZERO_STRUCT(set);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = dhandle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &set);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_setinfo_file\n");

	TALLOC_FREE(sd);
	smb2_util_close(tree, dhandle);

	torture_comment(tctx, "Create file\n");

	ZERO_STRUCT(fhandle);
	status = torture_smb2_testfile(tree, fname, &fhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create_complex_file\n");

	torture_comment(tctx, "Query file SD\n");

	ZERO_STRUCT(q);
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = fhandle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER | SECINFO_GROUP;
	status = smb2_getinfo_file(tree, tctx, &q);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_getinfo_file\n");
	sd = q.query_secdesc.out.sd;

	smb2_util_close(tree, fhandle);
	ZERO_STRUCT(fhandle);

	torture_comment(tctx, "Checking actual file SD against expected SD\n");

	exp_sd = security_descriptor_dacl_create(
		tctx, 0, owner_sid, group_sid,
		owner_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_RIGHTS_FILE_ALL, 0,
		group_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, FILE_GENERIC_READ|FILE_GENERIC_WRITE|FILE_GENERIC_EXECUTE, 0,
		SID_WORLD, SEC_ACE_TYPE_ACCESS_ALLOWED, FILE_GENERIC_READ|FILE_GENERIC_WRITE|FILE_GENERIC_EXECUTE, 0,
		SID_NT_SYSTEM, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_RIGHTS_FILE_ALL, 0,
		NULL);

	CHECK_SECURITY_DESCRIPTOR(sd, exp_sd);

done:
	if (!smb2_util_handle_empty(fhandle)) {
		smb2_util_close(tree, fhandle);
	}
	if (!smb2_util_handle_empty(dhandle)) {
		smb2_util_close(tree, dhandle);
	}
	if (tree != NULL) {
		smb2_deltree(tree, BASEDIR);
		smb2_tdis(tree);
	}

	return ret;
}

static bool test_default_acl_win(struct torture_context *tctx,
				   struct smb2_tree *tree_unused)
{
	struct smb2_tree *tree = NULL;
	NTSTATUS status;
	bool ok;
	bool ret = true;
	const char *dname = BASEDIR "\\testdir";
	const char *fname = BASEDIR "\\testdir\\testfile";
	struct smb2_handle fhandle = {{0}};
	struct smb2_handle dhandle = {{0}};
	union smb_fileinfo q;
	union smb_setfileinfo set;
	struct security_descriptor *sd = NULL;
	struct security_descriptor *exp_sd = NULL;
	char *owner_sid = NULL;
	char *group_sid = NULL;

	ok = torture_smb2_con_share(tctx, "acl_xattr_ign_sysacl_windows", &tree);
	torture_assert_goto(tctx, ok == true, ret, done,
			    "Unable to connect to 'acl_xattr_ign_sysacl_windows'\n");

	ok = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ok == true, ret, done, "Unable to setup testdir\n");

	ZERO_STRUCT(dhandle);
	status = torture_smb2_testdir(tree, dname, &dhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir\n");

	torture_comment(tctx, "Get the original sd\n");

	ZERO_STRUCT(q);
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = dhandle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER | SECINFO_GROUP;
	status = smb2_getinfo_file(tree, tctx, &q);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_getinfo_file\n");

	sd = q.query_secdesc.out.sd;
	owner_sid = dom_sid_string(tctx, sd->owner_sid);
	group_sid = dom_sid_string(tctx, sd->group_sid);
	torture_comment(tctx, "owner [%s] group [%s]\n", owner_sid, group_sid);

	torture_comment(tctx, "Set ACL with no inheritable ACE\n");

	sd = security_descriptor_dacl_create(tctx,
					     0, NULL, NULL,
					     owner_sid,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     SEC_RIGHTS_DIR_ALL,
					     0,
					     NULL);

	ZERO_STRUCT(set);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = dhandle;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &set);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_setinfo_file\n");

	TALLOC_FREE(sd);
	smb2_util_close(tree, dhandle);

	torture_comment(tctx, "Create file\n");

	ZERO_STRUCT(fhandle);
	status = torture_smb2_testfile(tree, fname, &fhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_create_complex_file\n");

	torture_comment(tctx, "Query file SD\n");

	ZERO_STRUCT(q);
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = fhandle;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER | SECINFO_GROUP;
	status = smb2_getinfo_file(tree, tctx, &q);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "smb2_getinfo_file\n");
	sd = q.query_secdesc.out.sd;

	smb2_util_close(tree, fhandle);
	ZERO_STRUCT(fhandle);

	torture_comment(tctx, "Checking actual file SD against expected SD\n");

	exp_sd = security_descriptor_dacl_create(
		tctx, 0, owner_sid, group_sid,
		owner_sid, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_RIGHTS_FILE_ALL, 0,
		SID_NT_SYSTEM, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_RIGHTS_FILE_ALL, 0,
		NULL);

	CHECK_SECURITY_DESCRIPTOR(sd, exp_sd);

done:
	if (!smb2_util_handle_empty(fhandle)) {
		smb2_util_close(tree, fhandle);
	}
	if (!smb2_util_handle_empty(dhandle)) {
		smb2_util_close(tree, dhandle);
	}
	if (tree != NULL) {
		smb2_deltree(tree, BASEDIR);
		smb2_tdis(tree);
	}

	return ret;
}

/*
   basic testing of vfs_acl_xattr
*/
struct torture_suite *torture_acl_xattr(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "acl_xattr");

	torture_suite_add_1smb2_test(suite, "default-acl-style-posix", test_default_acl_posix);
	torture_suite_add_1smb2_test(suite, "default-acl-style-windows", test_default_acl_win);

	suite->description = talloc_strdup(suite, "vfs_acl_xattr tests");

	return suite;
}
