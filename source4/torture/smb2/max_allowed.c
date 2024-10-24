/*
   Unix SMB/CIFS implementation.
   SMB torture tester - deny mode scanning functions
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) David Mulder 2019

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
#include "system/filesys.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/security/security.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"

#define MAXIMUM_ALLOWED_FILE    "torture_maximum_allowed"
static bool torture_smb2_maximum_allowed(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	struct security_descriptor *sd = NULL, *sd_orig = NULL;
	struct smb2_create io = {0};
	TALLOC_CTX *mem_ctx = NULL;
	struct smb2_handle fnum = {{0}}, fnum1 = {{0}};
	int i;
	bool ret = true;
	NTSTATUS status;
	union smb_fileinfo q;
	union smb_setfileinfo set;
	const char *owner_sid = NULL;
	bool has_restore_privilege, has_backup_privilege, has_system_security_privilege;

	mem_ctx = talloc_init("torture_maximum_allowed");
	torture_assert_goto(tctx, mem_ctx != NULL, ret, done,
			    "talloc allocation failed\n");

	if (!torture_setting_bool(tctx, "sacl_support", true))
		torture_warning(tctx, "Skipping SACL related tests!\n");

	sd = security_descriptor_dacl_create(mem_ctx,
	    0, NULL, NULL,
	    SID_NT_AUTHENTICATED_USERS,
	    SEC_ACE_TYPE_ACCESS_ALLOWED,
	    SEC_RIGHTS_FILE_READ,
	    0, NULL);
	torture_assert_goto(tctx, sd != NULL, ret, done,
			    "security descriptor creation failed\n");

	/* Blank slate */
	smb2_util_unlink(tree, MAXIMUM_ALLOWED_FILE);

	/* create initial file with restrictive SD */
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.fname = MAXIMUM_ALLOWED_FILE;
	io.in.sec_desc = sd;

	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		talloc_asprintf(tctx, "Incorrect status %s - should be %s\n",
				nt_errstr(status), nt_errstr(NT_STATUS_OK)));
	fnum = io.out.file.handle;

	/* the correct answers for this test depends on whether the
	   user has restore privileges. To find that out we first need
	   to know our SID - get it from the owner_sid of the file we
	   just created */
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = fnum;
	q.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;
	status = smb2_getinfo_file(tree, tctx, &q);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, set_sd,
		talloc_asprintf(tctx, "Incorrect status %s - should be %s\n",
				nt_errstr(status), nt_errstr(NT_STATUS_OK)));
	sd_orig = q.query_secdesc.out.sd;

	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	status = torture_smb2_check_privilege(tree,
					 owner_sid,
					 sec_privilege_name(SEC_PRIV_RESTORE));
	has_restore_privilege = NT_STATUS_IS_OK(status);
	torture_comment(tctx, "Checked SEC_PRIV_RESTORE for %s - %s\n",
			owner_sid,
			has_restore_privilege?"Yes":"No");

	status = torture_smb2_check_privilege(tree,
					 owner_sid,
					 sec_privilege_name(SEC_PRIV_BACKUP));
	has_backup_privilege = NT_STATUS_IS_OK(status);
	torture_comment(tctx, "Checked SEC_PRIV_BACKUP for %s - %s\n",
			owner_sid,
			has_backup_privilege?"Yes":"No");

	status = torture_smb2_check_privilege(tree,
					 owner_sid,
					 sec_privilege_name(SEC_PRIV_SECURITY));
	has_system_security_privilege = NT_STATUS_IS_OK(status);
	torture_comment(tctx, "Checked SEC_PRIV_SECURITY for %s - %s\n",
			owner_sid,
			has_system_security_privilege?"Yes":"No");

	smb2_util_close(tree, fnum);

	for (i = 0; i < 32; i++) {
		uint32_t mask = SEC_FLAG_MAXIMUM_ALLOWED | (1u << i);
		/*
		 * SEC_GENERIC_EXECUTE is a complete subset of
		 * SEC_GENERIC_READ when mapped to specific bits,
		 * so we need to include it in the basic OK mask.
		 */
		uint32_t ok_mask = SEC_RIGHTS_FILE_READ | SEC_GENERIC_READ | SEC_GENERIC_EXECUTE |
			SEC_STD_DELETE | SEC_STD_WRITE_DAC;

		/*
		 * Now SEC_RIGHTS_PRIV_RESTORE and SEC_RIGHTS_PRIV_BACKUP
		 * don't include any generic bits (they're used directly
		 * in the fileserver where the generic bits have already
		 * been mapped into file specific bits) we need to add the
		 * generic bits to the ok_mask when we have these privileges.
		 */
		if (has_restore_privilege) {
			ok_mask |= SEC_RIGHTS_PRIV_RESTORE|SEC_GENERIC_WRITE;
		}
		if (has_backup_privilege) {
			ok_mask |= SEC_RIGHTS_PRIV_BACKUP|SEC_GENERIC_READ;
		}
		if (has_system_security_privilege) {
			ok_mask |= SEC_FLAG_SYSTEM_SECURITY;
		}

		/* Skip all SACL related tests. */
		if ((!torture_setting_bool(tctx, "sacl_support", true)) &&
		    (mask & SEC_FLAG_SYSTEM_SECURITY))
			continue;

		io = (struct smb2_create){0};
		io.in.desired_access = mask;
		io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		io.in.create_disposition = NTCREATEX_DISP_OPEN;
		io.in.impersonation_level =
		    NTCREATEX_IMPERSONATION_ANONYMOUS;
		io.in.fname = MAXIMUM_ALLOWED_FILE;

		status = smb2_create(tree, mem_ctx, &io);
		if (mask & ok_mask ||
		    mask == SEC_FLAG_MAXIMUM_ALLOWED) {
			torture_assert_ntstatus_ok_goto(tctx, status, ret,
				set_sd, talloc_asprintf(tctx,
				"Incorrect status %s - should be %s\n",
				nt_errstr(status), nt_errstr(NT_STATUS_OK)));
		} else {
			if (mask & SEC_FLAG_SYSTEM_SECURITY) {
				torture_assert_ntstatus_equal_goto(tctx,
					status, NT_STATUS_PRIVILEGE_NOT_HELD,
					ret, set_sd, talloc_asprintf(tctx,
					"Incorrect status %s - should be %s\n",
					nt_errstr(status),
					nt_errstr(NT_STATUS_PRIVILEGE_NOT_HELD)));
			} else {
				torture_assert_ntstatus_equal_goto(tctx,
					status, NT_STATUS_ACCESS_DENIED,
					ret, set_sd, talloc_asprintf(tctx,
					"Incorrect status %s - should be %s\n",
					nt_errstr(status),
					nt_errstr(NT_STATUS_ACCESS_DENIED)));
			}
		}

		fnum = io.out.file.handle;

		smb2_util_close(tree, fnum);
	}

set_sd:
	io.in.desired_access = SEC_STD_WRITE_DAC;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.fname = MAXIMUM_ALLOWED_FILE;

	status = smb2_create(tree, mem_ctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		talloc_asprintf(tctx, "Incorrect status %s - should be %s\n",
				nt_errstr(status), nt_errstr(NT_STATUS_OK)));
	fnum1 = io.out.file.handle;

	sd = security_descriptor_dacl_create(tctx,
					0, NULL, NULL,
					SID_NT_AUTHENTICATED_USERS,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_STD_DELETE,
					0,
					NULL);
	set.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	set.set_secdesc.in.file.handle = fnum1;
	set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	set.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &set);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
		talloc_asprintf(tctx, "Incorrect status %s - should be %s\n",
				nt_errstr(status), nt_errstr(NT_STATUS_OK)));

 done:
	smb2_util_close(tree, fnum1);
	smb2_util_unlink(tree, MAXIMUM_ALLOWED_FILE);
	talloc_free(mem_ctx);
	return ret;
}

static bool torture_smb2_read_only_file(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	struct smb2_create c;
	struct smb2_handle h = {{0}};
	bool ret = true;
	NTSTATUS status;

	smb2_deltree(tree, MAXIMUM_ALLOWED_FILE);

	c = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_FILE_ALL,
		.in.file_attributes = FILE_ATTRIBUTE_READONLY,
		.in.create_disposition = NTCREATEX_DISP_CREATE,
		.in.fname = MAXIMUM_ALLOWED_FILE,
	};

	status = smb2_create(tree, tctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h = c.out.file.handle;
	smb2_util_close(tree, h);
	ZERO_STRUCT(h);

	c = (struct smb2_create) {
		.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED,
		.in.file_attributes = FILE_ATTRIBUTE_READONLY,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = MAXIMUM_ALLOWED_FILE,
	};

	status = smb2_create(tree, tctx, &c);
	torture_assert_ntstatus_ok_goto(
		tctx, status, ret, done,
		"Failed to open READ-ONLY file with SEC_FLAG_MAXIMUM_ALLOWED\n");
	h = c.out.file.handle;
	smb2_util_close(tree, h);
	ZERO_STRUCT(h);

done:
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, MAXIMUM_ALLOWED_FILE);
	return ret;
}

struct torture_suite *torture_smb2_max_allowed(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "maximum_allowed");

	torture_suite_add_1smb2_test(suite, "maximum_allowed", torture_smb2_maximum_allowed);
	torture_suite_add_1smb2_test(suite, "read_only", torture_smb2_read_only_file);
	return suite;
}
