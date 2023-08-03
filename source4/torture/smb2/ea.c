/*
   Unix SMB/CIFS implementation.
   SMB2 EA tests

   Copyright (C) Ralph Boehme 2022

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
#include "ntstatus_gen.h"
#include "system/time.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"

#define BASEDIR "test_ea"

static bool find_returned_ea(union smb_fileinfo *finfo2,
			     const char *eaname)
{
	unsigned int i;
	unsigned int num_eas = finfo2->all_eas.out.num_eas;
	struct ea_struct *eas = finfo2->all_eas.out.eas;

	for (i = 0; i < num_eas; i++) {
		if (eas[i].name.s == NULL) {
			continue;
		}
		/* Windows capitalizes returned EA names. */
		if (strequal(eas[i].name.s, eaname)) {
			return true;
		}
	}
	return false;
}

static bool torture_smb2_acl_xattr(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	const char *fname = BASEDIR "\\test_acl_xattr";
	const char *xattr_name = NULL;
	struct smb2_handle h1;
	struct ea_struct ea;
	union smb_fileinfo finfo;
	union smb_setfileinfo sfinfo;
	NTSTATUS status;
	bool ret = true;

	torture_comment(tctx, "Verify NTACL xattr can't be accessed\n");

	xattr_name = torture_setting_string(tctx, "acl_xattr_name", NULL);
	torture_assert_not_null(tctx, xattr_name, "Missing acl_xattr_name option\n");

	smb2_deltree(tree, BASEDIR);

	status = torture_smb2_testdir(tree, BASEDIR, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);

	status = torture_smb2_testfile(tree, fname, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testfile failed\n");

	/*
	 * 1. Set an EA, so we have something to list
	 */
	ZERO_STRUCT(ea);
	ea.name.s = "void";
	ea.name.private_length = strlen("void") + 1;
	ea.value = data_blob_string_const("testme");

	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_FULL_EA_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	sfinfo.full_ea_information.in.eas.num_eas = 1;
	sfinfo.full_ea_information.in.eas.eas = &ea;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Setting EA should fail\n");

	/*
	 * 2. Verify NT ACL EA is not listed
	 */
	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_SMB2_ALL_EAS;
	finfo.generic.in.file.handle = h1;

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");

	if (find_returned_ea(&finfo, xattr_name)) {
		torture_result(tctx, TORTURE_FAIL,
			       "%s: NTACL EA leaked\n",
			       __location__);
		ret = false;
		goto done;
	}

	/*
	 * 3. Try to set EA, should fail
	 */
	ZERO_STRUCT(ea);
	ea.name.s = xattr_name;
	ea.name.private_length = strlen(xattr_name) + 1;
	ea.value = data_blob_string_const("testme");

	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_FULL_EA_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	sfinfo.full_ea_information.in.eas.num_eas = 1;
	sfinfo.full_ea_information.in.eas.eas = &ea;

	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_equal_goto(
		tctx, status, NT_STATUS_ACCESS_DENIED,
		ret, done, "Setting EA should fail\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}

	smb2_deltree(tree, BASEDIR);

	return ret;
}

struct torture_suite *torture_smb2_ea(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "ea");
	suite->description = talloc_strdup(suite, "SMB2-EA tests");

	torture_suite_add_1smb2_test(suite, "acl_xattr", torture_smb2_acl_xattr);

	return suite;
}
