/*
   Unix SMB/CIFS implementation.

   SMB torture tester - charset test routines

   Copyright (C) Andrew Tridgell 2001

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
#include "libcli/libcli.h"
#include "torture/util.h"
#include "param/param.h"

#define BASEDIR "chartest"

/*
   open a file using a set of unicode code points for the name

   the prefix BASEDIR is added before the name
*/
static NTSTATUS unicode_open(struct torture_context *tctx,
			     struct smb2_tree *tree,
			     TALLOC_CTX *mem_ctx,
			     uint32_t create_disposition,
			     const uint32_t *u_name,
			     size_t u_name_len)
{
	struct smb2_create io = {0};
	char *fname = NULL;
	char *fname2 = NULL;
	char *ucs_name = NULL;
	size_t i;
	NTSTATUS status;

	ucs_name = talloc_size(mem_ctx, (1+u_name_len)*2);
	if (!ucs_name) {
		torture_comment(tctx, "Failed to create UCS2 Name - talloc() failure\n");
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<u_name_len;i++) {
		SSVAL(ucs_name, i*2, u_name[i]);
	}
	SSVAL(ucs_name, i*2, 0);

	if (!convert_string_talloc_handle(ucs_name, lpcfg_iconv_handle(tctx->lp_ctx), CH_UTF16, CH_UNIX, ucs_name, (1+u_name_len)*2, (void **)&fname, &i)) {
		torture_comment(tctx, "Failed to convert UCS2 Name into unix - convert_string_talloc() failure\n");
		talloc_free(ucs_name);
		return NT_STATUS_NO_MEMORY;
	}

	fname2 = talloc_asprintf(ucs_name, "%s\\%s", BASEDIR, fname);
	if (!fname2) {
		talloc_free(ucs_name);
		torture_comment(tctx, "Failed to create fname - talloc() failure\n");
		return NT_STATUS_NO_MEMORY;
	}

	io.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.in.create_options = 0;
	io.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = fname2;
	io.in.create_disposition = create_disposition;

	status = smb2_create(tree, tctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(ucs_name);
		return status;
	}

	smb2_util_close(tree, io.out.file.handle);
	talloc_free(ucs_name);
	return NT_STATUS_OK;
}


/*
  see if the server recognises composed characters
*/
static bool test_composed(struct torture_context *tctx,
			  struct smb2_tree *tree)
{
	const uint32_t name1[] = {0x61, 0x308};
	const uint32_t name2[] = {0xe4};
	NTSTATUS status;
	bool ret = true;

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done, "setting up basedir");

	status = unicode_open(tctx, tree, tctx,
			      NTCREATEX_DISP_CREATE, name1, 2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Failed to create composed name");

	status = unicode_open(tctx, tree, tctx,
			      NTCREATEX_DISP_CREATE, name2, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Failed to create accented character");

done:
	smb2_deltree(tree, BASEDIR);
	return ret;
}

/*
  see if the server recognises a naked diacritical
*/
static bool test_diacritical(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	const uint32_t name1[] = {0x308};
	const uint32_t name2[] = {0x308, 0x308};
	NTSTATUS status;
	bool ret = true;

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done, "setting up basedir");

	status = unicode_open(tctx, tree, tctx,
			      NTCREATEX_DISP_CREATE, name1, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Failed to create naked diacritical");

	/* try a double diacritical */
	status = unicode_open(tctx, tree, tctx,
			      NTCREATEX_DISP_CREATE, name2, 2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Failed to create double "
					"naked diacritical");

done:
	smb2_deltree(tree, BASEDIR);
	return ret;
}

/*
  see if the server recognises a partial surrogate pair
*/
static bool test_surrogate(struct torture_context *tctx,
			   struct smb2_tree *tree)
{
	const uint32_t name1[] = {0xd800};
	const uint32_t name2[] = {0xdc00};
	const uint32_t name3[] = {0xd800, 0xdc00};
	NTSTATUS status;
	bool ret = true;

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done, "setting up basedir");

	status = unicode_open(tctx, tree, tctx, NTCREATEX_DISP_CREATE, name1, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Failed to create partial surrogate 1");

	status = unicode_open(tctx, tree, tctx, NTCREATEX_DISP_CREATE, name2, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Failed to create partial surrogate 2");

	status = unicode_open(tctx, tree, tctx, NTCREATEX_DISP_CREATE, name3, 2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Failed to create full surrogate");

done:
	smb2_deltree(tree, BASEDIR);
	return true;
}

/*
  see if the server recognises wide-a characters
*/
static bool test_widea(struct torture_context *tctx,
		       struct smb2_tree *tree)
{
	const uint32_t name1[] = {'a'};
	const uint32_t name2[] = {0xff41};
	const uint32_t name3[] = {0xff21};
	NTSTATUS status;
	bool ret = true;

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ret, ret, done, "setting up basedir");

	status = unicode_open(tctx, tree, tctx, NTCREATEX_DISP_CREATE, name1, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Failed to create 'a'");

	status = unicode_open(tctx, tree, tctx, NTCREATEX_DISP_CREATE, name2, 1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Failed to create wide-a");

	status = unicode_open(tctx, tree, tctx, NTCREATEX_DISP_CREATE, name3, 1);
	torture_assert_ntstatus_equal_goto(tctx,
					   status,
					   NT_STATUS_OBJECT_NAME_COLLISION,
					   ret, done,
					   "Failed to create wide-A");

done:
	smb2_deltree(tree, BASEDIR);
	return ret;
}

struct torture_suite *torture_smb2_charset(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "charset");

	torture_suite_add_1smb2_test(suite, "Testing composite character (a umlaut)", test_composed);
	torture_suite_add_1smb2_test(suite, "Testing naked diacritical (umlaut)", test_diacritical);
	torture_suite_add_1smb2_test(suite, "Testing partial surrogate", test_surrogate);
	torture_suite_add_1smb2_test(suite, "Testing wide-a", test_widea);

	return suite;
}
