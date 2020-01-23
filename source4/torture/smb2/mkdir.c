/*
   Unix SMB/CIFS implementation.
   RAW_MKDIR_* and RAW_RMDIR_* individual test suite
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) David Mulder 2020

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
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "libcli/smb_composite/smb_composite.h"

#define BASEDIR "mkdirtest"

/*
  test mkdir ops
*/
bool torture_smb2_mkdir(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_handle h = {{0}};
	const char *path = BASEDIR "\\mkdir.dir";
	NTSTATUS status;
	bool ret = true;

	ret = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert(tctx, ret, "Failed to setup up test directory: " BASEDIR);

	/*
	   basic mkdir
	*/
	status = smb2_util_mkdir(tree, path);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Incorrect status");

	torture_comment(tctx, "Testing mkdir collision\n");

	/* 2nd create */
	status = smb2_util_mkdir(tree, path);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_COLLISION,
					   ret, done, "Incorrect status");

	/* basic rmdir */
	status = smb2_util_rmdir(tree, path);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Incorrect status");

	status = smb2_util_rmdir(tree, path);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "Incorrect status");

	torture_comment(tctx, "Testing mkdir collision with file\n");

	/* name collision with a file */
	smb2_create_complex_file(tctx, tree, path, &h);
	smb2_util_close(tree, h);
	status = smb2_util_mkdir(tree, path);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_COLLISION,
					   ret, done, "Incorrect status");

	torture_comment(tctx, "Testing rmdir with file\n");

	/* delete a file with rmdir */
	status = smb2_util_rmdir(tree, path);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_NOT_A_DIRECTORY,
					   ret, done, "Incorrect status");

	smb2_util_unlink(tree, path);

	torture_comment(tctx, "Testing invalid dir\n");

	/* create an invalid dir */
	status = smb2_util_mkdir(tree, "..\\..\\..");
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_PATH_SYNTAX_BAD,
					   ret, done, "Incorrect status");

	torture_comment(tctx, "Testing t2mkdir bad path\n");
	status = smb2_util_mkdir(tree, BASEDIR "\\bad_path\\bad_path");
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_PATH_NOT_FOUND,
					   ret, done, "Incorrect status");

done:
	smb2_deltree(tree, BASEDIR);
	return ret;
}
