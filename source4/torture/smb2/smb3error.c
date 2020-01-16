/*
   Unix SMB/CIFS implementation.

   SMB torture tests (smb2) for misc error paths

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
#include "lib/param/param.h"
#include "libcli/smb_composite/smb_composite.h"

bool torture_smb2_samba3_errorpaths(struct torture_context *tctx)
{
	bool client_ntlmv2_auth;
	struct smb2_tree *tree_nt = NULL;
	bool result = true;
	const char *os2_fname = ".+,;=[].";
	const char *dname = "samba3_errordir";
	const char *fname1 = "test.txt";
	const char *fname2 = "test_dir.txt";
	struct smb2_create io = {0};
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = NULL;

	mem_ctx = talloc_new(tctx);
	torture_assert_goto(tctx, mem_ctx != NULL, result, fail, "out of memory");

	client_ntlmv2_auth = lpcfg_client_ntlmv2_auth(tctx->lp_ctx);

	torture_assert_goto(tctx,
		lpcfg_set_cmdline(tctx->lp_ctx, "client ntlmv2 auth", "yes"),
		result,
		fail,
		"Could not set 'client ntlmv2 auth = yes'");

	torture_assert_goto(tctx,
		torture_smb2_connection(tctx, &tree_nt),
		result,
		fail,
		"Establishing SMB2 connection failed");

	/*
	 * This is a trick:
	 * The test might close the connection. If we steal the tree context
	 * before that and free the parent instead of tree directly, we avoid
	 * a double free error.
	 */
	talloc_steal(mem_ctx, tree_nt);

	/* reset "client ntlmv2 auth" */
	torture_assert_goto(tctx,
		lpcfg_set_cmdline(tctx->lp_ctx,
				"client ntlmv2 auth",
				client_ntlmv2_auth ? "yes":"no"),
		result,
		fail,
		"Could not reset 'client ntlmv2 auth'");

	smb2_util_unlink(tree_nt, os2_fname);
	smb2_util_rmdir(tree_nt, dname);

	status = smb2_util_mkdir(tree_nt, dname);
	torture_assert_ntstatus_ok_goto(tctx, status, result, fail,
				talloc_asprintf(tctx,
				"smbcli_mkdir(%s) failed: %s\n", dname,
				nt_errstr(status)));
	io.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.alloc_size = 1024*1024;
	io.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.create_options = 0;
	io.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.in.fname = dname;

	status= smb2_create(tree_nt, tctx, &io);
	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_OBJECT_NAME_COLLISION,
		result,
		fail,
		talloc_asprintf(tctx,
			"incorrect status %s should be %s\n",
			nt_errstr(status),
			nt_errstr(NT_STATUS_OBJECT_NAME_COLLISION)));

	status = smb2_util_mkdir(tree_nt, dname);
	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_OBJECT_NAME_COLLISION,
		result,
		fail,
		talloc_asprintf(tctx,
			"incorrect status %s should be %s\n",
			nt_errstr(status),
			nt_errstr(NT_STATUS_OBJECT_NAME_COLLISION)));

	io.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	status= smb2_create(tree_nt, tctx, &io);
	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_OBJECT_NAME_COLLISION,
		result,
		fail,
		talloc_asprintf(tctx,
			"incorrect status %s should be %s\n",
			nt_errstr(status),
			nt_errstr(NT_STATUS_OBJECT_NAME_COLLISION)));
	{
		/*
		 * Samba 3.0.23 has a bug that an existing file can be opened
		 * as a directory using ntcreate&x. Test this.
		 */

		struct smb2_create io2;
		io2 = io;
		io2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
		io2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
		io2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;;
		io2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
		io2.in.desired_access = SEC_RIGHTS_FILE_READ;
		io2.in.fname = fname2;

		status = smb2_create(tree_nt, tctx, &io2);
		torture_assert_ntstatus_ok_goto(
				tctx,
				status,
				result,
				fail,
				talloc_asprintf(
					tctx,
					"Incorrect status %s - should be %s\n",
					nt_errstr(status),
					nt_errstr(NT_STATUS_OK)));
		smb2_util_close(tree_nt, io2.out.file.handle);
		io2 = io;
		io2.in.alloc_size = 0;
		io2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
			NTCREATEX_SHARE_ACCESS_WRITE|
			NTCREATEX_SHARE_ACCESS_DELETE;
		io2.in.fname = fname2;
		io2.in.create_disposition = NTCREATEX_DISP_OPEN;
		status = smb2_create(tree_nt, tctx, &io2);
		torture_assert_ntstatus_equal_goto(
			tctx,
			status,
			NT_STATUS_NOT_A_DIRECTORY,
			result,
			fail,
			talloc_asprintf(tctx,
				"incorrect status %s should be %s\n",
				nt_errstr(status),
				nt_errstr(NT_STATUS_NOT_A_DIRECTORY)));
	}

	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;;
	io.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.in.fname = os2_fname;

	status = smb2_create(tree_nt, tctx, &io);

	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_OBJECT_NAME_NOT_FOUND,
		result,
		fail,
		talloc_asprintf(tctx,
			"incorrect status %s should be %s\n",
			nt_errstr(status),
			nt_errstr(NT_STATUS_OBJECT_NAME_NOT_FOUND)));
fail:
	smb2_util_unlink(tree_nt, fname1);
	smb2_util_unlink(tree_nt, fname2);
	TALLOC_FREE(mem_ctx);
	return result;
}
