/*
   Unix SMB/CIFS implementation.

   SMB2 maxfid test

   Copyright (C) Christof Schmitt 2016

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

bool torture_smb2_maxfid(struct torture_context *tctx)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_tree *tree = NULL;
	const char *dname = "smb2_maxfid";
	size_t i, maxfid;
	struct smb2_handle *handles,  dir_handle = { };
	size_t max_handles;

	/*
	 * We limited this to 65520 as socket_wrapper has a limit of
	 * 65535 (0xfff0) open sockets.
	 *
	 * It could be increased by setting the following env variable:
	 *
	 * SOCKET_WRAPPER_MAX_SOCKETS=100000
	 */
	max_handles = torture_setting_int(tctx, "maxopenfiles", 65520);

	if (!torture_smb2_connection(tctx, &tree)) {
		return false;
	}

	handles = talloc_array(tctx, struct smb2_handle, max_handles);
	if (handles == 0) {
		torture_fail(tctx, "Could not allocate handles array.\n");
		return false;
	}

	smb2_deltree(tree, dname);

	status = torture_smb2_testdir(tree, dname, &dir_handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed");
	smb2_util_close(tree, dir_handle);

	torture_comment(tctx, "Creating subdirectories\n");

	for (i = 0; i < max_handles; i += 1000) {
		char *name;
		struct smb2_create create = { };
		struct smb2_close close = { };

		name = talloc_asprintf(tctx, "%s\\%zu", dname, i / 1000);
		torture_assert_goto(tctx, (name != NULL), ret, done,
				    "no memory for directory name\n");

		create.in.desired_access = SEC_RIGHTS_DIR_ALL;
		create.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
		create.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
		create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			NTCREATEX_SHARE_ACCESS_WRITE |
			NTCREATEX_SHARE_ACCESS_DELETE;
		create.in.create_disposition = NTCREATEX_DISP_CREATE;
		create.in.fname = name;

		status = smb2_create(tree, tctx, &create);
		talloc_free(name);

		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"CREATE directory failed\n");

		close.in.file.handle = create.out.file.handle;
		status = smb2_close(tree, &close);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"CLOSE directory failed\n");
	}

	torture_comment(tctx, "Testing maximum number of open files\n");

	for (i = 0; i < max_handles; i++) {
		char *name;
		struct smb2_create create = { };

		name = talloc_asprintf(tctx, "%s\\%zu\\%zu", dname, i / 1000, i);
		torture_assert_goto(tctx, (name != NULL), ret, done,
				    "no memory for file name\n");

		create.in.desired_access = SEC_RIGHTS_DIR_ALL;
		create.in.create_options = 0;
		create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		create.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			NTCREATEX_SHARE_ACCESS_WRITE |
			NTCREATEX_SHARE_ACCESS_DELETE;
		create.in.create_disposition = NTCREATEX_DISP_CREATE;
		create.in.fname = name;

		status = smb2_create(tree, tctx, &create);
		if (!NT_STATUS_IS_OK(status)) {
			torture_comment(tctx, "create of %s failed: %s\n",
					name, nt_errstr(status));
			talloc_free(name);
			break;
		}
		talloc_free(name);

		handles[i] = create.out.file.handle;
	}

	maxfid = i;
	if (maxfid == max_handles) {
		torture_comment(tctx, "Reached test limit of %zu open files. "
				"Adjust to higher test with "
				"--option=torture:maxopenfiles=NNN\n", maxfid);
	}

	torture_comment(tctx, "Cleanup open files\n");

	for (i = 0; i < maxfid; i++) {
		union smb_setfileinfo sfinfo = { };

		sfinfo.disposition_info.in.delete_on_close = 1;
		sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
		sfinfo.generic.in.file.handle = handles[i];

		status = smb2_setinfo_file(tree, &sfinfo);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"SETINFO failed\n");

		status = smb2_util_close(tree, handles[i]);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"CLOSE failed\n");
	}

done:
	smb2_deltree(tree, dname);
	talloc_free(handles);

	return ret;
}
