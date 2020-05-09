/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 sharemodes

   Copyright (C) Christof Schmitt 2017

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
#include "libcli/security/security.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include <tevent.h>

#define BASEDIRHOLD "sharemode_hold_test"

struct hold_sharemode_info {
	const char *sharemode;
	const char *filename;
	struct smb2_handle handle;
} hold_sharemode_table[] = {
	{
		.sharemode = "",
		.filename  = BASEDIRHOLD "\\N",
	},
	{
		.sharemode = "R",
		.filename  = BASEDIRHOLD "\\R",
	},
	{
		.sharemode = "W",
		.filename  = BASEDIRHOLD "\\W",
	},
	{
		.sharemode = "D",
		.filename  = BASEDIRHOLD "\\D",
	},
	{
		.sharemode = "RW",
		.filename  = BASEDIRHOLD "\\RW",
	},
	{
		.sharemode = "RD",
		.filename  = BASEDIRHOLD "\\RD",
	},
	{
		.sharemode = "WD",
		.filename  = BASEDIRHOLD "\\WD",
	},
	{
		.sharemode = "RWD",
		.filename  = BASEDIRHOLD "\\RWD",
	},
};

static void signal_handler(struct tevent_context *ev,
			   struct tevent_signal *se,
			   int signum,
			   int count,
			   void *siginfo,
			   void *private_data)
{
	struct torture_context *tctx = private_data;

	torture_comment(tctx, "Received signal %d\n", signum);
}

/*
 * Used for manual testing of sharemodes - especially interaction with
 * other filesystems (such as NFS and local access). The scenario is
 * that this test holds files open and then concurrent access to the same
 * files outside of Samba can be tested.
 */
bool torture_smb2_hold_sharemode(struct torture_context *tctx)
{
	struct tevent_context *ev = tctx->ev;
	struct smb2_tree *tree = NULL;
	struct smb2_handle dir_handle;
	struct tevent_signal *s;
	NTSTATUS status;
	bool ret = true;
	int i;

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_comment(tctx, "Initializing smb2 connection failed.\n");
		return false;
	}

	s = tevent_add_signal(ev, tctx, SIGINT, 0, signal_handler, tctx);
	torture_assert_not_null_goto(tctx, s, ret, done,
				     "Error registering signal handler.");

	torture_comment(tctx, "Setting up open files with sharemodes in %s\n",
			BASEDIRHOLD);

	status = torture_smb2_testdir(tree, BASEDIRHOLD, &dir_handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"Error creating directory.");

	for (i = 0; i < ARRAY_SIZE(hold_sharemode_table); i++) {
		struct hold_sharemode_info *info = &hold_sharemode_table[i];
		struct smb2_create create = { };

		create.in.desired_access = SEC_RIGHTS_FILE_ALL;
		create.in.alloc_size = 0;
		create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		create.in.share_access =
			smb2_util_share_access(info->sharemode);
		create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
		create.in.create_options = 0;
		create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
		create.in.security_flags = 0;
		create.in.fname = info->filename;
		create.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
		create.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;

		torture_comment(tctx, "opening %s\n", info->filename);

		status = smb2_create(tree, tctx, &create);

		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"CREATE file failed\n");

		info->handle = create.out.file.handle;
	}

	torture_comment(tctx, "Waiting for SIGINT (ctrl-c)\n");
	tevent_loop_wait(ev);

	torture_comment(tctx, "Closing and deleting files\n");

	for (i = 0; i < ARRAY_SIZE(hold_sharemode_table); i++) {
		struct hold_sharemode_info *info = &hold_sharemode_table[i];

		union smb_setfileinfo sfinfo = { };

		sfinfo.disposition_info.in.delete_on_close = 1;
		sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
		sfinfo.generic.in.file.handle = info->handle;
		status = smb2_setinfo_file(tree, &sfinfo);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"SETINFO failed\n");

		status = smb2_util_close(tree, info->handle);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			torture_comment(tctx, "File %s not found, could have "
					"been deleted outside of SMB\n",
					info->filename);
			continue;
		}
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"CLOSE failed\n");
}

done:
	smb2_deltree(tree, BASEDIRHOLD);
	return ret;
}

/*
 * Used for manual testing of sharemodes, especially interaction with
 * file systems that can enforce sharemodes. The scenario here is that
 * a file is already open outside of Samba with a sharemode and this
 * can be used to test accessing the same file from Samba.
 */
bool torture_smb2_check_sharemode(struct torture_context *tctx)
{
	const char *sharemode_string, *access_string, *filename, *operation;
	uint32_t sharemode, access;
	struct smb2_tree *tree;
	struct smb2_create create = { };
	NTSTATUS status;
	bool ret = true;
	int error = 0;

	sharemode_string = torture_setting_string(tctx, "sharemode", "RWD");
	sharemode = smb2_util_share_access(sharemode_string);

	access_string = torture_setting_string(tctx, "access", "0xf01ff");
	access = smb_strtoul(access_string, NULL, 0, &error, SMB_STR_STANDARD);
	if (error != 0) {
		torture_comment(tctx, "Initializing access failed.\n");
		return false;
	}

	filename = torture_setting_string(tctx, "filename", "testfile");
	operation = torture_setting_string(tctx, "operation", "WD");

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_comment(tctx, "Initializing smb2 connection failed.\n");
		return false;
	}

	create.in.desired_access = access;
	create.in.alloc_size = 0;
	create.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	create.in.share_access = sharemode;
	create.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	create.in.create_options = 0;
	create.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	create.in.security_flags = 0;
	create.in.fname = filename;
	create.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	create.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE failed\n");

	if (strchr(operation, 'R')) {
		struct smb2_read read = { 0 };

		read.in.file.handle = create.out.file.handle;
		read.in.offset = 0;
		read.in.length = 1;

		status = smb2_read(tree, tctx, &read);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"READ failed\n");
	}

	if (strchr(operation, 'W')) {
		char buf[1];
		status = smb2_util_write(tree, create.out.file.handle,
					 &buf, 0, sizeof(buf));
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"WRITE failed\n");
	}

	if (strchr(operation, 'D')) {
		union smb_setfileinfo sfinfo = { };

		sfinfo.disposition_info.in.delete_on_close = 1;
		sfinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
		sfinfo.generic.in.file.handle = create.out.file.handle;

		status = smb2_setinfo_file(tree, &sfinfo);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"SETINFO failed\n");

		status = smb2_util_close(tree, create.out.file.handle);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"CLOSE failed\n");
	}

done:
	return ret;
}

struct sharemode_info {
	const char *sharemode;
	uint32_t access_mask;
	bool expect_ok;
} sharemode_table[] = {

	/*
	 * Basic tests, check each permission bit against every
	 * possible sharemode combination.
	 */

	{ "R",	 SEC_FILE_READ_DATA,		true,	},
	{ "R",	 SEC_FILE_WRITE_DATA,		false,	},
	{ "R",	 SEC_FILE_APPEND_DATA,		false,	},
	{ "R",	 SEC_FILE_READ_EA,		true,	},
	{ "R",	 SEC_FILE_WRITE_EA,		true,	},
	{ "R",	 SEC_FILE_EXECUTE,		true,	},
	{ "R",	 SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "R",	 SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "R",	 SEC_STD_DELETE,		false,	},
	{ "R",	 SEC_STD_READ_CONTROL,		true,	},
	{ "R",	 SEC_STD_WRITE_DAC,		true,	},
	{ "R",	 SEC_STD_WRITE_OWNER,		true,	},
	{ "R",	 SEC_STD_SYNCHRONIZE,		true,	},

	{ "W",	 SEC_FILE_READ_DATA,		false	},
	{ "W",	 SEC_FILE_WRITE_DATA,		true,	},
	{ "W",	 SEC_FILE_APPEND_DATA,		true,	},
	{ "W",	 SEC_FILE_READ_EA,		true,	},
	{ "W",	 SEC_FILE_WRITE_EA,		true,	},
	{ "W",	 SEC_FILE_EXECUTE,		false,	},
	{ "W",	 SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "W",	 SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "W",	 SEC_STD_DELETE,		false,	},
	{ "W",	 SEC_STD_READ_CONTROL,		true,	},
	{ "W",	 SEC_STD_WRITE_DAC,		true,	},
	{ "W",	 SEC_STD_WRITE_OWNER,		true,	},
	{ "W",	 SEC_STD_SYNCHRONIZE,		true,	},

	{ "D",	 SEC_FILE_READ_DATA,		false	},
	{ "D",	 SEC_FILE_WRITE_DATA,		false	},
	{ "D",	 SEC_FILE_APPEND_DATA,		false	},
	{ "D",	 SEC_FILE_READ_EA,		true,	},
	{ "D",	 SEC_FILE_WRITE_EA,		true,	},
	{ "D",	 SEC_FILE_EXECUTE,		false,	},
	{ "D",	 SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "D",	 SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "D",	 SEC_STD_DELETE,		true,	},
	{ "D",	 SEC_STD_READ_CONTROL,		true,	},
	{ "D",	 SEC_STD_WRITE_DAC,		true,	},
	{ "D",	 SEC_STD_WRITE_OWNER,		true,	},
	{ "D",	 SEC_STD_SYNCHRONIZE,		true,	},

	{ "RW",  SEC_FILE_READ_DATA,		true,	},
	{ "RW",  SEC_FILE_WRITE_DATA,		true,	},
	{ "RW",  SEC_FILE_APPEND_DATA,		true,	},
	{ "RW",  SEC_FILE_READ_EA,		true,	},
	{ "RW",  SEC_FILE_WRITE_EA,		true,	},
	{ "RW",  SEC_FILE_EXECUTE,		true,	},
	{ "RW",  SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "RW",  SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "RW",  SEC_STD_DELETE,		false,	},
	{ "RW",  SEC_STD_READ_CONTROL,		true,	},
	{ "RW",  SEC_STD_WRITE_DAC,		true,	},
	{ "RW",  SEC_STD_WRITE_OWNER,		true,	},
	{ "RW",  SEC_STD_SYNCHRONIZE,		true,	},

	{ "RD",  SEC_FILE_READ_DATA,		true,	},
	{ "RD",  SEC_FILE_WRITE_DATA,		false,	},
	{ "RD",  SEC_FILE_APPEND_DATA,		false,	},
	{ "RD",  SEC_FILE_READ_EA,		true,	},
	{ "RD",  SEC_FILE_WRITE_EA,		true,	},
	{ "RD",  SEC_FILE_EXECUTE,		true,	},
	{ "RD",  SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "RD",  SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "RD",  SEC_STD_DELETE,		true,	},
	{ "RD",  SEC_STD_READ_CONTROL,		true,	},
	{ "RD",  SEC_STD_WRITE_DAC,		true,	},
	{ "RD",  SEC_STD_WRITE_OWNER,		true,	},
	{ "RD",  SEC_STD_SYNCHRONIZE,		true,	},

	{ "WD",  SEC_FILE_READ_DATA,		false	},
	{ "WD",  SEC_FILE_WRITE_DATA,		true,	},
	{ "WD",  SEC_FILE_APPEND_DATA,		true,	},
	{ "WD",  SEC_FILE_READ_EA,		true	},
	{ "WD",  SEC_FILE_WRITE_EA,		true,	},
	{ "WD",  SEC_FILE_EXECUTE,		false	},
	{ "WD",  SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "WD",  SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "WD",  SEC_STD_DELETE,		true,	},
	{ "WD",  SEC_STD_READ_CONTROL,		true,	},
	{ "WD",  SEC_STD_WRITE_DAC,		true,	},
	{ "WD",  SEC_STD_WRITE_OWNER,		true,	},
	{ "WD",  SEC_STD_SYNCHRONIZE,		true,	},

	{ "RWD",  SEC_FILE_READ_DATA,		true	},
	{ "RWD",  SEC_FILE_WRITE_DATA,		true,	},
	{ "RWD",  SEC_FILE_APPEND_DATA,	true,	},
	{ "RWD",  SEC_FILE_READ_EA,		true	},
	{ "RWD",  SEC_FILE_WRITE_EA,		true,	},
	{ "RWD",  SEC_FILE_EXECUTE,		true,	},
	{ "RWD",  SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "RWD",  SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "RWD",  SEC_STD_DELETE,		true,	},
	{ "RWD",  SEC_STD_READ_CONTROL,	true,	},
	{ "RWD",  SEC_STD_WRITE_DAC,		true,	},
	{ "RWD",  SEC_STD_WRITE_OWNER,		true,	},
	{ "RWD",  SEC_STD_SYNCHRONIZE,		 true,  },

	/*
	 * Some more interesting cases. Always request READ or WRITE
	 * access, as that will trigger the opening of a file
	 * description in Samba. This especially useful for file
	 * systems that enforce share modes on open file descriptors.
	 */

	{ "R",	 SEC_FILE_READ_DATA,				true,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_FILE_WRITE_DATA,	false,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_FILE_APPEND_DATA,	false,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_FILE_READ_EA,		true,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_FILE_WRITE_EA,		true,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_FILE_EXECUTE,		true,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_STD_DELETE,		false,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_STD_READ_CONTROL,	true,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_STD_WRITE_DAC,		true,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_STD_WRITE_OWNER,	true,	},
	{ "R",	 SEC_FILE_READ_DATA|SEC_STD_SYNCHRONIZE,	true,	},

	{ "W",	 SEC_FILE_WRITE_DATA|SEC_FILE_READ_DATA,	false,	},
	{ "W",	 SEC_FILE_WRITE_DATA,				true,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_FILE_APPEND_DATA,	true,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_FILE_READ_EA,		true,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_FILE_WRITE_EA,	true,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_FILE_EXECUTE,		false,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_STD_DELETE,		false,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_STD_READ_CONTROL,	true,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_STD_WRITE_DAC,	true,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_STD_WRITE_OWNER,	true,	},
	{ "W",	 SEC_FILE_WRITE_DATA|SEC_STD_SYNCHRONIZE,	true,	},

	{ "RW",  SEC_FILE_READ_DATA,				true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_FILE_WRITE_DATA,	true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_FILE_APPEND_DATA,	true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_FILE_READ_EA,		true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_FILE_WRITE_EA,		true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_FILE_EXECUTE,		true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_STD_DELETE,		false,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_STD_READ_CONTROL,	true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_STD_WRITE_DAC,		true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_STD_WRITE_OWNER,	true,	},
	{ "RW",  SEC_FILE_READ_DATA|SEC_STD_SYNCHRONIZE,	true,	},

	{ "RD",  SEC_FILE_READ_DATA,				true,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_FILE_WRITE_DATA,	false,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_FILE_APPEND_DATA,	false,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_FILE_READ_EA,		true	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_FILE_WRITE_EA,		true,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_FILE_EXECUTE,		true,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_STD_DELETE,		true,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_STD_READ_CONTROL,	true,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_STD_WRITE_DAC,		true,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_STD_WRITE_OWNER,	true,	},
	{ "RD",  SEC_FILE_READ_DATA|SEC_STD_SYNCHRONIZE,	true,	},

	{ "WD",  SEC_FILE_WRITE_DATA|SEC_FILE_READ_DATA,	false	},
	{ "WD",  SEC_FILE_WRITE_DATA,				true,	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_FILE_APPEND_DATA,	true,	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_FILE_READ_EA,		true	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_FILE_WRITE_EA,	true,	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_FILE_EXECUTE,		false	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_STD_DELETE,		true,	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_STD_READ_CONTROL,	true,	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_STD_WRITE_DAC,	true,	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_STD_WRITE_OWNER,	true,	},
	{ "WD",  SEC_FILE_WRITE_DATA|SEC_STD_SYNCHRONIZE,	true,	},

	{ "RWD", SEC_FILE_READ_DATA,				true	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_FILE_WRITE_DATA,	true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_FILE_APPEND_DATA,	true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_FILE_READ_EA,		true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_FILE_WRITE_EA,		true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_FILE_EXECUTE,		true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_FILE_READ_ATTRIBUTE,	true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_FILE_WRITE_ATTRIBUTE,	true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_STD_DELETE,		true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_STD_READ_CONTROL,	true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_STD_WRITE_DAC,		true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_STD_WRITE_OWNER,	true,	},
	{ "RWD", SEC_FILE_READ_DATA|SEC_STD_SYNCHRONIZE,	true,	},
};

/*
 * Test conflicting sharemodes through SMB2: First open takes a
 * sharemode, second open with potentially conflicting access.
 */
static bool test_smb2_sharemode_access(struct torture_context *tctx,
				       struct smb2_tree *tree1,
				       struct smb2_tree *tree2)
{
	const char *fname = "test_sharemode";
	NTSTATUS status;
	bool ret = true;
	int i;

	for (i = 0; i < ARRAY_SIZE(sharemode_table); i++) {
		struct sharemode_info *info = &sharemode_table[i];
		struct smb2_create create1 = { }, create2 = { };
		NTSTATUS expected_status;

		torture_comment(tctx, "index %3d, sharemode %3s, "
				"access mask 0x%06x\n",
				i, info->sharemode, info->access_mask);

		create1.in.desired_access = SEC_RIGHTS_FILE_ALL;
		create1.in.alloc_size = 0;
		create1.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		create1.in.share_access =
			smb2_util_share_access(info->sharemode);
		create1.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
		create1.in.create_options = 0;
		create1.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
		create1.in.fname = fname;
		create1.in.security_flags = 0;
		create1.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
		create1.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;

		status = smb2_create(tree1, tctx, &create1);

		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"CREATE file failed\n");

		create2.in.desired_access = info->access_mask;
		create2.in.alloc_size = 0;
		create2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		create2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			NTCREATEX_SHARE_ACCESS_WRITE |
			NTCREATEX_SHARE_ACCESS_DELETE;
		create2.in.create_disposition = NTCREATEX_DISP_OPEN;
		create2.in.create_options = 0;
		create2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
		create2.in.fname = fname;
		create2.in.security_flags = 0;
		create2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
		create2.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;

		status = smb2_create(tree2, tctx, &create2);
		expected_status = info->expect_ok ?
			NT_STATUS_OK : NT_STATUS_SHARING_VIOLATION;
		torture_assert_ntstatus_equal_goto(tctx, status,
						   expected_status, ret,
						   done, "Unexpected status on "
						   "second create.\n");

		status = smb2_util_close(tree1, create1.out.file.handle);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"Failed to close "
						"first handle.\n");

		if (info->expect_ok) {
			status = smb2_util_close(tree2, create2.out.file.handle);
			torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
							"Failed to close  "
							"second handle.\n");
		}
	}

done:
	smb2_util_unlink(tree1, fname);
	return ret;
}

/*
 * Test conflicting sharemodes through SMB2: First open file with
 * different access masks, second open requests potentially conflicting
 * sharemode.
 */
static bool test_smb2_access_sharemode(struct torture_context *tctx,
				       struct smb2_tree *tree1,
				       struct smb2_tree *tree2)
{
	const char *fname = "test_sharemode";
	NTSTATUS status;
	bool ret = true;
	int i;

	for (i = 0; i < ARRAY_SIZE(sharemode_table); i++) {
		struct sharemode_info *info = &sharemode_table[i];
		struct smb2_create create1 = { }, create2 = { };
		NTSTATUS expected_status;

		torture_comment(tctx, "index %3d, access mask 0x%06x, "
				"sharemode %3s\n",
				i, info->access_mask, info->sharemode);

		create1.in.desired_access = info->access_mask;
		create1.in.alloc_size = 0;
		create1.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		create1.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			NTCREATEX_SHARE_ACCESS_WRITE |
			NTCREATEX_SHARE_ACCESS_DELETE;
		create1.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
		create1.in.create_options = 0;
		create1.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
		create1.in.fname = fname;
		create1.in.security_flags = 0;
		create1.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
		create1.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;

		status = smb2_create(tree1, tctx, &create1);

		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"CREATE file failed\n");

		create2.in.desired_access = SEC_RIGHTS_FILE_ALL;
		create2.in.alloc_size = 0;
		create2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
		create2.in.share_access =
			smb2_util_share_access(info->sharemode);
		create2.in.create_disposition = NTCREATEX_DISP_OPEN;
		create2.in.create_options = 0;
		create2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
		create2.in.fname = fname;
		create2.in.security_flags = 0;
		create2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
		create2.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;

		status = smb2_create(tree2, tctx, &create2);

		expected_status = info->expect_ok ?
			NT_STATUS_OK : NT_STATUS_SHARING_VIOLATION;
		torture_assert_ntstatus_equal_goto(tctx, status,
						   expected_status, ret,
						   done, "Unexpected status on "
						   "second create.\n");

		status = smb2_util_close(tree1, create1.out.file.handle);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"Failed to close "
						"first handle.\n");

		if (info->expect_ok) {
			status = smb2_util_close(tree2, create2.out.file.handle);
			torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
							"Failed to close "
							"second handle.\n");
		}
	}

done:
	smb2_util_unlink(tree1, fname);
	return ret;
}

/*
 * Test initial stat open with share nothing doesn't trigger SHARING_VIOLTION
 * errors.
 */
static bool test_smb2_bug14375(struct torture_context *tctx,
			       struct smb2_tree *tree)
{
	const char *fname = "test_bug14375";
	struct smb2_create cr1;
	struct smb2_create cr2;
	struct smb2_create cr3;
	NTSTATUS status;
	bool ret = true;

	smb2_util_unlink(tree, fname);

	cr1 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_ATTRIBUTE,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_NONE,
		.in.create_disposition = NTCREATEX_DISP_CREATE,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE file failed\n");

	cr2 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE file failed\n");

	cr3 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr3);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE file failed\n");

	status = smb2_util_close(tree, cr1.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CLOSE file failed\n");
	status = smb2_util_close(tree, cr2.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CLOSE file failed\n");
	status = smb2_util_close(tree, cr3.out.file.handle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CLOSE file failed\n");

	cr1 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE file failed\n");

	cr2 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_ATTRIBUTE,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_NONE,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE file failed\n");

	cr3 = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tctx, &cr3);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"CREATE file failed\n");

done:
	smb2_util_close(tree, cr1.out.file.handle);
	smb2_util_close(tree, cr2.out.file.handle);
	smb2_util_close(tree, cr3.out.file.handle);
	smb2_util_unlink(tree, fname);
	return ret;
}

struct torture_suite *torture_smb2_sharemode_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "sharemode");

	torture_suite_add_2smb2_test(suite, "sharemode-access",
				     test_smb2_sharemode_access);
	torture_suite_add_2smb2_test(suite, "access-sharemode",
				     test_smb2_access_sharemode);
	torture_suite_add_1smb2_test(suite, "bug14375",
				     test_smb2_bug14375);

	suite->description = talloc_strdup(suite, "SMB2-SHAREMODE tests");

	return suite;
}
