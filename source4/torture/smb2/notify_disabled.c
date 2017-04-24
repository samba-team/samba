/*
   Unix SMB/CIFS implementation.

   SMB2 notify test suite

   Copyright (C) Stefan Metzmacher 2006
   Copyright (C) Andrew Tridgell 2009
   Copyright (C) Ralph Boehme 2015

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
#include "../libcli/smb/smbXcli_base.h"

#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "torture/util.h"

#include "system/filesys.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include "librpc/gen_ndr/security.h"

#include "lib/events/events.h"

#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/libcli.h"

#define BASEDIR "test_notify_disabled"

/*
   basic testing of change notify on directories
*/
static bool torture_smb2_notify_disabled(struct torture_context *torture,
					 struct smb2_tree *tree1)
{
	bool ret = true;
	NTSTATUS status;
	union smb_notify notify;
	union smb_open io;
	struct smb2_handle h1;
	struct smb2_request *req;

	torture_comment(torture, "TESTING CHANGE NOTIFY DISABLED\n");

	smb2_deltree(tree1, BASEDIR);
	smb2_util_rmdir(tree1, BASEDIR);
	/*
	  get a handle on the directory
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = 0;
	io.smb2.in.desired_access = SEC_FILE_ALL;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = BASEDIR;

	status = smb2_create(tree1, torture, &(io.smb2));
	torture_assert_ntstatus_equal_goto(torture, status, NT_STATUS_OK,
					   ret, done, "smb2_create");
	h1 = io.smb2.out.file.handle;

	ZERO_STRUCT(notify.smb2);
	notify.smb2.level = RAW_NOTIFY_SMB2;
	notify.smb2.in.buffer_size = 1000;
	notify.smb2.in.completion_filter = FILE_NOTIFY_CHANGE_NAME;
	notify.smb2.in.file.handle = h1;
	notify.smb2.in.recursive = true;

	req = smb2_notify_send(tree1, &(notify.smb2));
	status = smb2_notify_recv(req, torture, &(notify.smb2));
	torture_assert_ntstatus_equal_goto(torture, status, NT_STATUS_NOT_IMPLEMENTED,
					   ret, done, "smb2_notify_recv");

	status = smb2_util_close(tree1, h1);
	torture_assert_ntstatus_equal_goto(torture, status, NT_STATUS_OK,
					   ret, done, "smb2_create");

done:
	smb2_deltree(tree1, BASEDIR);
	return ret;
}

/*
   basic testing of SMB2 change notify
*/
struct torture_suite *torture_smb2_notify_disabled_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx,
		"change_notify_disabled");

	torture_suite_add_1smb2_test(suite, "notfiy_disabled", torture_smb2_notify_disabled);
	suite->description = talloc_strdup(suite, "SMB2-CHANGE-NOTIFY-DISABLED tests");

	return suite;
}
