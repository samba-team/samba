/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
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
#include "torture/smbtorture.h"
#include "libcli/libcli.h"
#include "libcli/raw/raw_proto.h"
#include "system/filesys.h"
#include "system/time.h"
#include "libcli/resolve/resolve.h"
#include "lib/events/events.h"
#include "param/param.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/smb2/proto.h"
#include "libcli/smb/smbXcli_base.h"


static void smb2cli_session_set_id(struct smbXcli_session *session,
				   uint64_t session_id)
{
	smb2cli_session_set_id_and_flags(session, session_id,
					 smb2cli_session_get_flags(session));
}

/**
  Try with a wrong session id and check error message.
 */

bool run_sessidtest(struct torture_context *tctx, struct smb2_tree *tree)
{
	const char *fname = "sessid.tst";
	struct smb2_handle fnum;
	struct smb2_create io = {0};
	uint32_t session_id;
	union smb_fileinfo finfo;

	NTSTATUS status;

	smb2_util_unlink(tree, fname);

	io.in.fname = fname;
	io.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			     NTCREATEX_SHARE_ACCESS_WRITE |
			     NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree, tree, &io);
	if (NT_STATUS_IS_ERR(status)) {
		torture_result(tctx, TORTURE_FAIL, "open of %s failed (%s)\n",
			       fname, nt_errstr(status));
		return false;
	}
	fnum = io.out.file.handle;

	session_id = smb2cli_session_current_id(tree->session->smbXcli);
	smb2cli_session_set_id(tree->session->smbXcli, session_id+1234);

	torture_comment(tctx, "Testing qfileinfo with wrong sessid\n");

	finfo.all_info2.level = RAW_FILEINFO_SMB2_ALL_INFORMATION;
	finfo.all_info2.in.file.handle = fnum;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	if (NT_STATUS_IS_OK(status)) {
		torture_fail(tctx, "smb2_getinfo_file passed with wrong sessid");
	}

	torture_assert_ntstatus_equal(tctx, status,
				      NT_STATUS_USER_SESSION_DELETED,
				      "smb2_getinfo_file should have returned "
				      "NT_STATUS_USER_SESSION_DELETED");

	smb2cli_session_set_id(tree->session->smbXcli, session_id);

	status = smb2_util_close(tree, fnum);
	torture_assert_ntstatus_ok(tctx, status,
		talloc_asprintf(tctx, "close failed (%s)", nt_errstr(status)));

	smb2_util_unlink(tree, fname);

	return true;
}
