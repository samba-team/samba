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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/smbtorture.h"
#include "torture/smb2/proto.h"
#include "libcli/smb/smbXcli_base.h"
#include "torture/util.h"
#include "system/filesys.h"
#include "system/time.h"
#include "libcli/resolve/resolve.h"
#include "lib/events/events.h"
#include "param/param.h"

static void smb2cli_session_set_id(struct smbXcli_session *session,
				   uint64_t session_id)
{
	smb2cli_session_set_id_and_flags(session, session_id,
					 smb2cli_session_get_flags(session));
}

/**
  this checks to see if a secondary tconx can use open files from an
  earlier tconx
 */
bool run_tcon_test(struct torture_context *tctx, struct smb2_tree *tree)
{
	const char *fname = "tcontest.tmp";
	struct smb2_handle fnum1;
	uint32_t cnum1, cnum2, cnum3;
	uint64_t sessid1, sessid2;
	uint8_t buf[4];
	bool ret = true;
	struct smb2_tree *tree1 = NULL;
	const char *host = torture_setting_string(tctx, "host", NULL);
	struct smb2_create io = {0};
	NTSTATUS status;
	bool ok;

	if (smb2_deltree(tree, fname) == -1) {
		torture_comment(tctx, "unlink of %s failed\n", fname);
	}

	io.in.fname = fname;
	io.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			     NTCREATEX_SHARE_ACCESS_WRITE |
			     NTCREATEX_SHARE_ACCESS_DELETE;
	status = smb2_create(tree, tree, &io);
	if (NT_STATUS_IS_ERR(status)) {
		torture_result(tctx, TORTURE_FAIL, "open of %s failed (%s)\n", fname, nt_errstr(status));
		return false;
	}
	fnum1 = io.out.file.handle;

	cnum1 = smb2cli_tcon_current_id(tree->smbXcli);
	sessid1 = smb2cli_session_current_id(tree->session->smbXcli);

	memset(buf, 0, 4); /* init buf so valgrind won't complain */
	status = smb2_util_write(tree, fnum1, buf, 130, 4);
	if (NT_STATUS_IS_ERR(status)) {
		torture_result(tctx, TORTURE_FAIL, "initial write failed (%s)\n", nt_errstr(status));
		return false;
	}

	ok = torture_smb2_tree_connect(tctx, tree->session, tctx, &tree1);
	if (!ok) {
		torture_result(tctx, TORTURE_FAIL, "%s refused 2nd tree connect\n", host);
		return false;
	}

	cnum2 = smb2cli_tcon_current_id(tree1->smbXcli);
	cnum3 = MAX(cnum1, cnum2) + 1; /* any invalid number */
	sessid2 = smb2cli_session_current_id(tree1->session->smbXcli) + 1;

	/* try a write with the wrong tid */
	smb2cli_tcon_set_id(tree1->smbXcli, cnum2);

	status = smb2_util_write(tree1, fnum1, buf, 130, 4);
	if (NT_STATUS_IS_OK(status)) {
		torture_result(tctx, TORTURE_FAIL, "* server allows write with wrong TID\n");
		ret = false;
	} else {
		torture_comment(tctx, "server fails write with wrong TID : %s\n", nt_errstr(status));
	}


	/* try a write with an invalid tid */
	smb2cli_tcon_set_id(tree1->smbXcli, cnum3);

	status = smb2_util_write(tree1, fnum1, buf, 130, 4);
	if (NT_STATUS_IS_OK(status)) {
		torture_result(tctx, TORTURE_FAIL, "* server allows write with invalid TID\n");
		ret = false;
	} else {
		torture_comment(tctx, "server fails write with invalid TID : %s\n", nt_errstr(status));
	}

	/* try a write with an invalid session id */
	smb2cli_session_set_id(tree1->session->smbXcli, sessid2);
	smb2cli_tcon_set_id(tree1->smbXcli, cnum1);

	status = smb2_util_write(tree1, fnum1, buf, 130, 4);
	if (NT_STATUS_IS_OK(status)) {
		torture_result(tctx, TORTURE_FAIL, "* server allows write with invalid VUID\n");
		ret = false;
	} else {
		torture_comment(tctx, "server fails write with invalid VUID : %s\n", nt_errstr(status));
	}

	smb2cli_session_set_id(tree1->session->smbXcli, sessid1);
	smb2cli_tcon_set_id(tree1->smbXcli, cnum1);

	status = smb2_util_close(tree1, fnum1);
	if (NT_STATUS_IS_ERR(status)) {
		torture_result(tctx, TORTURE_FAIL, "close failed (%s)\n", nt_errstr(status));
		return false;
	}

	smb2cli_tcon_set_id(tree1->smbXcli, cnum2);

	smb2_util_unlink(tree1, fname);

	return ret;
}
