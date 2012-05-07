/* 
   Unix SMB/CIFS implementation.
   test suite for session setup operations
   Copyright (C) Gregor Beck 2012
   
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
#include "torture.h"
#include "smb_cli.h"
#include "torture/raw/proto.h"
#include "smb_composite/smb_composite.h"
#include "lib/cmdline/popt_common.h"
#include "param/param.h"
#include "torture/util.h"


static bool test_session_reauth(struct torture_context *tctx,
				struct smbcli_state *cli)
{
	NTSTATUS status;
	struct smb_composite_sesssetup io;
	int fnum, num;
	const int dlen = 255;
	char *data;
	char fname[256];
	char buf[dlen+1];
	bool ok = true;
	uint16_t vuid1 = cli->session->vuid;

	data = generate_random_str(tctx, dlen);
	torture_assert(tctx, (data != NULL), "memory allocation failed");
	snprintf(fname, sizeof(fname), "raw_session_reconnect_%.8s.dat", data);

	fnum = smbcli_nt_create_full(cli->tree, fname, 0,
				     SEC_RIGHTS_FILE_ALL,
				     FILE_ATTRIBUTE_NORMAL,
				     NTCREATEX_SHARE_ACCESS_NONE,
				     NTCREATEX_DISP_OPEN_IF,
				     NTCREATEX_OPTIONS_DELETE_ON_CLOSE,
				     0);
	torture_assert_ntstatus_ok_goto(tctx, smbcli_nt_error(cli->tree), ok,
					done, "create file");
	torture_assert_goto(tctx, fnum > 0, ok, done, "create file");

	num = smbcli_smbwrite(cli->tree, fnum, data, 0, dlen);
	torture_assert_int_equal_goto(tctx, num, dlen, ok, done, "write file");

	ZERO_STRUCT(io);
	io.in.sesskey         = cli->transport->negotiate.sesskey;
	io.in.capabilities    = cli->transport->negotiate.capabilities;
	io.in.credentials     = cmdline_credentials;
	io.in.workgroup       = lpcfg_workgroup(tctx->lp_ctx);
	io.in.gensec_settings = lpcfg_gensec_settings(tctx, tctx->lp_ctx);
	status = smb_composite_sesssetup(cli->session, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ok, done, "setup2");
	torture_assert_int_equal_goto(tctx, io.out.vuid, vuid1, ok, done, "setup2");

	num = smbcli_read(cli->tree, fnum, &buf, 0, dlen);
	torture_assert_int_equal_goto(tctx, num, dlen, ok, done, "read file");
	torture_assert_str_equal_goto(tctx, buf, data, ok, done, "read file");

done:
	talloc_free(data);

	if (fnum > 0) {
		status = smbcli_close(cli->tree, fnum);
		torture_assert_ntstatus_ok(tctx, status, "close");
	}
	return ok;
}

struct torture_suite *torture_raw_session(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "session");
	suite->description = talloc_strdup(suite, "RAW-SESSION tests");

	torture_suite_add_1smb_test(suite, "reauth", test_session_reauth);

	return suite;
}
