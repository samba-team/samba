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
#include "auth/credentials/credentials.h"


static bool test_session_reauth1(struct torture_context *tctx,
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

static bool test_session_reauth2_oplock_timeout(
	struct smbcli_transport *transport, uint16_t tid, uint16_t fnum,
	uint8_t level, void *private_data)
{
	return true;
}

static bool test_session_reauth2(struct torture_context *tctx,
				 struct smbcli_state *cli)
{
	char *random_string;
	char *fname;
	union smb_open io_open;
	struct smb_composite_sesssetup io_sesssetup;
	union smb_fileinfo io_qsecdesc;
	struct smbcli_request *req;
	struct cli_credentials *anon_creds;
	NTSTATUS status;
	uint16_t fnum;
	ssize_t nwritten;
	uint16_t vuid1 = cli->session->vuid;

	random_string = generate_random_str(tctx, 8);
	torture_assert(tctx, (random_string != NULL),
		       "memory allocation failed");
	fname = talloc_asprintf(tctx, "raw_session_reauth2_%s.dat",
				random_string);
	talloc_free(random_string);
	torture_assert(tctx, (fname != NULL), "memory allocation failed");

	smbcli_unlink(cli->tree, fname);
	smbcli_oplock_handler(cli->transport,
			      test_session_reauth2_oplock_timeout,
			      cli->tree);

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io_open);
	io_open.generic.level = RAW_OPEN_NTCREATEX;
	io_open.ntcreatex.in.root_fid.fnum = 0;
	io_open.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_READ |
		SEC_RIGHTS_FILE_WRITE | SEC_STD_DELETE;
	io_open.ntcreatex.in.alloc_size = 0;
	io_open.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io_open.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				       NTCREATEX_SHARE_ACCESS_WRITE;
	io_open.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
	io_open.ntcreatex.in.create_options = 0;
	io_open.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io_open.ntcreatex.in.security_flags = 0;
	io_open.ntcreatex.in.fname = fname;

	torture_comment(tctx, "open with batch oplock\n");
	io_open.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED |
		NTCREATEX_FLAGS_REQUEST_OPLOCK |
		NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;

	status = smb_raw_open(cli->tree, tctx, &io_open);
	torture_assert_ntstatus_ok(tctx, status, "smb_raw_open failed");

	fnum = io_open.ntcreatex.out.file.fnum;
	torture_assert(
		tctx,
		(io_open.ntcreatex.out.oplock_level == BATCH_OPLOCK_RETURN),
		"did not get batch oplock");

	io_open.ntcreatex.in.flags = NTCREATEX_FLAGS_EXTENDED;
	req = smb_raw_open_send(cli->tree, &io_open);
	torture_assert(tctx, (req != NULL), "memory allocation failed");

	/*
	 * Make sure the open went through
	 */
	status = smbcli_chkpath(cli->tree, "\\");
	torture_assert_ntstatus_ok(tctx, status, "smb_chkpath failed");

	status = smbcli_nt_delete_on_close(cli->tree, fnum, true);
	torture_assert_ntstatus_ok(tctx, status, "could not set delete on "
				   "close");

	anon_creds = cli_credentials_init_anon(tctx);
	torture_assert(tctx, (anon_creds != NULL), "memory allocation failed");

	ZERO_STRUCT(io_sesssetup);
	io_sesssetup.in.sesskey      = cli->transport->negotiate.sesskey;
	io_sesssetup.in.capabilities = cli->transport->negotiate.capabilities;
	io_sesssetup.in.credentials  = anon_creds;
	io_sesssetup.in.workgroup    = lpcfg_workgroup(tctx->lp_ctx);
	io_sesssetup.in.gensec_settings = lpcfg_gensec_settings(
		tctx, tctx->lp_ctx);
	status = smb_composite_sesssetup(cli->session, &io_sesssetup);
	torture_assert_ntstatus_ok(tctx, status, "setup2 failed");
	torture_assert_int_equal(tctx, io_sesssetup.out.vuid, vuid1, "setup2");

	status = smbcli_close(cli->tree, fnum);
	torture_assert_ntstatus_ok(tctx, status, "close failed");

	status = smb_raw_open_recv(req, tctx, &io_open);
	torture_assert_ntstatus_ok(tctx, status, "2nd open failed");

	fnum = io_open.ntcreatex.out.file.fnum;

	nwritten = smbcli_write(cli->tree, fnum, 0, fname, 0, strlen(fname));
	torture_assert(tctx, (nwritten == strlen(fname)),
		       "smbcli_write failed");

	ZERO_STRUCT(io_qsecdesc);
	io_qsecdesc.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	io_qsecdesc.query_secdesc.in.file.fnum = fnum;
	io_qsecdesc.query_secdesc.in.secinfo_flags = SECINFO_OWNER;
	status = smb_raw_fileinfo(cli->tree, tctx, &io_qsecdesc);
	torture_assert_ntstatus_equal(
		tctx, status, NT_STATUS_ACCESS_DENIED,
		"anon qsecdesc did not return ACCESS_DENIED");

	ZERO_STRUCT(io_sesssetup);
	io_sesssetup.in.sesskey      = cli->transport->negotiate.sesskey;
	io_sesssetup.in.capabilities = cli->transport->negotiate.capabilities;
	io_sesssetup.in.credentials  = cmdline_credentials;
	io_sesssetup.in.workgroup    = lpcfg_workgroup(tctx->lp_ctx);
	io_sesssetup.in.gensec_settings = lpcfg_gensec_settings(
		tctx, tctx->lp_ctx);
	status = smb_composite_sesssetup(cli->session, &io_sesssetup);
	torture_assert_ntstatus_ok(tctx, status, "setup3 failed");
	torture_assert_int_equal(tctx, io_sesssetup.out.vuid, vuid1, "setup2");

	status = smb_raw_fileinfo(cli->tree, tctx, &io_qsecdesc);
	torture_assert_ntstatus_ok(tctx, status, "2nd qsecdesc failed");

	status = smbcli_nt_delete_on_close(cli->tree, fnum, true);
	torture_assert_ntstatus_ok(tctx, status, "could not set delete on "
				   "close");

	status = smbcli_close(cli->tree, fnum);
	torture_assert_ntstatus_ok(tctx, status, "close failed");

	return true;
}

struct torture_suite *torture_raw_session(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "session");
	suite->description = talloc_strdup(suite, "RAW-SESSION tests");

	torture_suite_add_1smb_test(suite, "reauth1", test_session_reauth1);
	torture_suite_add_1smb_test(suite, "reauth2", test_session_reauth2);

	return suite;
}
