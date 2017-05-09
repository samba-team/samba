/* 
   Unix SMB/CIFS implementation.
   test suite for session setup operations
   Copyright (C) Andrew Tridgell 2003
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/smb_composite/smb_composite.h"
#include "lib/cmdline/popt_common.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "auth/credentials/credentials.h"
#include "param/param.h"
#include "torture/raw/proto.h"

#define BASEDIR "\\rawcontext"

#define CHECK_STATUS(status, correct) \
	torture_assert_ntstatus_equal_goto(tctx, status, correct, ret, done, __location__)

#define CHECK_VALUE(v, correct) \
	torture_assert_int_equal_goto(tctx, v, correct, ret, done, __location__)

#define CHECK_NOT_VALUE(v, correct) \
	torture_assert_goto(tctx, ((v) != (correct)), ret, done, \
		talloc_asprintf(tctx, "(%s) Incorrect value %s=%d - should not be %d\n", \
		       __location__, #v, v, correct));


/*
  test session ops
*/
static bool test_session(struct torture_context *tctx,
			 struct smbcli_state *cli)
{
	NTSTATUS status;
	bool ret = true;
	struct smbcli_session *session;
	struct smbcli_session *session2;
	uint16_t vuid3;
	struct smbcli_session *session3;
	struct smbcli_session *session4;
	struct cli_credentials *anon_creds;
	struct smbcli_session *sessions[15];
	struct composite_context *composite_contexts[15];
	struct smbcli_tree *tree;
	struct smb_composite_sesssetup setup;
	struct smb_composite_sesssetup setups[15];
	struct gensec_settings *gensec_settings;
	union smb_open io;
	union smb_write wr;
	union smb_close cl;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	uint8_t c = 1;
	int i;
	struct smbcli_session_options options;

	torture_comment(tctx, "TESTING SESSION HANDLING\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	torture_comment(tctx, "create a second security context on the same transport\n");

	lpcfg_smbcli_session_options(tctx->lp_ctx, &options);
	gensec_settings = lpcfg_gensec_settings(tctx, tctx->lp_ctx);

	session = smbcli_session_init(cli->transport, tctx, false, options);

	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities; /* ignored in secondary session setup, except by our libs, which care about the extended security bit */
	setup.in.workgroup = lpcfg_workgroup(tctx->lp_ctx);

	setup.in.credentials = popt_get_cmdline_credentials();
	setup.in.gensec_settings = gensec_settings;

	status = smb_composite_sesssetup(session, &setup);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	session->vuid = setup.out.vuid;

	torture_comment(tctx, "create a third security context on the same transport, with given vuid\n");
	session2 = smbcli_session_init(cli->transport, tctx, false, options);

	if (cli->transport->negotiate.capabilities & CAP_EXTENDED_SECURITY) {
		vuid3 = session->vuid+1;
		if (vuid3 == cli->session->vuid) {
			vuid3 += 1;
		}
		if (vuid3 == UINT16_MAX) {
			vuid3 += 2;
		}
	} else {
		vuid3 = session->vuid;
	}
	session2->vuid = vuid3;

	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities; /* ignored in secondary session setup, except by our libs, which care about the extended security bit */
	setup.in.workgroup = lpcfg_workgroup(tctx->lp_ctx);

	setup.in.credentials = popt_get_cmdline_credentials();

	torture_comment(tctx, "vuid1=%d vuid2=%d vuid3=%d\n", cli->session->vuid, session->vuid, vuid3);

	status = smb_composite_sesssetup(session2, &setup);
	if (cli->transport->negotiate.capabilities & CAP_EXTENDED_SECURITY) {
		CHECK_STATUS(status, NT_STATUS_DOS(ERRSRV, ERRbaduid));
	} else {
		CHECK_STATUS(status, NT_STATUS_OK);
		session2->vuid = setup.out.vuid;
		CHECK_NOT_VALUE(session2->vuid, vuid3);
	}

	torture_comment(tctx, "vuid1=%d vuid2=%d vuid3=%d=>%d (%s)\n",
			cli->session->vuid, session->vuid,
			vuid3, session2->vuid, nt_errstr(status));

	talloc_free(session2);

	if (cli->transport->negotiate.capabilities & CAP_EXTENDED_SECURITY) {
		torture_comment(tctx, "create a fourth security context on the same transport, without extended security\n");
		session3 = smbcli_session_init(cli->transport, tctx, false, options);

		session3->vuid = vuid3;
		setup.in.sesskey = cli->transport->negotiate.sesskey;
		setup.in.capabilities &= ~CAP_EXTENDED_SECURITY; /* force a non extended security login (should fail) */
		setup.in.workgroup = lpcfg_workgroup(tctx->lp_ctx);
	
		setup.in.credentials = popt_get_cmdline_credentials();

		status = smb_composite_sesssetup(session3, &setup);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_LOGON_FAILURE)) {
			/*
			 * Windows 2008 R2 returns INVALID_PARAMETER
			 * while Windows 2000 sp4 returns LOGON_FAILURE...
			 */
			CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
		}

		torture_comment(tctx, "create a fouth anonymous security context on the same transport, without extended security\n");
		session4 = smbcli_session_init(cli->transport, tctx, false, options);

		session4->vuid = vuid3;
		setup.in.sesskey = cli->transport->negotiate.sesskey;
		setup.in.capabilities &= ~CAP_EXTENDED_SECURITY; /* force a non extended security login (should fail) */
		setup.in.workgroup = lpcfg_workgroup(tctx->lp_ctx);
		
		anon_creds = cli_credentials_init(tctx);
		cli_credentials_set_conf(anon_creds, tctx->lp_ctx);
		cli_credentials_set_anonymous(anon_creds);

		setup.in.credentials = anon_creds;
	
		status = smb_composite_sesssetup(session3, &setup);
		CHECK_STATUS(status, NT_STATUS_OK);

		talloc_free(session4);
	}
		
	torture_comment(tctx, "use the same tree as the existing connection\n");
	tree = smbcli_tree_init(session, tctx, false);
	tree->tid = cli->tree->tid;

	torture_comment(tctx, "create a file using the new vuid\n");
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "write using the old vuid\n");
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.in.file.fnum = fnum;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;

	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "write with the new vuid\n");
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "logoff the new vuid\n");
	status = smb_raw_ulogoff(session);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "the new vuid should not now be accessible\n");
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "second logoff for the new vuid should fail\n");
	status = smb_raw_ulogoff(session);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRSRV, ERRbaduid));
	talloc_free(tree);
	talloc_free(session);

	torture_comment(tctx, "the fnum should have been auto-closed\n");
	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "create %d secondary security contexts on the same transport\n",
	       (int)ARRAY_SIZE(sessions));
	for (i=0; i <ARRAY_SIZE(sessions); i++) {
		setups[i].in.sesskey = cli->transport->negotiate.sesskey;
		setups[i].in.capabilities = cli->transport->negotiate.capabilities; /* ignored in secondary session setup, except by our libs, which care about the extended security bit */
		setups[i].in.workgroup = lpcfg_workgroup(tctx->lp_ctx);
		
		setups[i].in.credentials = popt_get_cmdline_credentials();
		setups[i].in.gensec_settings = gensec_settings;

		sessions[i] = smbcli_session_init(cli->transport, tctx, false, options);
		composite_contexts[i] = smb_composite_sesssetup_send(sessions[i], &setups[i]);

	}


	torture_comment(tctx, "finishing %d secondary security contexts on the same transport\n",
	       (int)ARRAY_SIZE(sessions));
	for (i=0; i< ARRAY_SIZE(sessions); i++) {
		status = smb_composite_sesssetup_recv(composite_contexts[i]);
		CHECK_STATUS(status, NT_STATUS_OK);
		sessions[i]->vuid = setups[i].out.vuid;
		torture_comment(tctx, "VUID: %d\n", sessions[i]->vuid);
		status = smb_raw_ulogoff(sessions[i]);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

done:
	return ret;
}


/*
  test tree ops
*/
static bool test_tree(struct torture_context *tctx, struct smbcli_state *cli)
{
	NTSTATUS status;
	bool ret = true;
	const char *share, *host;
	struct smbcli_tree *tree;
	union smb_tcon tcon;
	union smb_open io;
	union smb_write wr;
	union smb_close cl;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	uint8_t c = 1;

	torture_comment(tctx, "TESTING TREE HANDLING\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	share = torture_setting_string(tctx, "share", NULL);
	host  = torture_setting_string(tctx, "host", NULL);
	
	torture_comment(tctx, "create a second tree context on the same session\n");
	tree = smbcli_tree_init(cli->session, tctx, false);

	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = TCONX_FLAG_EXTENDED_RESPONSE;
	tcon.tconx.in.password = data_blob(NULL, 0);
	tcon.tconx.in.path = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	tcon.tconx.in.device = "A:";	
	status = smb_raw_tcon(tree, tctx, &tcon);
	CHECK_STATUS(status, NT_STATUS_OK);
	

	tree->tid = tcon.tconx.out.tid;
	torture_comment(tctx, "tid1=%d tid2=%d\n", cli->tree->tid, tree->tid);

	torture_comment(tctx, "try a tconx with a bad device type\n");
	tcon.tconx.in.device = "FOO";	
	status = smb_raw_tcon(tree, tctx, &tcon);
	CHECK_STATUS(status, NT_STATUS_BAD_DEVICE_TYPE);


	torture_comment(tctx, "create a file using the new tid\n");
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "write using the old tid\n");
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.in.file.fnum = fnum;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;

	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "write with the new tid\n");
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "disconnect the new tid\n");
	status = smb_tree_disconnect(tree);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "the new tid should not now be accessible\n");
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "the fnum should have been auto-closed\n");
	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	/* close down the new tree */
	talloc_free(tree);
	
done:
	return ret;
}

/*
  test tree with ulogoff
  this demonstrates that a tcon isn't autoclosed by a ulogoff
  the tcon can be reused using any other valid session later
*/
static bool test_tree_ulogoff(struct torture_context *tctx, struct smbcli_state *cli)
{
	NTSTATUS status;
	bool ret = true;
	const char *share, *host;
	struct smbcli_session *session1;
	struct smbcli_session *session2;
	struct smb_composite_sesssetup setup;
	struct smbcli_tree *tree;
	union smb_tcon tcon;
	union smb_open io;
	union smb_write wr;
	int fnum1, fnum2;
	const char *fname1 = BASEDIR "\\test1.txt";
	const char *fname2 = BASEDIR "\\test2.txt";
	uint8_t c = 1;
	struct smbcli_session_options options;

	torture_comment(tctx, "TESTING TREE with ulogoff\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	share = torture_setting_string(tctx, "share", NULL);
	host  = torture_setting_string(tctx, "host", NULL);

	lpcfg_smbcli_session_options(tctx->lp_ctx, &options);

	torture_comment(tctx, "create the first new sessions\n");
	session1 = smbcli_session_init(cli->transport, tctx, false, options);
	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities;
	setup.in.workgroup = lpcfg_workgroup(tctx->lp_ctx);
	setup.in.credentials = popt_get_cmdline_credentials();
	setup.in.gensec_settings = lpcfg_gensec_settings(tctx, tctx->lp_ctx);
	status = smb_composite_sesssetup(session1, &setup);
	CHECK_STATUS(status, NT_STATUS_OK);
	session1->vuid = setup.out.vuid;
	torture_comment(tctx, "vuid1=%d\n", session1->vuid);

	torture_comment(tctx, "create a tree context on the with vuid1\n");
	tree = smbcli_tree_init(session1, tctx, false);
	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = TCONX_FLAG_EXTENDED_RESPONSE;
	tcon.tconx.in.password = data_blob(NULL, 0);
	tcon.tconx.in.path = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	tcon.tconx.in.device = "A:";
	status = smb_raw_tcon(tree, tctx, &tcon);
	CHECK_STATUS(status, NT_STATUS_OK);
	tree->tid = tcon.tconx.out.tid;
	torture_comment(tctx, "tid=%d\n", tree->tid);

	torture_comment(tctx, "create a file using vuid1\n");
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname1;
	status = smb_raw_open(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum1 = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "write using vuid1\n");
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.in.file.fnum = fnum1;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "ulogoff the vuid1\n");
	status = smb_raw_ulogoff(session1);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "create the second new sessions\n");
	session2 = smbcli_session_init(cli->transport, tctx, false, options);
	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities;
	setup.in.workgroup = lpcfg_workgroup(tctx->lp_ctx);
	setup.in.credentials = popt_get_cmdline_credentials();
	setup.in.gensec_settings = lpcfg_gensec_settings(tctx, tctx->lp_ctx);
	status = smb_composite_sesssetup(session2, &setup);
	CHECK_STATUS(status, NT_STATUS_OK);
	session2->vuid = setup.out.vuid;
	torture_comment(tctx, "vuid2=%d\n", session2->vuid);

	torture_comment(tctx, "use the existing tree with vuid2\n");
	tree->session = session2;

	torture_comment(tctx, "create a file using vuid2\n");
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname2;
	status = smb_raw_open(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "write using vuid2\n");
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.in.file.fnum = fnum2;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "ulogoff the vuid2\n");
	status = smb_raw_ulogoff(session2);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* this also demonstrates that SMBtdis doesn't need a valid vuid */
	torture_comment(tctx, "disconnect the existing tree connection\n");
	status = smb_tree_disconnect(tree);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "disconnect the existing tree connection\n");
	status = smb_tree_disconnect(tree);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRSRV,ERRinvnid));

	/* close down the new tree */
	talloc_free(tree);
	
done:
	return ret;
}

/*
  test pid ops
  this test demonstrates that exit() only sees the PID
  used for the open() calls
*/
static bool test_pid_exit_only_sees_open(struct torture_context *tctx,
					 struct smbcli_state *cli)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = tctx;
	bool ret = true;
	union smb_open io;
	union smb_write wr;
	union smb_close cl;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	uint8_t c = 1;
	uint16_t pid1, pid2;

	torture_comment(tctx, "TESTING PID HANDLING exit() only cares about open() PID\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	pid1 = cli->session->pid;
	pid2 = pid1 + 1;

	torture_comment(tctx, "pid1=%d pid2=%d\n", pid1, pid2);

	torture_comment(tctx, "create a file using pid1\n");
	cli->session->pid = pid1;
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "write using pid2\n");
	cli->session->pid = pid2;
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.in.file.fnum = fnum;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "exit pid2\n");
	cli->session->pid = pid2;
	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "the fnum should still be accessible via pid2\n");
	cli->session->pid = pid2;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "exit pid2\n");
	cli->session->pid = pid2;
	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "the fnum should still be accessible via pid1 and pid2\n");
	cli->session->pid = pid1;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);
	cli->session->pid = pid2;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "exit pid1\n");
	cli->session->pid = pid1;
	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "the fnum should not now be accessible via pid1 or pid2\n");
	cli->session->pid = pid1;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);
	cli->session->pid = pid2;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "the fnum should have been auto-closed\n");
	cli->session->pid = pid1;
	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

done:
	return ret;
}

/*
  test pid ops with 2 sessions
*/
static bool test_pid_2sess(struct torture_context *tctx,
			   struct smbcli_state *cli)
{
	NTSTATUS status;
	bool ret = true;
	struct smbcli_session *session;
	struct smb_composite_sesssetup setup;
	union smb_open io;
	union smb_write wr;
	union smb_close cl;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	uint8_t c = 1;
	uint16_t vuid1, vuid2;
	struct smbcli_session_options options;

	torture_comment(tctx, "TESTING PID HANDLING WITH 2 SESSIONS\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	lpcfg_smbcli_session_options(tctx->lp_ctx, &options);

	torture_comment(tctx, "create a second security context on the same transport\n");
	session = smbcli_session_init(cli->transport, tctx, false, options);

	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities; /* ignored in secondary session setup, except by our libs, which care about the extended security bit */
	setup.in.workgroup = lpcfg_workgroup(tctx->lp_ctx);
	setup.in.credentials = popt_get_cmdline_credentials();
	setup.in.gensec_settings = lpcfg_gensec_settings(tctx, tctx->lp_ctx);

	status = smb_composite_sesssetup(session, &setup);
	CHECK_STATUS(status, NT_STATUS_OK);	
	session->vuid = setup.out.vuid;

	vuid1 = cli->session->vuid;
	vuid2 = session->vuid;

	torture_comment(tctx, "vuid1=%d vuid2=%d\n", vuid1, vuid2);

	torture_comment(tctx, "create a file using the vuid1\n");
	cli->session->vuid = vuid1;
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "write using the vuid1 (fnum=%d)\n", fnum);
	cli->session->vuid = vuid1;
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.in.file.fnum = fnum;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;

	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "exit the pid with vuid2\n");
	cli->session->vuid = vuid2;
	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "the fnum should still be accessible\n");
	cli->session->vuid = vuid1;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "exit the pid with vuid1\n");
	cli->session->vuid = vuid1;
	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "the fnum should not now be accessible\n");
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "the fnum should have been auto-closed\n");
	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

done:
	return ret;
}

/*
  test pid ops with 2 tcons
*/
static bool test_pid_2tcon(struct torture_context *tctx,
			   struct smbcli_state *cli)
{
	NTSTATUS status;
	bool ret = true;
	const char *share, *host;
	struct smbcli_tree *tree;
	union smb_tcon tcon;
	union smb_open io;
	union smb_write wr;
	union smb_close cl;
	int fnum1, fnum2;
	const char *fname1 = BASEDIR "\\test1.txt";
	const char *fname2 = BASEDIR "\\test2.txt";
	uint8_t c = 1;
	uint16_t tid1, tid2;

	torture_comment(tctx, "TESTING PID HANDLING WITH 2 TCONS\n");

	torture_assert(tctx, torture_setup_dir(cli, BASEDIR), "Failed to setup up test directory: " BASEDIR);

	share = torture_setting_string(tctx, "share", NULL);
	host  = torture_setting_string(tctx, "host", NULL);
	
	torture_comment(tctx, "create a second tree context on the same session\n");
	tree = smbcli_tree_init(cli->session, tctx, false);

	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = TCONX_FLAG_EXTENDED_RESPONSE;
	tcon.tconx.in.password = data_blob(NULL, 0);
	tcon.tconx.in.path = talloc_asprintf(tctx, "\\\\%s\\%s", host, share);
	tcon.tconx.in.device = "A:";	
	status = smb_raw_tcon(tree, tctx, &tcon);
	CHECK_STATUS(status, NT_STATUS_OK);	

	tree->tid = tcon.tconx.out.tid;

	tid1 = cli->tree->tid;
	tid2 = tree->tid;
	torture_comment(tctx, "tid1=%d tid2=%d\n", tid1, tid2);

	torture_comment(tctx, "create a file using the tid1\n");
	cli->tree->tid = tid1;
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname1;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum1 = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "write using the tid1\n");
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.in.file.fnum = fnum1;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;

	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "create a file using the tid2\n");
	cli->tree->tid = tid2;
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_CREATE;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = fname2;
	status = smb_raw_open(cli->tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum2 = io.ntcreatex.out.file.fnum;

	torture_comment(tctx, "write using the tid2\n");
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.in.file.fnum = fnum2;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;

	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	torture_comment(tctx, "exit the pid\n");
	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "the fnum1 on tid1 should not be accessible\n");
	cli->tree->tid = tid1;
	wr.writex.in.file.fnum = fnum1;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "the fnum1 on tid1 should have been auto-closed\n");
	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum1;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "the fnum2 on tid2 should not be accessible\n");
	cli->tree->tid = tid2;
	wr.writex.in.file.fnum = fnum2;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	torture_comment(tctx, "the fnum2 on tid2 should have been auto-closed\n");
	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.in.file.fnum = fnum2;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

done:
	return ret;
}

struct torture_suite *torture_raw_context(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "context");

	torture_suite_add_1smb_test(suite, "session1", test_session);
	/*
	 * TODO: add test_session with 'use spnego = false'
	 * torture_suite_add_1smb_test(suite, "session1", test_session);
	 */
	torture_suite_add_1smb_test(suite, "tree", test_tree);
	torture_suite_add_1smb_test(suite, "tree_ulogoff", test_tree_ulogoff);
	torture_suite_add_1smb_test(suite, "pid_only_sess", test_pid_exit_only_sees_open);
	torture_suite_add_1smb_test(suite, "pid_2sess", test_pid_2sess);
	torture_suite_add_1smb_test(suite, "pid_2tcon", test_pid_2tcon);

	return suite;
}
