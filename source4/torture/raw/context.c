/* 
   Unix SMB/CIFS implementation.
   test suite for session setup operations
   Copyright (C) Andrew Tridgell 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"
#include "libcli/libcli.h"

#define BASEDIR "\\rawcontext"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d - should be %d\n", \
		       __location__, #v, v, correct); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_NOT_VALUE(v, correct) do { \
	if ((v) == (correct)) { \
		printf("(%s) Incorrect value %s=%d - should not be %d\n", \
		       __location__, #v, v, correct); \
		ret = False; \
		goto done; \
	}} while (0)


/*
  test session ops
*/
static BOOL test_session(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	BOOL ret = True;
	struct smbcli_session *session;
	struct smbcli_session *session2;
	struct smbcli_session *session3;
	struct smbcli_session *session4;
	struct cli_credentials *anon_creds;
	struct smbcli_session *sessions[15];
	struct composite_context *composite_contexts[15];
	struct smbcli_tree *tree;
	struct smb_composite_sesssetup setup;
	struct smb_composite_sesssetup setups[15];
	union smb_open io;
	union smb_write wr;
	union smb_close cl;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	uint8_t c = 1;
	int i;

	printf("TESTING SESSION HANDLING\n");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	printf("create a second security context on the same transport\n");
	session = smbcli_session_init(cli->transport, mem_ctx, False);

	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities; /* ignored in secondary session setup, except by our libs, which care about the extended security bit */
	setup.in.workgroup = lp_workgroup();

	setup.in.credentials = cmdline_credentials;

	status = smb_composite_sesssetup(session, &setup);
	CHECK_STATUS(status, NT_STATUS_OK);
	
	session->vuid = setup.out.vuid;

	printf("create a third security context on the same transport, with vuid set\n");
	session2 = smbcli_session_init(cli->transport, mem_ctx, False);

	session2->vuid = session->vuid;
	setup.in.sesskey = cli->transport->negotiate.sesskey;
	setup.in.capabilities = cli->transport->negotiate.capabilities; /* ignored in secondary session setup, except by our libs, which care about the extended security bit */
	setup.in.workgroup = lp_workgroup();

	setup.in.credentials = cmdline_credentials;

	status = smb_composite_sesssetup(session2, &setup);
	CHECK_STATUS(status, NT_STATUS_OK);

	session2->vuid = setup.out.vuid;
	printf("vuid1=%d vuid2=%d vuid3=%d\n", cli->session->vuid, session->vuid, session2->vuid);
	
	if (cli->transport->negotiate.capabilities & CAP_EXTENDED_SECURITY) {
		/* Samba4 currently fails this - we need to determine if this insane behaviour is important */
		if (session2->vuid == session->vuid) {
			printf("server allows the user to re-use an existing vuid in session setup \n");
		}
	} else {
		CHECK_NOT_VALUE(session2->vuid, session->vuid);
	}
	talloc_free(session2);

	if (cli->transport->negotiate.capabilities & CAP_EXTENDED_SECURITY) {
		printf("create a fourth security context on the same transport, without extended security\n");
		session3 = smbcli_session_init(cli->transport, mem_ctx, False);

		session3->vuid = session->vuid;
		setup.in.sesskey = cli->transport->negotiate.sesskey;
		setup.in.capabilities &= ~CAP_EXTENDED_SECURITY; /* force a non extended security login (should fail) */
		setup.in.workgroup = lp_workgroup();
	
		setup.in.credentials = cmdline_credentials;
	

		status = smb_composite_sesssetup(session3, &setup);
		CHECK_STATUS(status, NT_STATUS_LOGON_FAILURE);

		printf("create a fouth anonymous security context on the same transport, without extended security\n");
		session4 = smbcli_session_init(cli->transport, mem_ctx, False);

		session4->vuid = session->vuid;
		setup.in.sesskey = cli->transport->negotiate.sesskey;
		setup.in.capabilities &= ~CAP_EXTENDED_SECURITY; /* force a non extended security login (should fail) */
		setup.in.workgroup = lp_workgroup();
		
		anon_creds = cli_credentials_init(mem_ctx);
		cli_credentials_set_conf(anon_creds);
		cli_credentials_set_anonymous(anon_creds);

		setup.in.credentials = anon_creds;
	
		status = smb_composite_sesssetup(session3, &setup);
		CHECK_STATUS(status, NT_STATUS_OK);

		talloc_free(session4);
	}
		
	printf("use the same tree as the existing connection\n");
	tree = smbcli_tree_init(session, mem_ctx, False);
	tree->tid = cli->tree->tid;

	printf("create a file using the new vuid\n");
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
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
	status = smb_raw_open(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.file.fnum;

	printf("write using the old vuid\n");
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.file.fnum = fnum;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;

	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("write with the new vuid\n");
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	printf("logoff the new vuid\n");
	status = smb_raw_ulogoff(session);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("the new vuid should not now be accessible\n");
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("second logoff for the new vuid should fail\n");
	status = smb_raw_ulogoff(session);
	CHECK_STATUS(status, NT_STATUS_DOS(ERRSRV, ERRbaduid));
	talloc_free(session);

	printf("the fnum should have been auto-closed\n");
	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("create %d secondary security contexts on the same transport\n", 
	       (int)ARRAY_SIZE(sessions));
	for (i=0; i <ARRAY_SIZE(sessions); i++) {
		setups[i].in.sesskey = cli->transport->negotiate.sesskey;
		setups[i].in.capabilities = cli->transport->negotiate.capabilities; /* ignored in secondary session setup, except by our libs, which care about the extended security bit */
		setups[i].in.workgroup = lp_workgroup();
		
		setups[i].in.credentials = cmdline_credentials;

		sessions[i] = smbcli_session_init(cli->transport, mem_ctx, False);
		composite_contexts[i] = smb_composite_sesssetup_send(sessions[i], &setups[i]);

	}


	/* flush the queue */
	for (i=0; i < ARRAY_SIZE(sessions); i++) {
		event_loop_once(composite_contexts[0]->event_ctx);
	}

	printf("finishing %d secondary security contexts on the same transport\n", 
	       (int)ARRAY_SIZE(sessions));
	for (i=0; i< ARRAY_SIZE(sessions); i++) {
		status = smb_composite_sesssetup_recv(composite_contexts[i]);
		CHECK_STATUS(status, NT_STATUS_OK);
		sessions[i]->vuid = setups[i].out.vuid;
		printf("VUID: %d\n", sessions[i]->vuid);
		status = smb_raw_ulogoff(sessions[i]);
		CHECK_STATUS(status, NT_STATUS_OK);
	}


	talloc_free(tree);
	
done:
	return ret;
}


/*
  test tree ops
*/
static BOOL test_tree(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	BOOL ret = True;
	const char *share, *host;
	struct smbcli_tree *tree;
	union smb_tcon tcon;
	union smb_open io;
	union smb_write wr;
	union smb_close cl;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	uint8_t c = 1;

	printf("TESTING TREE HANDLING\n");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	share = lp_parm_string(-1, "torture", "share");
	host  = lp_parm_string(-1, "torture", "host");
	
	printf("create a second tree context on the same session\n");
	tree = smbcli_tree_init(cli->session, mem_ctx, False);

	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = 0;
	tcon.tconx.in.password = data_blob(NULL, 0);
	tcon.tconx.in.path = talloc_asprintf(mem_ctx, "\\\\%s\\%s", host, share);
	tcon.tconx.in.device = "A:";	
	status = smb_raw_tcon(tree, mem_ctx, &tcon);
	CHECK_STATUS(status, NT_STATUS_OK);
	

	tree->tid = tcon.tconx.out.tid;
	printf("tid1=%d tid2=%d\n", cli->tree->tid, tree->tid);

	printf("try a tconx with a bad device type\n");
	tcon.tconx.in.device = "FOO";	
	status = smb_raw_tcon(tree, mem_ctx, &tcon);
	CHECK_STATUS(status, NT_STATUS_BAD_DEVICE_TYPE);


	printf("create a file using the new tid\n");
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
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
	status = smb_raw_open(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	fnum = io.ntcreatex.file.fnum;

	printf("write using the old tid\n");
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.file.fnum = fnum;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;

	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("write with the new tid\n");
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	printf("disconnect the new tid\n");
	status = smb_tree_disconnect(tree);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("the new tid should not now be accessible\n");
	status = smb_raw_write(tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("the fnum should have been auto-closed\n");
	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	/* close down the new tree */
	talloc_free(tree);
	
done:
	return ret;
}


/*
  test pid ops
*/
static BOOL test_pid(struct smbcli_state *cli, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	BOOL ret = True;
	union smb_open io;
	union smb_write wr;
	union smb_close cl;
	int fnum;
	const char *fname = BASEDIR "\\test.txt";
	uint8_t c = 1;
	uint16_t pid1, pid2;

	printf("TESTING PID HANDLING\n");

	if (!torture_setup_dir(cli, BASEDIR)) {
		return False;
	}

	printf("create a second pid\n");
	pid1 = cli->session->pid;
	pid2 = pid1+1;

	printf("pid1=%d pid2=%d\n", pid1, pid2);

	printf("create a file using the new pid\n");
	cli->session->pid = pid2;
	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid = 0;
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
	fnum = io.ntcreatex.file.fnum;

	printf("write using the old pid\n");
	cli->session->pid = pid1;
	wr.generic.level = RAW_WRITE_WRITEX;
	wr.writex.file.fnum = fnum;
	wr.writex.in.offset = 0;
	wr.writex.in.wmode = 0;
	wr.writex.in.remaining = 0;
	wr.writex.in.count = 1;
	wr.writex.in.data = &c;

	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	printf("write with the new pid\n");
	cli->session->pid = pid2;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	printf("exit the old pid\n");
	cli->session->pid = pid1;
	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("the fnum should still be accessible\n");
	cli->session->pid = pid1;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(wr.writex.out.nwritten, 1);

	printf("exit the new pid\n");
	cli->session->pid = pid2;
	status = smb_raw_exit(cli->session);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("the fnum should not now be accessible\n");
	cli->session->pid = pid1;
	status = smb_raw_write(cli->tree, &wr);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

	printf("the fnum should have been auto-closed\n");
	cl.close.level = RAW_CLOSE_CLOSE;
	cl.close.file.fnum = fnum;
	cl.close.in.write_time = 0;
	status = smb_raw_close(cli->tree, &cl);
	CHECK_STATUS(status, NT_STATUS_INVALID_HANDLE);

done:
	return ret;
}


/* 
   basic testing of session/tree context calls
*/
static BOOL torture_raw_context_int(void)
{
	struct smbcli_state *cli;
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;

	if (!torture_open_connection(&cli)) {
		return False;
	}

	mem_ctx = talloc_init("torture_raw_context");

	if (!test_session(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_tree(cli, mem_ctx)) {
		ret = False;
	}

	if (!test_pid(cli, mem_ctx)) {
		ret = False;
	}

	smb_raw_exit(cli->session);
	smbcli_deltree(cli->tree, BASEDIR);

	torture_close_connection(cli);
	talloc_free(mem_ctx);

	return ret;
}
/* 
   basic testing of session/tree context calls
*/
BOOL torture_raw_context(void)
{
	BOOL ret = True;
	if (lp_use_spnego()) {
		ret &= torture_raw_context_int();
		lp_set_cmdline("use spnego", "False");
	}

	ret &= torture_raw_context_int();

	return ret;
}
