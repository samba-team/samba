/* 
   Unix SMB/CIFS implementation.

   test suite for SMB2 connection operations

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"
#include "auth/gensec/gensec.h"

#define BASEDIR "\\testsmb2"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)


/*
  send a negotiate
 */
static struct smb2_transport *torture_smb2_negprot(TALLOC_CTX *mem_ctx, const char *host)
{
	struct smbcli_socket *socket;
	struct smb2_transport *transport;
	NTSTATUS status;
	struct smb2_negprot io;

	socket = smbcli_sock_connect_byname(host, 445, mem_ctx, NULL);
	if (socket == NULL) {
		printf("Failed to connect to %s\n", host);
		return False;
	}

	transport = smb2_transport_init(socket, mem_ctx);
	if (transport == NULL) {
		printf("Failed to setup smb2 transport\n");
		return False;
	}

	ZERO_STRUCT(io);
	io.in.unknown1 = 0x010024;

	/* send a negprot */
	status = smb2_negprot(transport, mem_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("negprot failed - %s\n", nt_errstr(status));
		return NULL;
	}

	printf("Negprot reply:\n");
	printf("current_time  = %s\n", nt_time_string(mem_ctx, io.out.current_time));
	printf("boot_time     = %s\n", nt_time_string(mem_ctx, io.out.boot_time));

	transport->negotiate.secblob = io.out.secblob;

	return transport;
}

/*
  send a session setup
*/
static struct smb2_session *torture_smb2_session(struct smb2_transport *transport, 
						 struct cli_credentials *credentials)
{
	struct smb2_session *session;
	struct smb2_session_setup io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(transport);
	DATA_BLOB secblob;

	ZERO_STRUCT(io);
	io.in.unknown1 = 0x11;
	io.in.unknown2 = 0xF;
	io.in.unknown3 = 0x00;

	session = smb2_session_init(transport, transport, True);

	status = gensec_set_credentials(session->gensec, credentials);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client credentails: %s\n", 
			  nt_errstr(status)));
		return NULL;
	}

	status = gensec_set_target_hostname(session->gensec, transport->socket->hostname);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target hostname: %s\n", 
			  nt_errstr(status)));
		return NULL;
	}

	status = gensec_set_target_service(session->gensec, "cifs");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target service: %s\n", 
			  nt_errstr(status)));
		return NULL;
	}

	status = gensec_start_mech_by_oid(session->gensec, GENSEC_OID_SPNEGO);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client - %s\n",
			  nt_errstr(status)));
		return NULL;
	}

	secblob = session->transport->negotiate.secblob;

	do {
		NTSTATUS status1;

		status1 = gensec_update(session->gensec, tmp_ctx, secblob, &io.in.secblob);
		if (!NT_STATUS_EQUAL(status1, NT_STATUS_MORE_PROCESSING_REQUIRED) && 
		    !NT_STATUS_IS_OK(status1)) {
			DEBUG(1, ("Failed initial gensec_update : %s\n", 
				  nt_errstr(status1)));
			status = status1;
			break;
		}
		
		status = smb2_session_setup(session, tmp_ctx, &io);
		secblob = io.out.secblob;

		session->uid = io.out.uid;

		if (NT_STATUS_IS_OK(status) && 
		    NT_STATUS_EQUAL(status1, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			status = gensec_update(session->gensec, tmp_ctx, secblob, 
					       &io.in.secblob);
		}
	} while (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED));

	if (!NT_STATUS_IS_OK(status)) {
		printf("session setup failed - %s\n", nt_errstr(status));
		return NULL;
	}

	printf("Session setup gave UID 0x%016llx\n", session->uid);

	return session;
}


/*
  send a tree connect
*/
static struct smb2_tree *torture_smb2_tree(struct smb2_session *session, 
					   const char *share)
{
	struct smb2_tree *tree;
	struct smb2_tree_connect io;
	NTSTATUS status;

	tree = smb2_tree_init(session, session, True);

	io.in.unknown1 = 0x09;
	io.in.path     = talloc_asprintf(tree, "\\\\%s\\%s",
					 session->transport->socket->hostname,
					 share);
	
	status = smb2_tree_connect(tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("tcon failed - %s\n", nt_errstr(status));
		return NULL;
	}
	
	printf("Tree connect gave tid = 0x%x\n", io.out.tid);

	tree->tid = io.out.tid;

	return tree;
}

/*
  send a create
*/
static struct smb2_handle torture_smb2_create(struct smb2_tree *tree, 
					      const char *fname)
{
	struct smb2_create io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(io);
	io.in.unknown1 = 0x09000039;
	io.in.access_mask = SEC_RIGHTS_FILE_ALL;
	io.in.file_attr   = FILE_ATTRIBUTE_NORMAL;
	io.in.open_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.fname = fname;
	status = smb2_create(tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("create failed - %s\n", nt_errstr(status));
		return io.out.handle;
	}

	printf("Open gave:\n");
	printf("create_time     = %s\n", nt_time_string(tmp_ctx, io.out.create_time));
	printf("access_time     = %s\n", nt_time_string(tmp_ctx, io.out.access_time));
	printf("write_time      = %s\n", nt_time_string(tmp_ctx, io.out.write_time));
	printf("change_time     = %s\n", nt_time_string(tmp_ctx, io.out.change_time));
	printf("handle          = %016llx%016llx\n", 
	       io.out.handle.data[0], 
	       io.out.handle.data[1]);

	talloc_free(tmp_ctx);
	
	return io.out.handle;
}

/*
  send a close
*/
static NTSTATUS torture_smb2_close(struct smb2_tree *tree, struct smb2_handle handle)
{
	struct smb2_close io;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(tree);

	ZERO_STRUCT(io);
	io.in.unknown1 = 0x10018;
	io.in.handle   = handle;
	status = smb2_close(tree, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("close failed - %s\n", nt_errstr(status));
		return status;
	}

	printf("Close gave:\n");
	printf("create_time     = %s\n", nt_time_string(tmp_ctx, io.out.create_time));
	printf("access_time     = %s\n", nt_time_string(tmp_ctx, io.out.access_time));
	printf("write_time      = %s\n", nt_time_string(tmp_ctx, io.out.write_time));
	printf("change_time     = %s\n", nt_time_string(tmp_ctx, io.out.change_time));

	talloc_free(tmp_ctx);
	
	return status;
}

/* 
   basic testing of SMB2 connection calls
*/
BOOL torture_smb2_connect(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_transport *transport;
	struct smb2_session *session;	
	struct smb2_tree *tree;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");
	struct cli_credentials *credentials = cmdline_credentials;
	struct smb2_handle h1, h2;

	transport = torture_smb2_negprot(mem_ctx, host);
	session   = torture_smb2_session(transport, credentials);
	tree      = torture_smb2_tree(session, share);
	h1        = torture_smb2_create(tree, "test1.dat");
	h2        = torture_smb2_create(tree, "test2.dat");
	torture_smb2_close(tree, h1);
	torture_smb2_close(tree, h2);

	talloc_free(mem_ctx);

	return True;
}
