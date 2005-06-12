/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

   Copyright (C) Tim Potter 2005
   
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
#include "lib/ejs/ejs.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"

/* Connect to a server */

static int ejs_cli_connect(MprVarHandle eid, int argc, char **argv)
{
	struct smbcli_socket *sock;
	struct smbcli_transport *transport;
	struct nbt_name calling, called;
	NTSTATUS result;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "connect invalid arguments");
		return -1;
	}

	/* Socket connect */

	sock = smbcli_sock_init(NULL, NULL);

	if (!sock) {
		ejsSetErrorMsg(eid, "socket initialisation failed");
		return -1;
	}

	if (!smbcli_sock_connect_byname(sock, argv[0], 0)) {
		ejsSetErrorMsg(eid, "socket connect failed");
		return -1;
	}

	transport = smbcli_transport_init(sock, sock, True);

	if (!transport) {
		ejsSetErrorMsg(eid, "transport init failed");
		return -1;
	}

	/* Send a netbios session request */

	make_nbt_name_client(&calling, lp_netbios_name());

	nbt_choose_called_name(NULL, &called, argv[0], NBT_NAME_SERVER);
		
	if (!smbcli_transport_connect(transport, &calling, &called)) {
		ejsSetErrorMsg(eid, "transport establishment failed");
		return -1;
	}

	result = smb_raw_negotiate(transport, lp_maxprotocol());

	if (!NT_STATUS_IS_OK(result)) {
		ejsSetReturnValue(eid, mprNTSTATUS(result));
		return 0;
	}

	/* Return a socket object */

	ejsSetReturnValue(eid, mprCreatePtrVar(transport, 
					       talloc_get_name(transport)));

	return 0;
}

/* Perform a session setup:
   
     session_setup(conn, "DOMAIN\\USERNAME%PASSWORD");
     session_setup(conn, USERNAME, PASSWORD);
     session_setup(conn, DOMAIN, USERNAME, PASSWORD);
     session_setup(conn);  // anonymous

 */

static int ejs_cli_ssetup(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_transport *transport;
	struct smbcli_session *session;
	struct smb_composite_sesssetup setup;
	struct cli_credentials *creds;
	NTSTATUS status;
	int result = -1;

	/* Argument parsing */

	if (argc < 1 || argc > 4) {
		ejsSetErrorMsg(eid, "session_setup invalid arguments");
		return -1;
	}

	if (!mprVarIsPtr(argv[0]->type)) {
		ejsSetErrorMsg(eid, "first arg is not a connect handle");
		return -1;
	}

	transport = argv[0]->ptr;
	creds = cli_credentials_init(transport);
	cli_credentials_set_conf(creds);

	if (argc == 4) {

		/* DOMAIN, USERNAME, PASSWORD form */

		if (!mprVarIsString(argv[1]->type)) {
			ejsSetErrorMsg(eid, "arg 1 must be a string");
			goto done;
		}

		cli_credentials_set_domain(creds, argv[1]->string, 
					   CRED_SPECIFIED);

		if (!mprVarIsString(argv[2]->type)) {
			ejsSetErrorMsg(eid, "arg 2 must be a string");
			goto done;
		}

		cli_credentials_set_username(creds, argv[2]->string, 
					     CRED_SPECIFIED);

		if (!mprVarIsString(argv[3]->type)) {
			ejsSetErrorMsg(eid, "arg 3 must be a string");
			goto done;
		}

		cli_credentials_set_password(creds, argv[3]->string,
					     CRED_SPECIFIED);

	} else if (argc == 3) {

		/* USERNAME, PASSWORD form */

		if (!mprVarIsString(argv[1]->type)) {
			ejsSetErrorMsg(eid, "arg1 must be a string");
			goto done;
		}

		cli_credentials_set_username(creds, argv[1]->string,
					     CRED_SPECIFIED);

		if (!mprVarIsString(argv[2]->type)) {

			ejsSetErrorMsg(eid, "arg2 must be a string");
			goto done;
		}

		cli_credentials_set_password(creds, argv[2]->string,
					     CRED_SPECIFIED);

	} else if (argc == 2) {

		/* DOMAIN/USERNAME%PASSWORD form */

		cli_credentials_parse_string(creds, argv[1]->string,
					     CRED_SPECIFIED);

	} else {

		/* Anonymous connection */

		cli_credentials_set_anonymous(creds);
	}

	/* Do session setup */

	session = smbcli_session_init(transport, transport, True);

	if (!session) {
		ejsSetErrorMsg(eid, "session init failed");
		return -1;
	}

	setup.in.sesskey = transport->negotiate.sesskey;
	setup.in.capabilities = transport->negotiate.capabilities;
	setup.in.credentials = creds;
	setup.in.workgroup = lp_workgroup();

	status = smb_composite_sesssetup(session, &setup);

	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "session setup: %s", nt_errstr(status));
		return -1;
	}

	session->vuid = setup.out.vuid;	

	/* Return a session object */

	ejsSetReturnValue(eid, mprCreatePtrVar(session, 
					       talloc_get_name(session)));

	result = 0;

 done:
	talloc_free(creds);
	return result;
}

/* Perform a tree connect
   
     session_setup(session, SHARE);

 */

static int ejs_cli_tcon(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_session *session;
	struct smbcli_tree *tree;
	union smb_tcon tcon;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	char *password = "";

	/* Argument parsing */

	if (argc != 2) {
		ejsSetErrorMsg(eid, "tree_connect invalid arguments");
		return -1;
	}

	if (!mprVarIsPtr(argv[0]->type)) {
		ejsSetErrorMsg(eid, "first arg is not a session handle");
		return -1;
	}

	session = argv[0]->ptr;
	tree = smbcli_tree_init(session, session, True);

	if (!tree) {
		ejsSetErrorMsg(eid, "tree init failed");
		return -1;
	}

	mem_ctx = talloc_init("tcon");
	if (!mem_ctx) {
		ejsSetErrorMsg(eid, "talloc_init failed");
		return -1;
	}

	/* Do tree connect */

	tcon.generic.level = RAW_TCON_TCONX;
	tcon.tconx.in.flags = 0;

	if (session->transport->negotiate.sec_mode & NEGOTIATE_SECURITY_USER_LEVEL) {
		tcon.tconx.in.password = data_blob(NULL, 0);
	} else if (session->transport->negotiate.sec_mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE) {
		tcon.tconx.in.password = data_blob_talloc(mem_ctx, NULL, 24);
		if (session->transport->negotiate.secblob.length < 8) {
			ejsSetErrorMsg(eid, "invalid security blob");
			return -1;
		}
		SMBencrypt(password, session->transport->negotiate.secblob.data, tcon.tconx.in.password.data);
	} else {
		tcon.tconx.in.password = data_blob_talloc(mem_ctx, password, strlen(password)+1);
	}

	tcon.tconx.in.path = argv[1]->string;
	tcon.tconx.in.device = "?????";
	
	status = smb_tree_connect(tree, mem_ctx, &tcon);

	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "session setup: %s", nt_errstr(status));
		return -1;
	}

	tree->tid = tcon.tconx.out.tid;

	talloc_free(mem_ctx);	

	return 0;
}

/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_cli(void)
{
	ejsDefineStringCFunction(-1, "connect", ejs_cli_connect, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "session_setup", ejs_cli_ssetup, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "tree_connect", ejs_cli_tcon, NULL, MPR_VAR_SCRIPT_HANDLE);
}
