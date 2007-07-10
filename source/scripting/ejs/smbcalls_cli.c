/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

   Copyright (C) Tim Potter 2005
   
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
#include "scripting/ejs/smbcalls.h"
#include "lib/appweb/ejs/ejs.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/libcli.h"
#include "auth/credentials/credentials.h"

#if 0

#include "librpc/gen_ndr/ndr_nbt.h"

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

	transport = smbcli_transport_init(sock, sock, False);

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
		mpr_Return(eid, mprNTSTATUS(result));
		return 0;
	}

	/* Return a socket object */

	mpr_Return(eid, mprCreatePtrVar(transport));

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

	session = smbcli_session_init(transport, transport, False);

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
		ejsSetErrorMsg(eid, "session_setup: %s", nt_errstr(status));
		return -1;
	}

	session->vuid = setup.out.vuid;	

	/* Return a session object */

	mpr_Return(eid, mprCreatePtrVar(session));

	result = 0;

 done:
	talloc_free(creds);
	return result;
}

/* Perform a tree connect
   
     tree_connect(session, SHARE);

 */

static int ejs_cli_tree_connect(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_session *session;
	struct smbcli_tree *tree;
	union smb_tcon tcon;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	const char *password = "";

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
	tree = smbcli_tree_init(session, session, False);

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
		ejsSetErrorMsg(eid, "tree_connect: %s", nt_errstr(status));
		return -1;
	}

	tree->tid = tcon.tconx.out.tid;

	talloc_free(mem_ctx);	

	mpr_Return(eid, mprCreatePtrVar(tree));

	return 0;
}

/* Perform a tree disconnect
   
     tree_disconnect(tree);

 */
static int ejs_cli_tree_disconnect(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_tree *tree;
	NTSTATUS status;

	/* Argument parsing */

	if (argc != 1) {
		ejsSetErrorMsg(eid, "tree_disconnect invalid arguments");
		return -1;
	}

	if (!mprVarIsPtr(argv[0]->type)) {
		ejsSetErrorMsg(eid, "first arg is not a tree handle");
		return -1;
	}	

	tree = argv[0]->ptr;

	status = smb_tree_disconnect(tree);

	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "tree_disconnect: %s", nt_errstr(status));
		return -1;
	}

	talloc_free(tree);

	return 0;
}

/* Perform a ulogoff
   
     session_logoff(session);

 */
static int ejs_cli_session_logoff(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_session *session;
	NTSTATUS status;

	/* Argument parsing */

	if (argc != 1) {
		ejsSetErrorMsg(eid, "session_logoff invalid arguments");
		return -1;
	}

	if (!mprVarIsPtr(argv[0]->type)) {
		ejsSetErrorMsg(eid, "first arg is not a session handle");
		return -1;
	}	

	session = argv[0]->ptr;

	status = smb_raw_ulogoff(session);

	if (!NT_STATUS_IS_OK(status)) {
		ejsSetErrorMsg(eid, "session_logoff: %s", nt_errstr(status));
		return -1;
	}

	talloc_free(session);

	return 0;
}

/* Perform a connection close
   
     disconnect(conn);

 */
static int ejs_cli_disconnect(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_sock *sock;

	/* Argument parsing */

	if (argc != 1) {
		ejsSetErrorMsg(eid, "disconnect invalid arguments");
		return -1;
	}

	if (!mprVarIsPtr(argv[0]->type)) {
		ejsSetErrorMsg(eid, "first arg is not a connect handle");
		return -1;
	}	

	sock = argv[0]->ptr;

	talloc_free(sock);

	return 0;
}

#endif

/* Perform a tree connect:

     tree_handle = tree_connect("\\\\frogurt\\homes", "user%pass");
 */

static int ejs_tree_connect(MprVarHandle eid, int argc, char **argv)
{
	struct cli_credentials *creds;
	struct smb_composite_connect io;
	struct smbcli_tree *tree;
	char *hostname, *sharename;
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "tree_connect(): invalid number of args");
		return -1;
	}

	/* Set up host, share destination */

	mem_ctx = talloc_new(mprMemCtx());
	smbcli_parse_unc(argv[0], mem_ctx, &hostname, &sharename);

	/* Set up credentials */

	creds = cli_credentials_init(NULL);
	cli_credentials_set_conf(creds);
	cli_credentials_parse_string(creds, argv[1], CRED_SPECIFIED);

	/* Do connect */

	io.in.dest_host              = hostname;
	io.in.port                   = 0;
	io.in.called_name            = strupper_talloc(mem_ctx, hostname);
	io.in.service                = sharename;
	io.in.service_type           = "?????";
	io.in.credentials            = creds;
	io.in.fallback_to_anonymous  = False;
	io.in.workgroup              = lp_workgroup();

	result = smb_composite_connect(&io, mem_ctx, NULL);
	tree = io.out.tree;

	talloc_free(mem_ctx);

	if (!NT_STATUS_IS_OK(result)) {
		mpr_Return(eid, mprNTSTATUS(result));
		return 0;
	}

	mpr_Return(eid, mprCreatePtrVar(tree));

	return 0;
}

#define IS_TREE_HANDLE(x) (mprVarIsPtr((x)->type) && \
                           talloc_check_name((x)->ptr, "struct smbcli_tree"))

/* Perform a tree disconnect:

     tree_disconnect(tree_handle);
 */

static int ejs_tree_disconnect(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_tree *tree;
	NTSTATUS result;

	if (argc != 1) {
		ejsSetErrorMsg(eid, 
			       "tree_disconnect(): invalid number of args");
		return -1;
	}

	if (!IS_TREE_HANDLE(argv[0])) {
		ejsSetErrorMsg(eid, "first arg is not a tree handle");
		return -1;
	}

	tree = talloc_check_name(argv[0]->ptr, "struct smbcli_tree");

	result = smb_tree_disconnect(tree);

	mpr_Return(eid, mprNTSTATUS(result));

	return 0;
}

/* Create a directory:

     result = mkdir(tree_handle, DIRNAME);
 */

static int ejs_mkdir(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_tree *tree;
	NTSTATUS result;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "mkdir(): invalid number of args");
		return -1;
	}

	if (!IS_TREE_HANDLE(argv[0])) {
		ejsSetErrorMsg(eid, "first arg is not a tree handle");
		return -1;
	}

	tree = argv[0]->ptr;

	if (!mprVarIsString(argv[1]->type)) {
		ejsSetErrorMsg(eid, "arg 2 must be a string");
		return -1;
	}

	result = smbcli_mkdir(tree, argv[1]->string);

	mpr_Return(eid, mprNTSTATUS(result));

	return 0;
}

/* Remove a directory:

     result = rmdir(tree_handle, DIRNAME);
 */

static int ejs_rmdir(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_tree *tree;
	NTSTATUS result;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "rmdir(): invalid number of args");
		return -1;
	}

	if (!IS_TREE_HANDLE(argv[0])) {
		ejsSetErrorMsg(eid, "first arg is not a tree handle");
		return -1;
	}

	tree = argv[0]->ptr;

	if (!mprVarIsString(argv[1]->type)) {
		ejsSetErrorMsg(eid, "arg 2 must be a string");
		return -1;
	}
	
	result = smbcli_rmdir(tree, argv[1]->string);

	mpr_Return(eid, mprNTSTATUS(result));

	return 0;
}

/* Rename a file or directory:

     result = rename(tree_handle, SRCFILE, DESTFILE);
 */

static int ejs_rename(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_tree *tree;
	NTSTATUS result;

	if (argc != 3) {
		ejsSetErrorMsg(eid, "rename(): invalid number of args");
		return -1;
	}

	if (!IS_TREE_HANDLE(argv[0])) {
		ejsSetErrorMsg(eid, "first arg is not a tree handle");
		return -1;
	}

	tree = argv[0]->ptr;

	if (!mprVarIsString(argv[1]->type)) {
		ejsSetErrorMsg(eid, "arg 2 must be a string");
		return -1;
	}
	
	if (!mprVarIsString(argv[2]->type)) {
		ejsSetErrorMsg(eid, "arg 3 must be a string");
		return -1;
	}
	
	result = smbcli_rename(tree, argv[1]->string, argv[2]->string);

	mpr_Return(eid, mprNTSTATUS(result));

	return 0;
}

/* Unlink a file or directory:

     result = unlink(tree_handle, FILENAME);
 */

static int ejs_unlink(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_tree *tree;
	NTSTATUS result;

	if (argc != 2) {
		ejsSetErrorMsg(eid, "unlink(): invalid number of args");
		return -1;
	}

	if (!IS_TREE_HANDLE(argv[0])) {
		ejsSetErrorMsg(eid, "first arg is not a tree handle");
		return -1;
	}

	tree = argv[0]->ptr;

	if (!mprVarIsString(argv[1]->type)) {
		ejsSetErrorMsg(eid, "arg 2 must be a string");
		return -1;
	}
	
	result = smbcli_unlink(tree, argv[1]->string);

	mpr_Return(eid, mprNTSTATUS(result));

	return 0;
}

/* List directory contents

     result = list(tree_handle, ARG1, ...);
 */

static void ejs_list_helper(struct clilist_file_info *info, const char *mask, 
			    void *state)

{
	MprVar *result = (MprVar *)state;
	char idx[16];

	mprItoa(result->properties->numDataItems, idx, sizeof(idx));
	mprSetVar(result, idx, mprString(info->name));
}

static int ejs_list(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_tree *tree;
	char *mask;
	uint16_t attribute;
	MprVar result;

	if (argc != 3) {
		ejsSetErrorMsg(eid, "list(): invalid number of args");
		return -1;
	}

	if (!IS_TREE_HANDLE(argv[0])) {
		ejsSetErrorMsg(eid, "first arg is not a tree handle");
		return -1;
	}

	tree = argv[0]->ptr;

	if (!mprVarIsString(argv[1]->type)) {
		ejsSetErrorMsg(eid, "arg 2 must be a string");
		return -1;
	}
	
	mask = argv[1]->string;

	if (!mprVarIsNumber(argv[2]->type)) {
		ejsSetErrorMsg(eid, "arg 3 must be a number");
		return -1;
	}

	attribute = mprVarToInteger(argv[2]);

	result = mprObject("list");

	smbcli_list(tree, mask, attribute, ejs_list_helper, &result);

	mpr_Return(eid, result);

	return 0;
}

/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_cli(void)
{
	ejsDefineStringCFunction(-1, "tree_connect", ejs_tree_connect, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "tree_disconnect", ejs_tree_disconnect, NULL, MPR_VAR_SCRIPT_HANDLE);

	ejsDefineCFunction(-1, "mkdir", ejs_mkdir, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "rmdir", ejs_rmdir, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "rename", ejs_rename, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "unlink", ejs_unlink, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "list", ejs_list, NULL, MPR_VAR_SCRIPT_HANDLE);
	

#if 0
	ejsDefineStringCFunction(-1, "connect", ejs_cli_connect, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "session_setup", ejs_cli_ssetup, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "tree_connect", ejs_cli_tree_connect, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "tree_disconnect", ejs_cli_tree_disconnect, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "session_logoff", ejs_cli_session_logoff, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "disconnect", ejs_cli_disconnect, NULL, MPR_VAR_SCRIPT_HANDLE);	
#endif
}
