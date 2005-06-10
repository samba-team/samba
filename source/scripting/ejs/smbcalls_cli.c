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

	ejsSetReturnValue(eid, mprCreatePtrVar(transport, talloc_get_name(transport)));

	return 0;
}

/* Perform a session setup:
   
     session_setup(conn, "DOMAIN\USERNAME%PASSWORD");
     session_setup(conn, USERNAME, PASSWORD);
     session_setup(conn, DOMAIN, USERNAME, PASSWORD);

 */

static int ejs_cli_ssetup(MprVarHandle eid, int argc, MprVar **argv)
{
	struct smbcli_transport *transport;
	struct smbcli_session *session;
	struct smb_composite_sesssetup setup;
	struct cli_credentials *creds;
	NTSTATUS status;

	/* Argument parsing */

	if (argc < 1 || argc > 3) {
		ejsSetErrorMsg(eid, "session_setup invalid arguments");
		return -1;
	}

	if (argv[0]->type != MPR_TYPE_PTR) {
		ejsSetErrorMsg(eid, "first arg is not a connect handle");
		return -1;
	}

	transport = argv[0]->ptr;

	/* Do session setup */

	session = smbcli_session_init(transport, transport, True);
	if (!session) {
		ejsSetErrorMsg(eid, "session init failed");
		return -1;
	}

	creds = cli_credentials_init(session);
	cli_credentials_set_anonymous(creds);

	setup.in.sesskey = transport->negotiate.sesskey;
	setup.in.capabilities = transport->negotiate.capabilities;
	setup.in.credentials = creds;
	setup.in.workgroup = lp_workgroup();

	status = smb_composite_sesssetup(session, &setup);

	session->vuid = setup.out.vuid;	

	/* Return a session object */

	ejsSetReturnValue(eid, mprCreatePtrVar(session, talloc_get_name(session)));

	return 0;
}

/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_cli(void)
{
	ejsDefineStringCFunction(-1, "connect", ejs_cli_connect, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "session_setup", ejs_cli_ssetup, NULL, MPR_VAR_SCRIPT_HANDLE);
}
