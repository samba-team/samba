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

static struct MprVar mprTransport(struct smbcli_transport *transport)
{
	struct MprVar res, val;

	res = mprCreateObjVar("transport", MPR_DEFAULT_HASH_SIZE);

	val = mprCreateStringVar(talloc_get_name(transport), 1);
	mprCreateProperty(&res, "name", &val);

	/* TODO: Create a C pointer "value" property */

	return res;
}

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

	ejsSetReturnValue(eid, mprTransport(transport));

	return 0;
}

/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_cli(void)
{
	ejsDefineStringCFunction(-1, "connect", ejs_cli_connect, NULL, MPR_VAR_SCRIPT_HANDLE);				
}
