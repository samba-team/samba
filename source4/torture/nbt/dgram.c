/* 
   Unix SMB/CIFS implementation.

   NBT dgram testing

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
#include "libcli/nbt/libnbt.h"
#include "libcli/dgram/libdgram.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "lib/socket/socket.h"
#include "lib/events/events.h"

#define TEST_NAME "TORTURE_TEST"

/*
  reply handler for netlogon request
*/
static void netlogon_handler(struct dgram_mailslot_handler *dgmslot, 
			     struct nbt_dgram_packet *packet, 
			     const char *src_address, int src_port)
{
	printf("netlogon reply from %s:%d\n", src_address, src_port);
}

/* test UDP/138 netlogon requests */
static BOOL nbt_test_netlogon(TALLOC_CTX *mem_ctx, 
			      struct nbt_name name, const char *address)
{
	struct dgram_mailslot_handler *dgmslot;
	struct nbt_dgram_socket *dgmsock = nbt_dgram_socket_init(mem_ctx, NULL);
	const char *myaddress = talloc_strdup(mem_ctx, iface_best_ip(address));
	struct nbt_netlogon_packet logon;
	struct nbt_name myname;
	NTSTATUS status;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	struct timeval tv = timeval_current();

	socket_listen(dgmsock->sock, myaddress, 0, 0, 0);

	/* setup a temporary mailslot listener for replies */
	dgmslot = dgram_mailslot_temp(dgmsock, "\\MAILSLOT\\NET\\GETDC", 
				      netlogon_handler, NULL);
	

	ZERO_STRUCT(logon);
	logon.command = NETLOGON_QUERY_FOR_PDC;
	logon.req.pdc.computer_name = TEST_NAME;
	logon.req.pdc.mailslot_name = dgmslot->mailslot_name;
	logon.req.pdc.unicode_name  = TEST_NAME;
	logon.req.pdc.nt_version    = 1;
	logon.req.pdc.lmnt_token    = 0xFFFF;
	logon.req.pdc.lm20_token    = 0xFFFF;

	myname.name = TEST_NAME;
	myname.type = NBT_NAME_CLIENT;
	myname.scope = NULL;

	status = dgram_mailslot_netlogon_send(dgmsock, &name, address, &myname, &logon);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to send netlogon request - %s\n", nt_errstr(status));
		goto failed;
	}


	while (timeval_elapsed(&tv) < timelimit) {
		event_loop_once(dgmsock->event_ctx);
	}

	talloc_free(dgmsock);
	return True;

failed:
	talloc_free(dgmsock);
	return False;
}


/*
  test nbt dgram operations
*/
BOOL torture_nbt_dgram(void)
{
	const char *address;
	struct nbt_name name;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	NTSTATUS status;
	BOOL ret = True;
	
	name.name = lp_parm_string(-1, "torture", "host");
	name.type = NBT_NAME_PDC;
	name.scope = NULL;

	/* do an initial name resolution to find its IP */
	status = resolve_name(&name, mem_ctx, &address);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to resolve %s - %s\n",
		       name.name, nt_errstr(status));
		talloc_free(mem_ctx);
		return False;
	}

	ret &= nbt_test_netlogon(mem_ctx, name, address);

	talloc_free(mem_ctx);

	return ret;
}
