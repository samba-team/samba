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
	NTSTATUS status;
	struct nbt_netlogon_packet netlogon;
	int *replies = dgmslot->private;

	printf("netlogon reply from %s:%d\n", src_address, src_port);

	status = dgram_mailslot_netlogon_parse(dgmslot, dgmslot, packet, &netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to parse netlogon packet from %s:%d\n",
		       src_address, src_port);
		return;
	}

	NDR_PRINT_DEBUG(nbt_netlogon_packet, &netlogon);

	(*replies)++;
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
	struct timeval tv = timeval_current();
	int replies = 0;

	/* try receiving replies on port 138 first, which will only
	   work if we are root and smbd/nmbd are not running - fall
	   back to listening on any port, which means replies from
	   some windows versions won't be seen */
	status = socket_listen(dgmsock->sock, myaddress, lp_dgram_port(), 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		socket_listen(dgmsock->sock, myaddress, 0, 0, 0);
	}

	/* setup a temporary mailslot listener for replies */
	dgmslot = dgram_mailslot_temp(dgmsock, NBT_MAILSLOT_GETDC,
				      netlogon_handler, &replies);
	

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

	status = dgram_mailslot_netlogon_send(dgmsock, &name, address, 
					      0, &myname, &logon);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to send netlogon request - %s\n", nt_errstr(status));
		goto failed;
	}


	while (timeval_elapsed(&tv) < 5 && replies == 0) {
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
