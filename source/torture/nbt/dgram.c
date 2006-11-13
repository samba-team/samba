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
#include "libcli/dgram/libdgram.h"
#include "librpc/gen_ndr/samr.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "lib/socket/socket.h"
#include "lib/events/events.h"
#include "torture/rpc/rpc.h"
#include "libcli/resolve/resolve.h"
#include "system/network.h"
#include "lib/socket/netif.h"

#define TEST_NAME "TORTURE_TEST"

/*
  reply handler for netlogon request
*/
static void netlogon_handler(struct dgram_mailslot_handler *dgmslot, 
			     struct nbt_dgram_packet *packet, 
			     struct socket_address *src)
{
	NTSTATUS status;
	struct nbt_netlogon_packet netlogon;
	int *replies = dgmslot->private;

	printf("netlogon reply from %s:%d\n", src->addr, src->port);

	status = dgram_mailslot_netlogon_parse(dgmslot, dgmslot, packet, &netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to parse netlogon packet from %s:%d\n",
		       src->addr, src->port);
		return;
	}

	NDR_PRINT_DEBUG(nbt_netlogon_packet, &netlogon);

	(*replies)++;
}


/* test UDP/138 netlogon requests */
static bool nbt_test_netlogon(struct torture_context *tctx)
{
	struct dgram_mailslot_handler *dgmslot;
	struct nbt_dgram_socket *dgmsock = nbt_dgram_socket_init(tctx, NULL);
	struct socket_address *dest;
	const char *myaddress;
	struct nbt_netlogon_packet logon;
	struct nbt_name myname;
	NTSTATUS status;
	struct timeval tv = timeval_current();
	int replies = 0;

	struct socket_address *socket_address;

	const char *address;
	struct nbt_name name;
	
	name.name = lp_workgroup();
	name.type = NBT_NAME_LOGON;
	name.scope = NULL;

	/* do an initial name resolution to find its IP */
	torture_assert_ntstatus_ok(tctx, 
				   resolve_name(&name, tctx, &address, event_context_find(tctx)),
				   talloc_asprintf(tctx, "Failed to resolve %s", name.name));

	myaddress = talloc_strdup(dgmsock, iface_best_ip(address));


	socket_address = socket_address_from_strings(dgmsock, dgmsock->sock->backend_name,
						     myaddress, lp_dgram_port());
	torture_assert(tctx, socket_address != NULL, "Error getting address");

	/* try receiving replies on port 138 first, which will only
	   work if we are root and smbd/nmbd are not running - fall
	   back to listening on any port, which means replies from
	   some windows versions won't be seen */
	status = socket_listen(dgmsock->sock, socket_address, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(socket_address);
		socket_address = socket_address_from_strings(dgmsock, dgmsock->sock->backend_name,
							     myaddress, 0);
		torture_assert(tctx, socket_address != NULL, "Error getting address");

		socket_listen(dgmsock->sock, socket_address, 0, 0);
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

	make_nbt_name_client(&myname, TEST_NAME);

	dest = socket_address_from_strings(dgmsock, dgmsock->sock->backend_name, 
					   address, 0);
	torture_assert(tctx, dest != NULL, "Error getting address");

	status = dgram_mailslot_netlogon_send(dgmsock, &name, dest,
					      &myname, &logon);
	torture_assert_ntstatus_ok(tctx, status, "Failed to send netlogon request");

	while (timeval_elapsed(&tv) < 5 && replies == 0) {
		event_loop_once(dgmsock->event_ctx);
	}

	return true;
}


/* test UDP/138 netlogon requests */
static bool nbt_test_netlogon2(struct torture_context *tctx)
{
	struct dgram_mailslot_handler *dgmslot;
	struct nbt_dgram_socket *dgmsock = nbt_dgram_socket_init(tctx, NULL);
	struct socket_address *dest;
	const char *myaddress;
	struct nbt_netlogon_packet logon;
	struct nbt_name myname;
	NTSTATUS status;
	struct timeval tv = timeval_current();
	int replies = 0;

	struct socket_address *socket_address;

	const char *address;
	struct nbt_name name;
	
	name.name = lp_workgroup();
	name.type = NBT_NAME_LOGON;
	name.scope = NULL;

	/* do an initial name resolution to find its IP */
	torture_assert_ntstatus_ok(tctx, 
				   resolve_name(&name, tctx, &address, event_context_find(tctx)),
				   talloc_asprintf(tctx, "Failed to resolve %s", name.name));

	myaddress = talloc_strdup(dgmsock, iface_best_ip(address));

	socket_address = socket_address_from_strings(dgmsock, dgmsock->sock->backend_name,
						     myaddress, lp_dgram_port());
	torture_assert(tctx, socket_address != NULL, "Error getting address");

	/* try receiving replies on port 138 first, which will only
	   work if we are root and smbd/nmbd are not running - fall
	   back to listening on any port, which means replies from
	   some windows versions won't be seen */
	status = socket_listen(dgmsock->sock, socket_address, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(socket_address);
		socket_address = socket_address_from_strings(dgmsock, dgmsock->sock->backend_name,
							     myaddress, 0);
		torture_assert(tctx, socket_address != NULL, "Error getting address");

		socket_listen(dgmsock->sock, socket_address, 0, 0);
	}

	/* setup a temporary mailslot listener for replies */
	dgmslot = dgram_mailslot_temp(dgmsock, NBT_MAILSLOT_GETDC,
				      netlogon_handler, &replies);
	

	ZERO_STRUCT(logon);
	logon.command = NETLOGON_QUERY_FOR_PDC2;
	logon.req.pdc2.request_count = 0;
	logon.req.pdc2.computer_name = TEST_NAME;
	logon.req.pdc2.user_name     = "";
	logon.req.pdc2.mailslot_name = dgmslot->mailslot_name;
	logon.req.pdc2.nt_version    = 11;
	logon.req.pdc2.lmnt_token    = 0xFFFF;
	logon.req.pdc2.lm20_token    = 0xFFFF;

	make_nbt_name_client(&myname, TEST_NAME);

	dest = socket_address_from_strings(dgmsock, dgmsock->sock->backend_name, 
					   address, 0);

	torture_assert(tctx, dest != NULL, "Error getting address");
	status = dgram_mailslot_netlogon_send(dgmsock, &name, dest,
					      &myname, &logon);
	torture_assert_ntstatus_ok(tctx, status, "Failed to send netlogon request");

	while (timeval_elapsed(&tv) < 5 && replies == 0) {
		event_loop_once(dgmsock->event_ctx);
	}

	return true;
}


/*
  reply handler for ntlogon request
*/
static void ntlogon_handler(struct dgram_mailslot_handler *dgmslot, 
			     struct nbt_dgram_packet *packet, 
			     struct socket_address *src)
{
	NTSTATUS status;
	struct nbt_ntlogon_packet ntlogon;
	int *replies = dgmslot->private;

	printf("ntlogon reply from %s:%d\n", src->addr, src->port);

	status = dgram_mailslot_ntlogon_parse(dgmslot, dgmslot, packet, &ntlogon);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to parse ntlogon packet from %s:%d\n",
		       src->addr, src->port);
		return;
	}

	NDR_PRINT_DEBUG(nbt_ntlogon_packet, &ntlogon);

	(*replies)++;
}


/* test UDP/138 ntlogon requests */
static bool nbt_test_ntlogon(struct torture_context *tctx)
{
	struct dgram_mailslot_handler *dgmslot;
	struct nbt_dgram_socket *dgmsock = nbt_dgram_socket_init(tctx, NULL);
	struct socket_address *dest;
	struct test_join *join_ctx;
	struct cli_credentials *machine_credentials;
	const struct dom_sid *dom_sid;

	const char *myaddress;
	struct nbt_ntlogon_packet logon;
	struct nbt_name myname;
	NTSTATUS status;
	struct timeval tv = timeval_current();
	int replies = 0;

	struct socket_address *socket_address;
	const char *address;
	struct nbt_name name;
	
	name.name = lp_workgroup();
	name.type = NBT_NAME_LOGON;
	name.scope = NULL;

	/* do an initial name resolution to find its IP */
	torture_assert_ntstatus_ok(tctx, 
				   resolve_name(&name, tctx, &address, event_context_find(tctx)),
				   talloc_asprintf(tctx, "Failed to resolve %s", name.name));

	myaddress = talloc_strdup(dgmsock, iface_best_ip(address));

	socket_address = socket_address_from_strings(dgmsock, dgmsock->sock->backend_name,
						     myaddress, lp_dgram_port());
	torture_assert(tctx, socket_address != NULL, "Error getting address");

	/* try receiving replies on port 138 first, which will only
	   work if we are root and smbd/nmbd are not running - fall
	   back to listening on any port, which means replies from
	   some windows versions won't be seen */
	status = socket_listen(dgmsock->sock, socket_address, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(socket_address);
		socket_address = socket_address_from_strings(dgmsock, dgmsock->sock->backend_name,
							     myaddress, 0);
		torture_assert(tctx, socket_address != NULL, "Error getting address");

		socket_listen(dgmsock->sock, socket_address, 0, 0);
	}

	join_ctx = torture_join_domain(TEST_NAME, 
				       ACB_WSTRUST, &machine_credentials);
	torture_assert(tctx, join_ctx != NULL,
		       talloc_asprintf(tctx, "Failed to join domain %s as %s\n",
		       		       lp_workgroup(), TEST_NAME));

	dom_sid = torture_join_sid(join_ctx);

	/* setup a temporary mailslot listener for replies */
	dgmslot = dgram_mailslot_temp(dgmsock, NBT_MAILSLOT_GETDC,
				      ntlogon_handler, &replies);
	

	ZERO_STRUCT(logon);
	logon.command = NTLOGON_SAM_LOGON;
	logon.req.logon.request_count = 0;
	logon.req.logon.computer_name = TEST_NAME;
	logon.req.logon.user_name     = TEST_NAME"$";
	logon.req.logon.mailslot_name = dgmslot->mailslot_name;
	logon.req.logon.acct_control  = ACB_WSTRUST;
	logon.req.logon.sid           = *dom_sid;
	logon.req.logon.nt_version    = 1;
	logon.req.logon.lmnt_token    = 0xFFFF;
	logon.req.logon.lm20_token    = 0xFFFF;

	make_nbt_name_client(&myname, TEST_NAME);

	dest = socket_address_from_strings(dgmsock, dgmsock->sock->backend_name, 
					   address, 0);
	torture_assert(tctx, dest != NULL, "Error getting address");
	status = dgram_mailslot_ntlogon_send(dgmsock, DGRAM_DIRECT_UNIQUE,
					     &name, dest, &myname, &logon);
	torture_assert_ntstatus_ok(tctx, status, "Failed to send ntlogon request");

	while (timeval_elapsed(&tv) < 5 && replies == 0) {
		event_loop_once(dgmsock->event_ctx);
	}

	torture_leave_domain(join_ctx);
	return true;
}


/*
  test nbt dgram operations
*/
struct torture_suite *torture_nbt_dgram(void)
{
	struct torture_suite *suite = torture_suite_create(talloc_autofree_context(), "DGRAM");

	torture_suite_add_simple_test(suite, "netlogon", nbt_test_netlogon);
	torture_suite_add_simple_test(suite, "netlogon2", nbt_test_netlogon2);
	torture_suite_add_simple_test(suite, "ntlogon", nbt_test_ntlogon);

	return suite;
}
