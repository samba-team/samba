/* 
   Unix SMB/CIFS implementation.

   NBT name registration testing

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
#include "lib/socket/socket.h"
#include "libcli/resolve/resolve.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "torture/torture.h"
#include "torture/nbt/proto.h"

#define CHECK_VALUE(tctx, v, correct) \
	torture_assert_int_equal(tctx, v, correct, "Incorrect value")

#define CHECK_STRING(tctx, v, correct) \
	torture_assert_casestr_equal(tctx, v, correct, "Incorrect value")




/*
  test that a server responds correctly to attempted registrations of its name
*/
static bool nbt_register_own(struct torture_context *tctx)
{
	struct nbt_name_register io;
	NTSTATUS status;
	struct nbt_name_socket *nbtsock = nbt_name_socket_init(tctx, NULL);
	struct socket_address *socket_address;
	struct nbt_name name;
	const char *address;
	const char *myaddress;

	if (!torture_nbt_get_name(tctx, &name, &address))
		return false;

	myaddress = iface_best_ip(address);

	socket_address = socket_address_from_strings(tctx, nbtsock->sock->backend_name,
						     myaddress, 0);
	torture_assert(tctx, socket_address != NULL, "Unable to get address");

	status = socket_listen(nbtsock->sock, socket_address, 0, 0);
	torture_assert_ntstatus_ok(tctx, status, 
				"socket_listen for nbt_register_own failed");

	torture_comment(tctx, "Testing name defense to name registration\n");

	io.in.name = name;
	io.in.dest_addr = address;
	io.in.address = myaddress;
	io.in.nb_flags = NBT_NODE_B | NBT_NM_ACTIVE;
	io.in.register_demand = False;
	io.in.broadcast = True;
	io.in.multi_homed = False;
	io.in.ttl = 1234;
	io.in.timeout = 3;
	io.in.retries = 0;
	
	status = nbt_name_register(nbtsock, tctx, &io);
	torture_assert_ntstatus_ok(tctx, status, 
				talloc_asprintf(tctx, "Bad response from %s for name register",
		       address));
	
	CHECK_STRING(tctx, io.out.name.name, name.name);
	CHECK_VALUE(tctx, io.out.name.type, name.type);
	CHECK_VALUE(tctx, io.out.rcode, NBT_RCODE_ACT);

	/* check a register demand */
	io.in.address = myaddress;
	io.in.register_demand = True;

	status = nbt_name_register(nbtsock, tctx, &io);

	torture_assert_ntstatus_ok(tctx, status, 
				talloc_asprintf(tctx, "Bad response from %s for name register demand", address));
	
	CHECK_STRING(tctx, io.out.name.name, name.name);
	CHECK_VALUE(tctx, io.out.name.type, name.type);
	CHECK_VALUE(tctx, io.out.rcode, NBT_RCODE_ACT);

	return true;
}


/*
  test that a server responds correctly to attempted name refresh requests
*/
static bool nbt_refresh_own(struct torture_context *tctx)
{
	struct nbt_name_refresh io;
	NTSTATUS status;
	struct nbt_name_socket *nbtsock = nbt_name_socket_init(tctx, NULL);
	const char *myaddress;
	struct socket_address *socket_address;
	struct nbt_name name;
	const char *address;

	if (!torture_nbt_get_name(tctx, &name, &address))
		return false;
	
	myaddress = iface_best_ip(address);

	socket_address = socket_address_from_strings(tctx, nbtsock->sock->backend_name,
						     myaddress, 0);
	torture_assert(tctx, socket_address != NULL, 
				   "Can't parse socket address");

	status = socket_listen(nbtsock->sock, socket_address, 0, 0);
	torture_assert_ntstatus_ok(tctx, status, 
							   "socket_listen for nbt_referesh_own failed");

	torture_comment(tctx, "Testing name defense to name refresh\n");

	io.in.name = name;
	io.in.dest_addr = address;
	io.in.address = myaddress;
	io.in.nb_flags = NBT_NODE_B | NBT_NM_ACTIVE;
	io.in.broadcast = False;
	io.in.ttl = 1234;
	io.in.timeout = 3;
	io.in.retries = 0;
	
	status = nbt_name_refresh(nbtsock, tctx, &io);

	torture_assert_ntstatus_ok(tctx, status, 
				talloc_asprintf(tctx, "Bad response from %s for name refresh", address));
	
	CHECK_STRING(tctx, io.out.name.name, name.name);
	CHECK_VALUE(tctx, io.out.name.type, name.type);
	CHECK_VALUE(tctx, io.out.rcode, NBT_RCODE_ACT);

	return true;
}


/*
  test name registration to a server
*/
struct torture_suite *torture_nbt_register(void)
{
	struct torture_suite *suite;

	suite = torture_suite_create(talloc_autofree_context(), "REGISTER");
	torture_suite_add_simple_test(suite, "register_own", nbt_register_own);
	torture_suite_add_simple_test(suite, "refresh_own", nbt_refresh_own);

	return suite;
}
