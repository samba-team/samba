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
#include "netif/netif.h"

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d - should be %d\n", \
		       __location__, #v, (int)v, (int)correct); \
		ret = False; \
	}} while (0)

#define CHECK_STRING(v, correct) do { \
	if (strcasecmp_m(v, correct) != 0) { \
		printf("(%s) Incorrect value %s='%s' - should be '%s'\n", \
		       __location__, #v, v, correct); \
		ret = False; \
	}} while (0)

/*
  test that a server responds correctly to attempted registrations of its name
*/
static BOOL nbt_register_own(TALLOC_CTX *mem_ctx, struct nbt_name *name, 
			     const char *address)
{
	struct nbt_name_register io;
	NTSTATUS status;
	struct nbt_name_socket *nbtsock = nbt_name_socket_init(mem_ctx, NULL);
	BOOL ret = True;
	const char *myaddress = iface_best_ip(address);
	struct socket_address *socket_address;

	socket_address = socket_address_from_strings(mem_ctx, nbtsock->sock->backend_name,
						     myaddress, 0);
	if (!socket_address) {
		return False;
	}

	status = socket_listen(nbtsock->sock, socket_address, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("socket_listen for nbt_register_own failed: %s\n", nt_errstr(status));
		return False;
	}

	printf("Testing name defense to name registration\n");

	io.in.name = *name;
	io.in.dest_addr = address;
	io.in.address = myaddress;
	io.in.nb_flags = NBT_NODE_B | NBT_NM_ACTIVE;
	io.in.register_demand = False;
	io.in.broadcast = True;
	io.in.multi_homed = False;
	io.in.ttl = 1234;
	io.in.timeout = 3;
	io.in.retries = 0;
	
	status = nbt_name_register(nbtsock, mem_ctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name register\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name register - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_STRING(io.out.name.name, name->name);
	CHECK_VALUE(io.out.name.type, name->type);
	CHECK_VALUE(io.out.rcode, NBT_RCODE_ACT);

	/* check a register demand */
	io.in.address = myaddress;
	io.in.register_demand = True;

	status = nbt_name_register(nbtsock, mem_ctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name register demand\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name register demand - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_STRING(io.out.name.name, name->name);
	CHECK_VALUE(io.out.name.type, name->type);
	CHECK_VALUE(io.out.rcode, NBT_RCODE_ACT);

	return ret;
}


/*
  test that a server responds correctly to attempted name refresh requests
*/
static BOOL nbt_refresh_own(TALLOC_CTX *mem_ctx, struct nbt_name *name, 
			    const char *address)
{
	struct nbt_name_refresh io;
	NTSTATUS status;
	struct nbt_name_socket *nbtsock = nbt_name_socket_init(mem_ctx, NULL);
	BOOL ret = True;
	const char *myaddress = iface_best_ip(address);
	struct socket_address *socket_address;

	socket_address = socket_address_from_strings(mem_ctx, nbtsock->sock->backend_name,
						     myaddress, 0);
	if (!socket_address) {
		return False;
	}

	status = socket_listen(nbtsock->sock, socket_address, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		printf("socket_listen for nbt_referesh_own failed: %s\n", nt_errstr(status));
		return False;
	}

	printf("Testing name defense to name refresh\n");

	io.in.name = *name;
	io.in.dest_addr = address;
	io.in.address = myaddress;
	io.in.nb_flags = NBT_NODE_B | NBT_NM_ACTIVE;
	io.in.broadcast = False;
	io.in.ttl = 1234;
	io.in.timeout = 3;
	io.in.retries = 0;
	
	status = nbt_name_refresh(nbtsock, mem_ctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name refresh\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name refresh - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_STRING(io.out.name.name, name->name);
	CHECK_VALUE(io.out.name.type, name->type);
	CHECK_VALUE(io.out.rcode, NBT_RCODE_ACT);

	return ret;
}



/*
  test name registration to a server
*/
BOOL torture_nbt_register(void)
{
	const char *address;
	struct nbt_name name;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	NTSTATUS status;
	BOOL ret = True;
	
	make_nbt_name_server(&name, strupper_talloc(mem_ctx, lp_parm_string(-1, "torture", "host")));

	/* do an initial name resolution to find its IP */
	status = resolve_name(&name, mem_ctx, &address, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to resolve %s - %s\n",
		       name.name, nt_errstr(status));
		talloc_free(mem_ctx);
		return False;
	}

	ret &= nbt_register_own(mem_ctx, &name, address);
	ret &= nbt_refresh_own(mem_ctx, &name, address);

	talloc_free(mem_ctx);

	return ret;
}
