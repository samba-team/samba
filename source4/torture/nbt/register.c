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
#include "libcli/nbt/libnbt.h"
#include "librpc/gen_ndr/ndr_nbt.h"

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d - should be %d\n", \
		       __location__, #v, v, correct); \
		ret = False; \
	}} while (0)

#define CHECK_STRING(v, correct) do { \
	if (StrCaseCmp(v, correct) != 0) { \
		printf("(%s) Incorrect value %s='%s' - should be '%s'\n", \
		       __location__, #v, v, correct); \
		ret = False; \
	}} while (0)

#define BOGUS_ADDRESS1 "255.255.255.254"
#define BOGUS_ADDRESS2 "255.255.255.253"

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

	printf("Testing name defense to name registration\n");

	io.in.name = *name;
	io.in.dest_addr = address;
	io.in.address = BOGUS_ADDRESS1;
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
	io.in.address = BOGUS_ADDRESS2;
	io.in.register_demand = True;

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

	printf("Testing name defense to name refresh\n");

	io.in.name = *name;
	io.in.dest_addr = address;
	io.in.address = BOGUS_ADDRESS1;
	io.in.nb_flags = NBT_NODE_B | NBT_NM_ACTIVE;
	io.in.broadcast = True;
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
  register names with a WINS server
*/
static BOOL nbt_register_wins(TALLOC_CTX *mem_ctx, struct nbt_name *name, 
			      const char *address)
{
	struct nbt_name_refresh_wins io;
	struct nbt_name_query q;
	NTSTATUS status;
	struct nbt_name_socket *nbtsock = nbt_name_socket_init(mem_ctx, NULL);
	BOOL ret = True;

	printf("Testing name registration to WINS\n");

	io.in.name.name = talloc_asprintf(mem_ctx, "_TORTURE-%5u", 
					  (unsigned)(random() % (100000)));
	io.in.name.type = NBT_NAME_CLIENT;
	io.in.name.scope = NULL;
	io.in.wins_servers = str_list_make(mem_ctx, address, NULL);
	io.in.addresses = str_list_make(mem_ctx, BOGUS_ADDRESS1, NULL);
	io.in.nb_flags = NBT_NODE_M | NBT_NM_ACTIVE;
	io.in.ttl = 12345;
	
	status = nbt_name_refresh_wins(nbtsock, mem_ctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name register\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name register - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_STRING(io.out.wins_server, address);
	CHECK_VALUE(io.out.rcode, 0);

	/* query the name to make sure its there */
	q.in.name = io.in.name;
	q.in.dest_addr = address;
	q.in.broadcast = False;
	q.in.wins_lookup = True;
	q.in.timeout = 3;
	q.in.retries = 0;

	status = nbt_name_query(nbtsock, mem_ctx, &q);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name query\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name query - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_STRING(q.out.name.name, q.in.name.name);
	CHECK_VALUE(q.out.name.type, q.in.name.type);
	CHECK_VALUE(q.out.num_addrs, 1);
	CHECK_STRING(q.out.reply_addrs[0], BOGUS_ADDRESS1);

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
	
	name.name = lp_parm_string(-1, "torture", "host");
	name.type = NBT_NAME_SERVER;
	name.scope = NULL;

	/* do an initial name resolution to find its IP */
	status = resolve_name(&name, mem_ctx, &address);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to resolve %s - %s\n",
		       name.name, nt_errstr(status));
		talloc_free(mem_ctx);
		return False;
	}

	ret &= nbt_register_own(mem_ctx, &name, address);
	ret &= nbt_refresh_own(mem_ctx, &name, address);
	ret &= nbt_register_wins(mem_ctx, &name, address);

	talloc_free(mem_ctx);

	return ret;
}
