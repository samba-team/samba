/* 
   Unix SMB/CIFS implementation.

   NBT WINS server testing

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


/*
  test operations against a WINS server
*/
static BOOL nbt_test_wins(TALLOC_CTX *mem_ctx, struct nbt_name *name, 
			      const char *address)
{
	struct nbt_name_register_wins io;
	struct nbt_name_query query;
	struct nbt_name_refresh_wins refresh;
	struct nbt_name_release release;
	NTSTATUS status;
	struct nbt_name_socket *nbtsock = nbt_name_socket_init(mem_ctx, NULL);
	BOOL ret = True;
	const char *myaddress = talloc_strdup(mem_ctx, iface_n_ip(0));
	const char *tname = talloc_asprintf(mem_ctx, "_TORTURE-%5u", 
					  (unsigned)(random() % (100000)));

	/* we do the listen here to ensure the WINS server receives the packets from
	   the right IP */
	socket_listen(nbtsock->sock, myaddress, 0, 0, 0);

	printf("Testing name registration to WINS with name '%s' at %s\n", tname, myaddress);

	io.in.name.name = tname;
	io.in.name.type = NBT_NAME_CLIENT;
	io.in.name.scope = NULL;
	io.in.wins_servers = str_list_make(mem_ctx, address, NULL);
	io.in.addresses = str_list_make(mem_ctx, myaddress, NULL);
	io.in.nb_flags = NBT_NODE_H;
	io.in.ttl = 300000;
	
	status = nbt_name_register_wins(nbtsock, mem_ctx, &io);
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

	printf("query the name to make sure its there\n");
	query.in.name = io.in.name;
	query.in.dest_addr = address;
	query.in.broadcast = False;
	query.in.wins_lookup = True;
	query.in.timeout = 3;
	query.in.retries = 0;

	status = nbt_name_query(nbtsock, mem_ctx, &query);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name query\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name query - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_STRING(query.out.name.name, tname);
	CHECK_VALUE(query.out.name.type, NBT_NAME_CLIENT);
	CHECK_VALUE(query.out.num_addrs, 1);
	CHECK_STRING(query.out.reply_addrs[0], myaddress);

	printf("refresh the name\n");
	refresh.in.name.name = tname;
	refresh.in.name.type = NBT_NAME_CLIENT;
	refresh.in.name.scope = NULL;
	refresh.in.wins_servers = str_list_make(mem_ctx, address, NULL);
	refresh.in.addresses = str_list_make(mem_ctx, myaddress, NULL);
	refresh.in.nb_flags = NBT_NODE_H;
	refresh.in.ttl = 12345;
	
	status = nbt_name_refresh_wins(nbtsock, mem_ctx, &refresh);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name refresh\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name refresh - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_STRING(io.out.wins_server, address);
	CHECK_VALUE(io.out.rcode, 0);

	printf("release the name\n");
	release.in.name = io.in.name;
	release.in.dest_addr = address;
	release.in.address = myaddress;
	release.in.nb_flags = NBT_NODE_H;
	release.in.broadcast = False;
	release.in.timeout = 3;
	release.in.retries = 0;

	status = nbt_name_release(nbtsock, mem_ctx, &release);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name release\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name query - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_STRING(release.out.name.name, tname);
	CHECK_VALUE(release.out.name.type, NBT_NAME_CLIENT);
	CHECK_VALUE(release.out.rcode, 0);

	printf("release again\n");
	status = nbt_name_release(nbtsock, mem_ctx, &release);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name release\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name query - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_STRING(release.out.name.name, tname);
	CHECK_VALUE(release.out.name.type, NBT_NAME_CLIENT);
	CHECK_VALUE(release.out.rcode, 0);


	printf("query the name to make sure its gone\n");
	status = nbt_name_query(nbtsock, mem_ctx, &query);
	if (NT_STATUS_IS_OK(status)) {
		printf("ERROR: Name query success after release\n");
		return False;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		printf("Incorrect response to name query - %s\n", nt_errstr(status));
		return False;
	}
	
	return ret;
}


/*
  test WINS operations
*/
BOOL torture_nbt_wins(void)
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

	ret &= nbt_test_wins(mem_ctx, &name, address);

	talloc_free(mem_ctx);

	return ret;
}
