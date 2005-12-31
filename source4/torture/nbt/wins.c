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
#include "lib/socket/socket.h"

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d (0x%X) - should be %d (0x%X)\n", \
		       __location__, #v, v, v, correct, correct); \
		ret = False; \
	}} while (0)

#define CHECK_STRING(v, correct) do { \
	if ((v) != (correct) && \
	    ((v)==NULL || (correct)==NULL || strcasecmp_m(v, correct) != 0)) { \
		printf("(%s) Incorrect value %s='%s' - should be '%s'\n", \
		       __location__, #v, v, correct); \
		ret = False; \
	}} while (0)

#define CHECK_NAME(_name, correct) do { \
	CHECK_STRING((_name).name, (correct).name); \
	CHECK_VALUE((uint8_t)(_name).type, (uint8_t)(correct).type); \
	CHECK_STRING((_name).scope, (correct).scope); \
} while (0)


/*
  test operations against a WINS server
*/
static BOOL nbt_test_wins_name(TALLOC_CTX *mem_ctx, const char *address,
			       struct nbt_name *name, uint16_t nb_flags)
{
	struct nbt_name_register_wins io;
	struct nbt_name_query query;
	struct nbt_name_refresh_wins refresh;
	struct nbt_name_release release;
	NTSTATUS status;
	struct nbt_name_socket *nbtsock = nbt_name_socket_init(mem_ctx, NULL);
	BOOL ret = True;
	const char *myaddress = talloc_strdup(mem_ctx, iface_best_ip(address));

	/* we do the listen here to ensure the WINS server receives the packets from
	   the right IP */
	socket_listen(nbtsock->sock, myaddress, 0, 0, 0);

	printf("Testing name registration to WINS with name %s at %s nb_flags=0x%x\n", 
	       nbt_name_string(mem_ctx, name), myaddress, nb_flags);

	printf("release the name\n");
	release.in.name = *name;
	release.in.dest_addr = address;
	release.in.address = myaddress;
	release.in.nb_flags = nb_flags;
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
	CHECK_VALUE(release.out.rcode, 0);

	printf("register the name\n");
	io.in.name = *name;
	io.in.wins_servers = str_list_make(mem_ctx, address, NULL);
	io.in.addresses = str_list_make(mem_ctx, myaddress, NULL);
	io.in.nb_flags = nb_flags;
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

	if (name->type != NBT_NAME_MASTER &&
	    name->type != NBT_NAME_LOGON && 
	    name->type != NBT_NAME_BROWSER && 
	    (nb_flags & NBT_NM_GROUP)) {
		printf("Try to register as non-group\n");
		io.in.nb_flags &= ~NBT_NM_GROUP;
		status = nbt_name_register_wins(nbtsock, mem_ctx, &io);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Bad response from %s for name register - %s\n",
			       address, nt_errstr(status));
			return False;
		}
		CHECK_VALUE(io.out.rcode, NBT_RCODE_ACT);
	}

	printf("query the name to make sure its there\n");
	query.in.name = *name;
	query.in.dest_addr = address;
	query.in.broadcast = False;
	query.in.wins_lookup = True;
	query.in.timeout = 3;
	query.in.retries = 0;

	status = nbt_name_query(nbtsock, mem_ctx, &query);
	if (name->type == NBT_NAME_MASTER) {
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			printf("Bad response from %s for name query - %s\n",
			       address, nt_errstr(status));
			return False;
		}
		return ret;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		printf("No response from %s for name query\n", address);
		return False;
	}
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad response from %s for name query - %s\n",
		       address, nt_errstr(status));
		return False;
	}
	
	CHECK_NAME(query.out.name, *name);
	CHECK_VALUE(query.out.num_addrs, 1);
	if (name->type != NBT_NAME_LOGON &&
	    (nb_flags & NBT_NM_GROUP)) {
		CHECK_STRING(query.out.reply_addrs[0], "255.255.255.255");
	} else {
		CHECK_STRING(query.out.reply_addrs[0], myaddress);
	}


	query.in.name.name = strupper_talloc(mem_ctx, name->name);
	if (query.in.name.name &&
	    strcmp(query.in.name.name, name->name) != 0) {
		printf("check case sensitivity\n");
		status = nbt_name_query(nbtsock, mem_ctx, &query);
		if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
			printf("No response from %s for name query\n", address);
			return False;
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			printf("Bad response from %s for name query - %s\n",
			       address, nt_errstr(status));
			return False;
		}
	}

	query.in.name = *name;
	if (name->scope) {
		query.in.name.scope = strupper_talloc(mem_ctx, name->scope);
	}
	if (query.in.name.scope &&
	    strcmp(query.in.name.scope, name->scope) != 0) {
		printf("check case sensitivity on scope\n");
		status = nbt_name_query(nbtsock, mem_ctx, &query);
		if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
			printf("No response from %s for name query\n", address);
			return False;
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			printf("Bad response from %s for name query - %s\n",
			       address, nt_errstr(status));
			return False;
		}
	}

	printf("refresh the name\n");
	refresh.in.name = *name;
	refresh.in.wins_servers = str_list_make(mem_ctx, address, NULL);
	refresh.in.addresses = str_list_make(mem_ctx, myaddress, NULL);
	refresh.in.nb_flags = nb_flags;
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
	
	CHECK_STRING(refresh.out.wins_server, address);
	CHECK_VALUE(refresh.out.rcode, 0);

	printf("release the name\n");
	release.in.name = *name;
	release.in.dest_addr = address;
	release.in.address = myaddress;
	release.in.nb_flags = nb_flags;
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
	
	CHECK_NAME(release.out.name, *name);
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
	
	CHECK_NAME(release.out.name, *name);
	CHECK_VALUE(release.out.rcode, 0);


	printf("query the name to make sure its gone\n");
	query.in.name = *name;
	status = nbt_name_query(nbtsock, mem_ctx, &query);
	if (name->type != NBT_NAME_LOGON &&
	    (nb_flags & NBT_NM_GROUP)) {
		if (!NT_STATUS_IS_OK(status)) {
			printf("ERROR: Name query failed after group release - %s\n",
			       nt_errstr(status));
			return False;
		}
	} else {
		if (NT_STATUS_IS_OK(status)) {
			printf("ERROR: Name query success after release\n");
			return False;
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			printf("Incorrect response to name query - %s\n", nt_errstr(status));
			return False;
		}
	}
	
	return ret;
}



/*
  test operations against a WINS server
*/
static BOOL nbt_test_wins(TALLOC_CTX *mem_ctx, const char *address)
{
	struct nbt_name name;
	BOOL ret = True;
	uint32_t r = (uint32_t)(random() % (100000));

	name.name = talloc_asprintf(mem_ctx, "_TORTURE-%5u", r);

	name.type = NBT_NAME_CLIENT;
	name.scope = NULL;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.type = NBT_NAME_MASTER;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H | NBT_NM_GROUP);

	name.type = NBT_NAME_SERVER;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.type = NBT_NAME_LOGON;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H | NBT_NM_GROUP);

	name.type = NBT_NAME_BROWSER;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H | NBT_NM_GROUP);

	name.type = NBT_NAME_PDC;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.type = 0xBF;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.type = 0xBE;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.scope = "example";
	name.type = 0x72;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.scope = "example";
	name.type = 0x71;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H | NBT_NM_GROUP);

	name.scope = "foo.example.com";
	name.type = 0x72;
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.name = talloc_asprintf(mem_ctx, "_T\01-%5u.foo", r);
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.name = "";
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.name = talloc_asprintf(mem_ctx, ".");
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

	name.name = talloc_asprintf(mem_ctx, "%5u-\377\200\300FOO", r);
	ret &= nbt_test_wins_name(mem_ctx, address, &name, NBT_NODE_H);

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
	
	make_nbt_name_server(&name, lp_parm_string(-1, "torture", "host"));

	/* do an initial name resolution to find its IP */
	status = resolve_name(&name, mem_ctx, &address, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to resolve %s - %s\n",
		       name.name, nt_errstr(status));
		talloc_free(mem_ctx);
		return False;
	}

	ret &= nbt_test_wins(mem_ctx, address);

	talloc_free(mem_ctx);

	return ret;
}
