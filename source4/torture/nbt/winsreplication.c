/* 
   Unix SMB/CIFS implementation.

   WINS replication testing

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
#include "libcli/wins/winsrepl.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_VALUE(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d - should be %d\n", \
		       __location__, #v, v, correct); \
		ret = False; \
		goto done; \
	}} while (0)

/*
  extract a nbt_name from a name buffer
*/
static struct nbt_name *wrepl_extract_name(TALLOC_CTX *mem_ctx, 
					   uint8_t *name, uint32_t len)
{
	struct nbt_name *ret = talloc_zero(mem_ctx, struct nbt_name);

	/* oh wow, what a nasty bug in windows ... */
	if (name[0] == 0x1b && len >= 16) {
		name[0] = name[15];
		name[15] = 0x1b;
	}

	if (ret == NULL) return NULL;
	if (len < 17) {
		ret->name = talloc_strndup(ret, name, len);
	} else {
		char *s = talloc_strndup(ret, name, 15);
		trim_string(s, NULL, " ");
		ret->name = s;
		ret->type = name[15];
		if (len > 18) {
			ret->scope = talloc_strndup(ret, name+17, len-17);
		}
	}
	return ret;
}

/*
  display a replication entry
*/
static void display_entry(TALLOC_CTX *mem_ctx, struct wrepl_wins_name *wname)
{
	struct nbt_name *name = wrepl_extract_name(mem_ctx, 
						   wname->name,
						   wname->name_len);
	int i;
	printf("%s\n", nbt_name_string(mem_ctx, name));
	if (wname->flags & 2) {
		for (i=0;i<wname->addresses.addresses.num_ips;i++) {
			printf("\t%s %s\n", 
			       wname->addresses.addresses.ips[i].owner,
			       wname->addresses.addresses.ips[i].ip);
		}
	} else {
		printf("\t%s %s\n", 
		       wname->addresses.address.owner,
		       wname->addresses.address.ip);
	}
}

/*
  test a full replication dump from a WINS server
*/
static BOOL nbt_test_wins_replication(TALLOC_CTX *mem_ctx, const char *address)
{
	BOOL ret = True;
	struct wrepl_socket *wrepl_socket;
	NTSTATUS status;
	struct wrepl_packet request, *reply;
	int i, j;
	struct wrepl_table *table;

	wrepl_socket = wrepl_socket_init(mem_ctx, NULL);
	
	status = wrepl_connect(wrepl_socket, address);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Send a start association request\n");

	ZERO_STRUCT(request);
	request.opcode                      = WREPL_OPCODE_BITS;
	request.mess_type                   = WREPL_START_ASSOCIATION;
	request.message.start.minor_version = 2;
	request.message.start.major_version = 5;
	request.padding                     = data_blob_talloc_zero(mem_ctx, 0);

	status = wrepl_request(wrepl_socket, mem_ctx, &request, &reply);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(reply->mess_type, WREPL_START_ASSOCIATION_REPLY);

	request.assoc_ctx = reply->message.start_reply.assoc_ctx;
	printf("association context: 0x%x\n", request.assoc_ctx);

	printf("Send a replication table query\n");
	request.mess_type = WREPL_REPLICATION;
	request.message.replication.command = WREPL_REPL_TABLE_QUERY;

	status = wrepl_request(wrepl_socket, mem_ctx, &request, &reply);
	CHECK_STATUS(status, NT_STATUS_OK);
	if (reply->mess_type == WREPL_STOP_ASSOCIATION) {
		printf("server refused table query - reason %d\n",
		       reply->message.stop.reason);
		ret = False;
		goto done;
	}
	CHECK_VALUE(reply->mess_type, WREPL_REPLICATION);
	CHECK_VALUE(reply->message.replication.command, WREPL_REPL_TABLE_REPLY);	

	table = &reply->message.replication.info.table;

	printf("Found %d replication partners\n", table->partner_count);

	for (i=0;i<table->partner_count;i++) {
		printf("%s   max_version=%6llu   min_version=%6llu type=%d\n",
		       table->partners[i].address, 
		       table->partners[i].max_version, 
		       table->partners[i].min_version, 
		       table->partners[i].type);

		request.message.replication.command = WREPL_REPL_SEND_REQUEST;
		request.message.replication.info.owner = table->partners[i];

		status = wrepl_request(wrepl_socket, mem_ctx, &request, &reply);
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_VALUE(reply->mess_type, WREPL_REPLICATION);
		CHECK_VALUE(reply->message.replication.command, WREPL_REPL_SEND_REPLY);

		printf("Received %d names\n", 
		       reply->message.replication.info.reply.num_names);

		for (j=0;j<reply->message.replication.info.reply.num_names;j++) {
			display_entry(mem_ctx,
				      &reply->message.replication.info.reply.names[j]);
		}
	}

done:
	talloc_free(wrepl_socket);
	return ret;
}

/*
  test WINS replication operations
*/
BOOL torture_nbt_winsreplication(void)
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

	ret &= nbt_test_wins_replication(mem_ctx, address);

	talloc_free(mem_ctx);

	return ret;
}
