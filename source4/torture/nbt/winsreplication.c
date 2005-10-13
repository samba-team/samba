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
#include "libcli/wrepl/winsrepl.h"

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
  test how assoc_ctx's are only usable on the connection
  they are created on.
*/
static BOOL test_assoc_ctx1(TALLOC_CTX *mem_ctx, const char *address)
{
	BOOL ret = True;
	struct wrepl_request *req;
	struct wrepl_socket *wrepl_socket1;
	struct wrepl_associate associate1;
	struct wrepl_socket *wrepl_socket2;
	struct wrepl_associate associate2;
	struct wrepl_pull_table pull_table;
	struct wrepl_packet *rep_packet;
	struct wrepl_associate_stop assoc_stop;
	NTSTATUS status;

	if (!lp_parm_bool(-1, "torture", "dangerous", False)) {
		printf("winsrepl: cross connection assoc_ctx usage disabled - enable dangerous tests to use\n");
		return True;
	}

	printf("Test if assoc_ctx is only valid on the conection it was created on\n");

	wrepl_socket1 = wrepl_socket_init(mem_ctx, NULL);
	wrepl_socket2 = wrepl_socket_init(mem_ctx, NULL);

	printf("Setup 2 wrepl connections\n");
	status = wrepl_connect(wrepl_socket1, NULL, address);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = wrepl_connect(wrepl_socket2, NULL, address);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Send a start association request (conn1)\n");
	status = wrepl_associate(wrepl_socket1, &associate1);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("association context (conn1): 0x%x\n", associate1.out.assoc_ctx);

	printf("Send a start association request (conn2)\n");
	status = wrepl_associate(wrepl_socket2, &associate2);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("association context (conn2): 0x%x\n", associate2.out.assoc_ctx);

	printf("Send a replication table query, with assoc 1 (conn2), the anwser should be on conn1\n");
	pull_table.in.assoc_ctx = associate1.out.assoc_ctx;
	req = wrepl_pull_table_send(wrepl_socket2, &pull_table);
	req->send_only = True;
	status = wrepl_request_recv(req, mem_ctx, &rep_packet);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Send a association request (conn2), to make sure the last request was ignored\n");
	status = wrepl_associate(wrepl_socket2, &associate2);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Send a replication table query, with invalid assoc (conn1), receive answer from conn2\n");
	pull_table.in.assoc_ctx = 0;
	req = wrepl_pull_table_send(wrepl_socket1, &pull_table);
	status = wrepl_request_recv(req, mem_ctx, &rep_packet);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Send a association request (conn1), to make sure the last request was handled correct\n");
	status = wrepl_associate(wrepl_socket1, &associate2);
	CHECK_STATUS(status, NT_STATUS_OK);

	assoc_stop.in.assoc_ctx	= associate1.out.assoc_ctx;
	assoc_stop.in.reason	= 4;
	printf("Send a association stop request (conn1), reson: %u\n", assoc_stop.in.reason);
	status = wrepl_associate_stop(wrepl_socket1, &assoc_stop);
	CHECK_STATUS(status, NT_STATUS_END_OF_FILE);

	assoc_stop.in.assoc_ctx	= associate2.out.assoc_ctx;
	assoc_stop.in.reason	= 0;
	printf("Send a association stop request (conn2), reson: %u\n", assoc_stop.in.reason);
	status = wrepl_associate_stop(wrepl_socket2, &assoc_stop);
	CHECK_STATUS(status, NT_STATUS_OK);

done:
	printf("Close 2 wrepl connections\n");
	talloc_free(wrepl_socket1);
	talloc_free(wrepl_socket2);
	return ret;
}

/*
  test if we always get back the same assoc_ctx
*/
static BOOL test_assoc_ctx2(TALLOC_CTX *mem_ctx, const char *address)
{
	BOOL ret = True;
	struct wrepl_socket *wrepl_socket;
	struct wrepl_associate associate;
	uint32_t assoc_ctx1;
	NTSTATUS status;

	printf("Test if we always get back the same assoc_ctx\n");

	wrepl_socket = wrepl_socket_init(mem_ctx, NULL);
	
	printf("Setup wrepl connections\n");
	status = wrepl_connect(wrepl_socket, NULL, address);
	CHECK_STATUS(status, NT_STATUS_OK);


	printf("Send 1st start association request\n");
	status = wrepl_associate(wrepl_socket, &associate);
	CHECK_STATUS(status, NT_STATUS_OK);
	assoc_ctx1 = associate.out.assoc_ctx;
	printf("1st association context: 0x%x\n", associate.out.assoc_ctx);

	printf("Send 2nd start association request\n");
	status = wrepl_associate(wrepl_socket, &associate);
	CHECK_VALUE(associate.out.assoc_ctx, assoc_ctx1);
	CHECK_STATUS(status, NT_STATUS_OK);
	printf("2nd association context: 0x%x\n", associate.out.assoc_ctx);

	printf("Send 3rd start association request\n");
	status = wrepl_associate(wrepl_socket, &associate);
	CHECK_VALUE(associate.out.assoc_ctx, assoc_ctx1);
	CHECK_STATUS(status, NT_STATUS_OK);
	printf("3rd association context: 0x%x\n", associate.out.assoc_ctx);

done:
	printf("Close wrepl connections\n");
	talloc_free(wrepl_socket);
	return ret;
}


/*
  display a replication entry
*/
static void display_entry(TALLOC_CTX *mem_ctx, struct wrepl_name *name)
{
	int i;

	printf("%s\n", nbt_name_string(mem_ctx, &name->name));
	printf("\tTYPE:%u STATE:%u NODE:%u STATIC:%u VERSION_ID: %llu\n",
		name->type, name->state, name->node, name->is_static, name->version_id);
	printf("\tRAW_FLAGS: 0x%08X OWNER: %-15s\n",
		name->raw_flags, name->owner);
	for (i=0;i<name->num_addresses;i++) {
		printf("\tADDR: %-15s OWNER: %-15s\n", 
			name->addresses[i].address, name->addresses[i].owner);
	}
}

/*
  test a full replication dump from a WINS server
*/
static BOOL test_wins_replication(TALLOC_CTX *mem_ctx, const char *address)
{
	BOOL ret = True;
	struct wrepl_socket *wrepl_socket;
	NTSTATUS status;
	int i, j;
	struct wrepl_associate associate;
	struct wrepl_pull_table pull_table;
	struct wrepl_pull_names pull_names;

	printf("Test one pull replication cycle\n");

	wrepl_socket = wrepl_socket_init(mem_ctx, NULL);
	
	printf("Setup wrepl connections\n");
	status = wrepl_connect(wrepl_socket, NULL, address);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Send a start association request\n");

	status = wrepl_associate(wrepl_socket, &associate);
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("association context: 0x%x\n", associate.out.assoc_ctx);

	printf("Send a replication table query\n");
	pull_table.in.assoc_ctx = associate.out.assoc_ctx;

	status = wrepl_pull_table(wrepl_socket, mem_ctx, &pull_table);
	if (NT_STATUS_EQUAL(NT_STATUS_NETWORK_ACCESS_DENIED,status)) {
		struct wrepl_packet packet;
		struct wrepl_request *req;

		ZERO_STRUCT(packet);
		packet.opcode                      = WREPL_OPCODE_BITS;
		packet.assoc_ctx                   = associate.out.assoc_ctx;
		packet.mess_type                   = WREPL_STOP_ASSOCIATION;
		packet.message.stop.reason         = 0;

		req = wrepl_request_send(wrepl_socket, &packet);
		talloc_free(req);

		printf("failed - We are not a valid pull partner for the server\n");
		ret = False;
		goto done;
	}
	CHECK_STATUS(status, NT_STATUS_OK);

	printf("Found %d replication partners\n", pull_table.out.num_partners);

	for (i=0;i<pull_table.out.num_partners;i++) {
		struct wrepl_wins_owner *partner = &pull_table.out.partners[i];
		printf("%s   max_version=%6llu   min_version=%6llu type=%d\n",
		       partner->address, 
		       partner->max_version, 
		       partner->min_version, 
		       partner->type);

		pull_names.in.assoc_ctx = associate.out.assoc_ctx;
		pull_names.in.partner = *partner;
		
		status = wrepl_pull_names(wrepl_socket, mem_ctx, &pull_names);
		CHECK_STATUS(status, NT_STATUS_OK);

		printf("Received %d names\n", pull_names.out.num_names);

		for (j=0;j<pull_names.out.num_names;j++) {
			display_entry(mem_ctx, &pull_names.out.names[j]);
		}
	}

done:
	printf("Close wrepl connections\n");
	talloc_free(wrepl_socket);
	return ret;
}

struct test_wrepl_conflict_conn {
	const char *address;
	struct wrepl_socket *pull;
	uint32_t pull_assoc;

#define TEST_OWNER_A_ADDRESS "127.65.65.1"
#define TEST_ADDRESS_A_PREFIX "127.0.65"
#define TEST_OWNER_B_ADDRESS "127.66.66.1"
#define TEST_ADDRESS_B_PREFIX "127.0.66"

	struct wrepl_wins_owner a, b;
};

static const struct wrepl_ip addresses_A_1[] = {
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".1"
	}
};
static const struct wrepl_ip addresses_A_2[] = {
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".2"
	}
};

static struct test_wrepl_conflict_conn *test_create_conflict_ctx(TALLOC_CTX *mem_ctx,
								 const char *address)
{
	struct test_wrepl_conflict_conn *ctx;
	struct wrepl_associate associate;
	struct wrepl_pull_table pull_table;
	NTSTATUS status;
	uint32_t i;

	ctx = talloc_zero(mem_ctx, struct test_wrepl_conflict_conn);
	if (!ctx) return NULL;

	ctx->address	= address;
	ctx->pull	= wrepl_socket_init(ctx, NULL);
	if (!ctx->pull) return NULL;

	printf("Setup wrepl conflict pull connection\n");
	status = wrepl_connect(ctx->pull, NULL, ctx->address);
	if (!NT_STATUS_IS_OK(status)) return NULL;

	status = wrepl_associate(ctx->pull, &associate);
	if (!NT_STATUS_IS_OK(status)) return NULL;

	ctx->pull_assoc = associate.out.assoc_ctx;

	ctx->a.address		= TEST_OWNER_A_ADDRESS;
	ctx->a.max_version	= 0;
	ctx->a.min_version	= 0;
	ctx->a.type		= 1;

	ctx->b.address		= TEST_OWNER_B_ADDRESS;
	ctx->b.max_version	= 0;
	ctx->b.min_version	= 0;
	ctx->b.type		= 1;

	pull_table.in.assoc_ctx	= ctx->pull_assoc;
	status = wrepl_pull_table(ctx->pull, ctx->pull, &pull_table);
	if (!NT_STATUS_IS_OK(status)) return NULL;

	for (i=0; i < pull_table.out.num_partners; i++) {
		if (strcmp(TEST_OWNER_A_ADDRESS,pull_table.out.partners[i].address)==0) {
			ctx->a.max_version	= pull_table.out.partners[i].max_version;
			ctx->a.min_version	= pull_table.out.partners[i].min_version;
		}
		if (strcmp(TEST_OWNER_B_ADDRESS,pull_table.out.partners[i].address)==0) {
			ctx->b.max_version	= pull_table.out.partners[i].max_version;
			ctx->b.min_version	= pull_table.out.partners[i].min_version;		
		}
	}

	talloc_free(pull_table.out.partners);

	return ctx;
}

static BOOL test_wrepl_update_one_A(struct test_wrepl_conflict_conn *ctx,
				    const struct wrepl_wins_name *name)
{
	BOOL ret = True;
	struct wrepl_socket *wrepl_socket;
	struct wrepl_associate associate;
	struct wrepl_packet update_packet, repl_send;
	struct wrepl_table *update;
	struct wrepl_wins_owner wrepl_wins_owners[1];
	struct wrepl_packet *repl_recv;
	struct wrepl_wins_owner *send_request;
	struct wrepl_send_reply *send_reply;
	struct wrepl_wins_name wrepl_wins_names[1];
	uint32_t assoc_ctx;
	NTSTATUS status;

	wrepl_socket = wrepl_socket_init(ctx, NULL);

	status = wrepl_connect(wrepl_socket, NULL, ctx->address);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = wrepl_associate(wrepl_socket, &associate);
	CHECK_STATUS(status, NT_STATUS_OK);
	assoc_ctx = associate.out.assoc_ctx;

	/* now send a WREPL_REPL_UPDATE message */
	ZERO_STRUCT(update_packet);
	update_packet.opcode			= WREPL_OPCODE_BITS;
	update_packet.assoc_ctx			= assoc_ctx;
	update_packet.mess_type			= WREPL_REPLICATION;
	update_packet.message.replication.command	= WREPL_REPL_UPDATE;
	update	= &update_packet.message.replication.info.table;

	update->partner_count	= ARRAY_SIZE(wrepl_wins_owners);
	update->partners	= wrepl_wins_owners;
	update->initiator	= "0.0.0.0";

	wrepl_wins_owners[0]	= ctx->a;

	status = wrepl_request(wrepl_socket, wrepl_socket,
			       &update_packet, &repl_recv);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(repl_recv->mess_type, WREPL_REPLICATION);
	CHECK_VALUE(repl_recv->message.replication.command, WREPL_REPL_SEND_REQUEST);
	send_request = &repl_recv->message.replication.info.owner;

	ZERO_STRUCT(repl_send);
	repl_send.opcode			= WREPL_OPCODE_BITS;
	repl_send.assoc_ctx			= assoc_ctx;
	repl_send.mess_type			= WREPL_REPLICATION;
	repl_send.message.replication.command	= WREPL_REPL_SEND_REPLY;
	send_reply = &repl_send.message.replication.info.reply;

	send_reply->num_names	= ARRAY_SIZE(wrepl_wins_names);
	send_reply->names	= wrepl_wins_names;

	wrepl_wins_names[0]	= *name;

	status = wrepl_request(wrepl_socket, wrepl_socket,
			       &repl_send, &repl_recv);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(repl_recv->mess_type, WREPL_STOP_ASSOCIATION);
	CHECK_VALUE(repl_recv->message.stop.reason, 0);

done:
	talloc_free(wrepl_socket);
	return ret;
}

static BOOL test_wrepl_is_applied_A(struct test_wrepl_conflict_conn *ctx,
				    const struct wrepl_wins_name *name)
{
	BOOL ret = True;
	NTSTATUS status;
	struct wrepl_pull_names pull_names;

	ctx->a.min_version	= ctx->a.max_version;

	pull_names.in.assoc_ctx	= ctx->pull_assoc;
	pull_names.in.partner	= ctx->a;
		
	status = wrepl_pull_names(ctx->pull, ctx->pull, &pull_names);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(pull_names.out.num_names, 1);

done:
	talloc_free(pull_names.out.names);
	return ret;
}

static BOOL test_conflict_same_owner(struct test_wrepl_conflict_conn *ctx)
{
	BOOL ret = True;
	struct nbt_name	name;
	struct wrepl_wins_name wins_name1;
	struct wrepl_wins_name wins_name2;
	struct wrepl_wins_name *wins_name_tmp;
	struct wrepl_wins_name *wins_name_last;
	struct wrepl_wins_name *wins_name_cur;
	uint32_t i,j;
	uint8_t types[] = { 0x00, 0x1C };
	struct {
		enum wrepl_name_type type;
		enum wrepl_name_state state;
		enum wrepl_name_node node;
		BOOL is_static;
		uint32_t num_ips;
		const struct wrepl_ip *ips;
	} records[] = {
		{
		.type		= WREPL_TYPE_GROUP,
		.state		= WREPL_STATE_ACTIVE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_1),
		.ips		= addresses_A_1,
		},{
		.type		= WREPL_TYPE_UNIQUE,
		.state		= WREPL_STATE_ACTIVE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_1),
		.ips		= addresses_A_1,
		},{
		.type		= WREPL_TYPE_UNIQUE,
		.state		= WREPL_STATE_ACTIVE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_2),
		.ips		= addresses_A_2,
		},{
		.type		= WREPL_TYPE_SGROUP,
		.state		= WREPL_STATE_TOMBSTONE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_2),
		.ips		= addresses_A_2,
		},{
		.type		= WREPL_TYPE_MHOMED,
		.state		= WREPL_STATE_TOMBSTONE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_1),
		.ips		= addresses_A_1,
		},{
		/* the last one should always be a tomstone record! */
		.type		= WREPL_TYPE_UNIQUE,
		.state		= WREPL_STATE_TOMBSTONE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_1),
		.ips		= addresses_A_1,
		}
	};

	if (!ctx) return False;

	name.name	= "_SAME_OWNER_A";
	name.type	= 0;
	name.scope	= NULL;

	wins_name_tmp	= NULL;
	wins_name_last	= &wins_name2;
	wins_name_cur	= &wins_name1;

	for (j=0; ret && j < ARRAY_SIZE(types); j++) {
		name.type = types[j];
		printf("Test Replica Conflicts with same owner[%s] for %s\n",
			nbt_name_string(ctx, &name), ctx->a.address);

		for(i=0; ret && i < ARRAY_SIZE(records); i++) {
			wins_name_tmp	= wins_name_last;
			wins_name_last	= wins_name_cur;
			wins_name_cur	= wins_name_tmp;

			wins_name_cur->name	= &name;
			wins_name_cur->flags	= WREPL_NAME_FLAGS(records[i].type,
								   records[i].state,
								   records[i].node,
								   records[i].is_static);
			wins_name_cur->id	= ++ctx->a.max_version;
			if (wins_name_cur->flags & 2) {
				wins_name_cur->addresses.addresses.num_ips = records[i].num_ips;
				wins_name_cur->addresses.addresses.ips     = discard_const(records[i].ips);
			} else {
				wins_name_cur->addresses.ip = records[i].ips[0].ip;
			}
			wins_name_cur->unknown	= "255.255.255.255";

			ret &= test_wrepl_update_one_A(ctx, wins_name_cur);
			ret &= test_wrepl_is_applied_A(ctx, wins_name_cur);
		}
	}
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
	struct test_wrepl_conflict_conn *ctx;

	make_nbt_name_server(&name, lp_parm_string(-1, "torture", "host"));

	/* do an initial name resolution to find its IP */
	status = resolve_name(&name, mem_ctx, &address, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to resolve %s - %s\n",
		       name.name, nt_errstr(status));
		talloc_free(mem_ctx);
		return False;
	}

	ret &= test_assoc_ctx1(mem_ctx, address);
	ret &= test_assoc_ctx2(mem_ctx, address);

	ret &= test_wins_replication(mem_ctx, address);

	ctx = test_create_conflict_ctx(mem_ctx, address);

	ret &= test_conflict_same_owner(ctx);

	talloc_free(mem_ctx);

	return ret;
}
