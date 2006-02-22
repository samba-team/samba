/* 
   Unix SMB/CIFS implementation.

   WINS replication testing

   Copyright (C) Andrew Tridgell	2005
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "libcli/wrepl/winsrepl.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"

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

#define CHECK_VALUE_UINT64(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%llu - should be %llu\n", \
		       __location__, #v, (long long)v, (long long)correct); \
		ret = False; \
		goto done; \
	}} while (0)

#define CHECK_VALUE_STRING(v, correct) do { \
	if ( ((!v) && (correct)) || \
	     ((v) && (!correct)) || \
	     ((v) && (correct) && strcmp(v,correct) != 0)) { \
		printf("(%s) Incorrect value %s='%s' - should be '%s'\n", \
		       __location__, #v, v, correct); \
		ret = False; \
		goto done; \
	}} while (0)

#define _NBT_NAME(n,t,s) {\
	.name	= n,\
	.type	= t,\
	.scope	= s\
}

static const char *wrepl_name_type_string(enum wrepl_name_type type)
{
	switch (type) {
	case WREPL_TYPE_UNIQUE: return "UNIQUE";
	case WREPL_TYPE_GROUP: return "GROUP";
	case WREPL_TYPE_SGROUP: return "SGROUP";
	case WREPL_TYPE_MHOMED: return "MHOMED";
	}
	return "UNKNOWN_TYPE";
}

static const char *wrepl_name_state_string(enum wrepl_name_state state)
{
	switch (state) {
	case WREPL_STATE_ACTIVE: return "ACTIVE";
	case WREPL_STATE_RELEASED: return "RELEASED";
	case WREPL_STATE_TOMBSTONE: return "TOMBSTONE";
	case WREPL_STATE_RESERVED: return "RESERVED";
	}
	return "UNKNOWN_STATE";
}

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
	struct wrepl_packet packet;
	struct wrepl_send_ctrl ctrl;
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
	ZERO_STRUCT(packet);
	packet.opcode                      = WREPL_OPCODE_BITS;
	packet.assoc_ctx                   = associate1.out.assoc_ctx;
	packet.mess_type                   = WREPL_REPLICATION;
	packet.message.replication.command = WREPL_REPL_TABLE_QUERY;
	ZERO_STRUCT(ctrl);
	ctrl.send_only = True;
	req = wrepl_request_send(wrepl_socket2, &packet, &ctrl);
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
		name->type, name->state, name->node, name->is_static, (long long)name->version_id);
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

		req = wrepl_request_send(wrepl_socket, &packet, NULL);
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
		       (long long)partner->max_version, 
		       (long long)partner->min_version, 
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
#define TEST_OWNER_X_ADDRESS "127.88.88.1"
#define TEST_ADDRESS_X_PREFIX "127.0.88"

	struct wrepl_wins_owner a, b, c, x;

	struct socket_address *myaddr;
	struct socket_address *myaddr2;
	struct nbt_name_socket *nbtsock;
	struct nbt_name_socket *nbtsock2;

	struct nbt_name_socket *nbtsock_srv;
	struct nbt_name_socket *nbtsock_srv2;

	uint32_t addresses_best_num;
	struct wrepl_ip *addresses_best;

	uint32_t addresses_best2_num;
	struct wrepl_ip *addresses_best2;

	uint32_t addresses_all_num;
	struct wrepl_ip *addresses_all;

	uint32_t addresses_mhomed_num;
	struct wrepl_ip *addresses_mhomed;
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
static const struct wrepl_ip addresses_A_3_4[] = {
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".4"
	}
};
static const struct wrepl_ip addresses_A_3_4_X_3_4[] = {
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".4"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".4"
	}
};
static const struct wrepl_ip addresses_A_3_4_B_3_4[] = {
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".4"
	},
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".4"
	}
};
static const struct wrepl_ip addresses_A_3_4_OWNER_B[] = {
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".4"
	}
};
static const struct wrepl_ip addresses_A_3_4_X_3_4_OWNER_B[] = {
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".4"
	},
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".4"
	}
};

static const struct wrepl_ip addresses_A_3_4_X_1_2[] = {
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_A_ADDRESS,
	.ip	= TEST_ADDRESS_A_PREFIX".4"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".1"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".2"
	}
};

static const struct wrepl_ip addresses_B_1[] = {
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".1"
	}
};
static const struct wrepl_ip addresses_B_2[] = {
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".2"
	}
};
static const struct wrepl_ip addresses_B_3_4[] = {
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".4"
	}
};
static const struct wrepl_ip addresses_B_3_4_X_3_4[] = {
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".4"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".4"
	}
};
static const struct wrepl_ip addresses_B_3_4_X_1_2[] = {
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_B_ADDRESS,
	.ip	= TEST_ADDRESS_B_PREFIX".4"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".1"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".2"
	}
};

static const struct wrepl_ip addresses_X_1_2[] = {
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".1"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".2"
	}
};
static const struct wrepl_ip addresses_X_3_4[] = {
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".3"
	},
	{
	.owner	= TEST_OWNER_X_ADDRESS,
	.ip	= TEST_ADDRESS_X_PREFIX".4"
	}
};

static struct test_wrepl_conflict_conn *test_create_conflict_ctx(TALLOC_CTX *mem_ctx,
								 const char *address)
{
	struct test_wrepl_conflict_conn *ctx;
	struct wrepl_associate associate;
	struct wrepl_pull_table pull_table;
	struct socket_address *nbt_srv_addr;
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

	ctx->x.address		= TEST_OWNER_X_ADDRESS;
	ctx->x.max_version	= 0;
	ctx->x.min_version	= 0;
	ctx->x.type		= 1;

	ctx->c.address		= address;
	ctx->c.max_version	= 0;
	ctx->c.min_version	= 0;
	ctx->c.type		= 1;

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
		if (strcmp(TEST_OWNER_X_ADDRESS,pull_table.out.partners[i].address)==0) {
			ctx->x.max_version	= pull_table.out.partners[i].max_version;
			ctx->x.min_version	= pull_table.out.partners[i].min_version;
		}
		if (strcmp(address,pull_table.out.partners[i].address)==0) {
			ctx->c.max_version	= pull_table.out.partners[i].max_version;
			ctx->c.min_version	= pull_table.out.partners[i].min_version;
		}
	}

	talloc_free(pull_table.out.partners);

	ctx->nbtsock = nbt_name_socket_init(ctx, NULL);
	if (!ctx->nbtsock) return NULL;

	ctx->myaddr = socket_address_from_strings(mem_ctx, ctx->nbtsock->sock->backend_name, iface_best_ip(address), 0);
	if (!ctx->myaddr) return NULL;

	for (i = 0; i < iface_count(); i++) {
		if (strcmp(ctx->myaddr->addr, iface_n_ip(i)) == 0) continue;
		ctx->myaddr2 = socket_address_from_strings(mem_ctx, ctx->nbtsock->sock->backend_name, iface_n_ip(i), 0);
		if (!ctx->myaddr2) return NULL;
		break;
	}

	status = socket_listen(ctx->nbtsock->sock, ctx->myaddr, 0, 0);
	if (!NT_STATUS_IS_OK(status)) return NULL;

	ctx->nbtsock_srv = nbt_name_socket_init(ctx, NULL);
	if (!ctx->nbtsock_srv) return NULL;

	/* Make a port 137 version of ctx->myaddr */
	nbt_srv_addr = socket_address_from_strings(mem_ctx, ctx->nbtsock_srv->sock->backend_name, ctx->myaddr->addr, lp_nbt_port());
	if (!nbt_srv_addr) return NULL;

	/* And if possible, bind to it.  This won't work unless we are root or in sockewrapper */
	status = socket_listen(ctx->nbtsock_srv->sock, nbt_srv_addr, 0, 0);
	talloc_free(nbt_srv_addr);
	if (!NT_STATUS_IS_OK(status)) {
		/* this isn't fatal */
		talloc_free(ctx->nbtsock_srv);
		ctx->nbtsock_srv = NULL;
	}

	if (ctx->myaddr2 && ctx->nbtsock_srv) {
		ctx->nbtsock2 = nbt_name_socket_init(ctx, NULL);
		if (!ctx->nbtsock2) return NULL;

		status = socket_listen(ctx->nbtsock2->sock, ctx->myaddr2, 0, 0);
		if (!NT_STATUS_IS_OK(status)) return NULL;

		ctx->nbtsock_srv2 = nbt_name_socket_init(ctx, ctx->nbtsock_srv->event_ctx);
		if (!ctx->nbtsock_srv2) return NULL;

		/* Make a port 137 version of ctx->myaddr2 */
		nbt_srv_addr = socket_address_from_strings(mem_ctx, 
							   ctx->nbtsock_srv->sock->backend_name, 
							   ctx->myaddr2->addr, lp_nbt_port());
		if (!nbt_srv_addr) return NULL;

		/* And if possible, bind to it.  This won't work unless we are root or in sockewrapper */
		status = socket_listen(ctx->nbtsock_srv2->sock, ctx->myaddr2, 0, 0);
		talloc_free(nbt_srv_addr);
		if (!NT_STATUS_IS_OK(status)) {
			/* this isn't fatal */
			talloc_free(ctx->nbtsock_srv2);
			ctx->nbtsock_srv2 = NULL;
		}
	}

	ctx->addresses_best_num = 1;
	ctx->addresses_best = talloc_array(ctx, struct wrepl_ip, ctx->addresses_best_num);
	if (!ctx->addresses_best) return NULL;
	ctx->addresses_best[0].owner	= ctx->b.address;
	ctx->addresses_best[0].ip	= ctx->myaddr->addr;

	ctx->addresses_all_num = iface_count();
	ctx->addresses_all = talloc_array(ctx, struct wrepl_ip, ctx->addresses_all_num);
	if (!ctx->addresses_all) return NULL;
	for (i=0; i < ctx->addresses_all_num; i++) {
		ctx->addresses_all[i].owner	= ctx->b.address;
		ctx->addresses_all[i].ip	= talloc_strdup(ctx->addresses_all, iface_n_ip(i));
		if (!ctx->addresses_all[i].ip) return NULL;
	}

	if (ctx->nbtsock_srv2) {
		ctx->addresses_best2_num = 1;
		ctx->addresses_best2 = talloc_array(ctx, struct wrepl_ip, ctx->addresses_best2_num);
		if (!ctx->addresses_best2) return NULL;
		ctx->addresses_best2[0].owner	= ctx->b.address;
		ctx->addresses_best2[0].ip	= ctx->myaddr2->addr;

		ctx->addresses_mhomed_num = 2;
		ctx->addresses_mhomed = talloc_array(ctx, struct wrepl_ip, ctx->addresses_mhomed_num);
		if (!ctx->addresses_mhomed) return NULL;
		ctx->addresses_mhomed[0].owner	= ctx->b.address;
		ctx->addresses_mhomed[0].ip	= ctx->myaddr->addr;
		ctx->addresses_mhomed[1].owner	= ctx->b.address;
		ctx->addresses_mhomed[1].ip	= ctx->myaddr2->addr;
	}

	return ctx;
}

static BOOL test_wrepl_update_one(struct test_wrepl_conflict_conn *ctx,
				  const struct wrepl_wins_owner *owner,
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

	wrepl_wins_owners[0]	= *owner;

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

static BOOL test_wrepl_is_applied(struct test_wrepl_conflict_conn *ctx,
				  const struct wrepl_wins_owner *owner,
				  const struct wrepl_wins_name *name,
				  BOOL expected)
{
	BOOL ret = True;
	NTSTATUS status;
	struct wrepl_pull_names pull_names;
	struct wrepl_name *names;

	pull_names.in.assoc_ctx	= ctx->pull_assoc;
	pull_names.in.partner	= *owner;
	pull_names.in.partner.min_version = pull_names.in.partner.max_version;
		
	status = wrepl_pull_names(ctx->pull, ctx->pull, &pull_names);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(pull_names.out.num_names, (expected?1:0));

	names = pull_names.out.names;

	if (expected) {
		uint32_t flags = WREPL_NAME_FLAGS(names[0].type,
						  names[0].state,
						  names[0].node,
						  names[0].is_static);
		CHECK_VALUE(names[0].name.type, name->name->type);
		CHECK_VALUE_STRING(names[0].name.name, name->name->name);
		CHECK_VALUE_STRING(names[0].name.scope, name->name->scope);
		CHECK_VALUE(flags, name->flags);
		CHECK_VALUE_UINT64(names[0].version_id, name->id);

		if (flags & 2) {
			CHECK_VALUE(names[0].num_addresses,
				    name->addresses.addresses.num_ips);
		} else {
			CHECK_VALUE(names[0].num_addresses, 1);
			CHECK_VALUE_STRING(names[0].addresses[0].address,
					   name->addresses.ip);
		}
	}
done:
	talloc_free(pull_names.out.names);
	return ret;
}

static BOOL test_wrepl_mhomed_merged(struct test_wrepl_conflict_conn *ctx,
				     const struct wrepl_wins_owner *owner1,
				     uint32_t num_ips1, const struct wrepl_ip *ips1,
				     const struct wrepl_wins_owner *owner2,
				     uint32_t num_ips2, const struct wrepl_ip *ips2,
				     const struct wrepl_wins_name *name2)
{
	BOOL ret = True;
	NTSTATUS status;
	struct wrepl_pull_names pull_names;
	struct wrepl_name *names;
	uint32_t flags;
	uint32_t i, j;
	uint32_t num_ips = num_ips1 + num_ips2;

	for (i = 0; i < num_ips2; i++) {
		for (j = 0; j < num_ips1; j++) {
			if (strcmp(ips2[i].ip,ips1[j].ip) == 0) {
				num_ips--;
				break;
			}
		} 
	}

	pull_names.in.assoc_ctx	= ctx->pull_assoc;
	pull_names.in.partner	= *owner2;
	pull_names.in.partner.min_version = pull_names.in.partner.max_version;

	status = wrepl_pull_names(ctx->pull, ctx->pull, &pull_names);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VALUE(pull_names.out.num_names, 1);

	names = pull_names.out.names;

	flags = WREPL_NAME_FLAGS(names[0].type,
				 names[0].state,
				 names[0].node,
				 names[0].is_static);
	CHECK_VALUE(names[0].name.type, name2->name->type);
	CHECK_VALUE_STRING(names[0].name.name, name2->name->name);
	CHECK_VALUE_STRING(names[0].name.scope, name2->name->scope);
	CHECK_VALUE(flags, name2->flags | WREPL_TYPE_MHOMED);
	CHECK_VALUE_UINT64(names[0].version_id, name2->id);

	CHECK_VALUE(names[0].num_addresses, num_ips);

	for (i = 0; i < names[0].num_addresses; i++) {
		const char *addr = names[0].addresses[i].address; 
		const char *owner = names[0].addresses[i].owner;
		BOOL found = False;

		for (j = 0; j < num_ips2; j++) {
			if (strcmp(addr, ips2[j].ip) == 0) {
				found = True;
				CHECK_VALUE_STRING(owner, owner2->address);
				break;
			}
		}

		if (found) continue;

		for (j = 0; j < num_ips1; j++) {
			if (strcmp(addr, ips1[j].ip) == 0) {
				found = True;
				CHECK_VALUE_STRING(owner, owner1->address);
				break;
			}
		}

		if (found) continue;

		CHECK_VALUE_STRING(addr, "not found in address list");
	}
done:
	talloc_free(pull_names.out.names);
	return ret;
}

static BOOL test_wrepl_sgroup_merged(struct test_wrepl_conflict_conn *ctx,
				     struct wrepl_wins_owner *merge_owner,
				     struct wrepl_wins_owner *owner1,
				     uint32_t num_ips1, const struct wrepl_ip *ips1,
				     struct wrepl_wins_owner *owner2,
				     uint32_t num_ips2, const struct wrepl_ip *ips2,
				     const struct wrepl_wins_name *name2)
{
	BOOL ret = True;
	NTSTATUS status;
	struct wrepl_pull_names pull_names;
	struct wrepl_name *names;
	struct wrepl_name *name = NULL;
	uint32_t flags;
	uint32_t i, j;
	uint32_t num_ips = num_ips1 + num_ips2;

	if (!merge_owner) {
		merge_owner = &ctx->c;
	}

	for (i = 0; i < num_ips1; i++) {
		if (owner1 != &ctx->c && strcmp(ips1[i].owner,owner2->address) == 0) {
			num_ips--;
			continue;
		}
		for (j = 0; j < num_ips2; j++) {
			if (strcmp(ips1[i].ip,ips2[j].ip) == 0) {
				num_ips--;
				break;
			}
		}
	}


	pull_names.in.assoc_ctx	= ctx->pull_assoc;
	pull_names.in.partner	= *merge_owner;
	pull_names.in.partner.min_version = pull_names.in.partner.max_version;
	pull_names.in.partner.max_version = 0;

	status = wrepl_pull_names(ctx->pull, ctx->pull, &pull_names);
	CHECK_STATUS(status, NT_STATUS_OK);

	names = pull_names.out.names;
	
	for (i = 0; i < pull_names.out.num_names; i++) {
		if (names[i].name.type != name2->name->type)	continue;
		if (!names[i].name.name) continue;
		if (strcmp(names[i].name.name, name2->name->name) != 0) continue;
		if (names[i].name.scope) continue;

		name = &names[i];
	}

	if (pull_names.out.num_names > 0) {
		merge_owner->max_version	= names[pull_names.out.num_names-1].version_id;
	}

	if (!name) {
		printf("%s: Name '%s' not found\n", __location__, nbt_name_string(ctx, name2->name));
		return False;
	}

	flags = WREPL_NAME_FLAGS(name->type,
				 name->state,
				 name->node,
				 name->is_static);
	CHECK_VALUE(name->name.type, name2->name->type);
	CHECK_VALUE_STRING(name->name.name, name2->name->name);
	CHECK_VALUE_STRING(name->name.scope, name2->name->scope);
	CHECK_VALUE(flags, name2->flags);

	CHECK_VALUE(name->num_addresses, num_ips);

	for (i = 0; i < name->num_addresses; i++) {
		const char *addr = name->addresses[i].address; 
		const char *owner = name->addresses[i].owner;
		BOOL found = False;

		for (j = 0; j < num_ips2; j++) {
			if (strcmp(addr, ips2[j].ip) == 0) {
				found = True;
				CHECK_VALUE_STRING(owner, ips2[j].owner);
				break;
			}
		}

		if (found) continue;

		for (j = 0; j < num_ips1; j++) {
			if (strcmp(addr, ips1[j].ip) == 0) {
				found = True;
				if (owner1 == &ctx->c) {
					CHECK_VALUE_STRING(owner, owner1->address);
				} else {
					CHECK_VALUE_STRING(owner, ips1[j].owner);
				}
				break;
			}
		}

		if (found) continue;

		CHECK_VALUE_STRING(addr, "not found in address list");
	}
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
		.type		= WREPL_TYPE_UNIQUE,
		.state		= WREPL_STATE_ACTIVE,
		.node		= WREPL_NODE_B,
		.is_static	= True,
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
		.type		= WREPL_TYPE_MHOMED,
		.state		= WREPL_STATE_RELEASED,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_2),
		.ips		= addresses_A_2,
		},{
		.type		= WREPL_TYPE_SGROUP,
		.state		= WREPL_STATE_ACTIVE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_1),
		.ips		= addresses_A_1,
		},{
		.type		= WREPL_TYPE_SGROUP,
		.state		= WREPL_STATE_ACTIVE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_3_4),
		.ips		= addresses_A_3_4,
		},{
		.type		= WREPL_TYPE_SGROUP,
		.state		= WREPL_STATE_TOMBSTONE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_B_3_4),
		.ips		= addresses_B_3_4,
		},{
		/* the last one should always be a unique,tomstone record! */
		.type		= WREPL_TYPE_UNIQUE,
		.state		= WREPL_STATE_TOMBSTONE,
		.node		= WREPL_NODE_B,
		.is_static	= False,
		.num_ips	= ARRAY_SIZE(addresses_A_1),
		.ips		= addresses_A_1,
		}
	};

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

			if (i > 0) {
				printf("%s,%s%s vs. %s,%s%s with %s ip(s) => %s\n",
					wrepl_name_type_string(records[i-1].type),
					wrepl_name_state_string(records[i-1].state),
					(records[i-1].is_static?",static":""),
					wrepl_name_type_string(records[i].type),
					wrepl_name_state_string(records[i].state),
					(records[i].is_static?",static":""),
					(records[i-1].ips==records[i].ips?"same":"different"),
					"REPLACE");
			}

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

			ret &= test_wrepl_update_one(ctx, &ctx->a,wins_name_cur);
			if (records[i].state == WREPL_STATE_RELEASED) {
				ret &= test_wrepl_is_applied(ctx, &ctx->a, wins_name_last, False);
				ret &= test_wrepl_is_applied(ctx, &ctx->a, wins_name_cur, False);
			} else {
				ret &= test_wrepl_is_applied(ctx, &ctx->a, wins_name_cur, True);
			}

			/* the first one is a cleanup run */
			if (!ret && i == 0) ret = True;

			if (!ret) {
				printf("conflict handled wrong or record[%u]: %s\n", i, __location__);
				return ret;
			}
		}
	}
	return ret;
}

static BOOL test_conflict_different_owner(struct test_wrepl_conflict_conn *ctx)
{
	BOOL ret = True;
	struct wrepl_wins_name wins_name1;
	struct wrepl_wins_name wins_name2;
	struct wrepl_wins_name *wins_name_r1;
	struct wrepl_wins_name *wins_name_r2;
	uint32_t i;
	struct {
		const char *line; /* just better debugging */
		struct nbt_name name;
		const char *comment;
		BOOL extra; /* not the worst case, this is an extra test */
		BOOL cleanup;
		struct {
			struct wrepl_wins_owner *owner;
			enum wrepl_name_type type;
			enum wrepl_name_state state;
			enum wrepl_name_node node;
			BOOL is_static;
			uint32_t num_ips;
			const struct wrepl_ip *ips;
			BOOL apply_expected;
			BOOL sgroup_merge;
			struct wrepl_wins_owner *merge_owner;
			BOOL sgroup_cleanup;
		} r1, r2;
	} records[] = {
	/* 
	 * NOTE: the first record and the last applied one
	 *       needs to be from the same owner,
	 *       to not conflict in the next smbtorture run!!!
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True /* ignored */
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True /* ignored */
		}
	},

/*
 * unique vs unique section
 */
	/* 
	 * unique,active vs. unique,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,active vs. unique,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * unique,released vs. unique,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,released vs. unique,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,tombstone vs. unique,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,tombstone vs. unique,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},


/*
 * unique vs normal groups section,
 */
	/* 
	 * unique,active vs. group,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,active vs. group,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * unique,released vs. group,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,released vs. group,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,tombstone vs. group,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,tombstone vs. group,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

/*
 * unique vs special groups section,
 */
	/* 
	 * unique,active vs. sgroup,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * unique,active vs. sgroup,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * unique,released vs. sgroup,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,released vs. sgroup,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,tombstone vs. sgroup,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,tombstone vs. sgroup,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		}
	},

/*
 * unique vs multi homed section,
 */
	/* 
	 * unique,active vs. mhomed,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,active vs. mhomed,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		}
	},

	/* 
	 * unique,released vs. mhomed,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,released vs. mhomed,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,tombstone vs. mhomed,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * unique,tombstone vs. mhomed,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		}
	},

/*
 * normal groups vs unique section,
 */
	/* 
	 * group,active vs. unique,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,active vs. unique,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,released vs. unique,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,released vs. unique,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,tombstone vs. unique,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,tombstone vs. unique,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

/*
 * normal groups vs normal groups section,
 */
	/* 
	 * group,active vs. group,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,active vs. group,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,released vs. group,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * group,released vs. group,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * group,tombstone vs. group,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * group,tombstone vs. group,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

/*
 * normal groups vs special groups section,
 */
	/* 
	 * group,active vs. sgroup,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,active vs. sgroup,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,released vs. sgroup,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * group,released vs. sgroup,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,tombstone vs. sgroup,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * group,tombstone vs. sgroup,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

/*
 * normal groups vs multi homed section,
 */
	/* 
	 * group,active vs. mhomed,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,active vs. mhomed,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,released vs. mhomed,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,released vs. mhomed,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * group,tombstone vs. mhomed,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * group,tombstone vs. mhomed,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

/*
 * special groups vs unique section,
 */
	/* 
	 * sgroup,active vs. unique,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * sgroup,active vs. unique,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * sgroup,released vs. unique,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,released vs. unique,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,tombstone vs. unique,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,tombstone vs. unique,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

/*
 * special groups vs normal group section,
 */
	/* 
	 * sgroup,active vs. group,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * sgroup,active vs. group,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * sgroup,released vs. group,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,released vs. group,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,tombstone vs. group,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,tombstone vs. group,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

/*
 * special groups (not active) vs special group section,
 */
	/* 
	 * sgroup,released vs. sgroup,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,released vs. sgroup,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,tombstone vs. sgroup,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,tombstone vs. sgroup,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

/*
 * special groups vs multi homed section,
 */
	/* 
	 * sgroup,active vs. mhomed,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * sgroup,active vs. mhomed,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * sgroup,released vs. mhomed,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,released vs. mhomed,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,tombstone vs. mhomed,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * sgroup,tombstone vs. mhomed,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

/*
 * multi homed vs. unique section,
 */
	/* 
	 * mhomed,active vs. unique,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,active vs. unique,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * mhomed,released vs. unique,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,released vs. uinique,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,tombstone vs. unique,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,tombstone vs. uinique,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

/*
 * multi homed vs. normal group section,
 */
	/* 
	 * mhomed,active vs. group,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,active vs. group,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		}
	},

	/* 
	 * mhomed,released vs. group,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,released vs. group,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,tombstone vs. group,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,tombstone vs. group,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

/*
 * multi homed vs. special group section,
 */
	/* 
	 * mhomed,active vs. sgroup,active
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * mhomed,active vs. sgroup,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		}
	},

	/* 
	 * mhomed,released vs. sgroup,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,released vs. sgroup,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,tombstone vs. sgroup,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,tombstone vs. sgroup,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	},

/*
 * multi homed vs. mlti homed section,
 */
	/* 
	 * mhomed,active vs. mhomed,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,active vs. mhomed,tombstone
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		}
	},

	/* 
	 * mhomed,released vs. mhomed,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,released vs. mhomed,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_RELEASED,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= False
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,tombstone vs. mhomed,active
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		}
	},

	/* 
	 * mhomed,tombstone vs. mhomed,tombstone
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		}
	},
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True,
		}
	},
/*
 * special group vs special group section,
 */
	/* 
	 * sgroup,active vs. sgroup,active same addresses
	 * => should be NOT replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:A_3_4 vs. B:A_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= False,
			.sgroup_cleanup	= True
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active same addresses
	 * => should be NOT replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:A_3_4 vs. B:NULL",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
			.sgroup_cleanup	= True
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active subset addresses, special case...
	 * => should NOT be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:A_3_4_X_3_4 vs. B:A_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4_X_3_4),
			.ips		= addresses_A_3_4_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected = False,
		}
	},
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		},
		.r2	= {
			.owner		= &ctx->x,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active different addresses, but owner changed
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:B_3_4 vs. B:A_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True,
			.sgroup_cleanup	= True
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active different addresses, but owner changed
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:A_3_4 vs. B:A_3_4_OWNER_B",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4_OWNER_B),
			.ips		= addresses_A_3_4_OWNER_B,
			.apply_expected	= True,
			.sgroup_cleanup	= True
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active different addresses, but owner changed
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:A_3_4_OWNER_B vs. B:A_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4_OWNER_B),
			.ips		= addresses_A_3_4_OWNER_B,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True,
			.sgroup_cleanup	= True
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active different addresses
	 * => should be merged
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:A_3_4 vs. B:B_3_4 => C:A_3_4_B_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.sgroup_merge	= True,
			.sgroup_cleanup = True,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active different addresses, special case...
	 * => should be merged
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:B_3_4_X_3_4 vs. B:A_3_4 => B:A_3_4_X_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4_X_3_4),
			.ips		= addresses_B_3_4_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.sgroup_merge	= True,
			.merge_owner	= &ctx->b,
			.sgroup_cleanup	= False
		}
	},
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4_X_3_4_OWNER_B),
			.ips		= addresses_A_3_4_X_3_4_OWNER_B,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active different addresses, special case...
	 * => should be merged
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:X_3_4 vs. B:A_3_4 => C:A_3_4_X_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_X_3_4),
			.ips		= addresses_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.sgroup_merge	= True,
			.sgroup_cleanup	= False
		}
	},
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		},
		.r2	= {
			.owner		= &ctx->x,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active different addresses, special case...
	 * => should be merged
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:A_3_4_X_3_4 vs. B:A_3_4_OWNER_B => B:A_3_4_OWNER_B_X_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4_X_3_4),
			.ips		= addresses_A_3_4_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4_OWNER_B),
			.ips		= addresses_A_3_4_OWNER_B,
			.sgroup_merge	= True,
			.merge_owner	= &ctx->b,
		}
	},
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		},
		.r2	= {
			.owner		= &ctx->x,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active partly different addresses, special case...
	 * => should be merged
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:B_3_4_X_3_4 vs. B:B_3_4_X_1_2 => C:B_3_4_X_1_2_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4_X_3_4),
			.ips		= addresses_B_3_4_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4_X_1_2),
			.ips		= addresses_B_3_4_X_1_2,
			.sgroup_merge	= True,
			.sgroup_cleanup	= False
		}
	},
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		},
		.r2	= {
			.owner		= &ctx->x,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active different addresses, special case...
	 * => should be merged
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:A_3_4_B_3_4 vs. B:NULL => B:A_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4_B_3_4),
			.ips		= addresses_A_3_4_B_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.sgroup_merge	= True,
			.merge_owner	= &ctx->b,
			.sgroup_cleanup	= True
		}
	},
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active different addresses, special case...
	 * => should be merged
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:B_3_4_X_3_4 vs. B:NULL => B:X_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4_X_3_4),
			.ips		= addresses_B_3_4_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.sgroup_merge	= True,
			.merge_owner	= &ctx->b,
			.sgroup_cleanup	= True
		}
	},
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->x,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= False,
		},
		.r2	= {
			.owner		= &ctx->x,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True,
		}
	},

	/* 
	 * sgroup,active vs. sgroup,tombstone different no addresses, special
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:B_3_4_X_3_4 vs. B:NULL => B:NULL",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4_X_3_4),
			.ips		= addresses_B_3_4_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= 0,
			.ips		= NULL,
			.apply_expected	= True,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,tombstone different addresses
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:B_3_4_X_3_4 vs. B:A_3_4 => B:A_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4_X_3_4),
			.ips		= addresses_B_3_4_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
			.apply_expected	= True,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,tombstone subset addresses
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:B_3_4_X_3_4 vs. B:B_3_4 => B:B_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4_X_3_4),
			.ips		= addresses_B_3_4_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True,
		}
	},
	/* 
	 * sgroup,active vs. sgroup,active same addresses
	 * => should be replaced
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.comment= "A:B_3_4_X_3_4 vs. B:B_3_4_X_3_4 => B:B_3_4_X_3_4",
		.extra	= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4_X_3_4),
			.ips		= addresses_B_3_4_X_3_4,
			.apply_expected	= True,
		},
		.r2	= {
			.owner		= &ctx->b,
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4_X_3_4),
			.ips		= addresses_B_3_4_X_3_4,
			.apply_expected	= True,
		}
	},

	/* 
	 * This should be the last record in this array,
	 * we need to make sure the we leave a tombstoned unique entry
	 * owned by OWNER_A
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_DIFF_OWNER", 0x00, NULL),
		.cleanup= True,
		.r1	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		},
		.r2	= {
			.owner		= &ctx->a,
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_A_1),
			.ips		= addresses_A_1,
			.apply_expected	= True
		}
	}}; /* do not add entries here, this should be the last record! */

	wins_name_r1	= &wins_name1;
	wins_name_r2	= &wins_name2;

	printf("Test Replica Conflicts with different owners\n");

	for(i=0; ret && i < ARRAY_SIZE(records); i++) {

		if (!records[i].extra && !records[i].cleanup) {
			/* we should test the worst cases */
			if (records[i].r2.apply_expected && records[i].r1.ips==records[i].r2.ips) {
				printf("(%s) Programmer error, invalid record[%u]: %s\n",
					__location__, i, records[i].line);
				return False;
			} else if (!records[i].r2.apply_expected && records[i].r1.ips!=records[i].r2.ips) {
				printf("(%s) Programmer error, invalid record[%u]: %s\n",
					__location__, i, records[i].line);
				return False;
			}
		}

		if (!records[i].cleanup) {
			const char *expected;
			const char *ips;

			if (records[i].r2.sgroup_merge) {
				expected = "SGROUP_MERGE";
			} else if (records[i].r2.apply_expected) {
				expected = "REPLACE";
			} else {
				expected = "NOT REPLACE";
			}

			if (!records[i].r1.ips && !records[i].r2.ips) {
				ips = "with no ip(s)";
			} else if (records[i].r1.ips==records[i].r2.ips) {
				ips = "with same ip(s)";
			} else {
				ips = "with different ip(s)";
			}

			printf("%s,%s%s vs. %s,%s%s %s => %s\n",
				wrepl_name_type_string(records[i].r1.type),
				wrepl_name_state_string(records[i].r1.state),
				(records[i].r1.is_static?",static":""),
				wrepl_name_type_string(records[i].r2.type),
				wrepl_name_state_string(records[i].r2.state),
				(records[i].r2.is_static?",static":""),
				(records[i].comment?records[i].comment:ips),
				expected);
		}

		/*
		 * Setup R1
		 */
		wins_name_r1->name	= &records[i].name;
		wins_name_r1->flags	= WREPL_NAME_FLAGS(records[i].r1.type,
							   records[i].r1.state,
							   records[i].r1.node,
							   records[i].r1.is_static);
		wins_name_r1->id	= ++records[i].r1.owner->max_version;
		if (wins_name_r1->flags & 2) {
			wins_name_r1->addresses.addresses.num_ips = records[i].r1.num_ips;
			wins_name_r1->addresses.addresses.ips     = discard_const(records[i].r1.ips);
		} else {
			wins_name_r1->addresses.ip = records[i].r1.ips[0].ip;
		}
		wins_name_r1->unknown	= "255.255.255.255";

		/* now apply R1 */
		ret &= test_wrepl_update_one(ctx, records[i].r1.owner, wins_name_r1);
		ret &= test_wrepl_is_applied(ctx, records[i].r1.owner,
					     wins_name_r1, records[i].r1.apply_expected);

		/*
		 * Setup R2
		 */
		wins_name_r2->name	= &records[i].name;
		wins_name_r2->flags	= WREPL_NAME_FLAGS(records[i].r2.type,
							   records[i].r2.state,
							   records[i].r2.node,
							   records[i].r2.is_static);
		wins_name_r2->id	= ++records[i].r2.owner->max_version;
		if (wins_name_r2->flags & 2) {
			wins_name_r2->addresses.addresses.num_ips = records[i].r2.num_ips;
			wins_name_r2->addresses.addresses.ips     = discard_const(records[i].r2.ips);
		} else {
			wins_name_r2->addresses.ip = records[i].r2.ips[0].ip;
		}
		wins_name_r2->unknown	= "255.255.255.255";

		/* now apply R2 */
		ret &= test_wrepl_update_one(ctx, records[i].r2.owner, wins_name_r2);
		if (records[i].r1.state == WREPL_STATE_RELEASED) {
			ret &= test_wrepl_is_applied(ctx, records[i].r1.owner,
						     wins_name_r1, False);
		} else if (records[i].r2.sgroup_merge) {
			ret &= test_wrepl_sgroup_merged(ctx, records[i].r2.merge_owner,
							records[i].r1.owner,
							records[i].r1.num_ips, records[i].r1.ips,
							records[i].r2.owner,
							records[i].r2.num_ips, records[i].r2.ips,
							wins_name_r2);
		} else if (records[i].r1.owner != records[i].r2.owner) {
			BOOL _expected;
			_expected = (records[i].r1.apply_expected && !records[i].r2.apply_expected);
			ret &= test_wrepl_is_applied(ctx, records[i].r1.owner,
						     wins_name_r1, _expected);
		}
		if (records[i].r2.state == WREPL_STATE_RELEASED) {
			ret &= test_wrepl_is_applied(ctx, records[i].r2.owner,
						     wins_name_r2, False);
		} else if (!records[i].r2.sgroup_merge) {
			ret &= test_wrepl_is_applied(ctx, records[i].r2.owner,
						     wins_name_r2, records[i].r2.apply_expected);
		}

		if (records[i].r2.sgroup_cleanup) {
			if (!ret) {
				printf("failed before sgroup_cleanup record[%u]: %s\n", i, records[i].line);
				return ret;
			}

			/* clean up the SGROUP record */
			wins_name_r1->name	= &records[i].name;
			wins_name_r1->flags	= WREPL_NAME_FLAGS(WREPL_TYPE_SGROUP,
								   WREPL_STATE_ACTIVE,
								   WREPL_NODE_B, False);
			wins_name_r1->id	= ++records[i].r1.owner->max_version;
			wins_name_r1->addresses.addresses.num_ips = 0;
			wins_name_r1->addresses.addresses.ips     = NULL;
			wins_name_r1->unknown	= "255.255.255.255";
			ret &= test_wrepl_update_one(ctx, records[i].r1.owner, wins_name_r1);

			/* here we test how names from an owner are deleted */
			if (records[i].r2.sgroup_merge && records[i].r2.num_ips) {
				ret &= test_wrepl_sgroup_merged(ctx, NULL,
								records[i].r2.owner,
								records[i].r2.num_ips, records[i].r2.ips,
								records[i].r1.owner,
								0, NULL,
								wins_name_r2);
			}

			/* clean up the SGROUP record */
			wins_name_r2->name	= &records[i].name;
			wins_name_r2->flags	= WREPL_NAME_FLAGS(WREPL_TYPE_SGROUP,
								   WREPL_STATE_ACTIVE,
								   WREPL_NODE_B, False);
			wins_name_r2->id	= ++records[i].r2.owner->max_version;
			wins_name_r2->addresses.addresses.num_ips = 0;
			wins_name_r2->addresses.addresses.ips     = NULL;
			wins_name_r2->unknown	= "255.255.255.255";
			ret &= test_wrepl_update_one(ctx, records[i].r2.owner, wins_name_r2);

			/* take ownership of the SGROUP record */
			wins_name_r2->name	= &records[i].name;
			wins_name_r2->flags	= WREPL_NAME_FLAGS(WREPL_TYPE_SGROUP,
								   WREPL_STATE_ACTIVE,
								   WREPL_NODE_B, False);
			wins_name_r2->id	= ++records[i].r2.owner->max_version;
			wins_name_r2->addresses.addresses.num_ips = ARRAY_SIZE(addresses_B_1);
			wins_name_r2->addresses.addresses.ips     = discard_const(addresses_B_1);
			wins_name_r2->unknown	= "255.255.255.255";
			ret &= test_wrepl_update_one(ctx, records[i].r2.owner, wins_name_r2);
			ret &= test_wrepl_is_applied(ctx, records[i].r2.owner, wins_name_r2, True);

			/* overwrite the SGROUP record with unique,tombstone */
			wins_name_r2->name	= &records[i].name;
			wins_name_r2->flags	= WREPL_NAME_FLAGS(WREPL_TYPE_SGROUP,
								   WREPL_STATE_TOMBSTONE,
								   WREPL_NODE_B, False);
			wins_name_r2->id	= ++records[i].r2.owner->max_version;
			wins_name_r2->addresses.addresses.num_ips = ARRAY_SIZE(addresses_B_1);
			wins_name_r2->addresses.addresses.ips     = discard_const(addresses_B_1);
			wins_name_r2->unknown	= "255.255.255.255";
			ret &= test_wrepl_update_one(ctx, records[i].r2.owner, wins_name_r2);
			ret &= test_wrepl_is_applied(ctx, records[i].r2.owner, wins_name_r2, True);

			if (!ret) {
				printf("failed in sgroup_cleanup record[%u]: %s\n", i, records[i].line);
				return ret;
			}
		}

		/* the first one is a cleanup run */
		if (!ret && i == 0) ret = True;

		if (!ret) {
			printf("conflict handled wrong or record[%u]: %s\n", i, records[i].line);
			return ret;
		}
	}

	return ret;
}

static BOOL test_conflict_owned_released_vs_replica(struct test_wrepl_conflict_conn *ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	struct wrepl_wins_name wins_name_;
	struct wrepl_wins_name *wins_name = &wins_name_;
	struct nbt_name_register name_register_;
	struct nbt_name_register *name_register = &name_register_;
	struct nbt_name_release release_;
	struct nbt_name_release *release = &release_;
	uint32_t i;
	struct {
		const char *line; /* just better debugging */
		struct nbt_name name;
		struct {
			uint32_t nb_flags;
			BOOL mhomed;
			uint32_t num_ips;
			const struct wrepl_ip *ips;
			BOOL apply_expected;
		} wins;
		struct {
			enum wrepl_name_type type;
			enum wrepl_name_state state;
			enum wrepl_name_node node;
			BOOL is_static;
			uint32_t num_ips;
			const struct wrepl_ip *ips;
			BOOL apply_expected;
		} replica;
	} records[] = {
/* 
 * unique vs. unique section
 */
	/*
	 * unique,released vs. unique,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_UA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. unique,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_UA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. unique,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_UT_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. unique,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_UT_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * unique vs. group section
 */
	/*
	 * unique,released vs. group,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_GA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. group,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_GA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. group,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_GT_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. group,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_GT_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * unique vs. special group section
 */
	/*
	 * unique,released vs. sgroup,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_SA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. sgroup,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_SA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. sgroup,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_ST_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. sgroup,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_ST_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * unique vs. multi homed section
 */
	/*
	 * unique,released vs. mhomed,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_MA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. mhomed,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_MA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. mhomed,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_MT_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,released vs. mhomed,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UR_MT_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * group vs. unique section
 */
	/*
	 * group,released vs. unique,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_UA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,released vs. unique,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_UA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * group,released vs. unique,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_UT_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,released vs. unique,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_UT_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * group vs. group section
 */
	/*
	 * group,released vs. group,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_GA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * group,released vs. group,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_GA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * group,released vs. group,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_GT_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * group,released vs. group,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_GT_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * group vs. special group section
 */
	/*
	 * group,released vs. sgroup,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_SA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,released vs. sgroup,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_SA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * group,released vs. sgroup,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_ST_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,released vs. sgroup,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_ST_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * group vs. multi homed section
 */
	/*
	 * group,released vs. mhomed,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_MA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,released vs. mhomed,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_MA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * group,released vs. mhomed,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_MT_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,released vs. mhomed,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GR_MT_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * special group vs. unique section
 */
	/*
	 * sgroup,released vs. unique,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_UA_SI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. unique,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_UA_DI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. unique,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_UT_SI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. unique,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_UT_DI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * special group vs. group section
 */
	/*
	 * sgroup,released vs. group,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_GA_SI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. group,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_GA_DI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. group,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_GT_SI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. group,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_GT_DI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * special group vs. special group section
 */
	/*
	 * sgroup,released vs. sgroup,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_SA_SI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. sgroup,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_SA_DI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. sgroup,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_ST_SI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. sgroup,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_ST_DI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * special group vs. multi homed section
 */
	/*
	 * sgroup,released vs. mhomed,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_MA_SI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. mhomed,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_MA_DI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. mhomed,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_MT_SI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * sgroup,released vs. mhomed,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SR_MT_DI", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * multi homed vs. unique section
 */
	/*
	 * mhomed,released vs. unique,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_UA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. unique,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_UA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. unique,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_UT_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. unique,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_UT_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * multi homed vs. group section
 */
	/*
	 * mhomed,released vs. group,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_GA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. group,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_GA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. group,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_GT_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. group,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_GT_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * multi homed vs. special group section
 */
	/*
	 * mhomed,released vs. sgroup,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_SA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. sgroup,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_SA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. sgroup,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_ST_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. sgroup,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_ST_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
/* 
 * multi homed vs. multi homed section
 */
	/*
	 * mhomed,released vs. mhomed,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_MA_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. mhomed,active with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_MA_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. mhomed,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_MT_SI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,released vs. mhomed,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MR_MT_DI", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	};

	printf("Test Replica records vs. owned released records\n");

	for(i=0; ret && i < ARRAY_SIZE(records); i++) {
		printf("%s => %s\n", nbt_name_string(ctx, &records[i].name),
			(records[i].replica.apply_expected?"REPLACE":"NOT REPLACE"));

		/*
		 * Setup Register
		 */
		name_register->in.name		= records[i].name;
		name_register->in.dest_addr	= ctx->address;
		name_register->in.address	= records[i].wins.ips[0].ip;
		name_register->in.nb_flags	= records[i].wins.nb_flags;
		name_register->in.register_demand= False;
		name_register->in.broadcast	= False;
		name_register->in.multi_homed	= records[i].wins.mhomed;
		name_register->in.ttl		= 300000;
		name_register->in.timeout	= 70;
		name_register->in.retries	= 0;

		status = nbt_name_register(ctx->nbtsock, ctx, name_register);
		if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
			printf("No response from %s for name register\n", ctx->address);
			ret = False;
		}
		if (!NT_STATUS_IS_OK(status)) {
			printf("Bad response from %s for name register - %s\n",
			       ctx->address, nt_errstr(status));
			ret = False;
		}
		CHECK_VALUE(name_register->out.rcode, 0);
		CHECK_VALUE_STRING(name_register->out.reply_from, ctx->address);
		CHECK_VALUE(name_register->out.name.type, records[i].name.type);
		CHECK_VALUE_STRING(name_register->out.name.name, records[i].name.name);
		CHECK_VALUE_STRING(name_register->out.name.scope, records[i].name.scope);
		CHECK_VALUE_STRING(name_register->out.reply_addr, records[i].wins.ips[0].ip);

		/* release the record */
		release->in.name	= records[i].name;
		release->in.dest_addr	= ctx->address;
		release->in.address	= records[i].wins.ips[0].ip;
		release->in.nb_flags	= records[i].wins.nb_flags;
		release->in.broadcast	= False;
		release->in.timeout	= 30;
		release->in.retries	= 0;

		status = nbt_name_release(ctx->nbtsock, ctx, release);
		if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
			printf("No response from %s for name release\n", ctx->address);
			return False;
		}
		if (!NT_STATUS_IS_OK(status)) {
			printf("Bad response from %s for name query - %s\n",
			       ctx->address, nt_errstr(status));
			return False;
		}
		CHECK_VALUE(release->out.rcode, 0);

		/*
		 * Setup Replica
		 */
		wins_name->name		= &records[i].name;
		wins_name->flags	= WREPL_NAME_FLAGS(records[i].replica.type,
							   records[i].replica.state,
							   records[i].replica.node,
							   records[i].replica.is_static);
		wins_name->id		= ++ctx->b.max_version;
		if (wins_name->flags & 2) {
			wins_name->addresses.addresses.num_ips = records[i].replica.num_ips;
			wins_name->addresses.addresses.ips     = discard_const(records[i].replica.ips);
		} else {
			wins_name->addresses.ip = records[i].replica.ips[0].ip;
		}
		wins_name->unknown	= "255.255.255.255";

		ret &= test_wrepl_update_one(ctx, &ctx->b, wins_name);
		ret &= test_wrepl_is_applied(ctx, &ctx->b, wins_name,
					     records[i].replica.apply_expected);

		if (records[i].replica.apply_expected) {
			wins_name->name		= &records[i].name;
			wins_name->flags	= WREPL_NAME_FLAGS(WREPL_TYPE_UNIQUE,
								   WREPL_STATE_TOMBSTONE,
								   WREPL_NODE_B, False);
			wins_name->id		= ++ctx->b.max_version;
			wins_name->addresses.ip = addresses_B_1[0].ip;
			wins_name->unknown	= "255.255.255.255";

			ret &= test_wrepl_update_one(ctx, &ctx->b, wins_name);
			ret &= test_wrepl_is_applied(ctx, &ctx->b, wins_name, True);
		} else {
			release->in.name	= records[i].name;
			release->in.dest_addr	= ctx->address;
			release->in.address	= records[i].wins.ips[0].ip;
			release->in.nb_flags	= records[i].wins.nb_flags;
			release->in.broadcast	= False;
			release->in.timeout	= 30;
			release->in.retries	= 0;

			status = nbt_name_release(ctx->nbtsock, ctx, release);
			if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
				printf("No response from %s for name release\n", ctx->address);
				return False;
			}
			if (!NT_STATUS_IS_OK(status)) {
				printf("Bad response from %s for name query - %s\n",
				       ctx->address, nt_errstr(status));
				return False;
			}
			CHECK_VALUE(release->out.rcode, 0);
		}
done:
		if (!ret) {
			printf("conflict handled wrong or record[%u]: %s\n", i, records[i].line);
			return ret;
		}
	}

	return ret;
}

struct test_conflict_owned_active_vs_replica_struct {
	const char *line; /* just better debugging */
	const char *section; /* just better debugging */
	struct nbt_name name;
	const char *comment;
	BOOL skip;
	struct {
		uint32_t nb_flags;
		BOOL mhomed;
		uint32_t num_ips;
		const struct wrepl_ip *ips;
		BOOL apply_expected;
	} wins;
	struct {
		uint32_t timeout;
		BOOL positive;
		BOOL expect_release;
		BOOL late_release;
		BOOL ret;
		/* when num_ips == 0, then .wins.ips are used */
		uint32_t num_ips;
		const struct wrepl_ip *ips;
	} defend;
	struct {
		enum wrepl_name_type type;
		enum wrepl_name_state state;
		enum wrepl_name_node node;
		BOOL is_static;
		uint32_t num_ips;
		const struct wrepl_ip *ips;
		BOOL apply_expected;
		BOOL mhomed_merge;
		BOOL sgroup_merge;
	} replica;
};

static void test_conflict_owned_active_vs_replica_handler(struct nbt_name_socket *nbtsock, 
							  struct nbt_name_packet *req_packet, 
							  struct socket_address *src);

static BOOL test_conflict_owned_active_vs_replica(struct test_wrepl_conflict_conn *ctx)
{
	BOOL ret = True;
	NTSTATUS status;
	struct wrepl_wins_name wins_name_;
	struct wrepl_wins_name *wins_name = &wins_name_;
	struct nbt_name_register name_register_;
	struct nbt_name_register *name_register = &name_register_;
	struct nbt_name_release release_;
	struct nbt_name_release *release = &release_;
	uint32_t i;
	struct test_conflict_owned_active_vs_replica_struct records[] = {
/* 
 * unique vs. unique section
 */
	/*
	 * unique,active vs. unique,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_UA_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,active vs. unique,active with different ip(s), positive response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_UA_DI_P", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * unique,active vs. unique,active with different ip(s), positive response other ips
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_UA_DI_O", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * unique,active vs. unique,active with different ip(s), negative response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_UA_DI_N", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= False,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * unique,active vs. unique,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_UT_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * unique,active vs. unique,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_UT_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * unique vs. group section
 */
	/*
	 * unique,active vs. group,active with same ip(s), release expected
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_GA_SI_R", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.expect_release	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,active vs. group,active with different ip(s), release expected
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_GA_DI_R", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.expect_release	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * unique,active vs. group,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_GT_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * unique,active vs. group,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_GT_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * unique vs. special group section
 */
	/*
	 * unique,active vs. sgroup,active with same ip(s), release expected
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_SA_SI_R", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.expect_release	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,active vs. group,active with different ip(s), release expected
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_SA_DI_R", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.expect_release	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * unique,active vs. sgroup,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_ST_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * unique,active vs. sgroup,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_ST_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * unique vs. multi homed section
 */
	/*
	 * unique,active vs. mhomed,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_MA_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * unique,active vs. mhomed,active with superset ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_MA_SP_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_all_num,
			.ips		= ctx->addresses_all,
			.apply_expected	= True
		},
	},
	/*
	 * unique,active vs. mhomed,active with different ip(s), positive response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_MA_DI_P", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
	/*
	 * unique,active vs. mhomed,active with different ip(s), positive response other ips
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_MA_DI_O", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
	/*
	 * unique,active vs. mhomed,active with different ip(s), negative response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_MA_DI_N", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= False,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		},
	},
	/*
	 * unique,active vs. mhomed,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_MT_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * unique,active vs. mhomed,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_MT_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
/* 
 * normal group vs. unique section
 */
	/*
	 * group,active vs. unique,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_UA_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. unique,active with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_UA_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. unique,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_UT_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. unique,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_UT_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * normal group vs. normal group section
 */
	/*
	 * group,active vs. group,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_GA_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * group,active vs. group,active with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_GA_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * group,active vs. group,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_GT_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. group,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_GT_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * normal group vs. special group section
 */
	/*
	 * group,active vs. sgroup,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_SA_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. sgroup,active with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_SA_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. sgroup,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_ST_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. sgroup,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_ST_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
/* 
 * normal group vs. multi homed section
 */
	/*
	 * group,active vs. mhomed,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_MA_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. mhomed,active with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_MA_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. mhomed,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_MT_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * group,active vs. mhomed,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_GA_MT_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
/* 
 * special group vs. unique section
 */
	/*
	 * sgroup,active vs. unique,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_UA_SI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. unique,active with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_UA_DI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. unique,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_UT_SI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. unique,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_UT_DI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * special group vs. normal group section
 */
	/*
	 * sgroup,active vs. group,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_GA_SI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. group,active with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_GA_DI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. group,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_GT_SI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. group,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_GT_DI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * special group vs. multi homed section
 */
	/*
	 * sgroup,active vs. mhomed,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_MA_SI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. mhomed,active with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_MA_DI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. mhomed,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_MT_SI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. mhomed,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_MT_DI_U", 0x1C, NULL),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * multi homed vs. unique section
 */
	/*
	 * mhomed,active vs. unique,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_UA_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. unique,active with different ip(s), positive response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_UA_DI_P", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. unique,active with different ip(s), positive response other ips
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_UA_DI_O", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. unique,active with different ip(s), negative response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_UA_DI_N", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= False,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. unique,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_UT_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. unique,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_UT_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * multi homed vs. normal group section
 */
	/*
	 * mhomed,active vs. group,active with same ip(s), release expected
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_GA_SI_R", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.expect_release	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. group,active with different ip(s), release expected
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_GA_DI_R", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.expect_release	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. group,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_GT_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. group,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_GT_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_GROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * multi homed vs. special group section
 */
	/*
	 * mhomed,active vs. sgroup,active with same ip(s), release expected
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_SA_SI_R", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.expect_release	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. group,active with different ip(s), release expected
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_SA_DI_R", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.expect_release	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. sgroup,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_ST_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. sgroup,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_ST_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_1),
			.ips		= addresses_B_1,
			.apply_expected	= False
		},
	},
/* 
 * multi homed vs. multi homed section
 */
	/*
	 * mhomed,active vs. mhomed,active with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with superset ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_SP_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_all_num,
			.ips		= ctx->addresses_all,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with different ip(s), positive response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_DI_P", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with different ip(s), positive response other ips
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_DI_O", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ARRAY_SIZE(addresses_A_3_4),
			.ips		= addresses_A_3_4,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with different ip(s), negative response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_DI_N", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= False,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. mhomed,tombstone with same ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MT_SI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. mhomed,tombstone with different ip(s), unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MT_DI_U", 0x00, NULL),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
/*
 * some more multi homed test, including merging
 */
	/*
	 * mhomed,active vs. mhomed,active with superset ip(s), unchecked
	 */
	{
		.line	= __location__,
		.section= "Test Replica vs. owned active: some more MHOMED combinations",
		.name	= _NBT_NAME("_MA_MA_SP_U", 0x00, NULL),
		.comment= "C:MHOMED vs. B:ALL => B:ALL",
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_all_num,
			.ips		= ctx->addresses_all,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with same ips, unchecked
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_SM_U", 0x00, NULL),
		.comment= "C:MHOMED vs. B:MHOMED => B:MHOMED",
		.skip	= (ctx->addresses_mhomed_num < 2),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with subset ip(s), positive response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_SB_P", 0x00, NULL),
		.comment= "C:MHOMED vs. B:BEST (C:MHOMED) => B:MHOMED",
		.skip	= (ctx->addresses_mhomed_num < 2),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.mhomed_merge	= True
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with subset ip(s), positive response, with all addresses
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_SB_A", 0x00, NULL),
		.comment= "C:MHOMED vs. B:BEST (C:ALL) => B:MHOMED",
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ctx->addresses_all_num,
			.ips		= ctx->addresses_all,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.mhomed_merge	= True
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with subset ip(s), positive response, with replicas addresses
	 * TODO: check why the server sends a name release demand for one address?
	 *       the release demand has no effect to the database record...
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_SB_PRA", 0x00, NULL),
		.comment= "C:MHOMED vs. B:BEST (C:BEST) => C:MHOMED",
		.skip	= (ctx->addresses_all_num < 2),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.late_release	= True
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with subset ip(s), positive response, with other addresses
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_SB_O", 0x00, NULL),
		.comment= "C:MHOMED vs. B:BEST (B:B_3_4) =>C:MHOMED",
		.skip	= (ctx->addresses_all_num < 2),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	/*
	 * mhomed,active vs. mhomed,active with subset ip(s), negative response
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_MA_MA_SB_N", 0x00, NULL),
		.comment= "C:MHOMED vs. B:BEST (NEGATIVE) => B:BEST",
		.skip	= (ctx->addresses_mhomed_num < 2),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= False
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
	},
/*
 * some more multi homed and unique test, including merging
 */
	/*
	 * mhomed,active vs. unique,active with subset ip(s), positive response
	 */
	{
		.line	= __location__,
		.section= "Test Replica vs. owned active: some more UNIQUE,MHOMED combinations",
		.name	= _NBT_NAME("_MA_UA_SB_P", 0x00, NULL),
		.comment= "C:MHOMED vs. B:UNIQUE,BEST (C:MHOMED) => B:MHOMED",
		.skip	= (ctx->addresses_all_num < 2),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= True,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.mhomed_merge	= True
		},
	},
	/*
	 * unique,active vs. unique,active with different ip(s), positive response, with replicas address
	 * TODO: check why the server sends a name release demand for one address?
	 *       the release demand has no effect to the database record...
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_UA_DI_PRA", 0x00, NULL),
		.comment= "C:BEST vs. B:BEST2 (C:BEST2,LR:BEST2) => C:BEST",
		.skip	= (ctx->addresses_all_num < 2),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ctx->addresses_best2_num,
			.ips		= ctx->addresses_best2,
			.late_release	= True
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best2_num,
			.ips		= ctx->addresses_best2,
			.apply_expected	= False,
		},
	},
	/*
	 * unique,active vs. unique,active with different ip(s), positive response, with all addresses
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_UA_DI_A", 0x00, NULL),
		.comment= "C:BEST vs. B:BEST2 (C:ALL) => B:MHOMED",
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ctx->addresses_all_num,
			.ips		= ctx->addresses_all,
		},
		.replica= {
			.type		= WREPL_TYPE_UNIQUE,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best2_num,
			.ips		= ctx->addresses_best2,
			.mhomed_merge	= True,
		},
	},
	/*
	 * unique,active vs. mhomed,active with different ip(s), positive response, with all addresses
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_UA_MA_DI_A", 0x00, NULL),
		.comment= "C:BEST vs. B:BEST2 (C:ALL) => B:MHOMED",
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= 0,
			.mhomed		= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 10,
			.positive	= True,
			.num_ips	= ctx->addresses_all_num,
			.ips		= ctx->addresses_all,
		},
		.replica= {
			.type		= WREPL_TYPE_MHOMED,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best2_num,
			.ips		= ctx->addresses_best2,
			.mhomed_merge	= True,
		},
	},
/*
 * special group vs. special group merging section
 */
	/*
	 * sgroup,active vs. sgroup,active with different ip(s)
	 */
	{
		.line	= __location__,
		.section= "Test Replica vs. owned active: SGROUP vs. SGROUP tests",
		.name	= _NBT_NAME("_SA_SA_DI_U", 0x1C, NULL),
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.sgroup_merge	= True
		},
	},
	/*
	 * sgroup,active vs. sgroup,active with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_SA_SI_U", 0x1C, NULL),
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.sgroup_merge	= True
		},
	},
	/*
	 * sgroup,active vs. sgroup,active with superset ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_SA_SP_U", 0x1C, NULL),
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_all_num,
			.ips		= ctx->addresses_all,
			.sgroup_merge	= True
		},
	},
	/*
	 * sgroup,active vs. sgroup,active with subset ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_SA_SB_U", 0x1C, NULL),
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_ACTIVE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.sgroup_merge	= True
		},
	},
	/*
	 * sgroup,active vs. sgroup,tombstone with different ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_ST_DI_U", 0x1C, NULL),
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ARRAY_SIZE(addresses_B_3_4),
			.ips		= addresses_B_3_4,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. sgroup,tombstone with same ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_ST_SI_U", 0x1C, NULL),
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. sgroup,tombstone with superset ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_ST_SP_U", 0x1C, NULL),
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_all_num,
			.ips		= ctx->addresses_all,
			.apply_expected	= False
		},
	},
	/*
	 * sgroup,active vs. sgroup,tombstone with subset ip(s)
	 */
	{
		.line	= __location__,
		.name	= _NBT_NAME("_SA_ST_SB_U", 0x1C, NULL),
		.skip	= (ctx->addresses_all_num < 3),
		.wins	= {
			.nb_flags	= NBT_NM_GROUP,
			.mhomed		= False,
			.num_ips	= ctx->addresses_mhomed_num,
			.ips		= ctx->addresses_mhomed,
			.apply_expected	= True
		},
		.defend	= {
			.timeout	= 0,
		},
		.replica= {
			.type		= WREPL_TYPE_SGROUP,
			.state		= WREPL_STATE_TOMBSTONE,
			.node		= WREPL_NODE_B,
			.is_static	= False,
			.num_ips	= ctx->addresses_best_num,
			.ips		= ctx->addresses_best,
			.apply_expected	= False
		},
	},
	};

	if (!ctx->nbtsock_srv) {
		printf("SKIP: Test Replica records vs. owned active records: not bound to port[%d]\n",
			lp_nbt_port());
		return True;
	}

	printf("Test Replica records vs. owned active records\n");

	for(i=0; ret && i < ARRAY_SIZE(records); i++) {
		struct timeval end;
		struct test_conflict_owned_active_vs_replica_struct record = records[i];
		uint32_t j, count = 1;
		const char *action;

		if (records[i].wins.mhomed || records[i].name.type == 0x1C) {
			count = records[i].wins.num_ips;
		}

		if (records[i].section) {
			printf("%s\n", records[i].section);
		}

		if (records[i].skip) {
			printf("%s => SKIPPED\n", nbt_name_string(ctx, &records[i].name));
			continue;
		}

		if (records[i].replica.mhomed_merge) {
			action = "MHOMED_MERGE";
		} else if (records[i].replica.sgroup_merge) {
			action = "SGROUP_MERGE";
		} else if (records[i].replica.apply_expected) {
			action = "REPLACE";
		} else {
			action = "NOT REPLACE";
		}

		printf("%s%s%s => %s\n",
			nbt_name_string(ctx, &records[i].name),
			(records[i].comment?": ":""),
			(records[i].comment?records[i].comment:""),
			action);

		/* Prepare for multi homed registration */
		ZERO_STRUCT(records[i].defend);
		records[i].defend.timeout	= 10;
		records[i].defend.positive	= True;
		nbt_set_incoming_handler(ctx->nbtsock_srv,
					 test_conflict_owned_active_vs_replica_handler,
					 &records[i]);
		if (ctx->nbtsock_srv2) {
			nbt_set_incoming_handler(ctx->nbtsock_srv2,
						 test_conflict_owned_active_vs_replica_handler,
						 &records[i]);
		}

		/*
		 * Setup Register
		 */
		for (j=0; j < count; j++) {
			struct nbt_name_request *req;

			name_register->in.name		= records[i].name;
			name_register->in.dest_addr	= ctx->address;
			name_register->in.address	= records[i].wins.ips[j].ip;
			name_register->in.nb_flags	= records[i].wins.nb_flags;
			name_register->in.register_demand= False;
			name_register->in.broadcast	= False;
			name_register->in.multi_homed	= records[i].wins.mhomed;
			name_register->in.ttl		= 300000;
			name_register->in.timeout	= 70;
			name_register->in.retries	= 0;

			req = nbt_name_register_send(ctx->nbtsock, name_register);

			/* push the request on the wire */
			event_loop_once(ctx->nbtsock->event_ctx);

			/*
			 * if we register multiple addresses,
			 * the server will do name queries to see if the old addresses
			 * are still alive
			 */
			if (records[i].wins.mhomed && j > 0) {
				end = timeval_current_ofs(records[i].defend.timeout,0);
				records[i].defend.ret = True;
				while (records[i].defend.timeout > 0) {
					event_loop_once(ctx->nbtsock_srv->event_ctx);
					if (timeval_expired(&end)) break;
				}
				ret &= records[i].defend.ret;
			}

			status = nbt_name_register_recv(req, ctx, name_register);
			if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
				printf("No response from %s for name register\n", ctx->address);
				ret = False;
			}
			if (!NT_STATUS_IS_OK(status)) {
				printf("Bad response from %s for name register - %s\n",
				       ctx->address, nt_errstr(status));
				ret = False;
			}
			CHECK_VALUE(name_register->out.rcode, 0);
			CHECK_VALUE_STRING(name_register->out.reply_from, ctx->address);
			CHECK_VALUE(name_register->out.name.type, records[i].name.type);
			CHECK_VALUE_STRING(name_register->out.name.name, records[i].name.name);
			CHECK_VALUE_STRING(name_register->out.name.scope, records[i].name.scope);
			CHECK_VALUE_STRING(name_register->out.reply_addr, records[i].wins.ips[j].ip);
		}

		/* Prepare for the current test */
		records[i].defend = record.defend;
		nbt_set_incoming_handler(ctx->nbtsock_srv,
					 test_conflict_owned_active_vs_replica_handler,
					 &records[i]);
		if (ctx->nbtsock_srv2) {
			nbt_set_incoming_handler(ctx->nbtsock_srv2,
						 test_conflict_owned_active_vs_replica_handler,
						 &records[i]);
		}

		/*
		 * Setup Replica
		 */
		wins_name->name		= &records[i].name;
		wins_name->flags	= WREPL_NAME_FLAGS(records[i].replica.type,
							   records[i].replica.state,
							   records[i].replica.node,
							   records[i].replica.is_static);
		wins_name->id		= ++ctx->b.max_version;
		if (wins_name->flags & 2) {
			wins_name->addresses.addresses.num_ips = records[i].replica.num_ips;
			wins_name->addresses.addresses.ips     = discard_const(records[i].replica.ips);
		} else {
			wins_name->addresses.ip = records[i].replica.ips[0].ip;
		}
		wins_name->unknown	= "255.255.255.255";

		ret &= test_wrepl_update_one(ctx, &ctx->b, wins_name);

		/*
		 * wait for the name query, which is handled in
		 * test_conflict_owned_active_vs_replica_handler()
		 */
		end = timeval_current_ofs(records[i].defend.timeout,0);
		records[i].defend.ret = True;
		while (records[i].defend.timeout > 0) {
			event_loop_once(ctx->nbtsock_srv->event_ctx);
			if (timeval_expired(&end)) break;
		}
		ret &= records[i].defend.ret;

		if (records[i].defend.late_release) {
			records[i].defend = record.defend;
			records[i].defend.expect_release = True;
			/*
			 * wait for the name release demand, which is handled in
			 * test_conflict_owned_active_vs_replica_handler()
			 */
			end = timeval_current_ofs(records[i].defend.timeout,0);
			records[i].defend.ret = True;
			while (records[i].defend.timeout > 0) {
				event_loop_once(ctx->nbtsock_srv->event_ctx);
				if (timeval_expired(&end)) break;
			}
			ret &= records[i].defend.ret;
		}

		if (records[i].replica.mhomed_merge) {
			ret &= test_wrepl_mhomed_merged(ctx, &ctx->c,
						        records[i].wins.num_ips, records[i].wins.ips,
						        &ctx->b,
							records[i].replica.num_ips, records[i].replica.ips,
							wins_name);
		} else if (records[i].replica.sgroup_merge) {
			ret &= test_wrepl_sgroup_merged(ctx, NULL,
							&ctx->c,
						        records[i].wins.num_ips, records[i].wins.ips,
							&ctx->b,
							records[i].replica.num_ips, records[i].replica.ips,
							wins_name);
		} else {
			ret &= test_wrepl_is_applied(ctx, &ctx->b, wins_name,
						     records[i].replica.apply_expected);
		}

		if (records[i].replica.apply_expected ||
		    records[i].replica.mhomed_merge) {
			wins_name->name		= &records[i].name;
			wins_name->flags	= WREPL_NAME_FLAGS(WREPL_TYPE_UNIQUE,
								   WREPL_STATE_TOMBSTONE,
								   WREPL_NODE_B, False);
			wins_name->id		= ++ctx->b.max_version;
			wins_name->addresses.ip = addresses_B_1[0].ip;
			wins_name->unknown	= "255.255.255.255";

			ret &= test_wrepl_update_one(ctx, &ctx->b, wins_name);
			ret &= test_wrepl_is_applied(ctx, &ctx->b, wins_name, True);
		} else {
			for (j=0; j < count; j++) {
				struct nbt_name_socket *nbtsock = ctx->nbtsock;

				if (ctx->myaddr2 && strcmp(records[i].wins.ips[j].ip, ctx->myaddr2->addr) == 0) {
					nbtsock = ctx->nbtsock2;
				}

				release->in.name	= records[i].name;
				release->in.dest_addr	= ctx->address;
				release->in.address	= records[i].wins.ips[j].ip;
				release->in.nb_flags	= records[i].wins.nb_flags;
				release->in.broadcast	= False;
				release->in.timeout	= 30;
				release->in.retries	= 0;

				status = nbt_name_release(nbtsock, ctx, release);
				if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
					printf("No response from %s for name release\n", ctx->address);
					return False;
				}
				if (!NT_STATUS_IS_OK(status)) {
					printf("Bad response from %s for name query - %s\n",
					       ctx->address, nt_errstr(status));
					return False;
				}
				CHECK_VALUE(release->out.rcode, 0);
			}

			if (records[i].replica.sgroup_merge) {
				/* clean up the SGROUP record */
				wins_name->name		= &records[i].name;
				wins_name->flags	= WREPL_NAME_FLAGS(WREPL_TYPE_SGROUP,
									   WREPL_STATE_ACTIVE,
									   WREPL_NODE_B, False);
				wins_name->id		= ++ctx->b.max_version;
				wins_name->addresses.addresses.num_ips = 0;
				wins_name->addresses.addresses.ips     = NULL;
				wins_name->unknown	= "255.255.255.255";
				ret &= test_wrepl_update_one(ctx, &ctx->b, wins_name);

				/* take ownership of the SGROUP record */
				wins_name->name		= &records[i].name;
				wins_name->flags	= WREPL_NAME_FLAGS(WREPL_TYPE_SGROUP,
									   WREPL_STATE_ACTIVE,
									   WREPL_NODE_B, False);
				wins_name->id		= ++ctx->b.max_version;
				wins_name->addresses.addresses.num_ips = ARRAY_SIZE(addresses_B_1);
				wins_name->addresses.addresses.ips     = discard_const(addresses_B_1);
				wins_name->unknown	= "255.255.255.255";
				ret &= test_wrepl_update_one(ctx, &ctx->b, wins_name);
				ret &= test_wrepl_is_applied(ctx, &ctx->b, wins_name, True);

				/* overwrite the SGROUP record with unique,tombstone */
				wins_name->name		= &records[i].name;
				wins_name->flags	= WREPL_NAME_FLAGS(WREPL_TYPE_UNIQUE,
									   WREPL_STATE_TOMBSTONE,
									   WREPL_NODE_B, False);
				wins_name->id		= ++ctx->b.max_version;
				wins_name->addresses.ip = addresses_A_1[0].ip;
				wins_name->unknown	= "255.255.255.255";
				ret &= test_wrepl_update_one(ctx, &ctx->b, wins_name);
				ret &= test_wrepl_is_applied(ctx, &ctx->b, wins_name, True);
			}
		}

done:
		if (!ret) {
			printf("conflict handled wrong or record[%u]: %s\n", i, records[i].line);
			return ret;
		}
	}

	return ret;
}

#define _NBT_ASSERT(v, correct) do { \
	if ((v) != (correct)) { \
		printf("(%s) Incorrect value %s=%d - should be %s (%d)\n", \
		       __location__, #v, v, #correct, correct); \
		return; \
	} \
} while (0)

#define _NBT_ASSERT_STRING(v, correct) do { \
	if ( ((!v) && (correct)) || \
	     ((v) && (!correct)) || \
	     ((v) && (correct) && strcmp(v,correct) != 0)) { \
		printf("(%s) Incorrect value %s=%s - should be %s\n", \
		       __location__, #v, v, correct); \
		return; \
	} \
} while (0)

static void test_conflict_owned_active_vs_replica_handler_query(struct nbt_name_socket *nbtsock, 
								struct nbt_name_packet *req_packet, 
								struct socket_address *src)
{
	struct nbt_name *name;
	struct nbt_name_packet *rep_packet;
	struct test_conflict_owned_active_vs_replica_struct *rec = nbtsock->incoming.private;

	_NBT_ASSERT(req_packet->qdcount, 1);
	_NBT_ASSERT(req_packet->questions[0].question_type, NBT_QTYPE_NETBIOS);
	_NBT_ASSERT(req_packet->questions[0].question_class, NBT_QCLASS_IP);

	name = &req_packet->questions[0].name;

	_NBT_ASSERT(name->type, rec->name.type);
	_NBT_ASSERT_STRING(name->name, rec->name.name);
	_NBT_ASSERT_STRING(name->scope, rec->name.scope);

	_NBT_ASSERT(rec->defend.expect_release, False);

	rep_packet = talloc_zero(nbtsock, struct nbt_name_packet);
	if (rep_packet == NULL) return;

	rep_packet->name_trn_id	= req_packet->name_trn_id;
	rep_packet->ancount	= 1;

	rep_packet->answers	= talloc_array(rep_packet, struct nbt_res_rec, 1);
	if (rep_packet->answers == NULL) return;

	rep_packet->answers[0].name      = *name;
	rep_packet->answers[0].rr_class  = NBT_QCLASS_IP;
	rep_packet->answers[0].ttl       = 0;

	if (rec->defend.positive) {
		uint32_t i, num_ips;
		const struct wrepl_ip *ips;		

		if (rec->defend.num_ips > 0) {
			num_ips	= rec->defend.num_ips;
			ips	= rec->defend.ips;
		} else {
			num_ips	= rec->wins.num_ips;
			ips	= rec->wins.ips;
		}

		/* send a positive reply */
		rep_packet->operation	= 
					NBT_FLAG_REPLY | 
					NBT_OPCODE_QUERY | 
					NBT_FLAG_AUTHORITIVE |
					NBT_FLAG_RECURSION_DESIRED |
					NBT_FLAG_RECURSION_AVAIL;

		rep_packet->answers[0].rr_type   = NBT_QTYPE_NETBIOS;

		rep_packet->answers[0].rdata.netbios.length = num_ips*6;
		rep_packet->answers[0].rdata.netbios.addresses = 
			talloc_array(rep_packet->answers, struct nbt_rdata_address, num_ips);
		if (rep_packet->answers[0].rdata.netbios.addresses == NULL) return;

		for (i=0; i < num_ips; i++) {
			struct nbt_rdata_address *addr = 
				&rep_packet->answers[0].rdata.netbios.addresses[i];
			addr->nb_flags	= rec->wins.nb_flags;
			addr->ipaddr	= ips[i].ip;
		}
		DEBUG(2,("Sending positive name query reply for %s to %s:%d\n", 
			nbt_name_string(rep_packet, name), src->addr, src->port));
	} else {
		/* send a negative reply */
		rep_packet->operation	=
					NBT_FLAG_REPLY | 
					NBT_OPCODE_QUERY | 
					NBT_FLAG_AUTHORITIVE |
					NBT_RCODE_NAM;

		rep_packet->answers[0].rr_type   = NBT_QTYPE_NULL;

		ZERO_STRUCT(rep_packet->answers[0].rdata);

		DEBUG(2,("Sending negative name query reply for %s to %s:%d\n", 
			nbt_name_string(rep_packet, name), src->addr, src->port));
	}

	nbt_name_reply_send(nbtsock, src, rep_packet);
	talloc_free(rep_packet);

	/* make sure we push the reply to the wire */
	event_loop_once(nbtsock->event_ctx);
	msleep(25);

	rec->defend.timeout	= 0;
	rec->defend.ret		= True;
}

static void test_conflict_owned_active_vs_replica_handler_release(struct nbt_name_socket *nbtsock, 
								  struct nbt_name_packet *req_packet, 
								  struct socket_address *src)
{
	struct nbt_name *name;
	struct nbt_name_packet *rep_packet;
	struct test_conflict_owned_active_vs_replica_struct *rec = nbtsock->incoming.private;

	_NBT_ASSERT(req_packet->qdcount, 1);
	_NBT_ASSERT(req_packet->questions[0].question_type, NBT_QTYPE_NETBIOS);
	_NBT_ASSERT(req_packet->questions[0].question_class, NBT_QCLASS_IP);

	name = &req_packet->questions[0].name;

	_NBT_ASSERT(name->type, rec->name.type);
	_NBT_ASSERT_STRING(name->name, rec->name.name);
	_NBT_ASSERT_STRING(name->scope, rec->name.scope);

	_NBT_ASSERT(rec->defend.expect_release, True);

	rep_packet = talloc_zero(nbtsock, struct nbt_name_packet);
	if (rep_packet == NULL) return;

	rep_packet->name_trn_id	= req_packet->name_trn_id;
	rep_packet->ancount	= 1;
	rep_packet->operation	= 
				NBT_FLAG_REPLY | 
				NBT_OPCODE_RELEASE |
				NBT_FLAG_AUTHORITIVE;

	rep_packet->answers	= talloc_array(rep_packet, struct nbt_res_rec, 1);
	if (rep_packet->answers == NULL) return;

	rep_packet->answers[0].name	= *name;
	rep_packet->answers[0].rr_type	= NBT_QTYPE_NETBIOS;
	rep_packet->answers[0].rr_class	= NBT_QCLASS_IP;
	rep_packet->answers[0].ttl	= req_packet->additional[0].ttl;
	rep_packet->answers[0].rdata    = req_packet->additional[0].rdata;

	DEBUG(2,("Sending name release reply for %s to %s:%d\n", 
		nbt_name_string(rep_packet, name), src->addr, src->port));

	nbt_name_reply_send(nbtsock, src, rep_packet);
	talloc_free(rep_packet);

	/* make sure we push the reply to the wire */
	event_loop_once(nbtsock->event_ctx);
	msleep(25);

	rec->defend.timeout	= 0;
	rec->defend.ret		= True;
}

static void test_conflict_owned_active_vs_replica_handler(struct nbt_name_socket *nbtsock, 
							  struct nbt_name_packet *req_packet, 
							  struct socket_address *src)
{
	struct test_conflict_owned_active_vs_replica_struct *rec = nbtsock->incoming.private;

	rec->defend.ret = False;

	switch (req_packet->operation & NBT_OPCODE) {
	case NBT_OPCODE_QUERY:
		test_conflict_owned_active_vs_replica_handler_query(nbtsock, req_packet, src);
		break;
	case NBT_OPCODE_RELEASE:
		test_conflict_owned_active_vs_replica_handler_release(nbtsock, req_packet, src);
		break;
	default:
		printf("%s: unexpected incoming packet\n", __location__);
		return;
	}
}

/*
  test simple WINS replication operations
*/
BOOL torture_nbt_winsreplication_simple(void)
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

	ret &= test_assoc_ctx1(mem_ctx, address);
	ret &= test_assoc_ctx2(mem_ctx, address);

	ret &= test_wins_replication(mem_ctx, address);

done:
	talloc_free(mem_ctx);

	return ret;
}

/*
  test WINS replication replica conflicts operations
*/
BOOL torture_nbt_winsreplication_replica(void)
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

	ctx = test_create_conflict_ctx(mem_ctx, address);
	if (!ctx) return False;

	ret &= test_conflict_same_owner(ctx);
	ret &= test_conflict_different_owner(ctx);

done:
	talloc_free(mem_ctx);

	return ret;
}

/*
  test WINS replication owned conflicts operations
*/
BOOL torture_nbt_winsreplication_owned(void)
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

	ctx = test_create_conflict_ctx(mem_ctx, address);
	if (!ctx) return False;

	ret &= test_conflict_owned_released_vs_replica(ctx);
	ret &= test_conflict_owned_active_vs_replica(ctx);

done:
	talloc_free(mem_ctx);

	return ret;
}
