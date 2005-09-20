/* 
   Unix SMB/CIFS implementation.
   
   WINS Replication server
   
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
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_winsrepl.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "wrepl_server/wrepl_server.h"
#include "nbt_server/wins/winsdb.h"
#include "lib/ldb/include/ldb.h"

static NTSTATUS wreplsrv_in_start_association(struct wreplsrv_in_call *call)
{
	struct wrepl_start *start	= &call->req_packet.message.start;
	struct wrepl_start *start_reply	= &call->rep_packet.message.start_reply;

	if (call->req_packet.opcode & WREPL_OPCODE_BITS) {
		/*
		 *if the assoc_ctx doesn't match ignore the packet
		 */
		if ((call->req_packet.assoc_ctx != call->wreplconn->assoc_ctx.our_ctx)
		   && (call->req_packet.assoc_ctx != 0)) {
			return ERROR_INVALID_PARAMETER;
		}
	} else {
		call->wreplconn->assoc_ctx.our_ctx = WREPLSRV_INVALID_ASSOC_CTX;
		return NT_STATUS_OK;
	}

	if (start->minor_version != 2 || start->major_version != 5) {
		/* w2k terminate the connection if the versions doesn't match */
		return NT_STATUS_UNKNOWN_REVISION;
	}

	call->wreplconn->assoc_ctx.stopped	= False;
	call->wreplconn->assoc_ctx.our_ctx	= WREPLSRV_VALID_ASSOC_CTX;
	call->wreplconn->assoc_ctx.peer_ctx	= start->assoc_ctx;

	call->rep_packet.mess_type		= WREPL_START_ASSOCIATION_REPLY;
	start_reply->assoc_ctx			= call->wreplconn->assoc_ctx.our_ctx;
	start_reply->minor_version		= 2;
	start_reply->major_version		= 5;

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_in_stop_assoc_ctx(struct wreplsrv_in_call *call)
{
	struct wrepl_stop *stop_out		= &call->rep_packet.message.stop;

	call->wreplconn->assoc_ctx.stopped	= True;

	call->rep_packet.mess_type		= WREPL_STOP_ASSOCIATION;
	stop_out->reason			= 4;

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_in_stop_association(struct wreplsrv_in_call *call)
{
	/*
	 * w2k only check the assoc_ctx if the opcode has the 0x00007800 bits are set
	 */
	if (call->req_packet.opcode & WREPL_OPCODE_BITS) {
		/*
		 *if the assoc_ctx doesn't match ignore the packet
		 */
		if (call->req_packet.assoc_ctx != call->wreplconn->assoc_ctx.our_ctx) {
			return ERROR_INVALID_PARAMETER;
		}
		/* when the opcode bits are set the connection should be directly terminated */
		return NT_STATUS_CONNECTION_RESET;
	}

	if (call->wreplconn->assoc_ctx.stopped) {
		/* this causes the connection to be directly terminated */
		return NT_STATUS_CONNECTION_RESET;
	}

	/* this will cause to not receive packets anymore and terminate the connection if the reply is send */
	call->wreplconn->terminate = True;
	return wreplsrv_in_stop_assoc_ctx(call);
}

static NTSTATUS wreplsrv_in_table_query(struct wreplsrv_in_call *call)
{
	struct wreplsrv_service *service = call->wreplconn->service;
	struct wrepl_replication *repl_out = &call->rep_packet.message.replication;
	struct wrepl_table *table_out = &call->rep_packet.message.replication.info.table;
	struct wreplsrv_owner *cur;
	uint64_t local_max_version;
	uint32_t i = 0;

	repl_out->command = WREPL_REPL_TABLE_REPLY;

	table_out->partner_count	= 0;
	table_out->partners		= NULL;
	table_out->initiator		= WINSDB_OWNER_LOCAL;

	local_max_version = wreplsrv_local_max_version(service);
	if (local_max_version > 0) {
		table_out->partner_count++;
	}

	for (cur = service->table; cur; cur = cur->next) {
		table_out->partner_count++;
	}

	table_out->partners = talloc_array(call, struct wrepl_wins_owner, table_out->partner_count);
	NT_STATUS_HAVE_NO_MEMORY(table_out->partners);

	if (local_max_version > 0) {
		table_out->partners[i].address		= call->wreplconn->our_ip;
		table_out->partners[i].min_version	= 0;
		table_out->partners[i].max_version	= local_max_version;
		table_out->partners[i].type		= 1;
		i++;
	}

	for (cur = service->table; cur; cur = cur->next) {
		table_out->partners[i] = cur->owner;
		i++;
	}

	return NT_STATUS_OK;
}

static int wreplsrv_in_sort_wins_name(struct wrepl_wins_name *n1,
				      struct wrepl_wins_name *n2)
{
	if (n1->id < n2->id) return -1;
	if (n1->id > n2->id) return 1;
	return 0;
}

static NTSTATUS wreplsrv_record2wins_name(TALLOC_CTX *mem_ctx, struct wrepl_wins_name *name, struct winsdb_record *rec)
{
	uint8_t *namebuf;
	uint32_t namebuf_len;
	uint32_t name_len;

	name_len = strlen(rec->name->name);
	if (name_len > 15) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	namebuf = (uint8_t *)talloc_asprintf(mem_ctx, "%-15s%c%s",
					    rec->name->name, 'X',
					    (rec->name->scope?rec->name->scope:""));
	NT_STATUS_HAVE_NO_MEMORY(namebuf);
	namebuf_len = strlen((char *)namebuf) + 1;

	/*
	 * we need to set the type here, and use a place-holder in the talloc_asprintf()
	 * as the type can be 0x00, and then the namebuf_len = strlen(namebuf); would give wrong results
	 */
	namebuf[15] = rec->name->type;

	/* oh wow, what a nasty bug in windows ... */
	if (rec->name->type == 0x1b) {
		namebuf[15] = namebuf[0];
		namebuf[0] = 0x1b;
	}

	name->name_len		= namebuf_len;
	name->name		= namebuf;
	name->id		= rec->version;
	name->unknown		= WINSDB_GROUP_ADDRESS;

	name->flags		= rec->nb_flags;
	name->group_flag	= 0;

	switch (name->flags & 2) {
	case 0:
		name->addresses.ip			= rec->addresses[0]->address;
		talloc_steal(mem_ctx, rec->addresses[0]->address);
		break;
	case 2:
		name->addresses.addresses.num_ips	= 0;
		name->addresses.addresses.ips		= NULL;
		break;
	}

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_in_send_request(struct wreplsrv_in_call *call)
{
	struct wreplsrv_service *service = call->wreplconn->service;
	struct wrepl_wins_owner *owner_in = &call->req_packet.message.replication.info.owner;
	struct wrepl_replication *repl_out = &call->rep_packet.message.replication;
	struct wrepl_send_reply *reply_out = &call->rep_packet.message.replication.info.reply;
	struct wreplsrv_owner local_owner;
	struct wreplsrv_owner *owner;
	const char *filter;
	struct ldb_message **res = NULL;
	int ret;
	struct wrepl_wins_name *names;
	struct winsdb_record *rec;
	NTSTATUS status;
	uint32_t i;

	if (strcmp(call->wreplconn->our_ip, owner_in->address) == 0) {
		ZERO_STRUCT(local_owner);
		local_owner.owner.address	= WINSDB_OWNER_LOCAL;
		local_owner.owner.min_version	= 0;
		local_owner.owner.max_version	= wreplsrv_local_max_version(service);
		local_owner.owner.type		= 1;
		owner = &local_owner;
	} else {
		owner = wreplsrv_find_owner(service->table, owner_in->address);
	}

	repl_out->command	= WREPL_REPL_SEND_REPLY;
	reply_out->num_names	= 0;
	reply_out->names	= NULL;

	/*
	 * if we didn't know this owner, must be a bug in the partners client code...
	 * return an empty list.
	 */
	if (!owner) {
		return NT_STATUS_OK;
	}

	/*
	 * if the partner ask for nothing, or give invalid ranges,
	 * return an empty list.
	 */
	if (owner_in->min_version >= owner_in->max_version) {
		return NT_STATUS_OK;
	}

	/*
	 * if the partner has already all records for nothing, or give invalid ranges,
	 * return an empty list.
	 */
	if (owner_in->min_version >= owner->owner.max_version) {
		return NT_STATUS_OK;
	}

	filter = talloc_asprintf(call, "(&(winsOwner=%s)(objectClass=winsRecord)(state>=%u)(versionID>=%llu)(versionID<=%llu))",
				 owner->owner.address, WINS_REC_ACTIVE, owner_in->min_version, owner_in->max_version);
	NT_STATUS_HAVE_NO_MEMORY(filter);
	ret = ldb_search(service->wins_db, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &res);
	if (res != NULL) {
		talloc_steal(call, res);
	}
	if (ret < 0) return  NT_STATUS_INTERNAL_DB_CORRUPTION;
	if (ret == 0) return NT_STATUS_OK;

	names = talloc_array(call, struct wrepl_wins_name, ret);
	NT_STATUS_HAVE_NO_MEMORY(names);

	for (i=0; i < ret; i++) {
		status = winsdb_record(res[i], NULL, call, &rec);
		NT_STATUS_NOT_OK_RETURN(status);

		status = wreplsrv_record2wins_name(names, &names[i], rec);
		NT_STATUS_NOT_OK_RETURN(status);
		talloc_free(rec);
		talloc_free(res[i]);
	}

	/* sort the names before we send them */
	qsort(names, ret, sizeof(struct wrepl_wins_name), (comparison_fn_t)wreplsrv_in_sort_wins_name);

	reply_out->num_names	= ret;
	reply_out->names	= names;

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_in_replication(struct wreplsrv_in_call *call)
{
	struct wrepl_replication *repl_in = &call->req_packet.message.replication;
	NTSTATUS status;

	/*
	 * w2k only check the assoc_ctx if the opcode has the 0x00007800 bits are set
	 */
	if (call->req_packet.opcode & WREPL_OPCODE_BITS) {
		/*
		 *if the assoc_ctx doesn't match ignore the packet
		 */
		if (call->req_packet.assoc_ctx != call->wreplconn->assoc_ctx.our_ctx) {
			return ERROR_INVALID_PARAMETER;
		}
	}

	if (!call->wreplconn->partner) {
		return wreplsrv_in_stop_assoc_ctx(call);
	}

	switch (repl_in->command) {
		case WREPL_REPL_TABLE_QUERY:
			status = wreplsrv_in_table_query(call);
			break;

		case WREPL_REPL_TABLE_REPLY:
			return ERROR_INVALID_PARAMETER;

		case WREPL_REPL_SEND_REQUEST:
			status = wreplsrv_in_send_request(call);
			break;

		case WREPL_REPL_SEND_REPLY:
			return ERROR_INVALID_PARAMETER;
	
		case WREPL_REPL_UPDATE:
			return ERROR_INVALID_PARAMETER;

		case WREPL_REPL_5:
			return ERROR_INVALID_PARAMETER;

		case WREPL_REPL_INFORM:
			return ERROR_INVALID_PARAMETER;

		case WREPL_REPL_9:
			return ERROR_INVALID_PARAMETER;

		default:
			return ERROR_INVALID_PARAMETER;
	}

	if (NT_STATUS_IS_OK(status)) {
		call->rep_packet.mess_type = WREPL_REPLICATION;
	}

	return status;
}

static NTSTATUS wreplsrv_in_invalid_assoc_ctx(struct wreplsrv_in_call *call)
{
	struct wrepl_start *start	= &call->rep_packet.message.start;

	call->rep_packet.opcode		= 0x00008583;
	call->rep_packet.assoc_ctx	= 0;
	call->rep_packet.mess_type	= WREPL_START_ASSOCIATION;

	start->assoc_ctx		= 0x0000000a;
	start->minor_version		= 0x0001;
	start->major_version		= 0x0000;

	call->rep_packet.padding	= data_blob_talloc(call, NULL, 4);
	memset(call->rep_packet.padding.data, '\0', call->rep_packet.padding.length);

	return NT_STATUS_OK;
}

NTSTATUS wreplsrv_in_call(struct wreplsrv_in_call *call)
{
	NTSTATUS status;

	if (!(call->req_packet.opcode & WREPL_OPCODE_BITS)
	    && (call->wreplconn->assoc_ctx.our_ctx == WREPLSRV_INVALID_ASSOC_CTX)) {
		return wreplsrv_in_invalid_assoc_ctx(call);
	}

	switch (call->req_packet.mess_type) {
		case WREPL_START_ASSOCIATION:
			status = wreplsrv_in_start_association(call);
			break;
		case WREPL_START_ASSOCIATION_REPLY:
			/* this is not valid here, so we ignore it */
			return ERROR_INVALID_PARAMETER;

		case WREPL_STOP_ASSOCIATION:
			status = wreplsrv_in_stop_association(call);
			break;

		case WREPL_REPLICATION:
			status = wreplsrv_in_replication(call);
			break;
		default:
			/* everythingelse is also not valid here, so we ignore it */
			return ERROR_INVALID_PARAMETER;
	}

	if (call->wreplconn->assoc_ctx.our_ctx == WREPLSRV_INVALID_ASSOC_CTX) {
		return wreplsrv_in_invalid_assoc_ctx(call);
	}

	if (NT_STATUS_IS_OK(status)) {
		call->rep_packet.opcode		= WREPL_OPCODE_BITS;
		call->rep_packet.assoc_ctx	= call->wreplconn->assoc_ctx.peer_ctx;
	}

	return status;
}
