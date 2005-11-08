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
#include "wrepl_server/wrepl_server.h"
#include "nbt_server/wins/winsdb.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"

/*
  open winsdb
*/
static NTSTATUS wreplsrv_open_winsdb(struct wreplsrv_service *service)
{
	service->wins_db     = winsdb_connect(service);
	if (!service->wins_db) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	return NT_STATUS_OK;
}

struct wreplsrv_partner *wreplsrv_find_partner(struct wreplsrv_service *service, const char *peer_addr)
{
	struct wreplsrv_partner *cur;

	for (cur = service->partners; cur; cur = cur->next) {
		if (strcmp(cur->address, peer_addr) == 0) {
			return cur;
		}
	}

	return NULL;
}

/*
  load our replication partners
*/
static NTSTATUS wreplsrv_load_partners(struct wreplsrv_service *service)
{
	struct ldb_result *res = NULL;
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(service);
	int i;

	/* find the record in the WINS database */
	ret = ldb_search(service->wins_db, ldb_dn_explode(tmp_ctx, "CN=PARTNERS"), LDB_SCOPE_ONELEVEL,
			 "(objectClass=wreplPartner)", NULL, &res);
	if (ret != LDB_SUCCESS) goto failed;
	talloc_steal(tmp_ctx, res);
	if (res->count == 0) goto done;

	for (i=0; i < res->count; i++) {
		struct wreplsrv_partner *partner;

		partner = talloc_zero(service, struct wreplsrv_partner);
		if (partner == NULL) goto failed;

		partner->service		= service;
		partner->address		= ldb_msg_find_string(res->msgs[i], "address", NULL);
		if (!partner->address) goto failed;
		partner->name			= ldb_msg_find_string(res->msgs[i], "name", partner->address);
		partner->type			= ldb_msg_find_uint(res->msgs[i], "type", WINSREPL_PARTNER_BOTH);
		partner->pull.interval		= ldb_msg_find_uint(res->msgs[i], "pullInterval",
								    WINSREPL_DEFAULT_PULL_INTERVAL);
		partner->pull.retry_interval	= ldb_msg_find_uint(res->msgs[i], "pullRetryInterval",
								    WINSREPL_DEFAULT_PULL_RETRY_INTERVAL);
		partner->our_address		= ldb_msg_find_string(res->msgs[i], "ourAddress", NULL);
		partner->push.change_count	= ldb_msg_find_uint(res->msgs[i], "pushChangeCount",
								    WINSREPL_DEFAULT_PUSH_CHANGE_COUNT);

		talloc_steal(partner, partner->address);
		talloc_steal(partner, partner->name);
		talloc_steal(partner, partner->our_address);

		DLIST_ADD(service->partners, partner);
	}
done:
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
failed:
	talloc_free(tmp_ctx);
	return NT_STATUS_FOOBAR;
}

BOOL wreplsrv_is_our_address(struct wreplsrv_service *service, const char *address)
{
	const char *our_address;

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;
		for(i = 0; i < num_interfaces; i++) {
			our_address = iface_n_ip(i);
			if (strcasecmp(our_address, address) == 0) {
				return True;
			}
		}
	} else {
		our_address = lp_socket_address();
		if (strcasecmp(our_address, address) == 0) {
			return True;
		}
	}

	return False;
}

uint64_t wreplsrv_local_max_version(struct wreplsrv_service *service)
{
	int ret;
	struct ldb_context *ldb = service->wins_db;
	struct ldb_dn *dn;
	struct ldb_result *res = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(service);
	uint64_t maxVersion = 0;

	dn = ldb_dn_explode(tmp_ctx, "CN=VERSION");
	if (!dn) goto failed;

	/* find the record in the WINS database */
	ret = ldb_search(ldb, dn, LDB_SCOPE_BASE, 
			 NULL, NULL, &res);
	if (ret != LDB_SUCCESS) goto failed;
	talloc_steal(tmp_ctx, res);
	if (res->count > 1) goto failed;

	if (res->count == 1) {
		maxVersion = ldb_msg_find_uint64(res->msgs[0], "maxVersion", 0);
	}

failed:
	talloc_free(tmp_ctx);
	return maxVersion;
}

NTSTATUS wreplsrv_fill_wrepl_table(struct wreplsrv_service *service,
				   TALLOC_CTX *mem_ctx,
				   struct wrepl_table *table_out,
				   const char *our_ip,
				   const char *initiator,
				   BOOL full_table)
{
	struct wreplsrv_owner *cur;
	uint64_t local_max_version;
	uint32_t i = 0;

	table_out->partner_count	= 0;
	table_out->partners		= NULL;
	table_out->initiator		= initiator;

	local_max_version = wreplsrv_local_max_version(service);
	if (local_max_version > 0) {
		table_out->partner_count++;
	}

	for (cur = service->table; full_table && cur; cur = cur->next) {
		table_out->partner_count++;
	}

	table_out->partners = talloc_array(mem_ctx, struct wrepl_wins_owner, table_out->partner_count);
	NT_STATUS_HAVE_NO_MEMORY(table_out->partners);

	if (local_max_version > 0) {
		table_out->partners[i].address		= our_ip;
		table_out->partners[i].min_version	= 0;
		table_out->partners[i].max_version	= local_max_version;
		table_out->partners[i].type		= 1;
		i++;
	}

	for (cur = service->table; full_table && cur; cur = cur->next) {
		table_out->partners[i] = cur->owner;
		i++;
	}

	return NT_STATUS_OK;
}

struct wreplsrv_owner *wreplsrv_find_owner(struct wreplsrv_owner *table, const char *wins_owner)
{
	struct wreplsrv_owner *cur;

	for (cur = table; cur; cur = cur->next) {
		if (strcmp(cur->owner.address, wins_owner) == 0) {
			return cur;
		}
	}

	return NULL;
}

/*
 update the wins_owner_table max_version, if the given version is the highest version
 if no entry for the wins_owner exists yet, create one
*/
NTSTATUS wreplsrv_add_table(struct wreplsrv_service *service,
			    TALLOC_CTX *mem_ctx, struct wreplsrv_owner **_table,
			    const char *wins_owner, uint64_t version)
{
	struct wreplsrv_owner *table = *_table;
	struct wreplsrv_owner *cur;

	if (strcmp(WINSDB_OWNER_LOCAL, wins_owner) == 0) {
		return NT_STATUS_OK;
	}

	cur = wreplsrv_find_owner(table, wins_owner);

	/* if it doesn't exists yet, create one */
	if (!cur) {
		cur = talloc_zero(mem_ctx, struct wreplsrv_owner);
		NT_STATUS_HAVE_NO_MEMORY(cur);

		cur->owner.address	= talloc_strdup(cur, wins_owner);
		NT_STATUS_HAVE_NO_MEMORY(cur->owner.address);
		cur->owner.min_version	= 0;
		cur->owner.max_version	= 0;
		cur->owner.type		= 1; /* don't know why this is always 1 */

		cur->partner		= wreplsrv_find_partner(service, wins_owner);

		DLIST_ADD(table, cur);
		*_table = table;
	}

	/* the min_version is always 0 here, and won't be updated */

	/* if the given version is higher the then current nax_version, update */
	if (cur->owner.max_version < version) {
		cur->owner.max_version = version;
	}

	return NT_STATUS_OK;
}

/*
  load the partner table
*/
static NTSTATUS wreplsrv_load_table(struct wreplsrv_service *service)
{
	struct ldb_result *res = NULL;
	int ret;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(service);
	int i;
	const char *wins_owner;
	uint64_t version;
	const char * const attrs[] = {
		"winsOwner",
		"versionID",
		NULL
	};

	/* find the record in the WINS database */
	ret = ldb_search(service->wins_db, NULL, LDB_SCOPE_SUBTREE,
			 "(objectClass=winsRecord)", attrs, &res);
	status = NT_STATUS_INTERNAL_DB_CORRUPTION;
	if (ret != LDB_SUCCESS) goto failed;
	talloc_steal(tmp_ctx, res);
	if (res->count == 0) goto done;

	for (i=0; i < res->count; i++) {
		wins_owner     = ldb_msg_find_string(res->msgs[i], "winsOwner", NULL);
		version        = ldb_msg_find_uint64(res->msgs[i], "versionID", 0);

		if (wins_owner) { 
			status = wreplsrv_add_table(service,
						    service, &service->table,
						    wins_owner, version);
			if (!NT_STATUS_IS_OK(status)) goto failed;
		}
		talloc_free(res->msgs[i]);

		/* TODO: what's abut the per address owners? */
	}
done:
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
failed:
	talloc_free(tmp_ctx);
	return status;
}

/*
  setup our replication partners
*/
static NTSTATUS wreplsrv_setup_partners(struct wreplsrv_service *service)
{
	NTSTATUS status;

	status = wreplsrv_load_partners(service);
	NT_STATUS_NOT_OK_RETURN(status);

	status = wreplsrv_load_table(service);
	NT_STATUS_NOT_OK_RETURN(status);

	status = wreplsrv_setup_out_connections(service);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

/*
  startup the wrepl task
*/
static void wreplsrv_task_init(struct task_server *task)
{
	NTSTATUS status;
	struct wreplsrv_service *service;

	service = talloc_zero(task, struct wreplsrv_service);
	if (!service) {
		task_server_terminate(task, "wreplsrv_task_init: out of memory");
		return;
	}
	service->task = task;
	task->private = service;

	/*
	 * setup up all partners, and open the winsdb
	 */
	status = wreplsrv_open_winsdb(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "wreplsrv_task_init: wreplsrv_open_winsdb() failed");
		return;
	}

	/*
	 * setup timed events for each partner we want to pull from
	 */
	status = wreplsrv_setup_partners(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "wreplsrv_task_init: wreplsrv_setup_partners() failed");
		return;
	}

	/* 
	 * setup listen sockets, so we can anwser requests from our partners,
	 * which pull from us
	 */
	status = wreplsrv_setup_sockets(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "wreplsrv_task_init: wreplsrv_setup_sockets() failed");
		return;
	}

	irpc_add_name(task->msg_ctx, "wrepl_server");
}

/*
  initialise the WREPL server
 */
static NTSTATUS wreplsrv_init(struct event_context *event_ctx, const struct model_ops *model_ops)
{
	if (!lp_wins_support()) {
		return NT_STATUS_OK;
	}

	return task_server_startup(event_ctx, model_ops, wreplsrv_task_init);
}

/*
  register ourselves as a available server
*/
NTSTATUS server_service_wrepl_init(void)
{
	return register_server_service("wrepl", wreplsrv_init);
}
