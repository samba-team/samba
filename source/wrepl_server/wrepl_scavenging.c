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
#include "librpc/gen_ndr/ndr_winsrepl.h"
#include "wrepl_server/wrepl_server.h"
#include "nbt_server/wins/winsdb.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "system/time.h"

const char *wreplsrv_owner_filter(struct wreplsrv_service *service,
				  TALLOC_CTX *mem_ctx,
				  const char *wins_owner)
{
	if (strcmp(wins_owner, service->wins_db->local_owner) == 0) {
		return talloc_asprintf(mem_ctx, "(|(winsOwner=%s)(winsOwner=0.0.0.0))",
				       wins_owner);
	}

	return talloc_asprintf(mem_ctx, "(&(winsOwner=%s)(!(winsOwner=0.0.0.0)))",
			       wins_owner);
}

static NTSTATUS wreplsrv_scavenging_owned_records(struct wreplsrv_service *service, TALLOC_CTX *tmp_mem)
{
	NTSTATUS status;
	struct winsdb_record *rec = NULL;
	struct ldb_result *res = NULL;
	const char *owner_filter;
	const char *filter;
	uint32_t i;
	int ret;
	time_t now = time(NULL);
	const char *now_timestr;
	const char *action;
	const char *old_state;
	uint32_t modify_flags;
	BOOL modify_record;
	BOOL delete_record;
	BOOL delete_tombstones;
	struct timeval tombstone_extra_time;

	now_timestr = ldb_timestring(tmp_mem, now);
	NT_STATUS_HAVE_NO_MEMORY(now_timestr);
	owner_filter = wreplsrv_owner_filter(service, tmp_mem,
					     service->wins_db->local_owner);
	NT_STATUS_HAVE_NO_MEMORY(owner_filter);
	filter = talloc_asprintf(tmp_mem,
				 "(&%s(objectClass=winsRecord)"
				 "(expireTime<=%s)(!(isStatic=1)))",
				 owner_filter, now_timestr);
	NT_STATUS_HAVE_NO_MEMORY(filter);
	ret = ldb_search(service->wins_db->ldb, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &res);
	if (ret != LDB_SUCCESS) return NT_STATUS_INTERNAL_DB_CORRUPTION;
	talloc_steal(tmp_mem, res);
	DEBUG(10,("WINS scavenging: filter '%s' count %d\n", filter, res->count));

	tombstone_extra_time = timeval_add(&service->startup_time,
					   service->config.tombstone_extra_timeout,
					   0);
	delete_tombstones = timeval_expired(&tombstone_extra_time);

	for (i=0; i < res->count; i++) {
		status = winsdb_record(service->wins_db, res->msgs[i], tmp_mem, &rec);
		NT_STATUS_NOT_OK_RETURN(status);

		if (rec->is_static) {
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (rec->expire_time > now) {
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		modify_flags	= 0;
		modify_record	= False;
		delete_record	= False;

		switch (rec->state) {
		case WREPL_STATE_ACTIVE:
			old_state	= "active";
			rec->state	= WREPL_STATE_RELEASED;
			rec->expire_time= service->config.tombstone_interval + now;
			modify_flags	= 0;
			modify_record	= True;
			break;

		case WREPL_STATE_RELEASED:
			old_state	= "released";
			rec->state	= WREPL_STATE_TOMBSTONE;
			rec->expire_time= service->config.tombstone_timeout + now;
			modify_flags	= WINSDB_FLAG_ALLOC_VERSION | WINSDB_FLAG_TAKE_OWNERSHIP;
			modify_record	= True;
			break;

		case WREPL_STATE_TOMBSTONE:
			old_state	= "tombstone";
			if (!delete_tombstones) break;
			delete_record = True;
			break;

		case WREPL_STATE_RESERVED:
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (modify_record) {
			action = "modify";
			ret = winsdb_modify(service->wins_db, rec, modify_flags);
		} else if (delete_record) {
			action = "delete";
			ret = winsdb_delete(service->wins_db, rec);
		} else {
			action = "skip";
			ret = NBT_RCODE_OK;
		}

		if (ret != NBT_RCODE_OK) {
			DEBUG(1,("WINS scavenging: failed to %s name %s (owned:%s): error:%u\n",
				action, nbt_name_string(rec, rec->name), old_state, ret));
		} else {
			DEBUG(4,("WINS scavenging: %s name: %s (owned:%s)\n",
				action, nbt_name_string(rec, rec->name), old_state));
		}

		talloc_free(rec);
	}

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_scavenging_replica_non_active_records(struct wreplsrv_service *service, TALLOC_CTX *tmp_mem)
{
	NTSTATUS status;
	struct winsdb_record *rec = NULL;
	struct ldb_result *res = NULL;
	const char *owner_filter;
	const char *filter;
	uint32_t i;
	int ret;
	time_t now = time(NULL);
	const char *now_timestr;
	const char *action;
	const char *old_state;
	uint32_t modify_flags;
	BOOL modify_record;
	BOOL delete_record;
	BOOL delete_tombstones;
	struct timeval tombstone_extra_time;

	now_timestr = ldb_timestring(tmp_mem, now);
	NT_STATUS_HAVE_NO_MEMORY(now_timestr);
	owner_filter = wreplsrv_owner_filter(service, tmp_mem,
					     service->wins_db->local_owner);
	NT_STATUS_HAVE_NO_MEMORY(owner_filter);
	filter = talloc_asprintf(tmp_mem,
				 "(&(!%s)(objectClass=winsRecord)"
				 "(!(recordState=%u))(expireTime<=%s)(!(isStatic=1)))",
				 owner_filter, WREPL_STATE_ACTIVE, now_timestr);
	NT_STATUS_HAVE_NO_MEMORY(filter);
	ret = ldb_search(service->wins_db->ldb, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &res);
	if (ret != LDB_SUCCESS) return NT_STATUS_INTERNAL_DB_CORRUPTION;
	talloc_steal(tmp_mem, res);
	DEBUG(10,("WINS scavenging: filter '%s' count %d\n", filter, res->count));

	tombstone_extra_time = timeval_add(&service->startup_time,
					   service->config.tombstone_extra_timeout,
					   0);
	delete_tombstones = timeval_expired(&tombstone_extra_time);

	for (i=0; i < res->count; i++) {
		status = winsdb_record(service->wins_db, res->msgs[i], tmp_mem, &rec);
		NT_STATUS_NOT_OK_RETURN(status);

		if (rec->is_static) {
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (rec->expire_time > now) {
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		modify_flags	= 0;
		modify_record	= False;
		delete_record	= False;

		switch (rec->state) {
		case WREPL_STATE_ACTIVE:
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;

		case WREPL_STATE_RELEASED:
			old_state	= "released";
			rec->state	= WREPL_STATE_TOMBSTONE;
			rec->expire_time= service->config.tombstone_timeout + now;
			modify_flags	= 0;
			modify_record	= True;
			break;

		case WREPL_STATE_TOMBSTONE:
			old_state	= "tombstone";
			if (!delete_tombstones) break;
			delete_record = True;
			break;

		case WREPL_STATE_RESERVED:
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (modify_record) {
			action = "modify";
			ret = winsdb_modify(service->wins_db, rec, modify_flags);
		} else if (delete_record) {
			action = "delete";
			ret = winsdb_delete(service->wins_db, rec);
		} else {
			action = "skip";
			ret = NBT_RCODE_OK;
		}

		if (ret != NBT_RCODE_OK) {
			DEBUG(1,("WINS scavenging: failed to %s name %s (replica:%s): error:%u\n",
				action, nbt_name_string(rec, rec->name), old_state, ret));
		} else {
			DEBUG(4,("WINS scavenging: %s name: %s (replica:%s)\n",
				action, nbt_name_string(rec, rec->name), old_state));
		}

		talloc_free(rec);
	}

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_scavenging_replica_active_records(struct wreplsrv_service *service, TALLOC_CTX *tmp_mem)
{
	NTSTATUS status;
	struct winsdb_record *rec = NULL;
	struct ldb_result *res = NULL;
	const char *owner_filter;
	const char *filter;
	uint32_t i;
	int ret;
	time_t now = time(NULL);
	const char *now_timestr;
	const char *action;
	const char *old_state;
	BOOL modify_flags;
	BOOL modify_record;
	BOOL delete_record;

	now_timestr = ldb_timestring(tmp_mem, now);
	NT_STATUS_HAVE_NO_MEMORY(now_timestr);
	owner_filter = wreplsrv_owner_filter(service, tmp_mem,
					     service->wins_db->local_owner);
	NT_STATUS_HAVE_NO_MEMORY(owner_filter);
	filter = talloc_asprintf(tmp_mem,
				 "(&(!%s)(objectClass=winsRecord)"
				 "(recordState=%u)(expireTime<=%s)(!(isStatic=1)))",
				 owner_filter, WREPL_STATE_ACTIVE, now_timestr);
	NT_STATUS_HAVE_NO_MEMORY(filter);
	ret = ldb_search(service->wins_db->ldb, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &res);
	if (ret != LDB_SUCCESS) return NT_STATUS_INTERNAL_DB_CORRUPTION;
	talloc_steal(tmp_mem, res);
	DEBUG(10,("WINS scavenging: filter '%s' count %d\n", filter, res->count));

	for (i=0; i < res->count; i++) {
		status = winsdb_record(service->wins_db, res->msgs[i], tmp_mem, &rec);
		NT_STATUS_NOT_OK_RETURN(status);

		if (rec->is_static) {
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (rec->expire_time > now) {
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (rec->state != WREPL_STATE_ACTIVE) {
			DEBUG(0,("%s: corrupted record: %s\n",
				__location__, nbt_name_string(rec, rec->name)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		old_state = "active";

		modify_flags	= 0;
		modify_record	= False;
		delete_record	= False;

		/* 
		 * TODO: ask the owning wins server if the record still exists,
		 *       if not delete the record
		 */
		DEBUG(0,("TODO: ask wins server '%s' if '%s' with version_id:%llu still exists\n",
			rec->wins_owner, nbt_name_string(rec, rec->name), rec->version));

		if (modify_record) {
			action = "modify";
			ret = winsdb_modify(service->wins_db, rec, modify_flags);
		} else if (delete_record) {
			action = "delete";
			ret = winsdb_delete(service->wins_db, rec);
		} else {
			action = "skip";
			ret = NBT_RCODE_OK;
		}

		if (ret != NBT_RCODE_OK) {
			DEBUG(1,("WINS scavenging: failed to %s name %s (replica:%s): error:%u\n",
				action, nbt_name_string(rec, rec->name), old_state, ret));
		} else {
			DEBUG(4,("WINS scavenging: %s name: %s (replica:%s)\n",
				action, nbt_name_string(rec, rec->name), old_state));
		}

		talloc_free(rec);
	}

	return NT_STATUS_OK;
}

NTSTATUS wreplsrv_scavenging_run(struct wreplsrv_service *service)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_mem;

	if (!timeval_expired(&service->scavenging.next_run)) {
		return NT_STATUS_OK;
	}

	service->scavenging.next_run = timeval_current_ofs(service->config.scavenging_interval, 0);
	status = wreplsrv_periodic_schedule(service, service->config.scavenging_interval);
	NT_STATUS_NOT_OK_RETURN(status);

	if (service->scavenging.processing) {
		return NT_STATUS_OK;
	}

	DEBUG(4,("wreplsrv_scavenging_run(): start\n"));

	tmp_mem = talloc_new(service);
	service->scavenging.processing = True;
	status = wreplsrv_scavenging_owned_records(service,tmp_mem);
	service->scavenging.processing = False;
	talloc_free(tmp_mem);
	NT_STATUS_NOT_OK_RETURN(status);

	tmp_mem = talloc_new(service);	
	service->scavenging.processing = True;
	status = wreplsrv_scavenging_replica_non_active_records(service, tmp_mem);
	service->scavenging.processing = False;
	talloc_free(tmp_mem);
	NT_STATUS_NOT_OK_RETURN(status);

	tmp_mem = talloc_new(service);
	service->scavenging.processing = True;
	status = wreplsrv_scavenging_replica_active_records(service, tmp_mem);
	service->scavenging.processing = False;
	talloc_free(tmp_mem);
	NT_STATUS_NOT_OK_RETURN(status);

	DEBUG(4,("wreplsrv_scavenging_run(): end\n"));

	return NT_STATUS_OK;
}
