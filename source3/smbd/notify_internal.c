/*
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2006
   Copyright (C) Volker Lendecke 2012

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  this is the change notify database. It implements mechanisms for
  storing current change notify waiters in a tdb, and checking if a
  given event matches any of the stored notify waiiters.
*/

#include "includes.h"
#include "system/filesys.h"
#include "librpc/gen_ndr/ndr_notify.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "dbwrap/dbwrap_tdb.h"
#include "smbd/smbd.h"
#include "messages.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "util_tdb.h"
#include "lib/param/param.h"
#include "lib/dbwrap/dbwrap_cache.h"
#include "ctdb_srvids.h"
#include "ctdbd_conn.h"
#include "ctdb_conn.h"
#include "lib/util/tevent_unix.h"

struct notify_list {
	struct notify_list *next, *prev;
	const char *path;
	void (*callback)(void *, const struct notify_event *);
	void *private_data;
};

struct notify_context {
	struct messaging_context *msg;
	struct notify_list *list;

	/*
	 * The notify database is split up into two databases: One
	 * relatively static index db and the real notify db with the
	 * volatile entries.
	 */

	/*
	 * "db_notify" is indexed by pathname. Per record it stores an
	 * array of notify_db_entry structs. These represent the
	 * notify records as requested by the smb client. This
	 * database is always held locally, it is never clustered.
	 */
	struct db_context *db_notify;

	/*
	 * "db_index" is indexed by pathname. The records are an array
	 * of VNNs which have any interest in notifies for this path
	 * name.
	 *
	 * In the non-clustered case this database is cached in RAM by
	 * means of db_cache_open, which maintains a cache per
	 * process. Cache consistency is maintained by the tdb
	 * sequence number.
	 *
	 * In the clustered case right now we can not use the tdb
	 * sequence number, but by means of read only records we
	 * should be able to avoid a lot of full migrations.
	 *
	 * In both cases, it is important to keep the update
	 * operations to db_index to a minimum. This is achieved by
	 * delayed deletion. When a db_notify is initially created,
	 * the db_index record is also created. When more notifies are
	 * add for a path, then only the db_notify record needs to be
	 * modified, the db_index record is not touched. When the last
	 * entry from the db_notify record is deleted, the db_index
	 * record is not immediately deleted. Instead, the db_notify
	 * record is replaced with a current timestamp. A regular
	 * cleanup process will delete all db_index records that are
	 * older than a minute.
	 */
	struct db_context *db_index;
};

static void notify_trigger_local(struct notify_context *notify,
				 uint32_t action, uint32_t filter,
				 const char *path, size_t path_len,
				 bool recursive);
static NTSTATUS notify_send(struct notify_context *notify,
			    struct server_id *pid,
			    const char *path, uint32_t action,
			    void *private_data);
static NTSTATUS notify_add_entry(struct db_record *rec,
				 const struct notify_db_entry *e,
				 bool *p_add_idx);
static NTSTATUS notify_add_idx(struct db_record *rec, uint32_t vnn);

static NTSTATUS notify_del_entry(struct db_record *rec,
				 const struct server_id *pid,
				 void *private_data);
static NTSTATUS notify_del_idx(struct db_record *rec, uint32_t vnn);

static int notify_context_destructor(struct notify_context *notify);

static void notify_handler(struct messaging_context *msg_ctx,
			   void *private_data, uint32_t msg_type,
			   struct server_id server_id, DATA_BLOB *data);

struct notify_context *notify_init(TALLOC_CTX *mem_ctx,
				   struct messaging_context *msg,
				   struct event_context *ev)
{
	struct loadparm_context *lp_ctx;
	struct notify_context *notify;

	notify = talloc(mem_ctx, struct notify_context);
	if (notify == NULL) {
		goto fail;
	}
	notify->msg = msg;
	notify->list = NULL;

	lp_ctx = loadparm_init_s3(notify, loadparm_s3_helpers());
	notify->db_notify = db_open_tdb(
		notify, lp_ctx, lock_path("notify.tdb"),
		0, TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
		O_RDWR|O_CREAT, 0644, DBWRAP_LOCK_ORDER_2);
		talloc_unlink(notify, lp_ctx);
	if (notify->db_notify == NULL) {
		goto fail;
	}
	notify->db_index = db_open(
		notify, lock_path("notify_index.tdb"),
		0, TDB_SEQNUM|TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
		O_RDWR|O_CREAT, 0644, DBWRAP_LOCK_ORDER_3);
	if (notify->db_index == NULL) {
		goto fail;
	}
	if (!lp_clustering()) {
		notify->db_index = db_open_cache(notify, notify->db_index);
		if (notify->db_index == NULL) {
			goto fail;
		}
	}

	if (notify->msg != NULL) {
		NTSTATUS status;

		status = messaging_register(notify->msg, notify,
					    MSG_PVFS_NOTIFY, notify_handler);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("messaging_register returned %s\n",
				  nt_errstr(status)));
			goto fail;
		}
	}

	talloc_set_destructor(notify, notify_context_destructor);

	return notify;
fail:
	TALLOC_FREE(notify);
	return NULL;
}

static int notify_context_destructor(struct notify_context *notify)
{
	DEBUG(10, ("notify_context_destructor called\n"));

	if (notify->msg != NULL) {
		messaging_deregister(notify->msg, MSG_PVFS_NOTIFY, notify);
	}

	while (notify->list != NULL) {
		DEBUG(10, ("Removing private_data=%p\n",
			   notify->list->private_data));
		notify_remove(notify, notify->list->private_data);
	}
	return 0;
}

NTSTATUS notify_add(struct notify_context *notify,
		    const char *path, uint32_t filter, uint32_t subdir_filter,
		    void (*callback)(void *, const struct notify_event *),
		    void *private_data)
{
	struct notify_db_entry e;
	struct notify_list *listel;
	struct db_record *notify_rec, *idx_rec;
	bool add_idx;
	NTSTATUS status;
	TDB_DATA key, notify_copy;

	if (notify == NULL) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	DEBUG(10, ("notify_add: path=[%s], private_data=%p\n", path,
		   private_data));

	listel = talloc(notify, struct notify_list);
	if (listel == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	listel->callback = callback;
	listel->private_data = private_data;
	listel->path = talloc_strdup(listel, path);
	if (listel->path == NULL) {
		TALLOC_FREE(listel);
		return NT_STATUS_NO_MEMORY;
	}
	DLIST_ADD(notify->list, listel);

	ZERO_STRUCT(e);
	e.filter = filter;
	e.subdir_filter = subdir_filter;
	e.server = messaging_server_id(notify->msg);
	e.private_data = private_data;

	key = string_tdb_data(path);

	notify_rec = dbwrap_fetch_locked(notify->db_notify,
					 talloc_tos(), key);
	if (notify_rec == NULL) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}

	/*
	 * Make a copy of the notify_rec for easy restore in case
	 * updating the index_rec fails;
	 */
	notify_copy = dbwrap_record_get_value(notify_rec);
	if (notify_copy.dsize != 0) {
		notify_copy.dptr = (uint8_t *)talloc_memdup(
			notify_rec, notify_copy.dptr,
			notify_copy.dsize);
		if (notify_copy.dptr == NULL) {
			TALLOC_FREE(notify_rec);
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(notify_db_entry, &e);
	}

	status = notify_add_entry(notify_rec, &e, &add_idx);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}
	if (!add_idx) {
		/*
		 * Someone else has added the idx entry already
		 */
		TALLOC_FREE(notify_rec);
		return NT_STATUS_OK;
	}

	idx_rec = dbwrap_fetch_locked(notify->db_index,
				      talloc_tos(), key);
	if (idx_rec == NULL) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto restore_notify;
	}
	status = notify_add_idx(idx_rec, get_my_vnn());
	if (!NT_STATUS_IS_OK(status)) {
		goto restore_notify;
	}

	TALLOC_FREE(idx_rec);
	TALLOC_FREE(notify_rec);
	return NT_STATUS_OK;

restore_notify:
	if (notify_copy.dsize != 0) {
		dbwrap_record_store(notify_rec, notify_copy, 0);
	} else {
		dbwrap_record_delete(notify_rec);
	}
	TALLOC_FREE(notify_rec);
fail:
	DLIST_REMOVE(notify->list, listel);
	TALLOC_FREE(listel);
	return status;
}

static NTSTATUS notify_add_entry(struct db_record *rec,
				 const struct notify_db_entry *e,
				 bool *p_add_idx)
{
	TDB_DATA value = dbwrap_record_get_value(rec);
	struct notify_db_entry *entries;
	size_t num_entries;
	bool add_idx = true;
	NTSTATUS status;

	if (value.dsize == sizeof(time_t)) {
		DEBUG(10, ("Re-using deleted entry\n"));
		value.dsize = 0;
		add_idx = false;
	}

	if ((value.dsize % sizeof(struct notify_db_entry)) != 0) {
		DEBUG(1, ("Invalid value.dsize = %u\n",
			  (unsigned)value.dsize));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	num_entries = value.dsize / sizeof(struct notify_db_entry);

	if (num_entries != 0) {
		add_idx = false;
	}

	entries = talloc_array(rec, struct notify_db_entry, num_entries + 1);
	if (entries == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(entries, value.dptr, value.dsize);

	entries[num_entries] = *e;
	value = make_tdb_data((uint8_t *)entries, talloc_get_size(entries));
	status = dbwrap_record_store(rec, value, 0);
	TALLOC_FREE(entries);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	*p_add_idx = add_idx;
	return NT_STATUS_OK;
}

static NTSTATUS notify_add_idx(struct db_record *rec, uint32_t vnn)
{
	TDB_DATA value = dbwrap_record_get_value(rec);
	uint32_t *vnns;
	size_t i, num_vnns;
	NTSTATUS status;

	if ((value.dsize % sizeof(uint32_t)) != 0) {
		DEBUG(1, ("Invalid value.dsize = %u\n",
			  (unsigned)value.dsize));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	num_vnns = value.dsize / sizeof(uint32_t);
	vnns = (uint32_t *)value.dptr;

	for (i=0; i<num_vnns; i++) {
		if (vnns[i] == vnn) {
			return NT_STATUS_OK;
		}
		if (vnns[i] > vnn) {
			break;
		}
	}

	value.dptr = (uint8_t *)talloc_realloc(
		rec, value.dptr, uint32_t, num_vnns + 1);
	if (value.dptr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	value.dsize = talloc_get_size(value.dptr);

	vnns = (uint32_t *)value.dptr;

	memmove(&vnns[i+1], &vnns[i], sizeof(uint32_t) * (num_vnns - i));
	vnns[i] = vnn;

	status = dbwrap_record_store(rec, value, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return NT_STATUS_OK;
}

NTSTATUS notify_remove(struct notify_context *notify, void *private_data)
{
	struct server_id pid;
	struct notify_list *listel;
	struct db_record *notify_rec;
	NTSTATUS status;

	if ((notify == NULL) || (notify->msg == NULL)) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	DEBUG(10, ("notify_remove: private_data=%p\n", private_data));

	pid = messaging_server_id(notify->msg);

	for (listel=notify->list;listel;listel=listel->next) {
		if (listel->private_data == private_data) {
			DLIST_REMOVE(notify->list, listel);
			break;
		}
	}
	if (listel == NULL) {
		DEBUG(10, ("%p not found\n", private_data));
		return NT_STATUS_NOT_FOUND;
	}
	notify_rec = dbwrap_fetch_locked(notify->db_notify, talloc_tos(),
					 string_tdb_data(listel->path));
	TALLOC_FREE(listel);
	if (notify_rec == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	status = notify_del_entry(notify_rec, &pid, private_data);
	DEBUG(10, ("del_entry returned %s\n", nt_errstr(status)));
	TALLOC_FREE(notify_rec);
	return status;
}

static NTSTATUS notify_del_entry(struct db_record *rec,
				 const struct server_id *pid,
				 void *private_data)
{
	TDB_DATA value = dbwrap_record_get_value(rec);
	struct notify_db_entry *entries;
	size_t i, num_entries;
	time_t now;

	DEBUG(10, ("del_entry called for %s %p\n", procid_str_static(pid),
		   private_data));

	if ((value.dsize % sizeof(struct notify_db_entry)) != 0) {
		DEBUG(1, ("Invalid value.dsize = %u\n",
			  (unsigned)value.dsize));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	num_entries = value.dsize / sizeof(struct notify_db_entry);
	entries = (struct notify_db_entry *)value.dptr;

	for (i=0; i<num_entries; i++) {
		struct notify_db_entry *e = &entries[i];

		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(notify_db_entry, e);
		}

		if (e->private_data != private_data) {
			continue;
		}
		if (serverid_equal(&e->server, pid)) {
			break;
		}
	}
	if (i == num_entries) {
		return NT_STATUS_NOT_FOUND;
	}
	entries[i] = entries[num_entries-1];
	value.dsize -= sizeof(struct notify_db_entry);

	if (value.dsize == 0) {
		now = time(NULL);
		value.dptr = (uint8_t *)&now;
		value.dsize = sizeof(now);
	}
	return dbwrap_record_store(rec, value, 0);
}

struct notify_trigger_index_state {
	TALLOC_CTX *mem_ctx;
	uint32_t *vnns;
	uint32_t my_vnn;
	bool found_my_vnn;
};

static void notify_trigger_index_parser(TDB_DATA key, TDB_DATA data,
					void *private_data)
{
	struct notify_trigger_index_state *state =
		(struct notify_trigger_index_state *)private_data;
	uint32_t *new_vnns;
	size_t i, num_vnns, num_new_vnns;

	if ((data.dsize % sizeof(uint32_t)) != 0) {
		DEBUG(1, ("Invalid record size in notify index db: %u\n",
			  (unsigned)data.dsize));
		return;
	}
	new_vnns = (uint32_t *)data.dptr;
	num_new_vnns = data.dsize / sizeof(uint32_t);

	num_vnns = talloc_array_length(state->vnns);

	for (i=0; i<num_new_vnns; i++) {
		if (new_vnns[i] == state->my_vnn) {
			state->found_my_vnn = true;
		}
	}

	state->vnns = talloc_realloc(state->mem_ctx, state->vnns, uint32_t,
				     num_vnns + num_new_vnns);
	if ((num_vnns + num_new_vnns != 0) && (state->vnns == NULL)) {
		DEBUG(1, ("talloc_realloc failed\n"));
		return;
	}
	memcpy(&state->vnns[num_vnns], data.dptr, data.dsize);
}

static int vnn_cmp(const void *p1, const void *p2)
{
	const uint32_t *vnn1 = (const uint32_t *)p1;
	const uint32_t *vnn2 = (const uint32_t *)p2;

	if (*vnn1 < *vnn2) {
		return -1;
	}
	if (*vnn1 == *vnn2) {
		return 0;
	}
	return 1;
}

static bool notify_push_remote_blob(TALLOC_CTX *mem_ctx, uint32_t action,
				    uint32_t filter, const char *path,
				    uint8_t **pblob, size_t *pblob_len)
{
	struct notify_remote_event ev;
	DATA_BLOB data;
	enum ndr_err_code ndr_err;

	ev.action = action;
	ev.filter = filter;
	ev.path = path;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(notify_remote_event, &ev);
	}

	ndr_err = ndr_push_struct_blob(
		&data, mem_ctx, &ev,
		(ndr_push_flags_fn_t)ndr_push_notify_remote_event);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}
	*pblob = data.data;
	*pblob_len = data.length;
	return true;
}

static bool notify_pull_remote_blob(TALLOC_CTX *mem_ctx,
				    const uint8_t *blob, size_t blob_len,
				    uint32_t *paction, uint32_t *pfilter,
				    char **path)
{
	struct notify_remote_event *ev;
	enum ndr_err_code ndr_err;
	DATA_BLOB data;
	char *p;

	data.data = discard_const_p(uint8_t, blob);
	data.length = blob_len;

	ev = talloc(mem_ctx, struct notify_remote_event);
	if (ev == NULL) {
		return false;
	}

	ndr_err = ndr_pull_struct_blob(
		&data, ev, ev,
		(ndr_pull_flags_fn_t)ndr_pull_notify_remote_event);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(ev);
		return false;
	}
	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(notify_remote_event, ev);
	}
	*paction = ev->action;
	*pfilter = ev->filter;
	p = discard_const_p(char, ev->path);
	*path = talloc_move(mem_ctx, &p);

	TALLOC_FREE(ev);
	return true;
}

void notify_trigger(struct notify_context *notify,
		    uint32_t action, uint32_t filter, const char *path)
{
	struct ctdbd_connection *ctdbd_conn;
	struct notify_trigger_index_state idx_state;
	const char *p, *next_p;
	size_t i, num_vnns;
	uint32_t last_vnn;
	uint8_t *remote_blob = NULL;
	size_t remote_blob_len = 0;

	DEBUG(10, ("notify_trigger called action=0x%x, filter=0x%x, "
		   "path=%s\n", (unsigned)action, (unsigned)filter, path));

	/* see if change notify is enabled at all */
	if (notify == NULL) {
		return;
	}

	idx_state.mem_ctx = talloc_tos();
	idx_state.vnns = NULL;
	idx_state.my_vnn = get_my_vnn();

	for (p = path; p != NULL; p = next_p) {
		ptrdiff_t path_len = p - path;
		bool recursive;

		next_p = strchr(p+1, '/');
		recursive = (next_p != NULL);

		idx_state.found_my_vnn = false;

		dbwrap_parse_record(
			notify->db_index,
			make_tdb_data(discard_const_p(uint8_t, path), path_len),
			notify_trigger_index_parser, &idx_state);

		if (!idx_state.found_my_vnn) {
			continue;
		}
		notify_trigger_local(notify, action, filter,
				     path, path_len, recursive);
	}

	ctdbd_conn = messaging_ctdbd_connection();
	if (ctdbd_conn == NULL) {
		goto done;
	}

	num_vnns = talloc_array_length(idx_state.vnns);
	qsort(idx_state.vnns, num_vnns, sizeof(uint32_t), vnn_cmp);

	last_vnn = 0xffffffff;
	remote_blob = NULL;

	for (i=0; i<num_vnns; i++) {
		uint32_t vnn = idx_state.vnns[i];
		NTSTATUS status;

		if (vnn == last_vnn) {
			continue;
		}
		if (vnn == idx_state.my_vnn) {
			continue;
		}
		if ((remote_blob == NULL) &&
		    !notify_push_remote_blob(
			    talloc_tos(), action, filter,
			    path, &remote_blob, &remote_blob_len)) {
			break;
		}

		status = ctdbd_messaging_send_blob(
			ctdbd_conn, vnn, CTDB_SRVID_SAMBA_NOTIFY_PROXY,
			remote_blob, remote_blob_len);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("ctdbd_messaging_send_blob to vnn %d "
				   "returned %s, ignoring\n", (int)vnn,
				   nt_errstr(status)));
		}

		last_vnn = vnn;
	}

done:
	TALLOC_FREE(remote_blob);
	TALLOC_FREE(idx_state.vnns);
}

static void notify_trigger_local(struct notify_context *notify,
				 uint32_t action, uint32_t filter,
				 const char *path, size_t path_len,
				 bool recursive)
{
	TDB_DATA data;
	struct notify_db_entry *entries;
	size_t i, num_entries;
	NTSTATUS status;

	DEBUG(10, ("notify_trigger_local called for %*s, path_len=%d, "
		   "filter=%d\n", (int)path_len, path, (int)path_len,
		   (int)filter));

	status = dbwrap_fetch(
		notify->db_notify, talloc_tos(),
		make_tdb_data(discard_const_p(uint8_t, path), path_len), &data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("dbwrap_fetch returned %s\n",
			   nt_errstr(status)));
		return;
	}
	if (data.dsize == sizeof(time_t)) {
		DEBUG(10, ("Got deleted record\n"));
		goto done;
	}
	if ((data.dsize % sizeof(struct notify_db_entry)) != 0) {
		DEBUG(1, ("Invalid data.dsize = %u\n",
			  (unsigned)data.dsize));
		goto done;
	}

	entries = (struct notify_db_entry *)data.dptr;
	num_entries = data.dsize / sizeof(struct notify_db_entry);

	DEBUG(10, ("recursive = %s pathlen=%d (%c)\n",
		   recursive ? "true" : "false", (int)path_len,
		   path[path_len]));

	for (i=0; i<num_entries; i++) {
		struct notify_db_entry *e = &entries[i];
		uint32_t e_filter;

		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_DEBUG(notify_db_entry, e);
		}

		e_filter = recursive ? e->subdir_filter : e->filter;

		if ((filter & e_filter) == 0) {
			continue;
		}

		if (!procid_is_local(&e->server)) {
			DEBUG(1, ("internal error: Non-local pid %s in "
				  "notify.tdb\n",
				  procid_str_static(&e->server)));
			continue;
		}

		status = notify_send(notify, &e->server, path + path_len + 1,
				     action, e->private_data);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("notify_send returned %s\n",
				   nt_errstr(status)));
		}
	}

done:
	TALLOC_FREE(data.dptr);
}

static NTSTATUS notify_send(struct notify_context *notify,
			    struct server_id *pid,
			    const char *path, uint32_t action,
			    void *private_data)
{
	struct notify_event ev;
	DATA_BLOB data;
	NTSTATUS status;
	enum ndr_err_code ndr_err;

	ev.action = action;
	ev.path = path;
	ev.private_data = private_data;

	ndr_err = ndr_push_struct_blob(
		&data, talloc_tos(), &ev,
		(ndr_push_flags_fn_t)ndr_push_notify_event);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}
	status = messaging_send(notify->msg, *pid, MSG_PVFS_NOTIFY,
				&data);
	TALLOC_FREE(data.data);
	return status;
}

static void notify_handler(struct messaging_context *msg_ctx,
			   void *private_data, uint32_t msg_type,
			   struct server_id server_id, DATA_BLOB *data)
{
	struct notify_context *notify = talloc_get_type_abort(
		private_data, struct notify_context);
	enum ndr_err_code ndr_err;
	struct notify_event *n;
	struct notify_list *listel;

	n = talloc(talloc_tos(), struct notify_event);
	if (n == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return;
	}

	ndr_err = ndr_pull_struct_blob(
		data, n, n, (ndr_pull_flags_fn_t)ndr_pull_notify_event);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(n);
		return;
	}
	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(notify_event, n);
	}

	for (listel=notify->list;listel;listel=listel->next) {
		if (listel->private_data == n->private_data) {
			listel->callback(listel->private_data, n);
			break;
		}
	}
	TALLOC_FREE(n);
}

struct notify_walk_idx_state {
	void (*fn)(const char *path,
		   uint32_t *vnns, size_t num_vnns,
		   void *private_data);
	void *private_data;
};

static int notify_walk_idx_fn(struct db_record *rec, void *private_data)
{
	struct notify_walk_idx_state *state =
		(struct notify_walk_idx_state *)private_data;
	TDB_DATA key, value;
	char *path;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	if ((value.dsize % sizeof(uint32_t)) != 0) {
		DEBUG(1, ("invalid value size in notify index db: %u\n",
			  (unsigned)(value.dsize)));
		return 0;
	}

	path = talloc_strndup(talloc_tos(), (char *)key.dptr, key.dsize);
	if (path == NULL) {
		DEBUG(1, ("talloc_strndup failed\n"));
		return 0;
	}
	state->fn(path, (uint32_t *)value.dptr, value.dsize/sizeof(uint32_t),
		  state->private_data);
	TALLOC_FREE(path);
	return 0;
}

void notify_walk_idx(struct notify_context *notify,
		     void (*fn)(const char *path,
				uint32_t *vnns, size_t num_vnns,
				void *private_data),
		     void *private_data)
{
	struct notify_walk_idx_state state;
	state.fn = fn;
	state.private_data = private_data;
	dbwrap_traverse_read(notify->db_index, notify_walk_idx_fn, &state,
			     NULL);
}

struct notify_walk_state {
	void (*fn)(const char *path,
		   struct notify_db_entry *entries, size_t num_entries,
		   time_t deleted_time, void *private_data);
	void *private_data;
};

static int notify_walk_fn(struct db_record *rec, void *private_data)
{
	struct notify_walk_state *state =
		(struct notify_walk_state *)private_data;
	TDB_DATA key, value;
	struct notify_db_entry *entries;
	size_t num_entries;
	time_t deleted_time;
	char *path;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	if (value.dsize == sizeof(deleted_time)) {
		memcpy(&deleted_time, value.dptr, sizeof(deleted_time));
		entries = NULL;
		num_entries = 0;
	} else {
		if ((value.dsize % sizeof(struct notify_db_entry)) != 0) {
			DEBUG(1, ("invalid value size in notify db: %u\n",
				  (unsigned)(value.dsize)));
			return 0;
		}
		entries = (struct notify_db_entry *)value.dptr;
		num_entries = value.dsize / sizeof(struct notify_db_entry);
		deleted_time = 0;
	}

	path = talloc_strndup(talloc_tos(), (char *)key.dptr, key.dsize);
	if (path == NULL) {
		DEBUG(1, ("talloc_strndup failed\n"));
		return 0;
	}
	state->fn(path, entries, num_entries, deleted_time,
		  state->private_data);
	TALLOC_FREE(path);
	return 0;
}

void notify_walk(struct notify_context *notify,
		 void (*fn)(const char *path,
			    struct notify_db_entry *entries,
			    size_t num_entries,
			    time_t deleted_time, void *private_data),
		 void *private_data)
{
	struct notify_walk_state state;
	state.fn = fn;
	state.private_data = private_data;
	dbwrap_traverse_read(notify->db_notify, notify_walk_fn, &state,
			     NULL);
}

struct notify_cleanup_state {
	TALLOC_CTX *mem_ctx;
	time_t delete_before;
	ssize_t array_size;
	uint32_t num_paths;
	char **paths;
};

static void notify_cleanup_collect(
	const char *path, struct notify_db_entry *entries, size_t num_entries,
	time_t deleted_time, void *private_data)
{
	struct notify_cleanup_state *state =
		(struct notify_cleanup_state *)private_data;
	char *p;

	if (num_entries != 0) {
		return;
	}
	if (deleted_time >= state->delete_before) {
		return;
	}

	p = talloc_strdup(state->mem_ctx, path);
	if (p == NULL) {
		DEBUG(1, ("talloc_strdup failed\n"));
		return;
	}
	add_to_large_array(state->mem_ctx, sizeof(p), (void *)&p,
			   &state->paths, &state->num_paths,
			   &state->array_size);
	if (state->array_size == -1) {
		TALLOC_FREE(p);
	}
}

static bool notify_cleanup_path(struct notify_context *notify,
			      const char *path, time_t delete_before);

void notify_cleanup(struct notify_context *notify)
{
	struct notify_cleanup_state state;
	uint32_t failure_pool;

	ZERO_STRUCT(state);
	state.mem_ctx = talloc_stackframe();

	state.delete_before = time(NULL)
		- lp_parm_int(-1, "smbd", "notify cleanup interval", 60);

	notify_walk(notify, notify_cleanup_collect, &state);

	failure_pool = state.num_paths;

	while (state.num_paths != 0) {
		size_t idx;

		/*
		 * This loop is designed to be as kind as possible to
		 * ctdb. ctdb does not like it if many smbds hammer on a
		 * single record. If on many nodes the cleanup process starts
		 * running, it can happen that all of them need to clean up
		 * records in the same order. This would generate a ctdb
		 * migrate storm on these records. Randomizing the load across
		 * multiple records reduces the load on the individual record.
		 */

		generate_random_buffer((uint8_t *)&idx, sizeof(idx));
		idx = idx % state.num_paths;

		if (!notify_cleanup_path(notify, state.paths[idx],
					 state.delete_before)) {
			/*
			 * notify_cleanup_path failed, the most likely reason
			 * is that dbwrap_try_fetch_locked failed due to
			 * contention. We allow one failed attempt per deleted
			 * path on average before we give up.
			 */
			failure_pool -= 1;
			if (failure_pool == 0) {
				/*
				 * Too many failures. We will come back here,
				 * maybe next time there is less contention.
				 */
				break;
			}
		}

		TALLOC_FREE(state.paths[idx]);
		state.paths[idx] = state.paths[state.num_paths-1];
		state.num_paths -= 1;
	}
	TALLOC_FREE(state.mem_ctx);
}

static bool notify_cleanup_path(struct notify_context *notify,
				const char *path, time_t delete_before)
{
	struct db_record *notify_rec = NULL;
	struct db_record *idx_rec = NULL;
	TDB_DATA key = string_tdb_data(path);
	TDB_DATA value;
	time_t deleted;
	NTSTATUS status;

	notify_rec = dbwrap_fetch_locked(notify->db_notify, talloc_tos(), key);
	if (notify_rec == NULL) {
		DEBUG(10, ("Could not fetch notify_rec\n"));
		return false;
	}
	value = dbwrap_record_get_value(notify_rec);

	if (value.dsize != sizeof(deleted)) {
		DEBUG(10, ("record %s has been re-used\n", path));
		goto done;
	}
	memcpy(&deleted, value.dptr, sizeof(deleted));

	if (deleted >= delete_before) {
		DEBUG(10, ("record %s too young\n", path));
		goto done;
	}

	/*
	 * Be kind to ctdb and only try one dmaster migration at most.
	 */
	idx_rec = dbwrap_try_fetch_locked(notify->db_index, talloc_tos(), key);
	if (idx_rec == NULL) {
		DEBUG(10, ("Could not fetch idx_rec\n"));
		goto done;
	}

	status = dbwrap_record_delete(notify_rec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Could not delete notify_rec: %s\n",
			   nt_errstr(status)));
	}

	status = notify_del_idx(idx_rec, get_my_vnn());
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Could not delete idx_rec: %s\n",
			   nt_errstr(status)));
	}

done:
	TALLOC_FREE(idx_rec);
	TALLOC_FREE(notify_rec);
	return true;
}

static NTSTATUS notify_del_idx(struct db_record *rec, uint32_t vnn)
{
	TDB_DATA value = dbwrap_record_get_value(rec);
	uint32_t *vnns;
	size_t i, num_vnns;

	if ((value.dsize % sizeof(uint32_t)) != 0) {
		DEBUG(1, ("Invalid value.dsize = %u\n",
			  (unsigned)value.dsize));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	num_vnns = value.dsize / sizeof(uint32_t);
	vnns = (uint32_t *)value.dptr;

	for (i=0; i<num_vnns; i++) {
		if (vnns[i] == vnn) {
			break;
		}
	}

	if (i == num_vnns) {
		/*
		 * Not found. Should not happen, but okay...
		 */
		return NT_STATUS_OK;
	}

	memmove(&vnns[i], &vnns[i+1], sizeof(uint32_t) * (num_vnns - i - 1));
	value.dsize -= sizeof(uint32_t);

	if (value.dsize == 0) {
		return dbwrap_record_delete(rec);
	}
	return dbwrap_record_store(rec, value, 0);
}

struct notify_cluster_proxy_state {
	struct tevent_context *ev;
	struct notify_context *notify;
	struct ctdb_msg_channel *chan;
};

static void notify_cluster_proxy_got_chan(struct tevent_req *subreq);
static void notify_cluster_proxy_got_msg(struct tevent_req *subreq);
static void notify_cluster_proxy_trigger(struct notify_context *notify,
					 uint32_t action, uint32_t filter,
					 char *path);

struct tevent_req *notify_cluster_proxy_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct notify_context *notify)
{
	struct tevent_req *req, *subreq;
	struct notify_cluster_proxy_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct notify_cluster_proxy_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->notify = notify;

	subreq = ctdb_msg_channel_init_send(
		state, state->ev,  lp_ctdbd_socket(),
		CTDB_SRVID_SAMBA_NOTIFY_PROXY);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, notify_cluster_proxy_got_chan, req);
	return req;
}

static void notify_cluster_proxy_got_chan(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_cluster_proxy_state *state = tevent_req_data(
		req, struct notify_cluster_proxy_state);
	int ret;

	ret = ctdb_msg_channel_init_recv(subreq, state, &state->chan);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}
	subreq = ctdb_msg_read_send(state, state->ev, state->chan);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_cluster_proxy_got_msg, req);
}

static void notify_cluster_proxy_got_msg(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_cluster_proxy_state *state = tevent_req_data(
		req, struct notify_cluster_proxy_state);
	uint8_t *msg;
	size_t msg_len;
	uint32_t action, filter;
	char *path;
	int ret;
	bool res;

	ret = ctdb_msg_read_recv(subreq, talloc_tos(), &msg, &msg_len);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	res = notify_pull_remote_blob(talloc_tos(), msg, msg_len,
				      &action, &filter, &path);
	TALLOC_FREE(msg);
	if (!res) {
		tevent_req_error(req, EIO);
		return;
	}
	notify_cluster_proxy_trigger(state->notify, action, filter, path);
	TALLOC_FREE(path);

	subreq = ctdb_msg_read_send(state, state->ev, state->chan);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_cluster_proxy_got_msg, req);
}

static void notify_cluster_proxy_trigger(struct notify_context *notify,
					 uint32_t action, uint32_t filter,
					 char *path)
{
	const char *p, *next_p;

	for (p = path; p != NULL; p = next_p) {
		ptrdiff_t path_len = p - path;
		bool recursive;

		next_p = strchr(p+1, '/');
		recursive = (next_p != NULL);

		notify_trigger_local(notify, action, filter,
				     path, path_len, recursive);
	}
}

int notify_cluster_proxy_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}
