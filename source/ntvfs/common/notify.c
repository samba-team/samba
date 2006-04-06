/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2006
   
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

/*
  this is the change notify database. It implements mechanisms for
  storing current change notify waiters in a tdb, and checking if a
  given event matches any of the stored notify waiiters.
*/

#include "includes.h"
#include "system/filesys.h"
#include "lib/tdb/include/tdb.h"
#include "lib/tdb/include/tdbutil.h"
#include "messaging/messaging.h"
#include "db_wrap.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_notify.h"
#include "dlinklist.h"
#include "ntvfs/sysdep/sys_notify.h"

struct notify_context {
	struct tdb_wrap *w;
	uint32_t server;
	struct messaging_context *messaging_ctx;
	struct notify_list *list;
	struct notify_array *array;
	int seqnum;
	struct sys_notify_context *sys_notify_ctx;
};


struct notify_list {
	struct notify_list *next, *prev;
	void *private;
	void (*callback)(void *, const struct notify_event *);
	void *sys_notify_handle;
};

#define NOTIFY_KEY "notify array"

static NTSTATUS notify_remove_all(struct notify_context *notify);
static void notify_handler(struct messaging_context *msg_ctx, void *private, 
			   uint32_t msg_type, uint32_t server_id, DATA_BLOB *data);

/*
  destroy the notify context
*/
static int notify_destructor(void *p)
{
	struct notify_context *notify = talloc_get_type(p, struct notify_context);
	messaging_deregister(notify->messaging_ctx, MSG_PVFS_NOTIFY, notify);
	notify_remove_all(notify);
	return 0;
}

/*
  Open up the notify.tdb database. You should close it down using
  talloc_free(). We need the messaging_ctx to allow for notifications
  via internal messages
*/
struct notify_context *notify_init(TALLOC_CTX *mem_ctx, uint32_t server, 
				   struct messaging_context *messaging_ctx,
				   struct event_context *ev, int snum)
{
	char *path;
	struct notify_context *notify;

	notify = talloc(mem_ctx, struct notify_context);
	if (notify == NULL) {
		return NULL;
	}

	path = smbd_tmp_path(notify, "notify.tdb");
	notify->w = tdb_wrap_open(notify, path, 0,  
				  TDB_SEQNUM,
				  O_RDWR|O_CREAT, 0600);
	talloc_free(path);
	if (notify->w == NULL) {
		talloc_free(notify);
		return NULL;
	}

	notify->server = server;
	notify->messaging_ctx = messaging_ctx;
	notify->list = NULL;
	notify->array = NULL;
	notify->seqnum = tdb_get_seqnum(notify->w->tdb);

	talloc_set_destructor(notify, notify_destructor);

	/* register with the messaging subsystem for the notify
	   message type */
	messaging_register(notify->messaging_ctx, notify, 
			   MSG_PVFS_NOTIFY, notify_handler);

	notify->sys_notify_ctx = sys_notify_init(snum, notify, ev);

	return notify;
}


/*
  lock the notify db
*/
static NTSTATUS notify_lock(struct notify_context *notify)
{
	if (tdb_lock_bystring(notify->w->tdb, NOTIFY_KEY) != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	return NT_STATUS_OK;
}

/*
  unlock the notify db
*/
static void notify_unlock(struct notify_context *notify)
{
	tdb_unlock_bystring(notify->w->tdb, NOTIFY_KEY);
}

/*
  load the notify array
*/
static NTSTATUS notify_load(struct notify_context *notify)
{
	TDB_DATA dbuf;
	DATA_BLOB blob;
	NTSTATUS status;
	int seqnum;

	seqnum = tdb_get_seqnum(notify->w->tdb);

	if (seqnum == notify->seqnum && notify->array != NULL) {
		return NT_STATUS_OK;
	}

	notify->seqnum = seqnum;

	talloc_free(notify->array);
	notify->array = talloc_zero(notify, struct notify_array);
	NT_STATUS_HAVE_NO_MEMORY(notify->array);

	dbuf = tdb_fetch_bystring(notify->w->tdb, NOTIFY_KEY);
	if (dbuf.dptr == NULL) {
		return NT_STATUS_OK;
	}

	blob.data = dbuf.dptr;
	blob.length = dbuf.dsize;

	status = ndr_pull_struct_blob(&blob, notify->array, notify->array, 
				      (ndr_pull_flags_fn_t)ndr_pull_notify_array);
	free(dbuf.dptr);

	return status;
}

/*
  compare notify entries for sorting
*/
static int notify_compare(const void *p1, const void *p2)
{
	const struct notify_entry *e1 = p1, *e2 = p2;
	return strcmp(e1->path, e2->path);
}

/*
  save the notify array
*/
static NTSTATUS notify_save(struct notify_context *notify)
{
	TDB_DATA dbuf;
	DATA_BLOB blob;
	NTSTATUS status;
	int ret;
	TALLOC_CTX *tmp_ctx;

	if (notify->array->num_entries == 0) {
		ret = tdb_delete_bystring(notify->w->tdb, NOTIFY_KEY);
		if (ret != 0) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		return NT_STATUS_OK;
	}

	if (notify->array->num_entries > 1) {
		qsort(notify->array->entries, notify->array->num_entries, 
		      sizeof(struct notify_entry), notify_compare);
	}

	tmp_ctx = talloc_new(notify);

	status = ndr_push_struct_blob(&blob, tmp_ctx, notify->array, 
				      (ndr_push_flags_fn_t)ndr_push_notify_array);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	dbuf.dptr = blob.data;
	dbuf.dsize = blob.length;
		
	ret = tdb_store_bystring(notify->w->tdb, NOTIFY_KEY, dbuf, TDB_REPLACE);
	talloc_free(tmp_ctx);
	if (ret != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS_OK;
}


/*
  handle incoming notify messages
*/
static void notify_handler(struct messaging_context *msg_ctx, void *private, 
			   uint32_t msg_type, uint32_t server_id, DATA_BLOB *data)
{
	struct notify_context *notify = talloc_get_type(private, struct notify_context);
	NTSTATUS status;
	struct notify_event ev;
	TALLOC_CTX *tmp_ctx = talloc_new(notify);
	struct notify_list *listel;

	status = ndr_pull_struct_blob(data, tmp_ctx, &ev, 
				      (ndr_pull_flags_fn_t)ndr_pull_notify_event);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}

	for (listel=notify->list;listel;listel=listel->next) {
		if (listel->private == ev.private) {
			listel->callback(listel->private, &ev);
			break;
		}
	}

	talloc_free(tmp_ctx);	
}

/*
  callback from sys_notify telling us about changes from the OS
*/
static void sys_notify_callback(struct sys_notify_context *ctx, 
				void *ptr, struct notify_event *ev)
{
	struct notify_list *listel = talloc_get_type(ptr, struct notify_list);
	ev->private = listel;
	listel->callback(listel->private, ev);
}

/*
  add an entry to the notify array
*/
static NTSTATUS notify_add_array(struct notify_context *notify, struct notify_entry *e,
				 const char *path, void *private)
{
	notify->array->entries[notify->array->num_entries] = *e;
	notify->array->entries[notify->array->num_entries].private = private;
	notify->array->entries[notify->array->num_entries].server = notify->server;
	
	if (path) {
		notify->array->entries[notify->array->num_entries].path = path;
	}

	notify->array->num_entries++;
	
	return notify_save(notify);
}

/*
  add a notify watch. This is called when a notify is first setup on a open
  directory handle.
*/
NTSTATUS notify_add(struct notify_context *notify, struct notify_entry *e0,
		    void (*callback)(void *, const struct notify_event *), 
		    void *private)
{
	struct notify_entry e = *e0;
	NTSTATUS status;
	struct notify_list *listel;
	char *path = NULL;
	size_t len;

	status = notify_lock(notify);
	NT_STATUS_NOT_OK_RETURN(status);

	status = notify_load(notify);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	notify->array->entries = talloc_realloc(notify->array, notify->array->entries, 
						struct notify_entry,
						notify->array->num_entries+1);

	if (notify->array->entries == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* cope with /. on the end of the path */
	len = strlen(e.path);
	if (len > 1 && e.path[len-1] == '.' && e.path[len-2] == '/') {
		e.path = talloc_strndup(notify, e.path, len-2);
		if (e.path == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	listel = talloc_zero(notify, struct notify_list);
	if (listel == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	listel->private = private;
	listel->callback = callback;
	DLIST_ADD(notify->list, listel);

	/* ignore failures from sys_notify */
	if (notify->sys_notify_ctx != NULL) {
		/*
		  this call will modify e.filter and e.subdir_filter
		  to remove bits handled by the backend
		*/
		status = sys_notify_watch(notify->sys_notify_ctx, &e,
					  sys_notify_callback, listel, 
					  &listel->sys_notify_handle);
		if (NT_STATUS_IS_OK(status)) {
			talloc_steal(listel, listel->sys_notify_handle);
		}
	}

	/* if the system notify handler couldn't handle some of the
	   filter bits, or couldn't handle a request for recursion
	   then we need to install it in the array used for the
	   intra-samba notify handling */
	if (e.filter != 0 || e.subdir_filter != 0) {
		status = notify_add_array(notify, &e, path, private);
	}

done:
	notify_unlock(notify);
	if (e.path != e0->path) {
		talloc_free(e.path);
	}

	return status;
}

/*
  remove a notify watch. Called when the directory handle is closed
*/
NTSTATUS notify_remove(struct notify_context *notify, void *private)
{
	NTSTATUS status;
	struct notify_list *listel;
	int i;

	for (listel=notify->list;listel;listel=listel->next) {
		if (listel->private == private) {
			DLIST_REMOVE(notify->list, listel);
			break;
		}
	}
	if (listel == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	talloc_free(listel);

	status = notify_lock(notify);
	NT_STATUS_NOT_OK_RETURN(status);

	status = notify_load(notify);
	if (!NT_STATUS_IS_OK(status)) {
		notify_unlock(notify);
		return status;
	}

	for (i=0;i<notify->array->num_entries;i++) {
		if (notify->server == notify->array->entries[i].server && 
		    private == notify->array->entries[i].private) {
			break;
		}
	}
	if (i == notify->array->num_entries) {
		notify_unlock(notify);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (i < notify->array->num_entries-1) {
		memmove(&notify->array->entries[i], &notify->array->entries[i+1], 
			sizeof(notify->array->entries[i])*(notify->array->num_entries-(i+1)));
	}
	notify->array->num_entries--;

	status = notify_save(notify);

	notify_unlock(notify);

	return status;
}

/*
  remove all notify watches for this messaging server
*/
static NTSTATUS notify_remove_all(struct notify_context *notify)
{
	NTSTATUS status;
	int i;

	if (notify->list == NULL) {
		return NT_STATUS_OK;
	}

	status = notify_lock(notify);
	NT_STATUS_NOT_OK_RETURN(status);

	status = notify_load(notify);
	if (!NT_STATUS_IS_OK(status)) {
		notify_unlock(notify);
		return status;
	}

	for (i=0;i<notify->array->num_entries;i++) {
		if (notify->server == notify->array->entries[i].server) {
			if (i < notify->array->num_entries-1) {
				memmove(&notify->array->entries[i], &notify->array->entries[i+1], 
					sizeof(notify->array->entries[i])*(notify->array->num_entries-(i+1)));
			}
			i--;
			notify->array->num_entries--;
		}
	}


	status = notify_save(notify);

	notify_unlock(notify);

	return status;
}


/*
  send a notify message to another messaging server
*/
static void notify_send(struct notify_context *notify, struct notify_entry *e,
			const char *path, uint32_t action)
{
	struct notify_event ev;
	DATA_BLOB data;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	ev.action = action;
	ev.path = path;
	ev.private = e->private;

	tmp_ctx = talloc_new(notify);

	status = ndr_push_struct_blob(&data, tmp_ctx, &ev, 
				      (ndr_push_flags_fn_t)ndr_push_notify_event);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}

	status = messaging_send(notify->messaging_ctx, e->server, 
				MSG_PVFS_NOTIFY, &data);
	talloc_free(tmp_ctx);
}

/*
  see if a notify event matches
*/
static BOOL notify_match(struct notify_context *notify, struct notify_entry *e,
			 const char *path, uint32_t filter)
{
	size_t len;
	BOOL subdir;

	if (!(filter & e->filter) && !(filter & e->subdir_filter)) {
		return False;
	}

	len = strlen(e->path);

	if (strncmp(path, e->path, len) != 0) {
		return False;
	}

	if (path[len] != '/') {
		return False;
	}

	/* the filter and subdir_filter are handled separately, allowing a backend
	   to flexibly choose what it can handle */
	subdir = (strchr(&path[len+1], '/') != NULL);

	if (subdir) {
		return (filter & e->subdir_filter) != 0;
	}

	return (filter & e->filter) != 0;
}


/*
  trigger a notify message for anyone waiting on a matching event
*/
void notify_trigger(struct notify_context *notify,
		    uint32_t action, uint32_t filter, const char *path)
{
	NTSTATUS status;
	int i;

	status = notify_load(notify);
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	/* TODO: this needs to be changed to a log(n) search */
	for (i=0;i<notify->array->num_entries;i++) {
		if (notify_match(notify, &notify->array->entries[i], path, filter)) {
			notify_send(notify, &notify->array->entries[i], 
				    path + strlen(notify->array->entries[i].path) + 1, 
				    action);
		}
	}
}
