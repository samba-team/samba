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
#include "smb_server/smb_server.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_notify.h"
#include "dlinklist.h"

struct notify_context {
	struct tdb_wrap *w;
	uint32_t server;
	struct messaging_context *messaging_ctx;
	struct notify_list *list;
	struct notify_array *array;
};


struct notify_list {
	struct notify_list *next, *prev;
	void *private;
	void (*callback)(void *, const struct notify_event *);
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
				   struct messaging_context *messaging_ctx)
{
	char *path;
	struct notify_context *notify;

	notify = talloc(mem_ctx, struct notify_context);
	if (notify == NULL) {
		return NULL;
	}

	path = smbd_tmp_path(notify, "notify.tdb");
	notify->w = tdb_wrap_open(notify, path, 0,  
			       TDB_DEFAULT,
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

	talloc_set_destructor(notify, notify_destructor);

	/* register with the messaging subsystem for the notify
	   message type */
	messaging_register(notify->messaging_ctx, notify, 
			   MSG_PVFS_NOTIFY, notify_handler);

	return notify;
}

/*
  load the notify array
*/
static NTSTATUS notify_load(struct notify_context *notify)
{
	TDB_DATA dbuf;
	DATA_BLOB blob;
	NTSTATUS status;

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
  add a notify watch. This is called when a notify is first setup on a open
  directory handle.
*/
NTSTATUS notify_add(struct notify_context *notify, struct notify_entry *e,
		    void (*callback)(void *, const struct notify_event *), 
		    void *private)
{
	NTSTATUS status;
	struct notify_list *listel;

	status = notify_load(notify);
	NT_STATUS_NOT_OK_RETURN(status);

	notify->array->entries = talloc_realloc(notify->array, notify->array->entries, 
						struct notify_entry,
						notify->array->num_entries+1);

	if (notify->array->entries == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	notify->array->entries[notify->array->num_entries] = *e;
	notify->array->entries[notify->array->num_entries].private = private;
	notify->array->entries[notify->array->num_entries].server = notify->server;
	notify->array->num_entries++;

	status = notify_save(notify);
	NT_STATUS_NOT_OK_RETURN(status);

	listel = talloc(notify, struct notify_list);
	NT_STATUS_HAVE_NO_MEMORY(listel);

	listel->private = private;
	listel->callback = callback;
	DLIST_ADD(notify->list, listel);

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

	status = notify_load(notify);
	NT_STATUS_NOT_OK_RETURN(status);

	for (i=0;i<notify->array->num_entries;i++) {
		if (notify->server == notify->array->entries[i].server && 
		    private == notify->array->entries[i].private) {
			break;
		}
	}
	if (i == notify->array->num_entries) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (i < notify->array->num_entries-1) {
		memmove(&notify->array->entries[i], &notify->array->entries[i+1], 
			sizeof(notify->array->entries[i])*(notify->array->num_entries-(i+1)));
	}
	notify->array->num_entries--;

	return notify_save(notify);
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

	status = notify_load(notify);
	NT_STATUS_NOT_OK_RETURN(status);

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


	return notify_save(notify);
}


/*
  see if a notify event matches
*/
static BOOL notify_match(struct notify_context *notify, struct notify_entry *e,
			 const char *path, uint32_t action)
{
	size_t len = strlen(e->path);

	/* TODO: check action */

	if (strncmp(path, e->path, len) != 0) {
		return False;
	}

	if (path[len] == 0) {
		return True;
	}
	if (path[len] != '/') {
		return False;
	}

	if (!e->recursive) {
		if (strchr(&path[len+1], '/') != NULL) {
			return False;
		}
	}

	return True;
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
  trigger a notify message for anyone waiting on a matching event
*/
void notify_trigger(struct notify_context *notify,
		    uint32_t action, const char *path)
{
	NTSTATUS status;
	int i;

	status = notify_load(notify);
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	/* this needs to be changed to a log(n) search */
	for (i=0;i<notify->array->num_entries;i++) {
		if (notify_match(notify, &notify->array->entries[i], path, action)) {
			notify_send(notify, &notify->array->entries[i], path, action);
		}
	}
}
