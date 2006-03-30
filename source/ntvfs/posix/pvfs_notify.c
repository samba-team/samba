/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - notify

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

#include "includes.h"
#include "vfs_posix.h"
#include "lib/messaging/irpc.h"
#include "messaging/messaging.h"

/* pending notifies buffer, hung off struct pvfs_file for open directories
   that have used change notify */
struct pvfs_notify_buffer {
	struct pvfs_file *f;
	uint32_t num_changes;
	struct notify_changes *changes;
	uint32_t max_buffer_size;
	uint32_t current_buffer_size;
	
	/* these last two are only present when a notify request is
	   pending */
	struct ntvfs_request *req;
	struct smb_notify *info;
};

/*
  send a reply to a pending notify request
*/
static void pvfs_notify_send(struct pvfs_notify_buffer *notify_buffer, NTSTATUS status)
{
	struct ntvfs_request *req = notify_buffer->req;
	struct smb_notify *info = notify_buffer->info;

	info->out.num_changes = notify_buffer->num_changes;
	info->out.changes = talloc_steal(req, notify_buffer->changes);
	notify_buffer->num_changes = 0;
	notify_buffer->changes = NULL;
	notify_buffer->current_buffer_size = 0;
	
	notify_buffer->req = NULL;
	notify_buffer->info = NULL;

	DEBUG(0,("sending %d changes\n", info->out.num_changes));

	if (info->out.num_changes != 0) {
		status = NT_STATUS_OK;
	}

	req->async_states->status = status;
	req->async_states->send_fn(req);
}

/*
  destroy a notify buffer. Called when the handle is closed
 */
static int pvfs_notify_destructor(void *ptr)
{
	struct pvfs_notify_buffer *n = talloc_get_type(ptr, struct pvfs_notify_buffer);
	notify_remove(n->f->pvfs->notify_context, n);
	n->f->notify_buffer = NULL;
	if (n->req) {
		pvfs_notify_send(n, NT_STATUS_OK);
	}
	return 0;
}


/*
  called when a async notify event comes in
*/
static void pvfs_notify_callback(void *private, const struct notify_event *ev)
{
	struct pvfs_notify_buffer *n = talloc_get_type(private, struct pvfs_notify_buffer);

	n->changes = talloc_realloc(n, n->changes, struct notify_changes, n->num_changes+1);
	n->changes[n->num_changes].action = ev->action;
	n->changes[n->num_changes].name.s = talloc_strdup(n->changes, ev->path);
	n->num_changes++;

	DEBUG(0,("got notify for '%s' action=%d\n", ev->path, ev->action));

	if (n->req != NULL) {
		pvfs_notify_send(n, NT_STATUS_OK);
	}
}

/*
  setup a notify buffer on a directory handle
*/
static NTSTATUS pvfs_notify_setup(struct pvfs_state *pvfs, struct pvfs_file *f, 
				  uint32_t buffer_size, uint32_t filter, BOOL recursive)
{
	NTSTATUS status;
	struct notify_entry e;

	f->notify_buffer = talloc_zero(f, struct pvfs_notify_buffer);
	NT_STATUS_HAVE_NO_MEMORY(f->notify_buffer);

	f->notify_buffer->max_buffer_size = buffer_size;
	f->notify_buffer->f = f;

	e.filter    = filter;
	e.path      = f->handle->name->full_name;
	e.recursive = recursive;

	status = notify_add(pvfs->notify_context, &e, 
			    pvfs_notify_callback, f->notify_buffer);
	NT_STATUS_NOT_OK_RETURN(status);

	talloc_set_destructor(f->notify_buffer, pvfs_notify_destructor);

	return NT_STATUS_OK;
}

/*
  called from the pvfs_wait code when either an event has come in, or
  the notify request has been cancelled
*/
static void pvfs_notify_end(void *private, enum pvfs_wait_notice reason)
{
	struct pvfs_notify_buffer *notify_buffer = talloc_get_type(private, struct pvfs_notify_buffer);
	struct ntvfs_request *req = notify_buffer->req;

	if (req == NULL) {
		/* nothing to do, nobody is waiting */
		return;
	}

	if (reason == PVFS_WAIT_CANCEL) {
		pvfs_notify_send(notify_buffer, NT_STATUS_CANCELLED);
	} else {
		pvfs_notify_send(notify_buffer, NT_STATUS_OK);
	}
}

/* change notify request - always async. This request blocks until the
   event buffer is non-empty */
NTSTATUS pvfs_notify(struct ntvfs_module_context *ntvfs, 
		     struct ntvfs_request *req,
		     struct smb_notify *info)
{
	struct pvfs_state *pvfs = talloc_get_type(ntvfs->private_data, 
						  struct pvfs_state);
	struct pvfs_file *f;
	NTSTATUS status;

	f = pvfs_find_fd(pvfs, req, info->in.file.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* this request doesn't make sense unless its async */
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* its only valid for directories */
	if (f->handle->fd != -1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* if the handle doesn't currently have a notify buffer then
	   create one */
	if (f->notify_buffer == NULL) {
		status = pvfs_notify_setup(pvfs, f, 
					   info->in.buffer_size, 
					   info->in.completion_filter,
					   info->in.recursive);
		NT_STATUS_NOT_OK_RETURN(status);
	}

	req->async_states->status = NT_STATUS_OK;
	
	if (f->notify_buffer->req != NULL) {
		DEBUG(0,("Notify already setup\n"));
		pvfs_notify_send(f->notify_buffer, NT_STATUS_CANCELLED);
	}

	f->notify_buffer->req = talloc_reference(f->notify_buffer, req);
	f->notify_buffer->info = info;

	/* if the buffer is empty then start waiting */
	if (f->notify_buffer->num_changes == 0) {
		void *wait_handle =
			pvfs_wait_message(pvfs, req, -1, timeval_zero(), 
					  pvfs_notify_end, f->notify_buffer);
		NT_STATUS_HAVE_NO_MEMORY(wait_handle);
		talloc_steal(req, wait_handle);
		return NT_STATUS_OK;
	}

	pvfs_notify_send(f->notify_buffer, NT_STATUS_OK);

	return NT_STATUS_OK;
}
