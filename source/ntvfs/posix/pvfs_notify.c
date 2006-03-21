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
	void *wait_handle;
};


/*
  destroy a notify buffer. Called when the handle is closed
 */
static int pvfs_notify_destructor(void *ptr)
{
	struct pvfs_notify_buffer *n = talloc_get_type(ptr, struct pvfs_notify_buffer);
	notify_remove(n->f->pvfs->notify_context, n);
	n->f->notify_buffer = NULL;
	return 0;
}


/*
  called when a async notify event comes in
*/
static void pvfs_notify_callback(void *private, const struct notify_event *ev)
{
	struct pvfs_notify_buffer *n = talloc_get_type(private, struct pvfs_notify_buffer);
	DEBUG(0,("got notify for '%s'\n", ev->path));
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
		return NT_STATUS_NOT_A_DIRECTORY;
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

	/* if the buffer is empty then start waiting */
	if (f->notify_buffer->num_changes == 0) {
		req->async_states->state |= NTVFS_ASYNC_STATE_ASYNC;
		return NT_STATUS_OK;
	}

	/* otherwise if the buffer is not empty then return its
	   contents immediately */
	info->out.num_changes = f->notify_buffer->num_changes;
	info->out.changes = talloc_steal(req, f->notify_buffer->changes);
	f->notify_buffer->num_changes = 0;
	f->notify_buffer->changes = NULL;
	f->notify_buffer->current_buffer_size = 0;

	return NT_STATUS_OK;
}
