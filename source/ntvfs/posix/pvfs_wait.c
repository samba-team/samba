/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - async request wait routines

   Copyright (C) Andrew Tridgell 2004

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
#include "events.h"
#include "dlinklist.h"
#include "vfs_posix.h"

/* the context for a single wait instance */
struct pvfs_wait {
	struct pvfs_wait *next, *prev;
	struct pvfs_state *pvfs;
	void (*handler)(void *, enum pvfs_wait_notice);
	void *private;
	struct timed_event *te;
	int msg_type;
	struct messaging_context *msg_ctx;
	struct event_context *ev;
	struct smbsrv_request *req;
	enum pvfs_wait_notice reason;
};

/*
  called from the ntvfs layer when we have requested setup of an async
  call.  this ensures that async calls runs with the right state of
  previous ntvfs handlers in the chain (such as security context)
*/
NTSTATUS pvfs_async_setup(struct ntvfs_module_context *ntvfs,
			  struct smbsrv_request *req, void *private)
{
	struct pvfs_wait *pwait = private;
	pwait->handler(pwait->private, pwait->reason);
	return NT_STATUS_OK;
}

/*
  receive a completion message for a wait
*/
static void pvfs_wait_dispatch(struct messaging_context *msg, void *private, uint32_t msg_type, 
			       servid_t src, DATA_BLOB *data)
{
	struct pvfs_wait *pwait = private;
	struct smbsrv_request *req;

	/* we need to check that this one is for us. See
	   messaging_send_ptr() for the other side of this.
	 */
	if (data->length != sizeof(void *) ||
	    *(void **)data->data != pwait->private) {
		return;
	}
	pwait->reason = PVFS_WAIT_EVENT;
	req = pwait->req;

	/* the extra reference here is to ensure that the req
	   structure is not destroyed when the async request reply is
	   sent, which would cause problems with the other ntvfs
	   modules above us */
	talloc_increase_ref_count(req);
	ntvfs_async_setup(pwait->req, pwait);
	talloc_free(req);
}


/*
  receive a timeout on a message wait
*/
static void pvfs_wait_timeout(struct event_context *ev, 
			      struct timed_event *te, struct timeval t)
{
	struct pvfs_wait *pwait = te->private;
	struct smbsrv_request *req = pwait->req;

	pwait->reason = PVFS_WAIT_TIMEOUT;

	talloc_increase_ref_count(req);
	ntvfs_async_setup(pwait->req, pwait);
	talloc_free(req);
}


/*
  destroy a pending wait
 */
static int pvfs_wait_destructor(void *ptr)
{
	struct pvfs_wait *pwait = ptr;
	messaging_deregister(pwait->msg_ctx, pwait->msg_type, pwait);
	event_remove_timed(pwait->ev, pwait->te);
	DLIST_REMOVE(pwait->pvfs->wait_list, pwait);
	return 0;
}

/*
  setup a request to wait on a message of type msg_type, with a
  timeout (given as an expiry time)

  the return value is a handle. To stop waiting talloc_free this
  handle.
*/
 void *pvfs_wait_message(struct pvfs_state *pvfs, 
			struct smbsrv_request *req, 
			int msg_type, 
			struct timeval end_time,
			void (*fn)(void *, enum pvfs_wait_notice),
			void *private)
{
	struct timed_event te;
	struct pvfs_wait *pwait;

	pwait = talloc_p(req, struct pvfs_wait);
	if (pwait == NULL) {
		return NULL;
	}

	pwait->private = private;
	pwait->handler = fn;
	pwait->msg_ctx = pvfs->tcon->smb_conn->connection->messaging_ctx;
	pwait->ev = req->tcon->smb_conn->connection->event.ctx;
	pwait->msg_type = msg_type;
	pwait->req = req;
	pwait->pvfs = pvfs;

	/* setup a timer */
	te.next_event = end_time;
	te.handler = pvfs_wait_timeout;
	te.private = pwait;
	pwait->te = event_add_timed(pwait->ev, &te);

	/* register with the messaging subsystem for this message
	   type */
	messaging_register(pwait->msg_ctx,
			   pwait,
			   msg_type,
			   pvfs_wait_dispatch);

	/* tell the main smb server layer that we will be replying 
	   asynchronously */
	req->async_states->state |= NTVFS_ASYNC_STATE_ASYNC;

	DLIST_ADD(pvfs->wait_list, pwait);

	/* make sure we cleanup the timer and message handler */
	talloc_set_destructor(pwait, pvfs_wait_destructor);

	/* make sure that on a disconnect the request is not destroyed
	   before pvfs */
	talloc_steal(pvfs, req);

	return pwait;
}


/*
  cancel an outstanding async request
*/
NTSTATUS pvfs_cancel(struct ntvfs_module_context *ntvfs, struct smbsrv_request *req)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_wait *pwait;
	for (pwait=pvfs->wait_list;pwait;pwait=pwait->next) {
		if (SVAL(req->in.hdr, HDR_MID) == SVAL(pwait->req->in.hdr, HDR_MID) &&
		    req->smbpid == pwait->req->smbpid) {
			/* trigger a cancel on the request */
			pwait->reason = PVFS_WAIT_CANCEL;
			ntvfs_async_setup(pwait->req, pwait);
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_UNSUCCESSFUL;
}
