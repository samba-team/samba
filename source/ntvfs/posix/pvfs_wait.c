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

#include "include/includes.h"
#include "vfs_posix.h"

/* the context for a single wait instance */
struct pvfs_wait {
	void (*handler)(void *, BOOL);
	void *private;
	struct timed_event *te;
	int msg_type;
	void *msg_ctx;
	struct event_context *ev;
};


/*
  receive a completion message for a wait
*/
static void pvfs_wait_dispatch(void *msg_ctx, void *private, uint32_t msg_type, 
			       servid_t src, DATA_BLOB *data)
{
	struct pvfs_wait *pwait = private;

	/* we need to check that this one is for us. This sender sends
	   the private pointer as the body of the message. This might
	   seem a little unusual, but as the pointer is guaranteed
	   unique for this server, it is a good token */
	if (data->length != sizeof(void *) ||
	    *(void **)data->data != pwait->private) {
		return;
	}

	pwait->handler(pwait->private, False);
}


/*
  receive a timeout on a message wait
*/
static void pvfs_wait_timeout(struct event_context *ev, struct timed_event *te, time_t t)
{
	struct pvfs_wait *pwait = te->private;
	pwait->handler(pwait->private, True);
}


/*
  destroy a pending wait
 */
static int pvfs_wait_destructor(void *ptr)
{
	struct pvfs_wait *pwait = ptr;
	messaging_deregister(pwait->msg_ctx, pwait->msg_type, pwait);
	event_remove_timed(pwait->ev, pwait->te);
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
			time_t end_time,
			void (*fn)(void *, BOOL),
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
	req->control_flags |= REQ_CONTROL_ASYNC;

	/* make sure we cleanup the timer and message handler */
	talloc_set_destructor(pwait, pvfs_wait_destructor);

	return pwait;
}
