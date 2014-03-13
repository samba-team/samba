/*
   Unix SMB/CIFS implementation.
   Infrastructure for async requests
   Copyright (C) Volker Lendecke 2008
   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/* Back-port of missing API from 4.2 for tevent_queues. */

#ifndef _SMBD_TEVENT_QUEUE_H_
#define _SMBD_TEVENT_QUEUE_H_
struct tevent_req *smbd_tevent_queue_wait_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tevent_queue *queue);

bool smbd_tevent_queue_wait_recv(struct tevent_req *req);
#endif
