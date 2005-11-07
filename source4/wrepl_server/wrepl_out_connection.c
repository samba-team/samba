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
#include "libcli/composite/composite.h"
#include "libcli/wrepl/winsrepl.h"
#include "wrepl_server/wrepl_out_helpers.h"

static void wreplsrv_pull_handler_te(struct event_context *ev, struct timed_event *te,
				     struct timeval t, void *ptr);

static void wreplsrv_pull_handler_creq(struct composite_context *creq)
{
	struct wreplsrv_partner *partner = talloc_get_type(creq->async.private_data, struct wreplsrv_partner);
	uint32_t interval;

	partner->pull.last_status = wreplsrv_pull_cycle_recv(partner->pull.creq);
	partner->pull.creq = NULL;
	talloc_free(partner->pull.cycle_io);
	partner->pull.cycle_io = NULL;

	if (!NT_STATUS_IS_OK(partner->pull.last_status)) {
		interval = partner->pull.error_count * partner->pull.retry_interval;
		interval = MIN(interval, partner->pull.interval);
		partner->pull.error_count++;

		DEBUG(1,("wreplsrv_pull_cycle(%s): %s: next: %us\n",
			 partner->address, nt_errstr(partner->pull.last_status),
			 interval));
	} else {
		interval = partner->pull.interval;
		partner->pull.error_count = 0;

		DEBUG(2,("wreplsrv_pull_cycle(%s): %s: next: %us\n",
			 partner->address, nt_errstr(partner->pull.last_status),
			 interval));
	}

	partner->pull.te = event_add_timed(partner->service->task->event_ctx, partner,
					   timeval_current_ofs(interval, 0),
					   wreplsrv_pull_handler_te, partner);
	if (!partner->pull.te) {
		DEBUG(0,("wreplsrv_pull_handler_creq: event_add_timed() failed! no memory!\n"));
	}
}

static void wreplsrv_pull_handler_te(struct event_context *ev, struct timed_event *te,
				     struct timeval t, void *ptr)
{
	struct wreplsrv_partner *partner = talloc_get_type(ptr, struct wreplsrv_partner);

	partner->pull.te = NULL;

	partner->pull.cycle_io = talloc(partner, struct wreplsrv_pull_cycle_io);
	if (!partner->pull.cycle_io) {
		goto requeue;
	}

	partner->pull.cycle_io->in.partner	= partner;
	partner->pull.cycle_io->in.num_owners	= 0;
	partner->pull.cycle_io->in.owners	= NULL;
	partner->pull.cycle_io->in.wreplconn	= NULL;
	partner->pull.creq = wreplsrv_pull_cycle_send(partner->pull.cycle_io, partner->pull.cycle_io);
	if (!partner->pull.creq) {
		DEBUG(1,("wreplsrv_pull_cycle_send(%s) failed\n",
			 partner->address));
		goto requeue;
	}

	partner->pull.creq->async.fn		= wreplsrv_pull_handler_creq;
	partner->pull.creq->async.private_data	= partner;

	return;
requeue:
	talloc_free(partner->pull.cycle_io);
	partner->pull.cycle_io = NULL;
	/* retry later */
	partner->pull.te = event_add_timed(partner->service->task->event_ctx, partner,
					   timeval_add(&t, partner->pull.retry_interval, 0),
					   wreplsrv_pull_handler_te, partner);
	if (!partner->pull.te) {
		DEBUG(0,("wreplsrv_pull_handler_te: event_add_timed() failed! no memory!\n"));
	}
}

NTSTATUS wreplsrv_sched_inform_action(struct wreplsrv_partner *partner, struct wrepl_table *inform_in)
{
	if (partner->pull.creq) {
		/* there's already a pull in progress, so we're done */
		return NT_STATUS_OK;
	}

	/* remove the scheduled pull */
	talloc_free(partner->pull.te);
	partner->pull.te = NULL;

	partner->pull.cycle_io = talloc(partner, struct wreplsrv_pull_cycle_io);
	if (!partner->pull.cycle_io) {
		goto requeue;
	}

	partner->pull.cycle_io->in.partner	= partner;
	partner->pull.cycle_io->in.num_owners	= inform_in->partner_count;
	partner->pull.cycle_io->in.owners	= inform_in->partners;
	talloc_steal(partner->pull.cycle_io, inform_in->partners);
	partner->pull.cycle_io->in.wreplconn	= NULL;
	partner->pull.creq = wreplsrv_pull_cycle_send(partner->pull.cycle_io, partner->pull.cycle_io);
	if (!partner->pull.creq) {
		DEBUG(1,("wreplsrv_pull_cycle_send(%s) failed\n",
			 partner->address));
		goto requeue;
	}

	partner->pull.creq->async.fn		= wreplsrv_pull_handler_creq;
	partner->pull.creq->async.private_data	= partner;

	return NT_STATUS_OK;
requeue:
	talloc_free(partner->pull.cycle_io);
	partner->pull.cycle_io = NULL;
	/* retry later */
	partner->pull.te = event_add_timed(partner->service->task->event_ctx, partner,
					   timeval_current_ofs(partner->pull.retry_interval, 0),
					   wreplsrv_pull_handler_te, partner);
	if (!partner->pull.te) {
		DEBUG(0,("wreplsrv_pull_handler_te: event_add_timed() failed! no memory!\n"));
	}

	return NT_STATUS_OK;
}

static void wreplsrv_push_handler_te(struct event_context *ev, struct timed_event *te,
				     struct timeval t, void *ptr);

static void wreplsrv_push_handler_creq(struct composite_context *creq)
{
	struct wreplsrv_partner *partner = talloc_get_type(creq->async.private_data, struct wreplsrv_partner);
	uint32_t interval;

	partner->push.last_status = wreplsrv_push_notify_recv(partner->push.creq);
	partner->push.creq = NULL;
	talloc_free(partner->push.notify_io);
	partner->push.notify_io = NULL;

	if (!NT_STATUS_IS_OK(partner->push.last_status)) {
		interval = 15;

		DEBUG(1,("wreplsrv_push_notify(%s): %s: next: %us\n",
			 partner->address, nt_errstr(partner->push.last_status),
			 interval));
	} else {
		interval = 100;

		DEBUG(2,("wreplsrv_push_notify(%s): %s: next: %us\n",
			 partner->address, nt_errstr(partner->push.last_status),
			 interval));
	}

	partner->push.te = event_add_timed(partner->service->task->event_ctx, partner,
					   timeval_current_ofs(interval, 0),
					   wreplsrv_push_handler_te, partner);
	if (!partner->push.te) {
		DEBUG(0,("wreplsrv_push_handler_creq: event_add_timed() failed! no memory!\n"));
	}
}

static void wreplsrv_push_handler_te(struct event_context *ev, struct timed_event *te,
				     struct timeval t, void *ptr)
{
	struct wreplsrv_partner *partner = talloc_get_type(ptr, struct wreplsrv_partner);

	partner->push.te = NULL;

	partner->push.notify_io = talloc(partner, struct wreplsrv_push_notify_io);
	if (!partner->push.notify_io) {
		goto requeue;
	}

	partner->push.notify_io->in.partner	= partner;
	partner->push.notify_io->in.inform	= False;
	partner->push.notify_io->in.propagate	= False;
	partner->push.creq = wreplsrv_push_notify_send(partner->push.notify_io, partner->push.notify_io);
	if (!partner->push.creq) {
		DEBUG(1,("wreplsrv_push_notify_send(%s) failed\n",
			 partner->address));
		goto requeue;
	}

	partner->push.creq->async.fn		= wreplsrv_push_handler_creq;
	partner->push.creq->async.private_data	= partner;

	return;
requeue:
	talloc_free(partner->push.notify_io);
	partner->push.notify_io = NULL;
	/* retry later */
	partner->push.te = event_add_timed(partner->service->task->event_ctx, partner,
					   timeval_add(&t, 5, 0),
					   wreplsrv_push_handler_te, partner);
	if (!partner->push.te) {
		DEBUG(0,("wreplsrv_push_handler_te: event_add_timed() failed! no memory!\n"));
	}
}

NTSTATUS wreplsrv_setup_out_connections(struct wreplsrv_service *service)
{
	struct wreplsrv_partner *cur;

	for (cur = service->partners; cur; cur = cur->next) {
		if ((cur->type & WINSREPL_PARTNER_PULL) && cur->pull.interval) {
			cur->pull.te = event_add_timed(service->task->event_ctx, cur,
						       timeval_zero(), wreplsrv_pull_handler_te, cur);
			NT_STATUS_HAVE_NO_MEMORY(cur->pull.te);
		}
		if ((cur->type & WINSREPL_PARTNER_PUSH) && cur->push.change_count) {
			cur->push.te = event_add_timed(service->task->event_ctx, cur,
						       timeval_zero(), wreplsrv_push_handler_te, cur);
			NT_STATUS_HAVE_NO_MEMORY(cur->push.te);
		}
	}

	return NT_STATUS_OK;
}
